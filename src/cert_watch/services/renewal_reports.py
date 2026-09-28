"""Renewal-report targeting, state reduction and history (#118 S2)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.guards import renewal_report_binding
from cert_watch.auth.scope import (
    ScopeDeniedError,
    ensure_write_scope_on,
    may_reveal_routing_identities,
)
from cert_watch.config import Settings
from cert_watch.database import get_write_lock
from cert_watch.database.connection import _connect, begin_immediate
from cert_watch.database.renewal_attempts import renewal_attempt_is_live
from cert_watch.tags import parse_tags


class RenewalReportServiceError(Exception):
    pass


class RenewalReportNotFoundError(RenewalReportServiceError):
    pass


class RenewalReportConflictError(RenewalReportServiceError):
    pass


class RenewalReportRateLimitError(RenewalReportServiceError):
    pass


class RenewalStatusOutOfDateError(ValueError):
    """An HTML form omitted the status value it originally displayed."""


@dataclass(frozen=True)
class RenewalTarget:
    host_id: str
    hostname: str
    port: int
    tags: str
    cert_tags: str
    baseline_fingerprint: str | None
    baseline_not_after: str | None


@dataclass(frozen=True)
class RenewalReportInput:
    outcome: str
    message: str | None
    tool: str | None
    correlation_id: str | None
    new_fingerprint: str | None
    occurred_at: str | None


@dataclass(frozen=True)
class RenewalReportResult:
    report_id: str
    attempt_id: str
    state: str | None
    effect: str


def renewal_lease_for(endpoint: RenewalTarget | Mapping[str, Any], settings: Settings) -> timedelta:
    """The single renewal-attempt lease policy seam.

    ``endpoint`` is intentionally accepted even though S2 has only a global
    setting; a future per-endpoint override belongs here and nowhere else.
    """
    del endpoint
    return timedelta(hours=settings.renewal_report_lease_hours)


def _binding_clause(auth: Any, *, alias: str = "h") -> tuple[str, list[Any]]:
    binding = renewal_report_binding(auth)
    if binding == "all":
        return "1=1", []
    return f"cw_tags_overlap({alias}.tags, ?) = 1", [",".join(binding)]


def _target_from_row(row: sqlite3.Row) -> RenewalTarget:
    return RenewalTarget(
        host_id=str(row["id"]),
        hostname=str(row["hostname"]),
        port=int(row["port"]),
        tags=str(row["tags"] or ""),
        cert_tags=str(row["cert_tags"] or ""),
        baseline_fingerprint=(
            str(row["baseline_fingerprint"]).lower() if row["baseline_fingerprint"] else None
        ),
        baseline_not_after=(str(row["baseline_not_after"]) if row["baseline_not_after"] else None),
    )


def resolve_target(
    db_path: str | Path,
    auth: Any,
    *,
    hostname: str | None = None,
    port: int | None = None,
    cert_fingerprint: str | None = None,
) -> RenewalTarget:
    """Resolve an endpoint and its live key binding in one SQL statement."""
    clause, binding_params = _binding_clause(auth)
    # An old alias merge can leave two scanned leaves on one endpoint. Match
    # the same deterministic head used by dashboard/readiness and cert_ops.
    leaf_join = """LEFT JOIN certificates c ON c.rowid=(
        SELECT head.rowid FROM certificates head
        WHERE head.hostname=h.hostname AND head.port=h.port
          AND head.is_leaf=1 AND head.source='scanned'
        ORDER BY head.created_at DESC, head.rowid DESC LIMIT 1
    )"""
    with _connect(db_path) as conn:
        if hostname is not None and port is not None:
            rows = conn.execute(
                f"SELECT h.id,h.hostname,h.port,h.tags,c.tags AS cert_tags,"
                f"c.fingerprint_sha256 AS baseline_fingerprint,"
                f"c.not_after AS baseline_not_after FROM hosts h {leaf_join} "
                f"WHERE h.hostname=? AND h.port=? AND {clause}",
                [hostname, port, *binding_params],
            ).fetchall()
        else:
            assert cert_fingerprint is not None
            cutoff = (datetime.now(UTC) - timedelta(days=7)).isoformat()
            rows = conn.execute(
                f"""SELECT DISTINCT h.id,h.hostname,h.port,h.tags,c.tags AS cert_tags,
                           CASE WHEN lower(c.fingerprint_sha256)=? THEN c.fingerprint_sha256
                                ELSE ? END AS baseline_fingerprint,
                           CASE WHEN lower(c.fingerprint_sha256)=? THEN c.not_after
                                ELSE (SELECT ch.not_after FROM cert_history ch
                                      WHERE ch.hostname=h.hostname AND ch.port=h.port
                                        AND lower(ch.fingerprint_sha256)=?
                                      ORDER BY ch.scanned_at DESC LIMIT 1)
                           END AS baseline_not_after
                    FROM hosts h
                    JOIN certificates c ON c.rowid=(
                        SELECT head.rowid FROM certificates head
                        WHERE head.hostname=h.hostname AND head.port=h.port
                          AND head.is_leaf=1 AND head.source='scanned'
                        ORDER BY head.created_at DESC, head.rowid DESC LIMIT 1
                    )
                    WHERE {clause} AND (
                        lower(c.fingerprint_sha256)=? OR EXISTS (
                            SELECT 1 FROM certificate_lineage cl
                            WHERE cl.hostname=h.hostname AND cl.port=h.port
                              AND cl.new_cert_id=c.id AND cl.created_at>=?
                              AND lower(cl.old_fingerprint)=?
                        )
                    ) ORDER BY h.id LIMIT 2""",
                [
                    cert_fingerprint,
                    cert_fingerprint,
                    cert_fingerprint,
                    cert_fingerprint,
                    *binding_params,
                    cert_fingerprint,
                    cutoff,
                    cert_fingerprint,
                ],
            ).fetchall()
    if not rows:
        raise RenewalReportNotFoundError("endpoint not found")
    if len(rows) > 1:
        raise RenewalReportConflictError(
            "fingerprint matches more than one endpoint; send hostname and port"
        )
    return _target_from_row(rows[0])


def _source(auth: Any) -> str:
    principal_id = str(getattr(auth, "principal_id", "") or "")
    if getattr(auth, "principal_kind", "") in {"api-key", "renewal-report"} and principal_id:
        return f"api_key:{principal_id}"
    return f"user:{principal_id or getattr(auth, 'username', '')}"


def _cache_renewal_status(conn: sqlite3.Connection, host_id: str, *, now: datetime) -> str:
    """Refresh the legacy host column from the post-transition attempt state."""
    attempt = conn.execute(
        "SELECT state,lease_expires_at FROM renewal_attempts WHERE host_id=? AND is_current=1",
        (host_id,),
    ).fetchone()
    status = (
        "in_progress"
        if attempt is not None
        and renewal_attempt_is_live(str(attempt["state"]), attempt["lease_expires_at"], now=now)
        else "pending"
    )
    conn.execute("UPDATE hosts SET renewal_status=? WHERE id=?", (status, host_id))
    return status


def _open_failure(
    attempt: sqlite3.Row | None,
) -> tuple[str | None, str | None, str | None]:
    """Return the endpoint-cycle failure carried by *attempt*, if unresolved."""
    if (
        attempt is None
        or not attempt["failure_reported_at"]
        or attempt["failure_cleared_at"]
    ):
        return None, None, None
    return (
        str(attempt["failure_attempt_id"] or attempt["attempt_id"]),
        str(attempt["failure_reported_at"]),
        (
            str(attempt["failure_expected_fingerprint"])
            if attempt["failure_expected_fingerprint"]
            else None
        ),
    )


def _starts_failure_after_clear(
    attempt: sqlite3.Row | None, report: RenewalReportInput, effect: str
) -> bool:
    return bool(
        attempt is not None
        and report.outcome == "failed"
        and attempt["failure_reported_at"]
        and attempt["failure_cleared_at"]
        and effect != "ignored_late"
    )


def _restart_failure_after_clear(
    attempt: sqlite3.Row | None,
    report: RenewalReportInput,
    effect: str,
    *,
    state: str,
    new_attempt: bool,
    attempt_id: str,
) -> tuple[str, str, bool, str, bool]:
    if _starts_failure_after_clear(attempt, report, effect):
        assert attempt is not None
        # Manual clear ends only the failure condition. A later failure is a
        # fresh incident on the same renewal attempt; it must not change S4
        # verification state or make a not-deployed attempt non-current.
        return str(attempt["state"]), "applied", False, str(attempt["attempt_id"]), True
    return state, effect, new_attempt, attempt_id, False


def _record_failed_report_on(
    conn: sqlite3.Connection,
    *,
    attempt_id: str,
    state: str,
    received_at: str,
    reported_fingerprint: str | None,
    restarted: bool,
) -> None:
    if restarted:
        conn.execute(
            """UPDATE renewal_attempts
               SET failure_attempt_id=?,failure_reported_at=?,
                   failure_cleared_at=NULL,
                   failure_expected_fingerprint=?,
                   rule_due_at=?
               WHERE attempt_id=?""",
            (
                uuid.uuid4().hex,
                received_at,
                reported_fingerprint,
                received_at,
                attempt_id,
            ),
        )
        return
    conn.execute(
        """UPDATE renewal_attempts
           SET state=?,suppresses_stalled=0,
               failure_attempt_id=COALESCE(failure_attempt_id,attempt_id),
               failure_reported_at=COALESCE(failure_reported_at,?),
               failure_expected_fingerprint=COALESCE(
                   failure_expected_fingerprint,new_fingerprint,?),
               rule_due_at=?,
               closed_reason=CASE
                   WHEN ?='failed' THEN 'reported_failed' ELSE closed_reason END
           WHERE attempt_id=?""",
        (
            state,
            received_at,
            reported_fingerprint,
            received_at,
            state,
            attempt_id,
        ),
    )


def write_through_renewal_status_on(
    conn: sqlite3.Connection,
    db_path: str | Path,
    settings: Settings,
    host_id: str,
    status: str | None,
    *,
    seen_status: str | None = None,
    require_seen_status: bool = False,
    auth: Any,
    actor: str,
    source_ip: str | None,
    now: datetime | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Apply the compatibility ``renewal_status`` write inside its caller's transaction.

    The host-writing service owns ``BEGIN IMMEDIATE`` and its other audit row.
    This helper repeats the authoritative host-scope check, reduces the same
    attempt tables as report ingestion, and returns an audit event for export
    only after the caller commits.
    """
    if require_seen_status and seen_status == "":
        seen_status = None
    if status is not None and status not in {"pending", "in_progress"}:
        raise ValueError("invalid renewal status")
    if seen_status is not None and seen_status not in {"pending", "in_progress"}:
        raise ValueError("invalid seen renewal status")
    if (
        status == "pending"
        and status != seen_status
        and getattr(auth, "principal_kind", "") == "renewal-report"
    ):
        raise ScopeDeniedError("renewal-report keys cannot cancel renewal attempts")
    ensure_write_scope_on(conn, auth, host_id=host_id)
    host = conn.execute("SELECT id,hostname,port FROM hosts WHERE id=?", (host_id,)).fetchone()
    if host is None:
        raise RenewalReportNotFoundError("endpoint not found")
    received = (now or datetime.now(UTC)).astimezone(UTC)
    received_at = received.isoformat()
    attempt = conn.execute(
        "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1", (host_id,)
    ).fetchone()

    derived_status = (
        "in_progress"
        if attempt is not None
        and renewal_attempt_is_live(
            str(attempt["state"]), attempt["lease_expires_at"], now=received
        )
        else "pending"
    )
    if (
        require_seen_status
        and status is not None
        and seen_status is None
        and status != derived_status
    ):
        raise RenewalStatusOutOfDateError("The form is out of date; reload and try again.")
    # HTML submits the value it rendered separately from the selected value.
    # An unchanged stale form is a no-op regardless of the state at commit.
    # JSON omits ``seen_status`` and retains explicit-intent semantics.
    unchanged = (
        status is None
        or status == derived_status
        or (seen_status is not None and status == seen_status)
    )
    if unchanged:
        _cache_renewal_status(conn, host_id, now=received)
        return derived_status, None

    outcome = "started" if status == "in_progress" else "cancelled"

    baseline_fingerprint, baseline_not_after = _current_leaf(conn, host_id)
    effect = "applied"
    new_attempt = False
    if outcome == "started":
        if attempt is not None and attempt["state"] == "open":
            conn.execute(
                "UPDATE renewal_attempts SET state='abandoned',suppresses_stalled=0,"
                "closed_reason='lease_expired' WHERE attempt_id=?",
                (attempt["attempt_id"],),
            )
            attempt = conn.execute(
                "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1", (host_id,)
            ).fetchone()
        attempt_id = uuid.uuid4().hex
        new_attempt = True
    else:
        assert attempt is not None
        attempt_id = str(attempt["attempt_id"])

    failure_attempt_id, failure_reported_at, failure_expected = _open_failure(attempt)

    report_id = uuid.uuid4().hex
    cursor = conn.execute(
        """INSERT INTO renewal_reports
           (report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
            correlation_id,new_fingerprint,occurred_at,received_at,source,effect,attempt_id)
           VALUES (?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?,?,?,?)""",
        (
            report_id,
            host_id,
            host["hostname"],
            host["port"],
            outcome,
            received_at,
            _source(auth),
            effect,
            attempt_id,
        ),
    )
    if cursor.lastrowid is None:  # pragma: no cover - SQLite INSERT contract
        raise RuntimeError("renewal report insert returned no sequence")
    if new_attempt:
        conn.execute(
            "UPDATE renewal_attempts SET is_current=0 WHERE host_id=? AND is_current=1",
            (host_id,),
        )
        claims_baseline = int(
            conn.execute(
                """SELECT 1 FROM renewal_attempts
                   WHERE host_id=? AND baseline_fingerprint IS ?
                   LIMIT 1""",
                (host_id, baseline_fingerprint),
            ).fetchone()
            is None
        )
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                baseline_not_after,new_fingerprint,lease_expires_at,suppresses_stalled,
                received_at,next_check_at,closed_reason,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at,failure_expected_fingerprint,
                rule_due_at)
               VALUES (?,?,1,?,'open',?,?,?,NULL,?,?,?,NULL,NULL,?,?,?,?,?)""",
            (
                attempt_id,
                host_id,
                _source(auth),
                int(cursor.lastrowid),
                baseline_fingerprint,
                baseline_not_after,
                (
                    received
                    + renewal_lease_for(
                        RenewalTarget(
                            host_id,
                            str(host["hostname"]),
                            int(host["port"]),
                            "",
                            "",
                            baseline_fingerprint,
                            baseline_not_after,
                        ),
                        settings,
                    )
                ).isoformat(),
                claims_baseline,
                received_at,
                claims_baseline,
                failure_attempt_id,
                failure_reported_at,
                failure_expected,
                failure_reported_at,
            ),
        )
    elif outcome == "cancelled":
        conn.execute(
            """UPDATE renewal_attempts SET state='cancelled',suppresses_stalled=0,
               closed_reason='manual_cancelled' WHERE attempt_id=?""",
            (attempt_id,),
        )

    post_status = _cache_renewal_status(conn, host_id, now=received)
    audit_event = record_audit(
        db_path,
        actor=actor,
        action="renewal_report.create",
        target_type="host",
        target_id=host_id,
        detail={
            "attempt_id": attempt_id,
            "effect": effect,
            "outcome": outcome,
            "report_id": report_id,
            "source": _source(auth),
        },
        source_ip=source_ip,
        conn=conn,
    )
    return post_status, audit_event


def clear_renewal_failure(
    db_path: str | Path,
    host_id: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    now: datetime | None = None,
) -> bool:
    """Explicitly clear every unresolved failure condition for one endpoint."""
    if auth is None:
        raise ScopeDeniedError("authenticated principal required")
    cleared_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    audit_event: dict[str, Any] | None = None
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            host = conn.execute(
                "SELECT id FROM hosts WHERE id=?", (host_id,)
            ).fetchone()
            if host is None:
                raise RenewalReportNotFoundError("endpoint not found")
            ensure_write_scope_on(conn, auth, host_id=host_id)
            cursor = conn.execute(
                """UPDATE renewal_attempts
                   SET failure_cleared_at=?,closed_reason='manual_clear',rule_due_at=?
                   WHERE host_id=? AND failure_reported_at IS NOT NULL
                     AND failure_cleared_at IS NULL""",
                (cleared_at, cleared_at, host_id),
            )
            changed = cursor.rowcount > 0
            if changed:
                audit_event = record_audit(
                    db_path,
                    actor=actor,
                    action="renewal_failure.clear",
                    target_type="host",
                    target_id=host_id,
                    detail={"cleared": True, "closed_reason": "manual_clear"},
                    source_ip=source_ip,
                    conn=conn,
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(audit_event)
    return changed


def _current_leaf(conn: sqlite3.Connection, host_id: str) -> tuple[str | None, str | None]:
    row = conn.execute(
        """SELECT c.fingerprint_sha256,c.not_after FROM hosts h
           LEFT JOIN certificates c ON c.rowid=(
               SELECT head.rowid FROM certificates head
               WHERE head.hostname=h.hostname AND head.port=h.port
                 AND head.is_leaf=1 AND head.source='scanned'
               ORDER BY head.created_at DESC, head.rowid DESC LIMIT 1
           )
           WHERE h.id=?""",
        (host_id,),
    ).fetchone()
    if row is None:
        raise RenewalReportNotFoundError("endpoint not found")
    return (
        str(row["fingerprint_sha256"]).lower() if row["fingerprint_sha256"] else None,
        str(row["not_after"]) if row["not_after"] else None,
    )


def _evaluate_succeeded_on(
    conn: sqlite3.Connection,
    attempt_id: str,
    baseline_fingerprint: str | None,
    *,
    received: datetime,
    settings: Settings,
) -> str:
    from cert_watch.renewal_verification import evaluate_evidence_on

    current_attempt = conn.execute(
        "SELECT * FROM renewal_attempts WHERE attempt_id=?", (attempt_id,)
    ).fetchone()
    assert current_attempt is not None
    return evaluate_evidence_on(
        conn,
        current_attempt,
        baseline_fingerprint,
        started_at=received,
        settings=settings,
        count_check=False,
    ).state


def _report_baseline(
    conn: sqlite3.Connection,
    target: RenewalTarget,
    current_fingerprint: str | None,
    current_not_after: str | None,
    *,
    received: datetime,
    use_current_predecessor: bool,
) -> tuple[str | None, str | None]:
    """Choose a safe, recent predecessor or the currently served leaf."""
    candidate = (
        target.baseline_fingerprint.lower() if target.baseline_fingerprint else None
    )
    requested_predecessor = (
        candidate if candidate is not None and candidate != current_fingerprint else None
    )
    observation_cutoff = (received - timedelta(hours=24)).isoformat()
    if current_fingerprint is not None and (
        use_current_predecessor or requested_predecessor is not None
    ):
        predecessor = conn.execute(
            """SELECT lower(cl.old_fingerprint) AS fingerprint,
                      COALESCE(
                          (SELECT old.not_after FROM certificates old
                           WHERE old.id=cl.old_cert_id),
                          (SELECT ch.not_after FROM cert_history ch
                           WHERE ch.hostname=cl.hostname AND ch.port=cl.port
                             AND lower(ch.fingerprint_sha256)=lower(cl.old_fingerprint)
                           ORDER BY ch.scanned_at DESC LIMIT 1)
                      ) AS not_after
               FROM certificate_lineage cl
               JOIN certificates current ON current.id=cl.new_cert_id
               WHERE cl.hostname=? AND cl.port=?
                 AND lower(current.fingerprint_sha256)=?
                 AND cl.old_fingerprint IS NOT NULL AND cl.created_at>=?
                 AND (? IS NULL OR lower(cl.old_fingerprint)=?)
                 AND NOT EXISTS (
                     SELECT 1 FROM certificate_lineage flap
                     WHERE flap.hostname=cl.hostname AND flap.port=cl.port
                       AND lower(flap.old_fingerprint)=?
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM renewal_attempts used
                     JOIN hosts used_host ON used_host.id=used.host_id
                     WHERE used_host.hostname=cl.hostname AND used_host.port=cl.port
                       AND (lower(used.baseline_fingerprint)=?
                            OR lower(used.verified_fingerprint)=?)
                 )
               ORDER BY cl.created_at DESC LIMIT 1""",
            (
                target.hostname,
                target.port,
                current_fingerprint,
                observation_cutoff,
                requested_predecessor,
                requested_predecessor,
                current_fingerprint,
                current_fingerprint,
                current_fingerprint,
            ),
        ).fetchone()
        if predecessor is not None:
            return str(predecessor["fingerprint"]), (
                str(predecessor["not_after"]) if predecessor["not_after"] else None
            )
    return current_fingerprint, current_not_after


def _fingerprint_not_after(
    conn: sqlite3.Connection,
    target: RenewalTarget,
    fingerprint: str,
) -> str | None:
    row = conn.execute(
        """SELECT not_after FROM (
               SELECT c.not_after AS not_after, c.created_at AS observed_at
               FROM certificates c
               WHERE c.hostname=? AND c.port=? AND lower(c.fingerprint_sha256)=?
               UNION ALL
               SELECT ch.not_after, ch.scanned_at
               FROM cert_history ch
               WHERE ch.hostname=? AND ch.port=? AND lower(ch.fingerprint_sha256)=?
           ) ORDER BY observed_at DESC LIMIT 1""",
        (
            target.hostname,
            target.port,
            fingerprint,
            target.hostname,
            target.port,
            fingerprint,
        ),
    ).fetchone()
    return str(row["not_after"]) if row is not None and row["not_after"] else None


def _initial_evidence_on(
    conn: sqlite3.Connection,
    target: RenewalTarget,
    report: RenewalReportInput,
    received: datetime,
    *,
    use_current_predecessor: bool,
) -> tuple[str | None, str | None, str | None, str | None]:
    current_fingerprint, current_not_after = _current_leaf(conn, target.host_id)
    baseline_fingerprint, baseline_not_after = _report_baseline(
        conn,
        target,
        current_fingerprint,
        current_not_after,
        received=received,
        use_current_predecessor=use_current_predecessor,
    )
    if (
        report.outcome == "succeeded"
        and current_fingerprint is None
        and report.new_fingerprint is None
    ):
        raise RenewalReportConflictError(
            "endpoint has not been scanned yet; report again after its first scan"
        )
    return (
        current_fingerprint,
        current_not_after,
        baseline_fingerprint,
        baseline_not_after,
    )


def _insert_report_on(
    conn: sqlite3.Connection,
    *,
    report_id: str,
    host: sqlite3.Row,
    report: RenewalReportInput,
    received_at: str,
    source: str,
    effect: str,
    attempt_id: str,
) -> int:
    cursor = conn.execute(
        """INSERT INTO renewal_reports
           (report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
            correlation_id,new_fingerprint,occurred_at,received_at,source,effect,attempt_id)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            report_id,
            host["id"],
            host["hostname"],
            host["port"],
            report.outcome,
            report.message,
            report.tool,
            report.correlation_id,
            report.new_fingerprint,
            report.occurred_at,
            received_at,
            source,
            effect,
            attempt_id,
        ),
    )
    if cursor.lastrowid is None:  # pragma: no cover - SQLite INSERT contract
        raise RuntimeError("renewal report insert returned no sequence")
    return int(cursor.lastrowid)


def _preserve_contradictory_attempt(
    attempt: sqlite3.Row | None,
    *,
    contradictory: bool,
    state: str,
    new_attempt: bool,
    attempt_id: str,
    effect: str,
) -> tuple[str, bool, str, str]:
    if not contradictory:
        return state, new_attempt, attempt_id, effect
    if attempt is None:
        return "open", False, attempt_id, "no_change"
    return str(attempt["state"]), False, str(attempt["attempt_id"]), "no_change"


def _store_idempotency_on(
    conn: sqlite3.Connection,
    *,
    source: str,
    key: str | None,
    host_id: str,
    body_sha256: str,
    response_body: str,
    received_at: str,
) -> None:
    if key:
        conn.execute(
            """INSERT INTO renewal_idempotency
               (source,key,host_id,body_sha256,response_status,response_body,created_at)
               VALUES (?,?,?,?,202,?,?)""",
            (source, key, host_id, body_sha256, response_body, received_at),
        )


def _record_report_audit(
    db_path: str | Path,
    conn: sqlite3.Connection,
    report: RenewalReportInput,
    *,
    actor: str,
    host_id: str,
    source_ip: str | None,
) -> dict[str, Any] | None:
    message = report.message or ""
    return record_audit(
        db_path,
        actor=actor,
        action="renewal_report.create",
        target_type="host",
        target_id=host_id,
        detail={
            "outcome": report.outcome,
            "tool": report.tool,
            "correlation_id": report.correlation_id,
            "message_len": len(message),
            "message_sha256": hashlib.sha256(message.encode()).hexdigest(),
        },
        source_ip=source_ip,
        conn=conn,
    )


def _expire_current_attempt_on(
    conn: sqlite3.Connection,
    host_id: str,
    attempt: sqlite3.Row | None,
    *,
    received: datetime,
) -> sqlite3.Row | None:
    if (
        attempt is not None
        and attempt["state"] == "open"
        and not renewal_attempt_is_live(
            str(attempt["state"]), attempt["lease_expires_at"], now=received
        )
    ):
        conn.execute(
            "UPDATE renewal_attempts SET state='abandoned',"
            "suppresses_stalled=0,closed_reason='lease_expired' WHERE attempt_id=?",
            (attempt["attempt_id"],),
        )
        return cast(
            sqlite3.Row | None,
            conn.execute(
                "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1",
                (host_id,),
            ).fetchone(),
        )
    return attempt


def _update_succeeded_attempt_on(
    conn: sqlite3.Connection,
    attempt_id: str,
    report: RenewalReportInput,
    *,
    state: str,
    prior_state: str | None,
    received_at: str,
) -> None:
    """Apply a success without moving an existing verification anchor/check."""
    fingerprint_sql = "?" if prior_state == "failed" else "COALESCE(new_fingerprint,?)"
    if state == "verifying" and prior_state != "verifying":
        conn.execute(
            f"""UPDATE renewal_attempts SET state=?,suppresses_stalled=0,
                      new_fingerprint={fingerprint_sql},
                      success_received_at=?,
                      next_check_at=CASE
                          WHEN next_check_at IS NOT NULL AND next_check_at<=?
                          THEN next_check_at ELSE ? END,
                      closed_reason=NULL
               WHERE attempt_id=?""",
            (
                state,
                report.new_fingerprint,
                received_at,
                received_at,
                received_at,
                attempt_id,
            ),
        )
        return
    conn.execute(
        f"""UPDATE renewal_attempts SET state=?,suppresses_stalled=0,
                  new_fingerprint={fingerprint_sql}
           WHERE attempt_id=?""",
        (state, report.new_fingerprint, attempt_id),
    )


def _reduce_verified_success(
    conn: sqlite3.Connection,
    target: RenewalTarget,
    attempt: sqlite3.Row,
    report: RenewalReportInput,
    *,
    received: datetime,
    same_correlation: bool,
    baseline_fingerprint: str | None,
    baseline_not_after: str | None,
) -> tuple[str, str, bool, str, str | None, str | None]:
    """Separate a verified attempt's late reports from a new renewal cycle."""
    verified_leaf = (
        str(attempt["verified_fingerprint"]).lower()
        if attempt["verified_fingerprint"]
        else None
    )
    comparison_leaf = verified_leaf or baseline_fingerprint
    explicit_new_leaf = bool(
        report.new_fingerprint
        and (
            comparison_leaf is None
            or report.new_fingerprint.lower() != comparison_leaf.lower()
        )
    )
    succeeded_at = datetime.fromisoformat(
        str(attempt["success_received_at"] or attempt["received_at"])
    )
    if succeeded_at.tzinfo is None:
        succeeded_at = succeeded_at.replace(tzinfo=UTC)
    duplicate_window = received <= succeeded_at.astimezone(UTC) + timedelta(hours=24)
    if same_correlation or (duplicate_window and not explicit_new_leaf):
        return (
            "verified",
            "ignored_late",
            False,
            str(attempt["attempt_id"]),
            baseline_fingerprint,
            baseline_not_after,
        )
    if explicit_new_leaf and verified_leaf is not None:
        baseline_fingerprint = verified_leaf
        baseline_not_after = _fingerprint_not_after(conn, target, verified_leaf)
    return (
        "verifying",
        "applied",
        True,
        uuid.uuid4().hex,
        baseline_fingerprint,
        baseline_not_after,
    )


def _correlation_owner_on(
    conn: sqlite3.Connection,
    host_id: str,
    source: str,
    correlation_id: str | None,
    *,
    received: datetime,
) -> sqlite3.Row | None:
    if not correlation_id:
        return None
    owner = conn.execute(
        """SELECT a.* FROM renewal_attempt_correlations ac
           JOIN renewal_attempts a ON a.attempt_id=ac.attempt_id
           WHERE ac.host_id=? AND ac.source=? AND ac.correlation_id=?""",
        (host_id, source, correlation_id),
    ).fetchone()
    if owner is not None:
        return cast(sqlite3.Row, owner)
    correlation_cutoff = (received - timedelta(days=1)).isoformat()
    correlation_count = int(
        conn.execute(
            """SELECT count(*) FROM renewal_attempt_correlations
               WHERE host_id=? AND source=? AND created_at>=?""",
            (host_id, source, correlation_cutoff),
        ).fetchone()[0]
    )
    if correlation_count >= 1_000:
        raise RenewalReportRateLimitError("rate limited")
    return None


def create_report(
    db_path: str | Path,
    settings: Settings,
    target: RenewalTarget,
    report: RenewalReportInput,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    idempotency_key: str | None,
    body_sha256: str,
    now: datetime | None = None,
) -> tuple[RenewalReportResult, bool]:
    """Store a report and reduce the endpoint's one current attempt atomically.

    Returns ``(result, replayed)``. Target resolution is advisory; host
    existence and binding are checked again after ``BEGIN IMMEDIATE``.
    """
    received = (now or datetime.now(UTC)).astimezone(UTC)
    received_at = received.isoformat()
    source = _source(auth)
    audit_event: dict[str, Any] | None = None
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            host = conn.execute(
                "SELECT id,hostname,port,tags FROM hosts WHERE id=?",
                (target.host_id,),
            ).fetchone()
            if host is None:
                raise RenewalReportNotFoundError("endpoint not found")
            try:
                ensure_write_scope_on(conn, auth, host_id=target.host_id)
            except Exception as exc:
                from cert_watch.auth.scope import ScopeDeniedError

                if isinstance(exc, ScopeDeniedError):
                    raise RenewalReportNotFoundError("endpoint not found") from None
                raise

            if idempotency_key:
                binding_clause, binding_params = _binding_clause(auth)
                old = conn.execute(
                    f"""SELECT ri.host_id,ri.body_sha256,ri.response_body,
                               EXISTS(SELECT 1 FROM hosts h
                                      WHERE h.id=ri.host_id AND {binding_clause}) AS in_binding
                        FROM renewal_idempotency ri WHERE ri.source=? AND ri.key=?""",
                    [*binding_params, source, idempotency_key],
                ).fetchone()
                if old is not None and not old["in_binding"]:
                    # An idempotency row is visible only while its endpoint is
                    # live in this caller's binding. Replacing an invisible row
                    # makes moved and deleted endpoints indistinguishable.
                    conn.execute(
                        "DELETE FROM renewal_idempotency WHERE source=? AND key=?",
                        (source, idempotency_key),
                    )
                    old = None
                if old is not None:
                    if old["host_id"] != target.host_id or old["body_sha256"] != body_sha256:
                        raise RenewalReportConflictError("idempotency key reused")
                    saved = json.loads(str(old["response_body"]))
                    conn.rollback()
                    return RenewalReportResult(**saved), True

            attempt = conn.execute(
                "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1",
                (target.host_id,),
            ).fetchone()
            attempt = _expire_current_attempt_on(conn, target.host_id, attempt, received=received)
            carried_failure_id, carried_failure_at, carried_failure_expected = (
                _open_failure(attempt)
            )

            (
                current_fingerprint,
                current_not_after,
                baseline_fingerprint,
                baseline_not_after,
            ) = _initial_evidence_on(
                conn,
                target,
                report,
                received,
                use_current_predecessor=False,
            )

            new_attempt = attempt is None
            prior_state = str(attempt["state"]) if attempt is not None else None
            effect = "applied"
            state = {
                "started": "open",
                "failed": "failed",
                "succeeded": "verifying",
            }[report.outcome]
            attempt_id = uuid.uuid4().hex
            correlation_owner = _correlation_owner_on(
                conn,
                target.host_id,
                source,
                report.correlation_id,
                received=received,
            )

            # While correlation ownership is retained, a stale retry belongs
            # to its original attempt and cannot reopen newer work or mint
            # another suppression lease.
            if correlation_owner is not None and (
                attempt is None or correlation_owner["attempt_id"] != attempt["attempt_id"]
            ):
                attempt_id = str(correlation_owner["attempt_id"])
                state = str(correlation_owner["state"])
                effect = "ignored_late"
                new_attempt = False
            if attempt is not None:
                current_state = str(attempt["state"])
                if effect == "ignored_late":
                    pass
                else:
                    attempt_id = str(attempt["attempt_id"])
                same_correlation = bool(
                    correlation_owner is not None
                    and correlation_owner["attempt_id"] == attempt["attempt_id"]
                )
                if effect == "ignored_late":
                    pass
                elif current_state == "open":
                    if report.outcome == "started":
                        state, effect = "open", "duplicate"
                    elif report.outcome == "succeeded":
                        state, effect = "verifying", "applied"
                    else:
                        state, effect = "failed", "applied"
                elif current_state in ("verifying", "not_deployed"):
                    if report.outcome == "failed" and current_state == "not_deployed":
                        state, effect = "not_deployed", "no_change"
                    elif report.outcome == "failed":
                        state, effect = "failed", "applied"
                    elif report.outcome == "succeeded":
                        state = current_state
                        effect = (
                            "applied"
                            if report.new_fingerprint and not attempt["new_fingerprint"]
                            else "no_change"
                        )
                    else:
                        state, effect, new_attempt = (
                            current_state,
                            "ignored_late",
                            False,
                        )
                elif current_state == "failed" and report.outcome == "failed":
                    state, effect = "failed", "no_change"
                elif current_state == "failed" and report.outcome == "succeeded":
                    state, effect = "verifying", "applied"
                elif current_state == "verified" and report.outcome == "succeeded":
                    (
                        state,
                        effect,
                        new_attempt,
                        attempt_id,
                        baseline_fingerprint,
                        baseline_not_after,
                    ) = _reduce_verified_success(
                        conn,
                        target,
                        attempt,
                        report,
                        received=received,
                        same_correlation=same_correlation,
                        baseline_fingerprint=baseline_fingerprint,
                        baseline_not_after=baseline_not_after,
                    )
                elif current_state == "verified" and (
                    report.outcome == "failed"
                    and attempt["baseline_fingerprint"] == baseline_fingerprint
                ):
                    state, effect, new_attempt = "verified", "ignored_late", False
                elif report.outcome == "started" and same_correlation:
                    state, effect, new_attempt = current_state, "ignored_late", False
                else:
                    new_attempt = True
                    attempt_id = uuid.uuid4().hex

                # A manual clear ends the old failure condition. Any later
                # accepted failure starts a new cycle, even when the ordinary
                # state/correlation reducer would reuse this attempt.
            state, effect, new_attempt, attempt_id, restarted_failure = (
                _restart_failure_after_clear(
                    attempt,
                    report,
                    effect,
                    state=state,
                    new_attempt=new_attempt,
                    attempt_id=attempt_id,
                )
            )

            if (
                new_attempt
                and report.outcome == "succeeded"
                and (
                    report.new_fingerprint is None
                    or (
                        prior_state != "verified"
                        and current_fingerprint is not None
                        and report.new_fingerprint.lower() == current_fingerprint
                    )
                )
            ):
                baseline_fingerprint, baseline_not_after = _report_baseline(
                    conn,
                    target,
                    current_fingerprint,
                    current_not_after,
                    received=received,
                    use_current_predecessor=True,
                )

            contradictory = bool(
                report.outcome == "succeeded"
                and report.new_fingerprint
                and baseline_fingerprint
                and report.new_fingerprint.lower() == baseline_fingerprint.lower()
            )

            # Preserve the report for audit/history, but a claimed fingerprint
            # that is the baseline is not renewal evidence and changes no live
            # attempt. A first-ever contradictory report is report history only;
            # it must not create an unleased open attempt.
            state, new_attempt, attempt_id, effect = _preserve_contradictory_attempt(
                attempt,
                contradictory=contradictory,
                state=state,
                new_attempt=new_attempt,
                attempt_id=attempt_id,
                effect=effect,
            )

            report_id = uuid.uuid4().hex
            seq = _insert_report_on(
                conn,
                report_id=report_id,
                host=host,
                report=report,
                received_at=received_at,
                source=source,
                effect=effect,
                attempt_id=attempt_id,
            )
            if new_attempt:
                conn.execute(
                    "UPDATE renewal_attempts SET is_current=0 WHERE host_id=? AND is_current=1",
                    (target.host_id,),
                )
                claims_baseline = int(
                    conn.execute(
                        """SELECT 1 FROM renewal_attempts
                           WHERE host_id=? AND baseline_fingerprint IS ?
                           LIMIT 1""",
                        (target.host_id, baseline_fingerprint),
                    ).fetchone()
                    is None
                )
                suppresses = int(report.outcome == "started" and claims_baseline)
                lease = (
                    (received + renewal_lease_for(target, settings)).astimezone(UTC).isoformat()
                    if report.outcome == "started"
                    else None
                )
                conn.execute(
                    """INSERT INTO renewal_attempts
                       (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                        baseline_not_after,new_fingerprint,lease_expires_at,
                        suppresses_stalled,received_at,next_check_at,closed_reason,
                        success_received_at,failure_attempt_id,failure_reported_at,
                        failure_expected_fingerprint,rule_due_at,
                        baseline_lease_claimed)
                       VALUES (?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        attempt_id,
                        target.host_id,
                        source,
                        state,
                        seq,
                        baseline_fingerprint,
                        baseline_not_after,
                        (
                            report.new_fingerprint
                            if state in {"failed", "verifying"} and not contradictory
                            else None
                        ),
                        lease,
                        suppresses,
                        received_at,
                        received_at if state == "verifying" else None,
                        None if state in {"open", "verifying"} else "reported_failed",
                        received_at if state == "verifying" else None,
                        carried_failure_id
                        or (attempt_id if state == "failed" else None),
                        carried_failure_at
                        or (received_at if state == "failed" else None),
                        carried_failure_expected
                        or (report.new_fingerprint if state == "failed" else None),
                        carried_failure_at
                        or (received_at if state == "failed" else None),
                        claims_baseline,
                    ),
                )
            elif report.outcome == "failed" and effect in {"applied", "no_change"}:
                _record_failed_report_on(
                    conn,
                    attempt_id=attempt_id,
                    state=state,
                    received_at=received_at,
                    reported_fingerprint=report.new_fingerprint,
                    restarted=restarted_failure,
                )
            elif (
                report.outcome == "succeeded"
                and effect in {"applied", "no_change"}
                and not contradictory
            ):
                _update_succeeded_attempt_on(
                    conn,
                    attempt_id,
                    report,
                    state=state,
                    prior_state=prior_state,
                    received_at=received_at,
                )

            if (
                report.outcome == "succeeded"
                and effect != "ignored_late"
                and not contradictory
                and prior_state != "not_deployed"
            ):
                state = _evaluate_succeeded_on(
                    conn,
                    attempt_id,
                    current_fingerprint,
                    received=received,
                    settings=settings,
                )

            _cache_renewal_status(conn, target.host_id, now=received)

            if (
                report.correlation_id
                and effect != "ignored_late"
                and (attempt is not None or new_attempt)
            ):
                conn.execute(
                    """INSERT INTO renewal_attempt_correlations
                       (host_id,source,correlation_id,attempt_id,created_at)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(host_id,source,correlation_id) DO UPDATE SET
                           attempt_id=excluded.attempt_id""",
                    (target.host_id, source, report.correlation_id, attempt_id, received_at),
                )

            response_state = None if contradictory and attempt is None else state
            result = RenewalReportResult(report_id, attempt_id, response_state, effect)
            response_body = json.dumps(result.__dict__, separators=(",", ":"), sort_keys=True)
            _store_idempotency_on(
                conn,
                source=source,
                key=idempotency_key,
                host_id=target.host_id,
                body_sha256=body_sha256,
                response_body=response_body,
                received_at=received_at,
            )
            # Audit detail is the deliberate admin-only exception to report
            # field confinement: tool and correlation aid incident tracing,
            # while free-form message content remains hash-and-length only.
            audit_event = _record_report_audit(
                db_path,
                conn,
                report,
                actor=actor,
                host_id=target.host_id,
                source_ip=source_ip,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(audit_event)
    return result, False


def resolve_history_target(
    db_path: str | Path, auth: Any, hostname: str, port: int
) -> RenewalTarget:
    """Resolve GET visibility in one statement for either supported principal."""
    if getattr(auth, "principal_kind", "") == "renewal-report":
        return resolve_target(db_path, auth, hostname=hostname, port=port)
    scope = tuple(parse_tags(getattr(auth, "scope_tag", "") or ""))
    # Session readers use normal effective certificate+host visibility, while
    # reporting keys deliberately use the narrower host-tag binding above.
    clause = "cw_tags_overlap(c.tags,h.tags,?)=1" if scope else "1=1"
    params: list[Any] = [",".join(scope)] if scope else []
    with _connect(db_path) as conn:
        row = conn.execute(
            f"""SELECT h.id,h.hostname,h.port,h.tags,c.tags AS cert_tags,
                       c.fingerprint_sha256 AS baseline_fingerprint,
                       c.not_after AS baseline_not_after
                FROM hosts h LEFT JOIN certificates c ON c.rowid=(
                    SELECT head.rowid FROM certificates head
                    WHERE head.hostname=h.hostname AND head.port=h.port
                      AND head.is_leaf=1 AND head.source='scanned'
                    ORDER BY head.created_at DESC, head.rowid DESC LIMIT 1
                )
                WHERE h.hostname=? AND h.port=? AND ({clause}) LIMIT 1""",
            [hostname, port, *params],
        ).fetchone()
    if row is None:
        raise RenewalReportNotFoundError("endpoint not found")
    return _target_from_row(row)


def list_reports(
    db_path: str | Path,
    target: RenewalTarget,
    *,
    auth: Any,
    page: int,
    limit: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    page = max(1, min(page, 10_000))
    limit = max(1, min(limit, 100))
    source_filter = ""
    params: list[Any] = [target.host_id]
    is_report_key = getattr(auth, "principal_kind", "") == "renewal-report"
    if is_report_key:
        source_filter = " AND r.source=?"
        params.append(_source(auth))
    offset = (page - 1) * limit
    current = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    with _connect(db_path) as conn:
        total = int(
            conn.execute(
                f"SELECT count(*) FROM renewal_reports r WHERE r.host_id=?{source_filter}",
                params,
            ).fetchone()[0]
        )
        rows = conn.execute(
            f"""SELECT r.*, CASE
                     WHEN a.state='open'
                          AND julianday(a.lease_expires_at)<=julianday(?) THEN 'abandoned'
                     ELSE COALESCE(
                         a.state,
                         CASE WHEN r.outcome='failed' THEN 'failed' ELSE 'abandoned' END
                     ) END AS state
                FROM renewal_reports r
                LEFT JOIN renewal_attempts a ON a.attempt_id=r.attempt_id
                WHERE r.host_id=?{source_filter}
                ORDER BY r.seq DESC LIMIT ? OFFSET ?""",
            [current, *params, limit, offset],
        ).fetchall()
    reveal = is_report_key or may_reveal_routing_identities(auth, parse_tags(target.tags))
    items: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "report_id": row["report_id"],
            "attempt_id": row["attempt_id"],
            "outcome": row["outcome"],
            "occurred_at": row["occurred_at"],
            "received_at": row["received_at"],
            "state": row["state"],
            "effect": row["effect"],
            "new_fingerprint": row["new_fingerprint"],
        }
        if reveal:
            item.update(
                message=row["message"],
                tool=row["tool"],
                source=row["source"],
                correlation_id=row["correlation_id"],
            )
        items.append(item)
    return {"items": items, "page": page, "limit": limit, "total": total}


def expire_renewal_leases(db_path: str | Path, *, now: datetime | None = None) -> int:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    instant = current.isoformat()
    with get_write_lock(), _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE renewal_attempts SET state='abandoned',suppresses_stalled=0,"
            "closed_reason='lease_expired' WHERE is_current=1 AND state='open' "
            "AND cw_epoch_ms(lease_expires_at)<=cw_epoch_ms(?)",
            (instant,),
        )
        conn.execute(
            "UPDATE hosts AS h SET renewal_status='pending' WHERE EXISTS ("
            "SELECT 1 FROM renewal_attempts a WHERE a.host_id=h.id "
            "AND a.is_current=1 AND a.state='abandoned' "
            "AND a.closed_reason='lease_expired' "
            "AND cw_epoch_ms(a.lease_expires_at)<=cw_epoch_ms(?))",
            (instant,),
        )
        conn.commit()
        return cursor.rowcount


def purge_renewal_reports(
    db_path: str | Path, retention_days: int, *, now: datetime | None = None
) -> int:
    """Apply report, attempt, correlation and idempotency retention."""
    instant = now or datetime.now(UTC)
    cutoff = instant - timedelta(days=max(retention_days, 0))
    with get_write_lock(), _connect(db_path) as conn:
        deleted = 0
        if retention_days > 0:
            cutoff_iso = cutoff.astimezone(UTC).isoformat()
            deleted = conn.execute(
                """DELETE FROM renewal_reports AS r
                   WHERE r.received_at < ? AND r.seq NOT IN (
                       SELECT kept.seq FROM renewal_reports kept
                       WHERE kept.host_id=r.host_id ORDER BY kept.seq DESC LIMIT 50
                   )""",
                (cutoff_iso,),
            ).rowcount
            conn.execute(
                "DELETE FROM renewal_attempt_correlations WHERE created_at < ?",
                (cutoff_iso,),
            )
            conn.execute(
                """DELETE FROM renewal_attempts AS a
                   WHERE a.received_at < ? AND a.is_current=0
                     AND NOT EXISTS (
                         SELECT 1 FROM renewal_reports r
                         WHERE r.attempt_id=a.attempt_id
                     )
                     AND a.attempt_id NOT IN (
                         SELECT kept.attempt_id FROM renewal_attempts kept
                         WHERE kept.host_id=a.host_id
                           AND kept.baseline_fingerprint IS a.baseline_fingerprint
                           AND kept.baseline_lease_claimed=1
                         ORDER BY kept.opened_seq DESC LIMIT 1
                     )""",
                (cutoff_iso,),
            )
        conn.execute(
            "DELETE FROM renewal_idempotency WHERE created_at < ?",
            ((instant - timedelta(days=7)).astimezone(UTC).isoformat(),),
        )
        conn.commit()
        return deleted
