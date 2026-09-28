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
from typing import Any

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


class RenewalReportUnavailableError(RenewalReportServiceError):
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
    state: str
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
                           c.fingerprint_sha256 AS baseline_fingerprint,
                           c.not_after AS baseline_not_after
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
                [*binding_params, cert_fingerprint, cutoff, cert_fingerprint],
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


def _cache_renewal_status(
    conn: sqlite3.Connection, host_id: str, *, now: datetime
) -> str:
    """Refresh the legacy host column from the post-transition attempt state."""
    attempt = conn.execute(
        "SELECT state,lease_expires_at FROM renewal_attempts "
        "WHERE host_id=? AND is_current=1",
        (host_id,),
    ).fetchone()
    status = (
        "in_progress"
        if attempt is not None
        and renewal_attempt_is_live(
            str(attempt["state"]), attempt["lease_expires_at"], now=now
        )
        else "pending"
    )
    conn.execute("UPDATE hosts SET renewal_status=? WHERE id=?", (status, host_id))
    return status


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
    host = conn.execute(
        "SELECT id,hostname,port FROM hosts WHERE id=?", (host_id,)
    ).fetchone()
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
        raise RenewalStatusOutOfDateError(
            "The form is out of date; reload and try again."
        )
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
            ).fetchone() is None
        )
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                baseline_not_after,new_fingerprint,lease_expires_at,suppresses_stalled,
                received_at,next_check_at,closed_reason,baseline_lease_claimed)
               VALUES (?,?,1,?,'open',?,?,?,NULL,?,?,?,NULL,NULL,?)""",
            (
                attempt_id,
                host_id,
                _source(auth),
                int(cursor.lastrowid),
                baseline_fingerprint,
                baseline_not_after,
                (received + renewal_lease_for(
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
                )).isoformat(),
                claims_baseline,
                received_at,
                claims_baseline,
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
    if report.outcome == "succeeded":
        raise RenewalReportUnavailableError("renewal verification is not available yet")
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

            baseline_fingerprint, baseline_not_after = _current_leaf(conn, target.host_id)
            attempt = conn.execute(
                "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1",
                (target.host_id,),
            ).fetchone()
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
                attempt = conn.execute(
                    "SELECT * FROM renewal_attempts WHERE host_id=? AND is_current=1",
                    (target.host_id,),
                ).fetchone()

            new_attempt = attempt is None
            effect = "applied"
            state = "open" if report.outcome == "started" else "failed"
            attempt_id = uuid.uuid4().hex
            correlation_owner = None
            if report.correlation_id:
                correlation_owner = conn.execute(
                    """SELECT a.* FROM renewal_attempt_correlations ac
                       JOIN renewal_attempts a ON a.attempt_id=ac.attempt_id
                       WHERE ac.host_id=? AND ac.source=? AND ac.correlation_id=?""",
                    (target.host_id, source, report.correlation_id),
                ).fetchone()
                if correlation_owner is None:
                    correlation_cutoff = (received - timedelta(days=1)).isoformat()
                    correlation_count = int(
                        conn.execute(
                            """SELECT count(*) FROM renewal_attempt_correlations
                               WHERE host_id=? AND source=? AND created_at>=?""",
                            (target.host_id, source, correlation_cutoff),
                        ).fetchone()[0]
                    )
                    if correlation_count >= 1_000:
                        raise RenewalReportRateLimitError("rate limited")

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
                    else:
                        state, effect = "failed", "applied"
                elif current_state in ("verifying", "not_deployed"):
                    if report.outcome == "failed":
                        state, effect = "failed", "applied"
                    else:
                        state, effect, new_attempt = (
                            current_state,
                            "ignored_late",
                            False,
                        )
                elif current_state == "failed" and report.outcome == "failed":
                    state, effect = "failed", "no_change"
                elif (
                    current_state == "verified"
                    and report.outcome == "failed"
                    and attempt["baseline_fingerprint"] == baseline_fingerprint
                ):
                    state, effect, new_attempt = "verified", "ignored_late", False
                elif report.outcome == "started" and same_correlation:
                    state, effect, new_attempt = current_state, "ignored_late", False
                else:
                    new_attempt = True
                    attempt_id = uuid.uuid4().hex

            report_id = uuid.uuid4().hex
            cursor = conn.execute(
                """INSERT INTO renewal_reports
                   (report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
                    correlation_id,new_fingerprint,occurred_at,received_at,source,
                    effect,attempt_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    report_id,
                    target.host_id,
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
            seq = int(cursor.lastrowid)
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
                    ).fetchone() is None
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
                        baseline_lease_claimed)
                       VALUES (?,?,1,?,?,?,?,?,?,?,?,?,NULL,?,?)""",
                    (
                        attempt_id,
                        target.host_id,
                        source,
                        state,
                        seq,
                        baseline_fingerprint,
                        baseline_not_after,
                        None,
                        lease,
                        suppresses,
                        received_at,
                        None if state == "open" else "reported_failed",
                        claims_baseline,
                    ),
                )
            elif effect == "applied" and state == "failed":
                conn.execute(
                    "UPDATE renewal_attempts SET state='failed',suppresses_stalled=0,"
                    "closed_reason='reported_failed' WHERE attempt_id=?",
                    (attempt_id,),
                )

            _cache_renewal_status(conn, target.host_id, now=received)

            if report.correlation_id and effect != "ignored_late":
                conn.execute(
                    """INSERT INTO renewal_attempt_correlations
                       (host_id,source,correlation_id,attempt_id,created_at)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(host_id,source,correlation_id) DO UPDATE SET
                           attempt_id=excluded.attempt_id""",
                    (target.host_id, source, report.correlation_id, attempt_id, received_at),
                )

            result = RenewalReportResult(report_id, attempt_id, state, effect)
            response_body = json.dumps(result.__dict__, separators=(",", ":"), sort_keys=True)
            if idempotency_key:
                conn.execute(
                    """INSERT INTO renewal_idempotency
                       (source,key,host_id,body_sha256,response_status,response_body,created_at)
                       VALUES (?,?,?,?,202,?,?)""",
                    (
                        source,
                        idempotency_key,
                        target.host_id,
                        body_sha256,
                        response_body,
                        received_at,
                    ),
                )
            message = report.message or ""
            # Audit detail is the deliberate admin-only exception to report
            # field confinement: tool and correlation aid incident tracing,
            # while free-form message content remains hash-and-length only.
            audit_event = record_audit(
                db_path,
                actor=actor,
                action="renewal_report.create",
                target_type="host",
                target_id=target.host_id,
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
