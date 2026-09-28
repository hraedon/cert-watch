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
from cert_watch.auth.scope import ensure_write_scope_on, may_reveal_routing_identities
from cert_watch.config import Settings
from cert_watch.database import get_write_lock
from cert_watch.database.connection import _connect, begin_immediate
from cert_watch.tags import merge_tags, parse_tags


class RenewalReportNotFoundError(Exception):
    pass


class RenewalReportConflictError(Exception):
    pass


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
    report_id: int
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
    leaf_join = (
        "LEFT JOIN certificates c ON c.hostname=h.hostname AND c.port=h.port "
        "AND c.is_leaf=1 AND c.source='scanned'"
    )
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
                    JOIN certificates c ON c.hostname=h.hostname AND c.port=h.port
                     AND c.is_leaf=1 AND c.source='scanned'
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
    if getattr(auth, "principal_kind", "") == "renewal-report" and principal_id:
        return f"api_key:{principal_id}"
    return f"user:{principal_id or getattr(auth, 'username', '')}"


def _current_leaf(conn: sqlite3.Connection, host_id: str) -> tuple[str | None, str | None]:
    row = conn.execute(
        """SELECT c.fingerprint_sha256,c.not_after FROM hosts h
           LEFT JOIN certificates c ON c.hostname=h.hostname AND c.port=h.port
            AND c.is_leaf=1 AND c.source='scanned'
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
                old = conn.execute(
                    "SELECT body_sha256,response_body FROM renewal_idempotency "
                    "WHERE source=? AND key=?",
                    (source, idempotency_key),
                ).fetchone()
                if old is not None:
                    if old["body_sha256"] != body_sha256:
                        raise RenewalReportConflictError("idempotency key reused")
                    saved = json.loads(str(old["response_body"]))
                    conn.rollback()
                    return RenewalReportResult(**saved), True

            baseline_fingerprint, baseline_not_after = _current_leaf(conn, target.host_id)
            attempt = conn.execute(
                "SELECT * FROM renewal_attempts WHERE host_id=?", (target.host_id,)
            ).fetchone()
            if (
                attempt is not None
                and attempt["state"] == "open"
                and attempt["lease_expires_at"]
                and str(attempt["lease_expires_at"]) <= received_at
            ):
                conn.execute(
                    "UPDATE renewal_attempts SET state='abandoned',"
                    "suppresses_stalled=0,closed_reason='lease_expired' WHERE host_id=?",
                    (target.host_id,),
                )
                attempt = conn.execute(
                    "SELECT * FROM renewal_attempts WHERE host_id=?", (target.host_id,)
                ).fetchone()

            new_attempt = attempt is None
            effect = "applied"
            state = "open" if report.outcome == "started" else "failed"
            attempt_id = uuid.uuid4().hex
            previous_baseline: str | None = None
            if attempt is not None:
                current_state = str(attempt["state"])
                attempt_id = str(attempt["attempt_id"])
                previous_baseline = attempt["baseline_fingerprint"]
                same_correlation = bool(
                    report.correlation_id
                    and conn.execute(
                        "SELECT 1 FROM renewal_reports WHERE attempt_id=? "
                        "AND correlation_id=? LIMIT 1",
                        (attempt_id, report.correlation_id),
                    ).fetchone()
                )
                if current_state == "open":
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

            cursor = conn.execute(
                """INSERT INTO renewal_reports
                   (host_id,hostname_snapshot,port_snapshot,outcome,message,tool,
                    correlation_id,new_fingerprint,occurred_at,received_at,source,
                    effect,attempt_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
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
                suppresses = int(
                    report.outcome == "started"
                    and not (
                        previous_baseline == baseline_fingerprint
                        and attempt is not None
                        and attempt["state"] in ("abandoned", "failed")
                    )
                )
                lease = (
                    (received + renewal_lease_for(target, settings)).isoformat()
                    if report.outcome == "started"
                    else None
                )
                conn.execute(
                    """INSERT INTO renewal_attempts
                       (host_id,attempt_id,state,opened_seq,baseline_fingerprint,
                        baseline_not_after,new_fingerprint,lease_expires_at,
                        suppresses_stalled,received_at,next_check_at,closed_reason)
                       VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)
                       ON CONFLICT(host_id) DO UPDATE SET
                         attempt_id=excluded.attempt_id,state=excluded.state,
                         opened_seq=excluded.opened_seq,
                         baseline_fingerprint=excluded.baseline_fingerprint,
                         baseline_not_after=excluded.baseline_not_after,
                         new_fingerprint=excluded.new_fingerprint,
                         lease_expires_at=excluded.lease_expires_at,
                         suppresses_stalled=excluded.suppresses_stalled,
                         received_at=excluded.received_at,next_check_at=NULL,
                         closed_reason=excluded.closed_reason""",
                    (
                        target.host_id,
                        attempt_id,
                        state,
                        seq,
                        baseline_fingerprint,
                        baseline_not_after,
                        None,
                        lease,
                        suppresses,
                        received_at,
                        None if state == "open" else "reported_failed",
                    ),
                )
            elif effect == "applied" and state == "failed":
                conn.execute(
                    "UPDATE renewal_attempts SET state='failed',suppresses_stalled=0,"
                    "closed_reason='reported_failed' WHERE host_id=? AND attempt_id=?",
                    (target.host_id, attempt_id),
                )

            result = RenewalReportResult(seq, attempt_id, state, effect)
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
    clause = "cw_tags_overlap(c.tags,h.tags,?)=1" if scope else "1=1"
    params: list[Any] = [",".join(scope)] if scope else []
    with _connect(db_path) as conn:
        row = conn.execute(
            f"""SELECT h.id,h.hostname,h.port,h.tags,c.tags AS cert_tags,
                       c.fingerprint_sha256 AS baseline_fingerprint,
                       c.not_after AS baseline_not_after
                FROM hosts h LEFT JOIN certificates c
                  ON c.hostname=h.hostname AND c.port=h.port
                 AND c.is_leaf=1 AND c.source='scanned'
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
                     WHEN a.attempt_id=r.attempt_id AND a.state='open'
                          AND a.lease_expires_at<=? THEN 'abandoned'
                     WHEN a.attempt_id=r.attempt_id THEN a.state
                     WHEN r.outcome='failed' THEN 'failed'
                     ELSE 'abandoned' END AS state
                FROM renewal_reports r
                LEFT JOIN renewal_attempts a ON a.host_id=r.host_id
                WHERE r.host_id=?{source_filter}
                ORDER BY r.seq DESC LIMIT ? OFFSET ?""",
            [current, *params, limit, offset],
        ).fetchall()
    reveal = is_report_key or may_reveal_routing_identities(
        auth, merge_tags(target.cert_tags, target.tags)
    )
    items: list[dict[str, Any]] = []
    for row in rows:
        item = {
            "report_id": row["seq"],
            "attempt_id": row["attempt_id"],
            "outcome": row["outcome"],
            "occurred_at": row["occurred_at"],
            "received_at": row["received_at"],
            "state": row["state"],
            "effect": row["effect"],
            "correlation_id": row["correlation_id"],
            "new_fingerprint": row["new_fingerprint"],
        }
        if reveal:
            item.update(message=row["message"], tool=row["tool"], source=row["source"])
        items.append(item)
    return {"items": items, "page": page, "limit": limit, "total": total}


def expire_renewal_leases(db_path: str | Path, *, now: datetime | None = None) -> int:
    instant = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
    with get_write_lock(), _connect(db_path) as conn:
        cursor = conn.execute(
            "UPDATE renewal_attempts SET state='abandoned',suppresses_stalled=0,"
            "closed_reason='lease_expired' WHERE state='open' AND lease_expires_at<=?",
            (instant,),
        )
        conn.commit()
        return cursor.rowcount


def purge_renewal_reports(
    db_path: str | Path, retention_days: int, *, now: datetime | None = None
) -> int:
    """Keep each endpoint's newest 50 reports plus every row inside retention."""
    instant = now or datetime.now(UTC)
    cutoff = instant - timedelta(days=max(retention_days, 0))
    with get_write_lock(), _connect(db_path) as conn:
        deleted = 0
        if retention_days > 0:
            deleted = conn.execute(
                """DELETE FROM renewal_reports AS r
                   WHERE r.received_at < ? AND r.seq NOT IN (
                       SELECT kept.seq FROM renewal_reports kept
                       WHERE kept.host_id=r.host_id ORDER BY kept.seq DESC LIMIT 50
                   )""",
                (cutoff.astimezone(UTC).isoformat(),),
            ).rowcount
        conn.execute(
            "DELETE FROM renewal_idempotency WHERE created_at < ?",
            ((instant - timedelta(days=7)).astimezone(UTC).isoformat(),),
        )
        conn.commit()
        return deleted
