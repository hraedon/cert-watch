"""Audit log — append-only record of state-changing actions."""

from __future__ import annotations

import json
import logging
import sqlite3
import typing
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Request

from cert_watch.database.connection import _connect

logger = logging.getLogger("cert_watch.audit")


class _ApiKeyAuditActor(str):
    """String-compatible actor carrying the key name to the audit writer."""

    api_key_name: str

    def __new__(cls, key_id: str, key_name: str) -> _ApiKeyAuditActor:
        value = super().__new__(cls, f"api_key:{key_id}")
        value.api_key_name = key_name
        return value


def record_audit(
    db_path: str | Path,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: dict[str, Any] | None = None,
    source_ip: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Insert one audit row. Best-effort; logs WARNING on failure but never raises
    when *conn* is None. When *conn* is provided, re-raises so the caller can
    roll back the transaction — the audit entry is part of the caller's
    transaction and a failure must not be silently swallowed.

    When *conn* is provided, the insert is written without committing — the
    caller manages the transaction (WI-129). This allows the audit entry to
    be part of the same transaction as the mutation it records, so a crash
    between the mutation and the audit write rolls back both.

    SIEM export is network I/O, so it never runs inside the caller's
    transaction: with *conn*, the SIEM event is returned instead of sent, and
    the caller passes it to :func:`export_audit` after it commits and releases
    the write lock. Without *conn*, the row is committed here and the event is
    exported immediately; the return value is then ``None``.
    """
    ts = datetime.now(UTC).isoformat()
    try:
        api_key_name = getattr(actor, "api_key_name", "")
        if api_key_name:
            detail = {**(detail or {}), "api_key_name": api_key_name}
        actor = actor[:256] if actor else actor
        target_id = target_id[:256] if target_id else target_id
        row_id = uuid.uuid4().hex
        detail_json = json.dumps(detail, default=str) if detail else None
        if conn is not None:
            conn.execute(
                "INSERT INTO audit_log"
                " (id, ts, actor, action, target_type, target_id, detail, source_ip)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, ts, actor, action, target_type, target_id, detail_json, source_ip),
            )
        else:
            with _connect(db_path) as c:
                c.execute(
                    "INSERT INTO audit_log"
                    " (id, ts, actor, action, target_type, target_id, detail, source_ip)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (row_id, ts, actor, action, target_type, target_id, detail_json, source_ip),
                )
                c.commit()
    except Exception:
        if conn is not None:
            raise
        logger.warning(
            "audit write failed: action=%s target=%s/%s actor=%s",
            action, target_type, target_id, actor,
            exc_info=True,
        )

    event = {
        "event_type": "cert_watch.audit",
        "ts": ts,
        "actor": actor,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "detail": detail,
        "source_ip": source_ip,
    }
    if conn is not None:
        return event
    export_audit(event)
    return None


def export_audit(event: dict[str, Any] | None) -> None:
    """Send one committed audit event to the SIEM sinks (Plan 028).

    Fail-open and a no-op when no sink is configured. Call outside the write
    lock, after the audit row is committed (or its best-effort write has been
    attempted): a sink can block.
    """
    if not event:
        return
    try:
        from cert_watch.siem import export_audit_event, siem_enabled

        if siem_enabled():
            export_audit_event({**event, "instance": _siem_instance()})
    except Exception:
        logger.warning("siem audit export failed", exc_info=True)


def _siem_instance() -> str:
    from cert_watch.siem import _instance_id

    return _instance_id()


def purge_old_audit(db_path: str | Path, retention_days: int) -> int:
    """Delete audit rows older than *retention_days*. Returns the count deleted.

    A non-positive ``retention_days`` disables purging (returns 0). Best-effort:
    logs WARNING on failure but never raises, mirroring :func:`record_audit`.
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    try:
        with _connect(db_path) as conn:
            cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
            deleted = cur.rowcount
            conn.commit()
        if deleted:
            logger.info(
                "purged %d audit rows older than %d days", deleted, retention_days
            )
        return deleted
    except (sqlite3.Error, OSError):
        logger.warning("audit purge failed", exc_info=True)
        return 0


def list_audit(
    db_path: str | Path,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    actor: str | None = None,
    page: int = 1,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Query audit log with optional filters. Returns newest-first."""
    conditions: list[str] = []
    params: list[Any] = []
    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if target_id:
        conditions.append("target_id = ?")
        params.append(target_id)
    if actor:
        conditions.append("actor = ?")
        params.append(actor)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    offset = (page - 1) * limit
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM audit_log{where} ORDER BY ts DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    return [dict(r) for r in rows]


def count_audit(
    db_path: str | Path,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    actor: str | None = None,
) -> int:
    """Count audit rows with optional filters."""
    conditions: list[str] = []
    params: list[Any] = []
    if target_type:
        conditions.append("target_type = ?")
        params.append(target_type)
    if target_id:
        conditions.append("target_id = ?")
        params.append(target_id)
    if actor:
        conditions.append("actor = ?")
        params.append(actor)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    with _connect(db_path) as conn:
        row = conn.execute(f"SELECT COUNT(*) FROM audit_log{where}", params).fetchone()
    return row[0] if row else 0


def resolve_actor(request: Request) -> str:
    """Resolve the actor from a FastAPI Request object.

    Falls back to "anonymous" when auth is off or no user is set.
    """
    username = request.scope.get("auth_user", "")
    state = getattr(request, "state", None)
    context = getattr(state, "auth_context", None)
    principal_id = getattr(context, "principal_id", "")
    if principal_id:
        return _ApiKeyAuditActor(principal_id, username)
    return username or "anonymous"


def audit_actor_display(row: dict[str, Any]) -> str:
    """Human-readable actor label without changing the stored identity."""
    actor = row.get("actor") or "anonymous"
    if not actor.startswith("api_key:"):
        return actor
    key_id = actor.removeprefix("api_key:")
    try:
        detail = json.loads(row.get("detail") or "{}")
    except (json.JSONDecodeError, TypeError):
        detail = {}
    key_name = detail.get("api_key_name") if isinstance(detail, dict) else None
    name = str(key_name) if key_name else "API key"
    return f"{name} (API key {key_id[:8]})"


def resolve_source_ip(request: typing.Any) -> str | None:
    """Resolve source IP from a FastAPI Request object.

    Uses the proxy-aware IP extraction when CERT_WATCH_TRUST_PROXY is set.
    Returns None when the source IP cannot be determined.
    """
    try:
        from cert_watch.security.ratelimit import _extract_client_ip

        ip = _extract_client_ip(request)
        return ip if ip != "unknown" else None
    except Exception:
        logger.debug("proxy-aware IP extraction failed", exc_info=True)
        try:
            client = getattr(request, "client", None)
            return client.host if client else None
        except Exception:
            logger.debug("client IP fallback failed", exc_info=True)
            return None
