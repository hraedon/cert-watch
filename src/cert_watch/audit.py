"""Audit log — append-only record of state-changing actions."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database.connection import _connect

logger = logging.getLogger("cert_watch.audit")


def record_audit(
    db_path: str | Path,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str,
    detail: dict | None = None,
    source_ip: str | None = None,
) -> None:
    """Insert one audit row. Best-effort; logs WARNING on failure but never raises."""
    try:
        row_id = uuid.uuid4().hex
        ts = datetime.now(UTC).isoformat()
        detail_json = json.dumps(detail, default=str) if detail else None
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO audit_log"
                " (id, ts, actor, action, target_type, target_id, detail, source_ip)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (row_id, ts, actor, action, target_type, target_id, detail_json, source_ip),
            )
            conn.commit()
    except Exception:
        logger.warning(
            "audit write failed: action=%s target=%s/%s actor=%s",
            action, target_type, target_id, actor,
            exc_info=True,
        )


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
    except Exception:
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
) -> list[dict]:
    """Query audit log with optional filters. Returns newest-first."""
    conditions: list[str] = []
    params: list = []
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
            params + [limit, offset],
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
    params: list = []
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


def resolve_actor(request: object) -> str:
    """Resolve the actor from a FastAPI Request object.

    Falls back to "anonymous" when auth is off or no user is set.
    """
    try:
        return getattr(request, "scope", {}).get("auth_user", "") or "anonymous"
    except Exception:
        return "anonymous"


def resolve_source_ip(request: object) -> str | None:
    """Resolve source IP from a FastAPI Request object.

    Uses the proxy-aware IP extraction when CERT_WATCH_TRUST_PROXY is set.
    Returns None when the source IP cannot be determined.
    """
    try:
        from cert_watch.middleware import _extract_client_ip

        ip = _extract_client_ip(request)
        return ip if ip != "unknown" else None
    except Exception:
        try:
            client = getattr(request, "client", None)
            return client.host if client else None
        except Exception:
            return None