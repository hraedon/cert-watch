"""Application services for user-visible alert read state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.audit import record_audit
from cert_watch.auth.scope import (
    ensure_write_scope,
    ensure_write_scope_on,
    require_auth_context,
)
from cert_watch.database import SqliteAlertRepository, get_write_lock
from cert_watch.database.connection import _connect, begin_immediate
from cert_watch.tags import parse_tags


class AlertNotFoundError(LookupError):
    """The requested alert does not exist."""


def mark_alert_read(db_path: str | Path, alert_id: str, *, auth: Any) -> bool:
    require_auth_context(auth)
    with get_write_lock(), _connect(db_path) as conn:
        # Advisory check keeps missing and out-of-scope alerts indistinguishable.
        row = conn.execute("SELECT cert_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        ensure_write_scope(auth, db_path, cert_id=row["cert_id"] if row else None)
        if row is None:
            raise AlertNotFoundError("alert not found")
        begin_immediate(conn)
        row = conn.execute("SELECT cert_id FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        ensure_write_scope_on(conn, auth, cert_id=row["cert_id"] if row else None)
        if row is None:
            raise AlertNotFoundError("alert not found")
        cursor = conn.execute("UPDATE alerts SET read = 1 WHERE id = ?", (alert_id,))
        conn.commit()
    return cursor.rowcount > 0


def mark_all_alerts_read(
    db_path: str | Path,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> int:
    require_auth_context(auth)
    scope_tags: tuple[str, ...] = ()
    if auth is not None and not getattr(auth, "is_admin", False):
        scope_tags = tuple(parse_tags(getattr(auth, "scope_tag", "") or ""))
    with get_write_lock():
        count = SqliteAlertRepository(db_path).mark_all_read(scope_tags)
    record_audit(
        db_path,
        actor=actor,
        action="alert.mark_all_read",
        target_type="alert",
        target_id="all",
        detail={"count": count},
        source_ip=source_ip,
    )
    return count
