"""Alert and scan history pagination helpers."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema


def list_alerts_with_subject(db_path: str | Path, *, page: int = 1, limit: int = 0) -> list[dict]:
    """Return alerts joined with the cert subject, newest first.

    When ``limit > 0``, applies SQL-level pagination.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        if limit > 0:
            offset = max(0, (page - 1) * limit)
            rows = conn.execute(
                """
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                ORDER BY a.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                ORDER BY a.created_at DESC
                """
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Pagination helpers ----------


def _total_alerts(db_path: str | Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    return row[0] if row else 0


def _total_scan_history(db_path: str | Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
    return row[0] if row else 0


def list_scan_history(db_path: str | Path, *, page: int = 1, limit: int = 0) -> list[dict]:
    """Return scan_history rows, newest first.

    When ``limit > 0``, applies SQL-level pagination.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        if limit > 0:
            offset = max(0, (page - 1) * limit)
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY scanned_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY scanned_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Alert retention ----------


def purge_old_alerts(db_path: str | Path, retention_days: int) -> int:
    """Delete alerts rows older than *retention_days*. Returns count deleted.

    A non-positive ``retention_days`` disables purging (returns 0).
    """
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    try:
        init_schema(db_path)
        with _connect(db_path) as conn:
            cur = conn.execute("DELETE FROM alerts WHERE created_at < ?", (cutoff,))
            deleted = cur.rowcount
            conn.commit()
        if deleted:
            import logging
            logging.getLogger("cert_watch.database").info(
                "purged %d alert rows older than %d days", deleted, retention_days
            )
        return deleted
    except Exception:
        import logging
        logging.getLogger("cert_watch.database").warning("alert purge failed", exc_info=True)
        return 0
