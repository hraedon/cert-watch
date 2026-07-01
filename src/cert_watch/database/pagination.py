"""Alert and scan history pagination helpers."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.schema import init_schema


def list_alerts_with_subject(
    db_path: str | Path,
    *,
    page: int = 1,
    limit: int = 0,
    unread_only: bool = False,
    critical_only: bool = False,
    warning_only: bool = False,
    scope_tags: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Return alerts joined with the cert subject, newest first.

    When ``limit > 0``, applies SQL-level pagination.
    Filters:
      - unread_only: only alerts where read=0
      - critical_only: only expired or scan_failure alerts
      - warning_only: only expiry_warning or drift alerts
    When ``scope_tags`` is non-empty, only alerts whose cert or host
    tags match any of the scope tags are returned (tag-scoped access control).
    """
    init_schema(db_path)
    conditions: list[str] = []
    params: list[Any] = []
    if unread_only:
        conditions.append("a.read = 0")
    if critical_only:
        conditions.append("a.alert_type IN ('expired', 'scan_failure')")
    if warning_only:
        conditions.append("a.alert_type IN ('expiry_warning', 'drift')")
    where = "WHERE " + " AND ".join(conditions) if conditions else ""
    if scope_tags:
        from cert_watch.database.dashboard import _add_effective_tag_filter

        base = where if where else "WHERE 1=1"
        where, params = _add_effective_tag_filter(
            base, params, scope_tags,
            col_cert="c.tags", col_host="h.tags",
        )
    with _connect(db_path) as conn:
        if limit > 0:
            offset = max(0, (page - 1) * limit)
            rows = conn.execute(
                f"""
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       a.read, c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
                {where}
                ORDER BY a.created_at DESC
                LIMIT ? OFFSET ?
                """,
                (*params, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT a.id, a.cert_id, a.created_at, a.alert_type, a.status,
                       a.threshold_days, a.sent_at, a.error_message, a.message,
                       a.read, c.subject AS subject
                FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
                {where}
                ORDER BY a.created_at DESC
                """,
                params,
            ).fetchall()
    return [dict(r) for r in rows]


# ---------- Pagination helpers ----------


def _total_alerts(db_path: str | Path, scope_tags: tuple[str, ...] = ()) -> int:
    if scope_tags:
        from cert_watch.database.dashboard import _add_effective_tag_filter

        where, params = _add_effective_tag_filter(
            "WHERE 1=1", [], scope_tags,
            col_cert="c.tags", col_host="h.tags",
        )
        with _connect(db_path) as conn:
            row = conn.execute(
                f"""
                SELECT COUNT(*) FROM alerts a
                LEFT JOIN certificates c ON c.id = a.cert_id
                LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
                {where}
                """,
                params,
            ).fetchone()
    else:
        with _connect(db_path) as conn:
            row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    return row[0] if row else 0


def _count_alerts_by_filter(
    db_path: str | Path, scope_tags: tuple[str, ...] = ()
) -> dict[str, int]:
    """Return counts for all, unread, critical, and warning alerts."""
    if scope_tags:
        from cert_watch.database.dashboard import _add_effective_tag_filter

        base_where, base_params = _add_effective_tag_filter(
            "WHERE 1=1", [], scope_tags, col_cert="c.tags", col_host="h.tags"
        )
        with _connect(db_path) as conn:
            all_row = conn.execute(
                f"SELECT COUNT(*) FROM alerts a "
                f"LEFT JOIN certificates c ON c.id = a.cert_id "
                f"LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
                f"{base_where}",
                base_params,
            ).fetchone()
            unread_row = conn.execute(
                f"SELECT COUNT(*) FROM alerts a "
                f"LEFT JOIN certificates c ON c.id = a.cert_id "
                f"LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
                f"{base_where} AND a.read = 0",
                base_params,
            ).fetchone()
            crit_row = conn.execute(
                f"SELECT COUNT(*) FROM alerts a "
                f"LEFT JOIN certificates c ON c.id = a.cert_id "
                f"LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
                f"{base_where} AND a.alert_type IN ('expired', 'scan_failure')",
                base_params,
            ).fetchone()
            warn_row = conn.execute(
                f"SELECT COUNT(*) FROM alerts a "
                f"LEFT JOIN certificates c ON c.id = a.cert_id "
                f"LEFT JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port "
                f"{base_where} AND a.alert_type IN ('expiry_warning', 'drift')",
                base_params,
            ).fetchone()
    else:
        with _connect(db_path) as conn:
            all_row = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
            unread_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE read = 0"
            ).fetchone()
            crit_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE alert_type IN ('expired', 'scan_failure')"
            ).fetchone()
            warn_row = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE alert_type IN ('expiry_warning', 'drift')"
            ).fetchone()
    return {
        "all": all_row[0] if all_row else 0,
        "unread": unread_row[0] if unread_row else 0,
        "critical": crit_row[0] if crit_row else 0,
        "warning": warn_row[0] if warn_row else 0,
    }


def _total_scan_history(db_path: str | Path) -> int:
    with _connect(db_path) as conn:
        row = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()
    return row[0] if row else 0


def list_scan_history(
    db_path: str | Path, *, page: int = 1, limit: int = 0,
) -> list[dict[str, Any]]:
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


def _total_scan_batches(db_path: str | Path) -> int:
    """Count scan batches (grouped by 5-minute time windows)."""
    rows = list_scan_history(db_path, limit=0)
    return len(_group_scan_batches(rows))


def _group_scan_batches(
    rows: list[dict[str, Any]], window_minutes: int = 5,
) -> list[dict[str, Any]]:
    """Group per-host scan rows into batch-oriented runs.

    A batch is a set of scans whose first and last record are within
    *window_minutes* of each other.
    """
    from datetime import UTC, datetime

    def _parse(ts: str) -> datetime:
        # Handle both ISO-8601 and SQLite formats
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts[:26], fmt).replace(tzinfo=UTC)
            except ValueError:
                continue
        return datetime.now(UTC)

    batches: list[dict[str, Any]] = []
    for row in rows:
        ts = _parse(row.get("scanned_at", ""))
        placed = False
        for batch in batches:
            if abs((ts - batch["_ts"]).total_seconds()) <= window_minutes * 60:
                batch["hosts"].append(row)
                batch["_ts"] = max(ts, batch["_ts"])
                placed = True
                break
        if not placed:
            batches.append({
                "scanned_at": row.get("scanned_at", ""),
                "hosts": [row],
                "_ts": ts,
            })
    # Sort by newest batch first
    batches.sort(key=lambda b: b["_ts"], reverse=True)
    # Compute summary fields
    for batch in batches:
        hosts = batch["hosts"]
        total = len(hosts)
        failures = sum(1 for h in hosts if h.get("status") == "failure")
        successes = total - failures
        if failures == 0:
            result = "success"
        elif successes == 0:
            result = "failure"
        else:
            result = "partial"
        batch["total"] = total
        batch["failures"] = failures
        batch["successes"] = successes
        batch["result"] = result
        batch["trigger"] = "Scheduled" if total > 1 else "Manual"
        # Remove internal sort key
        del batch["_ts"]
    return batches


def list_scan_batches(
    db_path: str | Path,
    *,
    page: int = 1,
    per_page: int = 20,
) -> tuple[list[dict[str, Any]], int]:
    """Return scan batches paginated, plus total batch count."""
    rows = list_scan_history(db_path, limit=0)
    batches = _group_scan_batches(rows)
    total = len(batches)
    start = (page - 1) * per_page
    end = start + per_page
    return batches[start:end], total


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
    except (sqlite3.Error, OSError):
        import logging
        logging.getLogger("cert_watch.database").warning("alert purge failed", exc_info=True)
        return 0
