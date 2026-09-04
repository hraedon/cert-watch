"""Urgency-bucket statistics for dashboard summary cards."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import (
    _add_effective_tag_filter,
    _escape_like,
    build_scope_tag_clause,
)


def _empty_stats() -> dict[str, int]:
    return {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}


def _count_urgencies(entries: list[dict[str, Any]]) -> dict[str, int]:
    result = _empty_stats()
    for entry in entries:
        urgency = entry.get("urgency")
        if urgency in result:
            result[urgency] += 1
    return result


def pivot_urgency_stats(
    db_path: str | Path, scope_tags: list[str] | tuple[str, ...] | None = None
) -> dict[str, int]:
    """Chain-aware urgency counts matching the scanned pivot rows."""
    from cert_watch.database.dashboard_page import list_dashboard_page

    entries, _ = list_dashboard_page(db_path, source="scanned", per_page=0, scope_tags=scope_tags)
    return _count_urgencies(entries)


def dashboard_urgency_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """Chain-aware urgency counts matching the filtered dashboard rows."""
    from cert_watch.database.dashboard_page import list_dashboard_page

    entries, _ = list_dashboard_page(db_path, q=q, source=source, per_page=0, scope_tags=scope_tags)
    return _count_urgencies(entries)


def dashboard_expiry_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """Expiry-only counts for Home; Browse uses chain-aware urgency counts."""
    include_scanned = source in (None, "scanned")
    include_uploaded = source != "scanned"
    like = f"%{_escape_like(q.lower())}%" if q else None
    buckets = """
        SUM(CASE WHEN julianday(c.not_after) < julianday('now')
            THEN 1 ELSE 0 END) AS expired,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
            AND CAST(julianday(c.not_after) - julianday('now') AS INTEGER) < 7
            THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
            AND CAST(julianday(c.not_after) - julianday('now') AS INTEGER) >= 7
            AND CAST(julianday(c.not_after) - julianday('now') AS INTEGER) < 30
            THEN 1 ELSE 0 END) AS warning,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
            AND CAST(julianday(c.not_after) - julianday('now') AS INTEGER) >= 30
            THEN 1 ELSE 0 END) AS healthy
    """
    selects: list[str] = []
    params: list[Any] = []
    if include_scanned:
        sql = f"""SELECT {buckets}
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1 AND c.source = 'scanned'"""
        sql_params: list[Any] = []
        if like:
            sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.tags) LIKE ? ESCAPE '\\'"
                " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
            )
            sql_params.extend([like] * 5)
        sql, sql_params = _add_effective_tag_filter(
            sql, sql_params, scope_tags or (), col_cert="c.tags", col_host="h.tags"
        )
        selects.append(sql)
        params.extend(sql_params)
    if include_uploaded:
        sql = f"""SELECT {buckets} FROM certificates c
            WHERE c.is_leaf = 1 AND c.source != 'scanned'"""
        sql_params = []
        if like:
            sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.tags) LIKE ? ESCAPE '\\')"
            )
            sql_params.extend([like] * 3)
        sql, sql_params = _add_effective_tag_filter(
            sql, sql_params, scope_tags or (), col_cert="c.tags", col_host="''"
        )
        selects.append(sql)
        params.extend(sql_params)
    if not selects:
        return _empty_stats()
    with _connect(db_path) as conn:
        rows = conn.execute(" UNION ALL ".join(selects), params).fetchall()
    result = _empty_stats()
    for row in rows:
        for key in result:
            result[key] += row[key] or 0
    return result


def count_leaf_certs(
    db_path: str | Path, *, scope_tags: list[str] | tuple[str, ...] | None = None
) -> int:
    """Count leaf certificates, optionally filtered by scope tags."""
    if scope_tags:
        scope_clause, scope_params = build_scope_tag_clause(scope_tags)
        sql = f"SELECT COUNT(*) FROM certificates WHERE is_leaf = 1 AND {scope_clause}"
        params: list[Any] = scope_params
    else:
        sql = "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
        params = []
    with _connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    return row[0] if row else 0
