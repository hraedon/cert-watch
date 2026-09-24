"""Urgency-bucket statistics for dashboard summary cards."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cert_watch.database.connection import _connect, _sql_now

if TYPE_CHECKING:
    from cert_watch.database.chain_status_cache import StatusContext
from cert_watch.database.dashboard_helpers import (
    _add_effective_tag_filter,
    _escape_like,
    build_scope_tag_clause,
)


def _empty_stats() -> dict[str, int]:
    return {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}


def pivot_urgency_stats(
    db_path: str | Path, scope_tags: list[str] | tuple[str, ...] | None = None
) -> dict[str, int]:
    """Chain-aware urgency counts matching the pivot rows.

    The pivots group every inventory row, uploaded files included, so their
    cards are the unfiltered inventory's cards. Counting only scanned rows here
    made the owner view report fewer tracked and warning rows than Browse for
    the same estate (#113).
    """
    return dashboard_urgency_stats(db_path, scope_tags=scope_tags)


def dashboard_urgency_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    now: datetime | None = None,
    status: StatusContext | None = None,
) -> dict[str, int]:
    """Status-card counts of the (filtered) inventory rows, counted in SQL.

    Uses the SQL form of the one status rule (:mod:`cert_watch.status_rule`),
    the rule every built row carries, so the cards always match the rows
    without building them (#113 review: Home, Browse and /metrics used to
    materialise the whole estate to count it). Pending rows have no status.
    """
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.dashboard_page import inventory_candidates_sql
    from cert_watch.database.schema import init_schema

    init_schema(db_path)
    candidates = inventory_candidates_sql(
        q=q, source=source, scope_tags=scope_tags,
        status=status or prepare_status(db_path, now),
    )
    result = _empty_stats()
    if candidates is None:
        return result
    sql, params = candidates
    with _connect(db_path) as conn:
        for row in conn.execute(
            f"SELECT urgency, COUNT(*) AS n FROM ({sql}) GROUP BY urgency", params
        ).fetchall():
            if row["urgency"] in result:
                result[row["urgency"]] = row["n"]
    return result


def dashboard_expiry_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    now: datetime | None = None,
) -> dict[str, int]:
    """Expiry-only counts for Home; Browse uses chain-aware urgency counts."""
    include_scanned = source in (None, "scanned")
    include_uploaded = source != "scanned"
    like = f"%{_escape_like(q.lower())}%" if q else None
    buckets = """
        SUM(CASE WHEN julianday(c.not_after) < julianday(?)
            THEN 1 ELSE 0 END) AS expired,
        SUM(CASE WHEN julianday(c.not_after) >= julianday(?)
            AND CAST(julianday(c.not_after) - julianday(?) AS INTEGER) < 7
            THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN julianday(c.not_after) >= julianday(?)
            AND CAST(julianday(c.not_after) - julianday(?) AS INTEGER) >= 7
            AND CAST(julianday(c.not_after) - julianday(?) AS INTEGER) < 30
            THEN 1 ELSE 0 END) AS warning,
        SUM(CASE WHEN julianday(c.not_after) >= julianday(?)
            AND CAST(julianday(c.not_after) - julianday(?) AS INTEGER) >= 30
            THEN 1 ELSE 0 END) AS healthy
    """
    # The bucket fragment precedes every WHERE placeholder in each SELECT.
    bucket_params: list[Any] = [_sql_now(now)] * buckets.count("?")
    selects: list[str] = []
    params: list[Any] = []
    if include_scanned:
        sql = f"""SELECT {buckets}
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1 AND c.source = 'scanned'"""
        sql_params: list[Any] = list(bucket_params)
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
        sql_params = list(bucket_params)
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
