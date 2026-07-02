"""Urgency-bucket statistics for dashboard summary cards."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import (
    _add_effective_tag_filter,
    _escape_like,
)


def pivot_urgency_stats(
    db_path: str | Path,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """Urgency-bucket counts (expired/critical/warning/healthy) for the pivot.

    Feeds the dashboard pivot summary cards (BC-048).  The not_after boundary is
    compared with ``julianday()`` rather than a string compare against
    ``datetime('now')``: not_after is stored as a T-separated ISO timestamp
    (e.g. ``2026-06-16T17:00:00+00:00``) while ``datetime('now')`` is
    space-separated, so a lexicographic ``<`` misbuckets certs expiring within
    the current UTC day.  ``CAST(... AS INTEGER)`` truncates toward zero, so the
    expired bucket must use the raw ``< now`` test, not ``days < 0``.

    Population and scoping mirror :func:`list_fleet_pivot`'s scanned aggregate so
    the summary cards agree with the grouped rows they sit above: scanned leaf
    certs (``is_leaf = 1`` joined to a host), filtered by effective (cert ∪ host)
    tags for ``scope_tags``.  A scoped (non-admin) user therefore sees counts only
    for certs in their tag scope — previously the cards aggregated every leaf cert
    globally, leaking out-of-scope counts and disagreeing with the group totals.
    """
    sql = """SELECT
            SUM(CASE WHEN julianday(c.not_after) < julianday('now') THEN 1 ELSE 0 END) AS expired,
            SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                     AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 7
                THEN 1 ELSE 0 END) AS critical,
            SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                     AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 7
                     AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 30
                THEN 1 ELSE 0 END) AS warning,
            SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                     AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 30
                THEN 1 ELSE 0 END) AS healthy
        FROM certificates c
        JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
        WHERE c.is_leaf = 1
        """
    params: list[Any] = []
    sql, params = _add_effective_tag_filter(
        sql, params, scope_tags or (), col_cert="c.tags", col_host="h.tags"
    )
    with _connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
    r = dict(row) if row is not None else {}
    return {
        "expired": r.get("expired") or 0,
        "critical": r.get("critical") or 0,
        "warning": r.get("warning") or 0,
        "healthy": r.get("healthy") or 0,
    }


def dashboard_urgency_stats(
    db_path: str | Path,
    *,
    q: str | None = None,
    source: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> dict[str, int]:
    """Urgency-bucket counts for the non-pivot dashboard stat cards.

    Mirrors :func:`pivot_urgency_stats` julianday-based bucketing and includes
    both scanned leaf certs (joined to hosts) and uploaded leaf certs
    (``source != 'scanned'``, no host JOIN). Applies the same ``q``/``source``/
    ``scope_tags`` filtering as :func:`list_dashboard_page` so the stat-card
    urgency totals reflect the full filtered fleet, not just the current page.
    """
    include_scanned = True
    include_uploaded = True
    if source:
        if source == "scanned":
            include_uploaded = False
        else:
            include_scanned = False

    like = f"%{_escape_like(q.lower())}%" if q else None

    bucket_sql = """
        SUM(CASE WHEN julianday(c.not_after) < julianday('now') THEN 1 ELSE 0 END)
            AS expired,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                 AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 7
            THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                 AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 7
                 AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) < 30
            THEN 1 ELSE 0 END) AS warning,
        SUM(CASE WHEN julianday(c.not_after) >= julianday('now')
                 AND CAST((julianday(c.not_after) - julianday('now')) AS INTEGER) >= 30
            THEN 1 ELSE 0 END) AS healthy
    """

    selects: list[str] = []
    params: list[Any] = []

    if include_scanned:
        scanned_sql = f"""
            SELECT {bucket_sql}
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1 AND c.source = 'scanned'
        """
        scanned_params: list[Any] = []
        if like:
            scanned_sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.tags) LIKE ? ESCAPE '\\'"
                " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
            )
            scanned_params += [like, like, like, like, like]
        scanned_sql, scanned_params = _add_effective_tag_filter(
            scanned_sql, scanned_params, scope_tags or (), col_cert="c.tags", col_host="h.tags"
        )
        selects.append(scanned_sql)
        params += scanned_params

    if include_uploaded:
        uploaded_sql = f"""
            SELECT {bucket_sql}
            FROM certificates c
            WHERE c.is_leaf = 1 AND c.source != 'scanned'
        """
        uploaded_params: list[Any] = []
        if like:
            uploaded_sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.tags) LIKE ? ESCAPE '\\')"
            )
            uploaded_params += [like, like, like]
        uploaded_sql, uploaded_params = _add_effective_tag_filter(
            uploaded_sql, uploaded_params, scope_tags or (), col_cert="c.tags", col_host="''"
        )
        selects.append(uploaded_sql)
        params += uploaded_params

    if not selects:
        return {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}

    union_sql = " UNION ALL ".join(selects)
    with _connect(db_path) as conn:
        rows = conn.execute(union_sql, params).fetchall()

    result = {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}
    for row in rows:
        for key in result:
            result[key] += row[key] or 0
    return result
