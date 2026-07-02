"""SQL-paginated ungrouped dashboard query path (BC-073)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_ALIAS,
    _add_effective_tag_filter,
    _clamp_page,
    _escape_like,
    _filter_unified,
    _reorder_by_candidates,
    _safe_col,
    _safe_dir,
)
from cert_watch.database.dashboard_unified import (
    _build_pending_entries,
    _build_unified_for_leaf_ids,
)
from cert_watch.database.schema import init_schema


def list_dashboard_page(
    db_path: str | Path,
    *,
    urgency: str | None = None,
    source: str | None = None,
    q: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 50,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return a SQL-filtered, sorted, paginated page of unified dashboard rows.

    Ungrouped dashboard path (BC-073).  Filtering on ``source``/``q`` and the
    chosen sort + LIMIT/OFFSET are pushed into SQL via a UNION over leaf
    certificates, pending hosts (no leaf), and uploaded certs.  Only the rows
    for the requested page are then materialised into rich dashboard dicts.

    ``urgency`` filtering depends on computed chain status (which cannot be
    expressed faithfully in SQL), so when an ``urgency`` filter is requested the
    SQL-narrowed candidate set is built and filtered in Python before
    pagination.

    ``scope_tags`` restricts results to certificates/hosts whose effective tags
    (cert tags ∪ host tags) include at least one of the supplied tags (WI-051).
    Admins with an empty scope can pass an empty sequence to see everything.
    Returns ``(rows, total)``.
    """
    init_schema(db_path)

    _SORT_COLS = {
        "name": "sort_name",
        "issue_date": "sort_issue",
        "last_scan": "sort_scan",
        "expiry": "sort_expiry",
        "days": "sort_expiry",
    }
    sort_col = _safe_col(_SORT_COLS.get(sort_by, "sort_expiry"), _SORT_COLUMNS_ALIAS)
    sql_dir = _safe_dir("DESC" if sort_order == "desc" else "ASC")

    # Source filter pushed to SQL: which candidate kinds to include.
    include_scanned = True
    include_uploaded = True
    if source:
        if source == "scanned":
            include_uploaded = False
        else:  # "uploaded" (or any explicit source value): leaf certs only
            include_scanned = False

    # q is pushed to SQL for leaf/host candidates; grouped cross-host search
    # never applies to the ungrouped path, so per-field LIKE is faithful.
    like = f"%{_escape_like(q.lower())}%" if q else None

    with _connect(db_path) as conn:
        host_rows = conn.execute(
            "SELECT * FROM hosts ORDER BY added_at"
        ).fetchall()
        scan_rows = conn.execute(
            """
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            """
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        # Build the ordered candidate set in SQL.  Each candidate carries the
        # entity kind + key plus the four sort keys so ORDER BY matches the
        # Python sort semantics (NULL cert fields fall back to sentinels).
        select_parts: list[str] = []
        params: list[Any] = []

        if include_scanned:
            # Scanned leaf certs.
            scanned_sql = """
                SELECT 'leaf' AS etype, c.id AS ekey,
                       LOWER(c.subject) AS sort_name,
                       c.not_before AS sort_issue,
                       COALESCE((
                           SELECT MAX(sh.scanned_at) FROM scan_history sh
                           WHERE sh.hostname = c.hostname AND sh.port = c.port
                       ), '0000-01-01T00:00:00') AS sort_scan,
                       c.not_after AS sort_expiry
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
            select_parts.append(scanned_sql)
            params += scanned_params

            # Pending hosts (no leaf certificate).
            pending_sql = """
                SELECT 'pending' AS etype, h.id AS ekey,
                       LOWER(h.hostname || ':' || h.port) AS sort_name,
                       '9999-12-31T23:59:59' AS sort_issue,
                       COALESCE((
                           SELECT MAX(sh.scanned_at) FROM scan_history sh
                           WHERE sh.hostname = h.hostname AND sh.port = h.port
                       ), '0000-01-01T00:00:00') AS sort_scan,
                       '9999-12-31T23:59:59' AS sort_expiry
                FROM hosts h
                WHERE NOT EXISTS (
                    SELECT 1 FROM certificates c
                    WHERE c.hostname = h.hostname AND c.port = h.port
                      AND c.is_leaf = 1
                )
            """
            pending_params: list[Any] = []
            if like:
                pending_sql += (
                    " AND (LOWER(h.hostname || ':' || h.port) LIKE ? ESCAPE '\\'"
                    " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
                )
                pending_params += [like, like]
            pending_sql, pending_params = _add_effective_tag_filter(
                pending_sql, pending_params, scope_tags or (), col_cert=None, col_host="h.tags"
            )
            select_parts.append(pending_sql)
            params += pending_params

        if include_uploaded:
            uploaded_sql = """
                SELECT 'leaf' AS etype, c.id AS ekey,
                       LOWER(c.subject) AS sort_name,
                       c.not_before AS sort_issue,
                       '0000-01-01T00:00:00' AS sort_scan,
                       c.not_after AS sort_expiry
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
            select_parts.append(uploaded_sql)
            params += uploaded_params

        if not select_parts:
            return [], 0

        union_sql = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in select_parts)

        if urgency:
            # Urgency depends on computed chain status — build the full
            # candidate set, then filter + paginate in Python.
            ordered = conn.execute(
                f"SELECT etype, ekey FROM ({union_sql}) "
                f"ORDER BY {sort_col} {sql_dir}",
                params,
            ).fetchall()
            leaf_ids = [r["ekey"] for r in ordered if r["etype"] == "leaf"]
            pending_ids = {r["ekey"] for r in ordered if r["etype"] == "pending"}
            built = _build_unified_for_leaf_ids(
                conn, leaf_ids,
                host_rows=host_rows, scan_rows=scan_rows, anchor_rows=anchor_rows,
            )
            built += _build_pending_entries(
                [h for h in host_rows if h["id"] in pending_ids], scan_rows
            )
            built = _reorder_by_candidates(built, ordered)
            built = _filter_unified(built, urgency=urgency)
            total = len(built)
            if per_page > 0:
                clamped = _clamp_page(page, total, per_page)
                start = (clamped - 1) * per_page
                built = built[start : start + per_page]
            return built, total

        # No urgency filter: pagination is fully SQL-level.
        total_row = conn.execute(
            f"SELECT COUNT(*) FROM ({union_sql})", params
        ).fetchone()
        total = total_row[0] if total_row else 0

        page_sql = f"SELECT etype, ekey FROM ({union_sql}) ORDER BY {sort_col} {sql_dir}"
        page_params = list(params)
        if per_page > 0:
            clamped = _clamp_page(page, total, per_page)
            offset = (clamped - 1) * per_page
            page_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, offset]
        ordered = conn.execute(page_sql, page_params).fetchall()

        leaf_ids = [r["ekey"] for r in ordered if r["etype"] == "leaf"]
        pending_ids = {r["ekey"] for r in ordered if r["etype"] == "pending"}
        built = _build_unified_for_leaf_ids(
            conn, leaf_ids,
            host_rows=host_rows, scan_rows=scan_rows, anchor_rows=anchor_rows,
        )
        built += _build_pending_entries(
            [h for h in host_rows if h["id"] in pending_ids], scan_rows
        )
        built = _reorder_by_candidates(built, ordered)
    return built, total


def list_unified_entries_page(
    db_path: str | Path,
    *,
    offset: int = 0,
    limit: int = 0,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
) -> tuple[list[dict[str, Any]], int]:
    """Return a paginated slice of unified entries plus the total count.

    Thin compatibility wrapper kept for callers and tests that predate the
    purpose-built dashboard queries (BC-047/BC-073).  Delegates to
    :func:`list_dashboard_page`, which pushes filtering, sorting and
    pagination into SQL where it can.
    """
    page = (offset // limit) + 1 if limit > 0 else 1
    per_page = limit if limit > 0 else 0
    return list_dashboard_page(
        db_path,
        urgency=urgency,
        source=source,
        q=q,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        per_page=per_page,
    )
