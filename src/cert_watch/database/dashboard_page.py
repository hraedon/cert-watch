"""SQL-paginated ungrouped dashboard query path (BC-073)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cert_watch.database.chain_status_cache import (
    StatusContext,
    leaf_chain_statuses,
    prepare_status,
    verified_chain_status_sql,
)
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_ALIAS,
    _add_effective_tag_filter,
    _clamp_page,
    _reorder_by_candidates,
    _safe_col,
    _safe_dir,
    search_patterns,
)
from cert_watch.database.dashboard_unified import (
    _build_pending_entries,
    _build_unified_for_leaf_ids,
)
from cert_watch.database.schema import init_schema
from cert_watch.status_rule import effective_days_sql


def inventory_candidates_sql(
    *,
    source: str | None = None,
    q: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    status: StatusContext | None = None,
) -> tuple[str, list[Any]] | None:
    """SQL selecting one row per Browse inventory row, and its parameters.

    The inventory is scanned endpoints (their current leaf), pending endpoints
    (no leaf yet) and uploaded files -- the population every count and every
    group view splits (docs/operations.md, "What the numbers mean"). Each row
    carries ``etype``/``ekey`` (``leaf`` + certificate id, or ``pending`` +
    host id), the four sort keys, the raw group columns ``grp_issuer``,
    ``grp_owner`` and ``grp_method``, and ``host_id``/``hostname``/``port``/
    ``subject``.

    With a ``status`` context (:func:`prepare_status`: one instant and one
    trust digest for the request) each row also carries ``eff_days``,
    ``chain_status`` (the cached status while current, else ``unverified``)
    and ``urgency``, computed in SQL by the one status rule
    (:mod:`cert_watch.status_rule`), so callers can count, group and filter by
    status without materialising rows. Returns ``None`` when ``source``
    excludes everything.
    """
    include_scanned = True
    include_uploaded = True
    if source:
        if source == "scanned":
            include_uploaded = False
        else:  # "uploaded" (or any explicit source value): leaf certs only
            include_scanned = False

    # q is pushed to SQL for leaf/host candidates; grouped cross-host search
    # never applies to the ungrouped path, so per-field LIKE is faithful.
    like, host_like = search_patterns(q)
    status_cols = (
        f"{effective_days_sql('c')} AS eff_days,"
        f" {verified_chain_status_sql('c')} AS chain_status"
        if status is not None
        else "NULL AS eff_days, NULL AS chain_status"
    )
    status_params: list[Any] = [status.sql_now, status.trust] if status is not None else []

    select_parts: list[str] = []
    params: list[Any] = []

    if include_scanned:
        # Scanned leaf certs.
        scanned_sql = f"""
            SELECT 'leaf' AS etype, c.id AS ekey,
                   LOWER(c.subject) AS sort_name,
                   c.not_before AS sort_issue,
                   COALESCE((
                       SELECT MAX(sh.scanned_at) FROM scan_history sh
                       WHERE sh.hostname = c.hostname AND sh.port = c.port
                   ), '0000-01-01T00:00:00') AS sort_scan,
                   c.not_after AS sort_expiry,
                   {status_cols},
                   COALESCE(c.issuer, '') AS grp_issuer,
                   COALESCE(h.owner_name, '') AS grp_owner,
                   COALESCE(h.renewal_method, '') AS grp_method,
                   h.id AS host_id, c.hostname AS hostname, c.port AS port,
                   c.subject AS subject
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            WHERE c.is_leaf = 1 AND c.source = 'scanned'
        """
        scanned_params: list[Any] = list(status_params)
        if like:
            scanned_sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.tags) LIKE ? ESCAPE '\\'"
                " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
            )
            scanned_params += [like, like, like, host_like, like, like]
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
                   '9999-12-31T23:59:59' AS sort_expiry,
                   NULL AS eff_days, NULL AS chain_status,
                   '' AS grp_issuer,
                   COALESCE(h.owner_name, '') AS grp_owner,
                   COALESCE(h.renewal_method, '') AS grp_method,
                   h.id AS host_id, h.hostname AS hostname, h.port AS port,
                   NULL AS subject
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
                " OR LOWER(h.hostname || ':' || h.port) LIKE ? ESCAPE '\\'"
                " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
            )
            pending_params += [like, host_like, like]
        pending_sql, pending_params = _add_effective_tag_filter(
            pending_sql, pending_params, scope_tags or (), col_cert=None, col_host="h.tags"
        )
        select_parts.append(pending_sql)
        params += pending_params

    if include_uploaded:
        uploaded_sql = f"""
            SELECT 'leaf' AS etype, c.id AS ekey,
                   LOWER(c.subject) AS sort_name,
                   c.not_before AS sort_issue,
                   '0000-01-01T00:00:00' AS sort_scan,
                   c.not_after AS sort_expiry,
                   {status_cols},
                   COALESCE(c.issuer, '') AS grp_issuer,
                   '' AS grp_owner,
                   '' AS grp_method,
                   NULL AS host_id, NULL AS hostname, NULL AS port,
                   c.subject AS subject
            FROM certificates c
            WHERE c.is_leaf = 1 AND c.source != 'scanned'
        """
        uploaded_params: list[Any] = list(status_params)
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
        return None

    union_sql = " UNION ALL ".join(f"SELECT * FROM ({p})" for p in select_parts)
    urgency_col = "cw_urgency(eff_days, chain_status)" if status is not None else "NULL"
    return f"SELECT *, {urgency_col} AS urgency FROM ({union_sql})", params


_IN_CHUNK = 400


def _chunks(values: list[Any]) -> list[list[Any]]:
    return [values[i : i + _IN_CHUNK] for i in range(0, len(values), _IN_CHUNK)]


def build_inventory_entries(
    conn: Any, ordered: list[Any], *, status: StatusContext
) -> list[dict[str, Any]]:
    """Materialise the rich rows for *ordered* candidates, in that order.

    Every read is keyed by the candidates -- their leaves, chains, hosts and
    latest scans, in bounded ``IN`` chunks -- so the work is proportional to
    ``len(ordered)`` however large that is, never to the estate. The rows are
    judged with the request's *status* context -- its instant and the chain
    status its SQL used (a candidate's own ``chain_status`` column when the
    selection computed one) -- so a row shows exactly the status it was
    counted and selected with.
    """
    leaf_ids = [r["ekey"] for r in ordered if r["etype"] == "leaf"]
    pending_ids = [r["ekey"] for r in ordered if r["etype"] == "pending"]
    host_rows: list[Any] = []
    for chunk in _chunks(leaf_ids):
        ph = ",".join("?" * len(chunk))
        host_rows += conn.execute(
            f"""SELECT DISTINCT h.* FROM hosts h JOIN certificates c
                ON c.hostname = h.hostname AND c.port = h.port
                WHERE c.id IN ({ph})""",
            chunk,
        ).fetchall()
    pending_hosts: list[Any] = []
    for chunk in _chunks(pending_ids):
        ph = ",".join("?" * len(chunk))
        pending_hosts += conn.execute(
            f"SELECT * FROM hosts WHERE id IN ({ph})", chunk
        ).fetchall()
    pairs = sorted({(h["hostname"], h["port"]) for h in [*host_rows, *pending_hosts]})
    scan_rows: list[Any] = []
    for chunk in _chunks(pairs):
        match = " OR ".join("(sh1.hostname = ? AND sh1.port = ?)" for _ in chunk)
        scan_rows += conn.execute(
            f"""
            SELECT sh1.hostname, sh1.port, sh1.status, sh1.scanned_at, sh1.error_message
            FROM scan_history sh1
            WHERE ({match})
              AND sh1.scanned_at = (
                SELECT MAX(scanned_at) FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
              )
            """,
            [v for pair in chunk for v in pair],
        ).fetchall()
    anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()
    selected = {
        r["ekey"]: r["chain_status"]
        for r in ordered
        # sqlite3.Row: `in` tests values, so the keys must be asked for.
        if r["etype"] == "leaf" and "chain_status" in r.keys() and r["chain_status"]  # noqa: SIM118
    }
    missing = [lid for lid in leaf_ids if lid not in selected]
    chain_statuses = {**leaf_chain_statuses(conn, missing, status), **selected}
    built = _build_unified_for_leaf_ids(
        conn, leaf_ids, host_rows=host_rows, scan_rows=scan_rows, anchor_rows=anchor_rows,
        now=status.now, chain_statuses=chain_statuses,
    )
    built += _build_pending_entries(pending_hosts, scan_rows)
    return _reorder_by_candidates(built, ordered)


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
    now: datetime | None = None,
    status: StatusContext | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return a SQL-filtered, sorted, paginated page of unified dashboard rows.

    Ungrouped dashboard path (BC-073).  Filtering on ``source``/``q``/
    ``urgency``, the chosen sort and LIMIT/OFFSET are pushed into SQL via
    :func:`inventory_candidates_sql`; only the rows of the requested page are
    then materialised into rich dashboard dicts. ``urgency`` filters with the
    SQL form of the one status rule, the same rule the built rows carry, and
    both are judged with one status context: *status* when the caller shares
    one across the request (it then wins over ``now``), else one prepared
    here at ``now`` (default: the time of the call).

    ``scope_tags`` restricts results to certificates/hosts whose effective tags
    (cert tags ∪ host tags) include at least one of the supplied tags (WI-051).
    Admins with an empty scope can pass an empty sequence to see everything.
    ``per_page=0`` returns every row (exports only; never on a page render).
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

    status = status or prepare_status(db_path, now)
    candidates = inventory_candidates_sql(
        source=source, q=q, scope_tags=scope_tags, status=status if urgency else None
    )
    if candidates is None:
        return [], 0
    base_sql, params = candidates
    if urgency:
        base_sql = f"SELECT * FROM ({base_sql}) WHERE urgency = ?"
        params = [*params, urgency]

    with _connect(db_path) as conn:
        total_row = conn.execute(f"SELECT COUNT(*) FROM ({base_sql})", params).fetchone()
        total = total_row[0] if total_row else 0

        # The status filter's chain status comes along, so the rows show it.
        cols = "etype, ekey, chain_status" if urgency else "etype, ekey"
        page_sql = f"SELECT {cols} FROM ({base_sql}) ORDER BY {sort_col} {sql_dir}"
        page_params = list(params)
        if per_page > 0:
            clamped = _clamp_page(page, total, per_page)
            offset = (clamped - 1) * per_page
            page_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, offset]
        ordered = conn.execute(page_sql, page_params).fetchall()
        built = build_inventory_entries(conn, ordered, status=status)
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
