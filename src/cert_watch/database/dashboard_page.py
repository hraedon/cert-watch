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
from cert_watch.status_model import (
    AxisSettings,
    StatusModelContext,
    attach_status_models,
    load_delivery_statuses,
    prepare_status_model_context,
    register_status_model_functions,
)
from cert_watch.status_rule import effective_days_sql


def inventory_candidates_sql(
    *,
    source: str | None = None,
    q: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
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
    condition_col = (
        f"cw_condition({effective_days_sql('c')})"
        if status is not None and axes is not None
        else "NULL"
    )
    status_params: list[Any] = (
        [status.sql_now, status.trust, status.sql_now]
        if status is not None and axes is not None
        else [status.sql_now, status.trust]
        if status is not None
        else []
    )

    latest_success = (
        "(SELECT MAX(sh.scanned_at) FROM scan_history sh"
        " WHERE sh.hostname = h.hostname AND sh.port = h.port AND sh.status = 'success')"
    )
    latest_attempt = (
        "(SELECT sh.scanned_at FROM scan_history sh"
        " WHERE sh.hostname = h.hostname AND sh.port = h.port"
        " ORDER BY sh.scanned_at DESC, sh.id DESC LIMIT 1)"
    )
    latest_scan_status = (
        "(SELECT sh.status FROM scan_history sh"
        " WHERE sh.hostname = h.hostname AND sh.port = h.port"
        " ORDER BY sh.scanned_at DESC, sh.id DESC LIMIT 1)"
    )
    latest_error = (
        "(SELECT sh.error_message FROM scan_history sh"
        " WHERE sh.hostname = h.hostname AND sh.port = h.port"
        " ORDER BY sh.scanned_at DESC, sh.id DESC LIMIT 1)"
    )
    first_failed = (
        "(SELECT MIN(sf.scanned_at) FROM scan_history sf"
        " WHERE sf.hostname = h.hostname AND sf.port = h.port AND sf.status != 'success'"
        " AND sf.scanned_at > COALESCE((SELECT MAX(ss.scanned_at) FROM scan_history ss"
        " WHERE ss.hostname = h.hostname AND ss.port = h.port"
        " AND ss.status = 'success'), ''))"
    )
    monitoring_cols = (
        f"cw_monitoring_state({latest_success}, {latest_attempt}, {latest_scan_status},"
        " h.scan_interval_hours) AS monitoring,"
        f" {latest_success} AS monitoring_last_success,"
        f" {latest_attempt} AS monitoring_last_attempt,"
        f" {latest_scan_status} AS monitoring_attempt_status,"
        f" {latest_error} AS monitoring_error,"
        f" {first_failed} AS monitoring_first_failed"
        if axes is not None
        else "NULL AS monitoring, NULL AS monitoring_last_success,"
        " NULL AS monitoring_last_attempt, NULL AS monitoring_attempt_status,"
        " NULL AS monitoring_error, NULL AS monitoring_first_failed"
    )
    renewal_col = (
        "cw_renewal_state(h.hostname, h.port, h.renewal_method, h.renewal_status,"
        " c.not_after, EXISTS(SELECT 1 FROM certificates succ"
        " WHERE succ.replaces_cert_id = c.id AND succ.id != c.id)) AS renewal"
        if axes is not None
        else "NULL AS renewal"
    )
    pending_renewal_col = (
        "cw_renewal_state(h.hostname, h.port, h.renewal_method, h.renewal_status,"
        " NULL, 0) AS renewal"
        if axes is not None
        else "NULL AS renewal"
    )
    delivery_col = "cw_delivery_state(c.id)" if axes is not None else "NULL"

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
                   {condition_col} AS condition,
                   {monitoring_cols},
                   {renewal_col},
                   {delivery_col} AS delivery,
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
        pending_sql = f"""
            SELECT 'pending' AS etype, h.id AS ekey,
                   LOWER(h.hostname || ':' || h.port) AS sort_name,
                   '9999-12-31T23:59:59' AS sort_issue,
                   COALESCE((
                       SELECT MAX(sh.scanned_at) FROM scan_history sh
                       WHERE sh.hostname = h.hostname AND sh.port = h.port
                   ), '0000-01-01T00:00:00') AS sort_scan,
                   '9999-12-31T23:59:59' AS sort_expiry,
                   NULL AS eff_days, NULL AS chain_status,
                   NULL AS condition,
                   {monitoring_cols},
                   {pending_renewal_col},
                   'unrouted' AS delivery,
                   '' AS grp_issuer,
                   COALESCE(h.owner_name, '') AS grp_owner,
                   COALESCE(h.renewal_method, '') AS grp_method,
                   h.id AS host_id, h.hostname AS hostname, h.port AS port,
                   NULL AS subject
            FROM hosts h
            WHERE NOT EXISTS (
                SELECT 1 FROM certificates c
                WHERE c.hostname = h.hostname AND c.port = h.port
                  AND c.is_leaf = 1 AND c.source = 'scanned'
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
                   {condition_col} AS condition,
                   'never_scanned' AS monitoring,
                   NULL AS monitoring_last_success,
                   NULL AS monitoring_last_attempt,
                   NULL AS monitoring_attempt_status,
                   NULL AS monitoring_error,
                   NULL AS monitoring_first_failed,
                   'unknown' AS renewal,
                   {delivery_col} AS delivery,
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
    conn: Any,
    ordered: list[Any],
    *,
    status: StatusContext,
    axes: StatusModelContext | None = None,
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
    result = _reorder_by_candidates(built, ordered)
    candidate_by_key = {(r["etype"], r["ekey"]): r for r in ordered}
    for entry in result:
        etype = "pending" if entry.get("kind") == "pending" else "leaf"
        candidate = candidate_by_key.get((etype, entry.get("id")))
        if candidate is None:
            continue
        keys = set(candidate.keys())
        for key in (
            "eff_days", "condition", "monitoring", "monitoring_last_success",
            "monitoring_last_attempt", "monitoring_attempt_status", "monitoring_error",
            "monitoring_first_failed", "renewal", "delivery",
        ):
            if key in keys:
                entry["effective_days" if key == "eff_days" else key] = candidate[key]
        from cert_watch.status_model import monitoring_since

        cfg = axes.settings if axes is not None else AxisSettings()
        entry["monitoring_since"] = monitoring_since(
            str(entry.get("monitoring") or "never_scanned"),
            entry.get("monitoring_last_success"),
            entry.get("monitoring_attempt_status"),
            entry.get("scan_interval_hours"),
            cfg.sched_hour,
            cfg.sched_min,
            entry.get("monitoring_first_failed"),
        )
        renewal = entry.get("renewal") or "unknown"
        method = str(entry.get("renewal_method") or "").casefold()
        entry["renewal_source"] = (
            "operator_report" if renewal == "in_progress"
            else "renewal_window" if renewal == "stalled"
            else "renewal_method" if method in {"acme", "cert-manager", "manual"}
            else "renewal_analytics" if renewal != "unknown"
            else "none"
        )
    return result


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
    axes: StatusModelContext | None = None,
    axis_settings: AxisSettings | None = None,
    condition: str | None = None,
    monitoring: str | None = None,
    renewal: str | None = None,
    delivery: str | None = None,
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
    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    candidates = inventory_candidates_sql(
        source=source, q=q, scope_tags=scope_tags, status=status, axes=axes
    )
    if candidates is None:
        return [], 0
    base_sql, params = candidates
    axis_filters = {
        "condition": condition,
        "monitoring": monitoring,
        "renewal": renewal,
        "delivery": delivery,
    }
    if delivery:
        with _connect(db_path) as conn:
            register_status_model_functions(conn, axes)
            cert_ids = tuple(
                row[0]
                for row in conn.execute(
                    f"SELECT ekey FROM ({base_sql}) WHERE etype = 'leaf'", params
                ).fetchall()
            )
        load_delivery_statuses(db_path, cert_ids, axes)
        # The request-bound UDF closes over the now-populated map.
    if urgency:
        base_sql = f"SELECT * FROM ({base_sql}) WHERE urgency = ?"
        params = [*params, urgency]
    for column, value in axis_filters.items():
        if value:
            base_sql = f"SELECT * FROM ({base_sql}) WHERE {column} = ?"
            params = [*params, value]

    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        total_row = conn.execute(f"SELECT COUNT(*) FROM ({base_sql})", params).fetchone()
        total = total_row[0] if total_row else 0

        # The status filter's chain status comes along, so the rows show it.
        cols = (
            "etype, ekey, chain_status, eff_days, condition, monitoring,"
            " monitoring_last_success, monitoring_last_attempt,"
            " monitoring_attempt_status, monitoring_error, monitoring_first_failed,"
            " renewal, delivery"
        )
        page_sql = f"SELECT {cols} FROM ({base_sql}) ORDER BY {sort_col} {sql_dir}"
        page_params = list(params)
        if per_page > 0:
            clamped = _clamp_page(page, total, per_page)
            offset = (clamped - 1) * per_page
            page_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, offset]
        ordered = conn.execute(page_sql, page_params).fetchall()
        built = build_inventory_entries(conn, ordered, status=status, axes=axes)
    attach_status_models(db_path, built, axes)
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
