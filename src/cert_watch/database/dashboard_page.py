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
    delivery_state_sql,
    load_renewal_analytics,
    prepare_status_model_context,
    register_status_model_functions,
    renewal_state_for_row,
)
from cert_watch.status_rule import effective_days_sql


def inventory_candidates_sql(
    *,
    source: str | None = None,
    q: str | None = None,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
    entry_id: str | None = None,
    sql_delivery: bool = False,
    axis_columns: frozenset[str] | None = None,
    entry_keys: tuple[tuple[str, str], ...] | None = None,
    history_endpoints: tuple[tuple[str, int], ...] | None = None,
) -> tuple[str, list[Any]] | None:
    """SQL selecting one row per Browse inventory row, and its parameters.

    The inventory is scanned endpoints (their current leaf), pending endpoints
    (no leaf yet) and uploaded files -- the population every count and every
    group view splits (docs/operations.md, "What the numbers mean"). Each row
    carries ``etype``/``ekey`` (``leaf`` + certificate id, or ``pending`` +
    host id), the four sort keys, the raw group columns ``grp_issuer``,
    ``grp_owner`` and ``grp_method``, and ``host_id``/``hostname``/``port``/
    ``subject``.

    ``axis_columns`` controls which derived facts SQL evaluates. ``None``
    preserves the full projection used by aggregate/group callers; an empty
    set is the lean key/sort projection used by list counts and pagination.
    ``entry_keys`` bounds the full projection to rows already selected by that
    lean pass. Returns ``None`` when ``source`` excludes everything.
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
    requested = (
        frozenset({"condition", "monitoring", "renewal", "delivery", "urgency", "overall"})
        if axis_columns is None and axes is not None
        else frozenset({"urgency"})
        if axis_columns is None and status is not None
        else axis_columns or frozenset()
    )
    if "overall" in requested:
        requested = requested | {"monitoring", "urgency"}
    need_effective_days = bool(requested & {"condition", "urgency"})
    need_chain_status = "urgency" in requested
    need_monitoring = "monitoring" in requested and axes is not None
    need_renewal = "renewal" in requested and axes is not None
    need_delivery = "delivery" in requested and axes is not None
    delivery_settings = axes.settings if axes is not None else AxisSettings()

    status_cols = (
        f"{effective_days_sql('c')} AS eff_days"
        if status is not None and need_effective_days
        else "NULL AS eff_days"
    )
    status_params: list[Any] = (
        [status.sql_now] if status is not None and need_effective_days else []
    )
    if status is not None and need_chain_status:
        status_cols += f", {verified_chain_status_sql('c')} AS chain_status"
        status_params.append(status.trust)
    else:
        status_cols += ", NULL AS chain_status"

    history_prefix = ""
    history_params: list[Any] = []
    if need_monitoring:
        history_where = ""
        if history_endpoints is not None:
            if history_endpoints:
                history_where = " WHERE " + " OR ".join(
                    "(sh.hostname = ? AND sh.port = ?)" for _ in history_endpoints
                )
                history_params = [
                    value for endpoint in history_endpoints for value in endpoint
                ]
            else:
                history_where = " WHERE 0"
        # One ordered history pass supplies every monitoring fact.  The
        # success key preserves the timestamp+id tie-break without six
        # correlated probes per endpoint.
        history_prefix = f"""
            history_ranked AS MATERIALIZED (
                SELECT sh.*,
                       ROW_NUMBER() OVER (
                           PARTITION BY sh.hostname, sh.port
                           ORDER BY sh.scanned_at DESC, sh.id DESC
                       ) AS attempt_rank,
                       MAX(CASE WHEN sh.status = 'success'
                           THEN sh.scanned_at || char(31) || sh.id END) OVER (
                           PARTITION BY sh.hostname, sh.port
                       ) AS success_key
                FROM scan_history sh{history_where}
            ),
            history_summary AS MATERIALIZED (
                SELECT hostname, port,
                       CASE WHEN MAX(success_key) IS NULL THEN NULL ELSE
                           substr(MAX(success_key), 1,
                               instr(MAX(success_key), char(31)) - 1) END AS last_success,
                       MAX(CASE WHEN attempt_rank = 1 THEN scanned_at END)
                           AS latest_attempt,
                       MAX(CASE WHEN attempt_rank = 1 THEN status END)
                           AS latest_status,
                       MAX(CASE WHEN attempt_rank = 1 THEN error_message END)
                           AS latest_error,
                       MIN(CASE WHEN status != 'success' AND (
                           success_key IS NULL
                           OR scanned_at > substr(success_key, 1,
                               instr(success_key, char(31)) - 1)
                           OR (scanned_at = substr(success_key, 1,
                               instr(success_key, char(31)) - 1)
                               AND id > substr(success_key,
                                   instr(success_key, char(31)) + 1))
                       ) THEN scanned_at END) AS first_failed
                FROM history_ranked GROUP BY hostname, port
            ),
        """

    history_join = (
        " LEFT JOIN history_summary hs"
        " ON hs.hostname = h.hostname AND hs.port = h.port"
        if need_monitoring
        else ""
    )
    latest_attempt = (
        "hs.latest_attempt"
        if need_monitoring
        else "(SELECT MAX(sh.scanned_at) FROM scan_history sh"
        " WHERE sh.hostname = h.hostname AND sh.port = h.port)"
    )
    monitoring_cols = (
        "cw_monitoring_state(hs.last_success, hs.latest_attempt, hs.latest_status,"
        " h.scan_interval_hours) AS monitoring,"
        " hs.last_success AS monitoring_last_success,"
        " hs.latest_attempt AS monitoring_last_attempt,"
        " hs.latest_status AS monitoring_attempt_status,"
        " hs.latest_error AS monitoring_error,"
        " hs.first_failed AS monitoring_first_failed"
        if need_monitoring
        else "NULL AS monitoring, NULL AS monitoring_last_success,"
        " NULL AS monitoring_last_attempt, NULL AS monitoring_attempt_status,"
        " NULL AS monitoring_error, NULL AS monitoring_first_failed"
    )
    renewal_col = (
        "cw_renewal_state(h.hostname, h.port, h.renewal_method, h.renewal_status,"
        " c.not_after, EXISTS(SELECT 1 FROM certificates succ"
        " WHERE succ.replaces_cert_id = c.id AND succ.id != c.id)) AS renewal"
        if need_renewal
        else "NULL AS renewal"
    )
    pending_renewal_col = (
        "cw_renewal_state(h.hostname, h.port, h.renewal_method, h.renewal_status,"
        " NULL, 0) AS renewal"
        if need_renewal
        else "NULL AS renewal"
    )
    delivery_col = (
        delivery_state_sql("c", "h", delivery_settings)
        if need_delivery and sql_delivery
        else "'unrouted'"
    )
    # Pending hosts have no certificate alert identity yet, so the canonical
    # display model leaves them unrouted even when global fallbacks exist.
    pending_delivery_col = "'unrouted'"
    uploaded_delivery_col = (
        delivery_state_sql("c", None, delivery_settings)
        if need_delivery and sql_delivery
        else "'unrouted'"
    )

    select_parts: list[str] = []
    params: list[Any] = []

    if include_scanned:
        # Scanned leaf certs.
        scanned_sql = f"""
            SELECT 'leaf' AS etype, c.id AS ekey,
                   LOWER(c.subject) AS sort_name,
                   c.not_before AS sort_issue,
                   COALESCE({latest_attempt}, '0000-01-01T00:00:00') AS sort_scan,
                   c.not_after AS sort_expiry,
                   h.added_at AS sort_added,
                   {status_cols},
                   {monitoring_cols},
                   {renewal_col},
                   EXISTS(SELECT 1 FROM certificates succ
                       WHERE succ.replaces_cert_id = c.id AND succ.id != c.id)
                       AS has_successor,
                   {delivery_col} AS delivery,
                   COALESCE(c.issuer, '') AS grp_issuer,
                   COALESCE(h.owner_name, '') AS grp_owner,
                   COALESCE(h.renewal_method, '') AS grp_method,
                   h.id AS host_id, c.hostname AS hostname, c.port AS port,
                   c.subject AS subject
            FROM certificates c
            JOIN hosts h ON h.hostname = c.hostname AND h.port = c.port
            {history_join}
            WHERE c.is_leaf = 1 AND c.source = 'scanned'
        """
        scanned_params: list[Any] = list(status_params)
        if entry_id:
            scanned_sql += " AND c.id = ?"
            scanned_params.append(entry_id)
        if entry_keys:
            leaf_keys = [key for kind, key in entry_keys if kind == "leaf"]
            if not leaf_keys:
                scanned_sql += " AND 0"
            else:
                scanned_sql += f" AND c.id IN ({','.join('?' for _ in leaf_keys)})"
                scanned_params += leaf_keys
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
                   COALESCE({latest_attempt}, '0000-01-01T00:00:00') AS sort_scan,
                   '9999-12-31T23:59:59' AS sort_expiry,
                   h.added_at AS sort_added,
                   NULL AS eff_days, NULL AS chain_status,
                   {monitoring_cols},
                   {pending_renewal_col},
                   0 AS has_successor,
                   {pending_delivery_col} AS delivery,
                   '' AS grp_issuer,
                   COALESCE(h.owner_name, '') AS grp_owner,
                   COALESCE(h.renewal_method, '') AS grp_method,
                   h.id AS host_id, h.hostname AS hostname, h.port AS port,
                   NULL AS subject
            FROM hosts h
            {history_join}
            WHERE NOT EXISTS (
                SELECT 1 FROM certificates c
                WHERE c.hostname = h.hostname AND c.port = h.port
                  AND c.is_leaf = 1 AND c.source = 'scanned'
            )
        """
        pending_params: list[Any] = []
        if entry_id:
            pending_sql += " AND h.id = ?"
            pending_params.append(entry_id)
        if entry_keys:
            pending_keys = [key for kind, key in entry_keys if kind == "pending"]
            if not pending_keys:
                pending_sql += " AND 0"
            else:
                pending_sql += f" AND h.id IN ({','.join('?' for _ in pending_keys)})"
                pending_params += pending_keys
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
                   c.created_at AS sort_added,
                   {status_cols},
                   'not_monitored' AS monitoring,
                   NULL AS monitoring_last_success,
                   NULL AS monitoring_last_attempt,
                   NULL AS monitoring_attempt_status,
                   NULL AS monitoring_error,
                   NULL AS monitoring_first_failed,
                   'unknown' AS renewal,
                   0 AS has_successor,
                   {uploaded_delivery_col} AS delivery,
                   COALESCE(c.issuer, '') AS grp_issuer,
                   '' AS grp_owner,
                   '' AS grp_method,
                   NULL AS host_id, NULL AS hostname, NULL AS port,
                   c.subject AS subject
            FROM certificates c
            WHERE c.is_leaf = 1 AND c.source != 'scanned'
        """
        uploaded_params: list[Any] = list(status_params)
        if entry_id:
            uploaded_sql += " AND c.id = ?"
            uploaded_params.append(entry_id)
        if entry_keys:
            leaf_keys = [key for kind, key in entry_keys if kind == "leaf"]
            if not leaf_keys:
                uploaded_sql += " AND 0"
            else:
                uploaded_sql += f" AND c.id IN ({','.join('?' for _ in leaf_keys)})"
                uploaded_params += leaf_keys
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
    condition_col = "cw_condition(eff_days)" if "condition" in requested else "NULL"
    urgency_col = "cw_urgency(eff_days, chain_status)" if "urgency" in requested else "NULL"
    overall_col = (
        "CASE WHEN host_id IS NOT NULL AND monitoring = 'failing' THEN 'failing' "
        "WHEN host_id IS NOT NULL AND monitoring = 'never_scanned' THEN 'gray' "
        f"ELSE {urgency_col} END"
        if "overall" in requested
        else "NULL"
    )
    # Materialization is intentional when deriving axes: it guarantees each
    # Python UDF runs once per candidate instead of once per downstream CASE.
    if requested:
        sql = (
            f"WITH {history_prefix} inventory_raw AS MATERIALIZED ({union_sql}),"
            " inventory_states AS MATERIALIZED ("
            f"SELECT *, {condition_col} AS condition, {urgency_col} AS urgency "
            "FROM inventory_raw) "
            f"SELECT *, {overall_col} AS overall_state FROM inventory_states"
        )
    else:
        sql = (
            f"SELECT *, NULL AS condition, NULL AS urgency, NULL AS overall_state "
            f"FROM ({union_sql})"
        )
    return (
        sql,
        [*history_params, *params],
    )


_IN_CHUNK = 400


def _chunks(values: list[Any]) -> list[list[Any]]:
    return [values[i : i + _IN_CHUNK] for i in range(0, len(values), _IN_CHUNK)]


def build_inventory_entries(
    db_path: str | Path,
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
    if axes is not None:
        load_renewal_analytics(
            db_path,
            tuple((str(hostname), int(port)) for hostname, port in pairs),
            axes,
        )
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
            "has_successor", "overall_state", "hostname", "port",
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
        if axes is not None and entry.get("host_id"):
            renewal, source = renewal_state_for_row(
                hostname=str(entry.get("hostname") or ""),
                port=int(entry.get("port") or 0),
                renewal_method=str(entry.get("renewal_method") or ""),
                operator_status=str(entry.get("renewal_status") or ""),
                not_after=str(entry.get("not_after")) if entry.get("not_after") else None,
                has_successor=bool(entry.get("has_successor")),
                context=axes,
            )
            entry["renewal"] = renewal
            entry["renewal_source"] = source
        else:
            entry["renewal"] = "unknown"
            entry["renewal_source"] = "none"
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
    entry_id: str | None = None,
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
        "added_at": "sort_added",
    }
    sort_col = _safe_col(_SORT_COLS.get(sort_by, "sort_expiry"), _SORT_COLUMNS_ALIAS)
    sql_dir = _safe_dir("DESC" if sort_order == "desc" else "ASC")

    status = status or prepare_status(db_path, now)
    axes = axes or prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )
    filter_axes = frozenset(
        axis
        for axis, value in (
            ("urgency", urgency),
            ("condition", condition),
            ("monitoring", monitoring),
            ("renewal", renewal),
            ("delivery", delivery),
        )
        if value
    )
    # COUNT and key selection use only the axes required by active filters.
    # The full four-axis projection is applied after LIMIT to the returned
    # keys, so an unfiltered 20k estate evaluates at most 25/50 display rows.
    candidates = inventory_candidates_sql(
        source=source, q=q, scope_tags=scope_tags, status=status, axes=axes,
        entry_id=entry_id, sql_delivery=bool(delivery), axis_columns=filter_axes,
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

        cols = "etype, ekey, hostname, port"
        page_sql = f"SELECT {cols} FROM ({base_sql}) ORDER BY {sort_col} {sql_dir}"
        page_params = list(params)
        if per_page > 0:
            clamped = _clamp_page(page, total, per_page)
            offset = (clamped - 1) * per_page
            page_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, offset]
        selected = conn.execute(page_sql, page_params).fetchall()
        if not selected:
            return [], int(total)
        keys = tuple((str(row["etype"]), str(row["ekey"])) for row in selected)
        endpoints = tuple(
            dict.fromkeys(
                (str(row["hostname"]), int(row["port"]))
                for row in selected
                if row["hostname"] is not None and row["port"] is not None
            )
        )
        full_candidates = inventory_candidates_sql(
            source=source,
            q=q,
            scope_tags=scope_tags,
            status=status,
            axes=axes,
            entry_id=entry_id,
            entry_keys=keys,
            history_endpoints=endpoints,
        )
        assert full_candidates is not None
        full_sql, full_params = full_candidates
        full_rows = conn.execute(full_sql, full_params).fetchall()
        by_key = {(str(row["etype"]), str(row["ekey"])): row for row in full_rows}
        ordered = [by_key[key] for key in keys if key in by_key]
        built = build_inventory_entries(db_path, conn, ordered, status=status, axes=axes)
    attach_status_models(db_path, built, axes)
    return built, total


def get_dashboard_entry(
    db_path: str | Path,
    entry_id: str,
    *,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    axis_settings: AxisSettings | None = None,
) -> dict[str, Any] | None:
    """Build one inventory row by its certificate or pending-host id."""
    rows, _ = list_dashboard_page(
        db_path,
        entry_id=entry_id,
        per_page=1,
        scope_tags=scope_tags,
        axis_settings=axis_settings,
    )
    return rows[0] if rows else None


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
