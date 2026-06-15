"""Dashboard and unified entry queries."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect, _parse_iso, _row_to_cert
from cert_watch.database.posture import get_posture_for_cert
from cert_watch.database.schema import init_schema
from cert_watch.filters import subject_cn

_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")

_SORT_COLUMNS_BARE = frozenset({
    "subject", "not_before", "not_after", "created_at",
})

_SORT_COLUMNS_ALIAS = frozenset({
    "sort_name", "sort_issue", "sort_scan", "sort_expiry",
})

_SORT_COLUMNS_GROUPED = frozenset({
    "LOWER(COALESCE(c.subject, c.hostname || ':' || c.port))",
    "c.not_before",
    "COALESCE(last_scan_at, '0000-01-01T00:00:00')",
    "c.not_after",
})

_SQL_DIRS = frozenset({"ASC", "DESC"})


def _safe_col(col: str, allowed: frozenset[str]) -> str:
    if col not in allowed:
        raise ValueError(f"Invalid sort column: {col!r}")
    return col


def _safe_dir(direction: str) -> str:
    if direction not in _SQL_DIRS:
        raise ValueError(f"Invalid sort direction: {direction!r}")
    return direction


def _escape_like(s: str) -> str:
    """Escape ``%``, ``_`` and ``\\`` so they are treated as literals in a LIKE pattern."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def _build_dashboard_rows(
    cert_rows,
    anchor_rows,
) -> list[dict]:
    """Build rich dashboard rows from raw certificate and anchor rows."""
    from cert_watch.cert_chain import chain_status

    # anchor_rows come from trust_anchors, which lacks the certificate-only
    # columns (is_leaf, source, notes) that _row_to_cert reads — default them.
    anchors = [_row_to_cert({**dict(r), "is_leaf": 0}) for r in anchor_rows]

    leaf_rows: list[dict] = []
    children_by_leaf: dict[str, list[dict]] = {}
    for r in cert_rows:
        d = dict(r)
        if d["is_leaf"]:
            leaf_rows.append(d)
        else:
            children_by_leaf.setdefault(d["parent_cert_id"] or "", []).append(d)

    def _days(iso_str: str) -> int:
        return (_parse_iso(iso_str) - datetime.now(UTC)).days

    def _urgency(days: int) -> str:
        if days < 0:
            return "expired"
        if days < 7:
            return "critical"
        if days < 30:
            return "warning"
        return "healthy"

    dash: list[dict] = []
    for leaf in leaf_rows:
        chain = children_by_leaf.get(leaf["id"], [])
        leaf_days = _days(leaf["not_after"])
        chain_view = []
        for c in chain:
            days = _days(c["not_after"])
            chain_view.append({
                "id": c["id"],
                "subject": c["subject"],
                "issuer": c["issuer"],
                "not_before": c["not_before"],
                "not_after": c["not_after"],
                "days_remaining": days,
                "urgency": _urgency(days),
            })
        all_days = [leaf_days, *[c["days_remaining"] for c in chain_view]]
        min_days = min(all_days)
        host = (
            f"{leaf['hostname']}:{leaf['port']}"
            if leaf["hostname"]
            else f"(uploaded:{leaf['source']})"
        )
        leaf_cert = _row_to_cert(leaf)
        chain_certs = [_row_to_cert(c) for c in chain]
        _chain_status = chain_status(leaf_cert, chain_certs, anchors)
        row_urgency = _urgency(min_days)
        if _chain_status in ("incomplete", "invalid") and row_urgency == "healthy":
            row_urgency = "warning"
        dash.append(
            {
                "id": leaf["id"],
                "host": host,
                "source": leaf["source"],
                "subject": leaf["subject"],
                "issuer": leaf["issuer"],
                "not_before": leaf["not_before"],
                "not_after": leaf["not_after"],
                "days_remaining": leaf_days,
                "urgency": row_urgency,
                "leaf_urgency": _urgency(leaf_days),
                "chain": chain_view,
                "chain_valid": (
                    None if leaf["chain_valid"] is None else bool(leaf["chain_valid"])
                ),
                "chain_status": _chain_status,
                "replaces_cert_id": leaf.get("replaces_cert_id"),
                "notes": dict(leaf).get("notes", ""),
                "fingerprint_sha256": leaf.get("fingerprint_sha256", ""),
                "san_dns_names": json.loads(leaf.get("san_dns_names", "[]")),
                "tags": leaf.get("tags", ""),
                "owner_name": "",
            }
        )

    return dash


def list_dashboard_rows(
    db_path: str | Path,
    *,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 0,
) -> list[dict]:
    """
    Return rich rows for the dashboard. Per the scope extension, each scanned host
    or uploaded bundle surfaces leaf + intermediate + root, and the row's urgency
    is driven by the most-urgent cert in that group.

    When per_page > 0, applies pagination at the SQL level for leaf certificates
    and fetches only the chain children needed for that page.
    """
    init_schema(db_path)

    # Map sort_by to SQL ORDER BY for leaf certificates
    _sort_map = {
        "name": "subject",
        "issue_date": "not_before",
        "expiry": "not_after",
        "days": "not_after",
        "last_scan": "not_after",
    }
    sql_col = _safe_col(_sort_map.get(sort_by, "not_after"), _SORT_COLUMNS_BARE)
    sql_dir = _safe_dir("ASC" if sort_order == "asc" else "DESC")

    with _connect(db_path) as conn:
        if per_page > 0:
            offset = max(0, (page - 1) * per_page)
            leaf_rows = conn.execute(
                f"SELECT * FROM certificates WHERE is_leaf = 1 "
                f"ORDER BY {sql_col} {sql_dir} LIMIT ? OFFSET ?",
                (per_page, offset),
            ).fetchall()
            leaf_ids = [r["id"] for r in leaf_rows]
            if leaf_ids:
                ph = ",".join("?" * len(leaf_ids))
                chain_rows = conn.execute(
                    f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                    leaf_ids,
                ).fetchall()
            else:
                chain_rows = []
            rows = list(leaf_rows) + list(chain_rows)
        else:
            rows = conn.execute(
                "SELECT * FROM certificates ORDER BY created_at"
            ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

    dash = _build_dashboard_rows(rows, anchor_rows)
    if per_page == 0:
        dash.sort(
            key=lambda d: min(
                [d["days_remaining"], *[c["days_remaining"] for c in d["chain"]]]
            )
        )
    return dash


def count_dashboard_leaves(db_path: str | Path) -> int:
    """Return the total number of leaf certificates for pagination."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE is_leaf = 1"
        ).fetchone()
    return row[0] if row else 0


def list_unified_entries(db_path: str | Path) -> list[dict]:
    """Return a merged list of hosts (pending or scanned) and uploaded certificates.

    Each entry has a ``kind`` of ``scanned``, ``uploaded``, or ``pending``.
    Pending hosts carry cert fields set to ``None`` and urgency ``gray``.

    Uses SQL-level filtering via :func:`_load_unified_filtered` so the full
    inventory is not materialised in Python (BC-073).
    """
    return _load_unified_filtered(db_path, include_uploaded=True)


def _matches_q(e: dict, ql: str) -> bool:
    """Python text match used by the dashboard filter (case-insensitive)."""
    fields = [e.get("name"), e.get("subject"), e.get("issuer"), e.get("host"),
              e.get("tags")]
    if e.get("kind") == "grouped":
        for h in e.get("hosts", []):
            fields.extend([h.get("host"), h.get("name")])
    return any(ql in (f or "").lower() for f in fields)


def _filter_unified(
    entries: list[dict],
    *,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
) -> list[dict]:
    """Apply the dashboard q/urgency/source filters to built unified entries.

    This mirrors the filter semantics used by the dashboard route exactly so
    grouped and ungrouped paths stay identical.
    """
    if q:
        ql = q.lower()
        entries = [e for e in entries if _matches_q(e, ql)]
    if urgency:
        entries = [e for e in entries if e.get("urgency") == urgency]
    if source:
        if source == "scanned":
            entries = [
                e for e in entries
                if e.get("kind") in ("scanned", "pending", "grouped")
            ]
        else:
            entries = [e for e in entries if e.get("source") == source]
    return entries


_UNIFIED_SORT_KEYS = {
    "name": lambda e: (e.get("name") or "").lower(),
    "issue_date": lambda e: e.get("not_before") or "9999-12-31T23:59:59",
    "last_scan": lambda e: e.get("last_scanned_at") or "0000-01-01T00:00:00",
    "expiry": lambda e: e.get("not_after") or "9999-12-31T23:59:59",
    "days": lambda e: (
        e["days_remaining"] if e.get("days_remaining") is not None else 9999
    ),
}


def _sort_unified(
    entries: list[dict], *, sort_by: str = "days", sort_order: str = "asc"
) -> list[dict]:
    """Sort built unified entries with the dashboard's sort semantics."""
    key_fn = _UNIFIED_SORT_KEYS.get(sort_by, _UNIFIED_SORT_KEYS["days"])
    entries.sort(key=key_fn, reverse=(sort_order == "desc"))
    return entries


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
) -> tuple[list[dict], int]:
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


def _build_unified_for_leaf_ids(
    conn,
    leaf_ids: list[str],
    *,
    host_rows,
    scan_rows,
    anchor_rows,
) -> list[dict]:
    """Build scanned/uploaded unified entries for a specific set of leaf ids.

    Fetches the leaf rows + their chain children, builds dashboard rows, and
    merges in host/scan context.  Pending hosts (no leaf) are added by the
    caller via :func:`_build_unified_from_dash`-style logic; this helper only
    covers leaf-backed entries (scanned + uploaded).
    """
    if not leaf_ids:
        return []
    ph = ",".join("?" * len(leaf_ids))
    leaf_rows = conn.execute(
        f"SELECT * FROM certificates WHERE id IN ({ph})", leaf_ids
    ).fetchall()
    chain_rows = conn.execute(
        f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})", leaf_ids
    ).fetchall()
    dash = _build_dashboard_rows(list(leaf_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows)


def _clamp_page(page: int, total: int, per_page: int) -> int:
    """Clamp a 1-based page index into the valid range for ``total`` rows."""
    if per_page <= 0:
        return 1
    total_pages = max((total + per_page - 1) // per_page, 1)
    return max(1, min(page, total_pages))


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
) -> tuple[list[dict], int]:
    """Return a SQL-filtered, sorted, paginated page of unified dashboard rows.

    Ungrouped dashboard path (BC-073).  Filtering on ``source``/``q`` and the
    chosen sort + LIMIT/OFFSET are pushed into SQL via a UNION over leaf
    certificates, pending hosts (no leaf), and uploaded certs.  Only the rows
    for the requested page are then materialised into rich dashboard dicts.

    ``urgency`` filtering depends on computed chain status (which cannot be
    expressed faithfully in SQL), so when an ``urgency`` filter is requested the
    SQL-narrowed candidate set is built and filtered in Python before
    pagination.  Returns ``(rows, total)``.
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
        params: list = []

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
            scanned_params: list = []
            if like:
                scanned_sql += (
                    " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                    " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                    " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\'"
                    " OR LOWER(c.tags) LIKE ? ESCAPE '\\'"
                    " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
                )
                scanned_params += [like, like, like, like, like]
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
            pending_params: list = []
            if like:
                pending_sql += (
                    " AND (LOWER(h.hostname || ':' || h.port) LIKE ? ESCAPE '\\'"
                    " OR LOWER(h.tags) LIKE ? ESCAPE '\\')"
                )
                pending_params += [like, like]
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
            uploaded_params: list = []
            if like:
                uploaded_sql += (
                    " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                    " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                    " OR LOWER(c.tags) LIKE ? ESCAPE '\\')"
                )
                uploaded_params += [like, like, like]
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


def _reorder_by_candidates(entries: list[dict], ordered) -> list[dict]:
    """Reorder built entries to match the SQL candidate ordering by id."""
    by_id: dict[str, dict] = {e["id"]: e for e in entries}
    result: list[dict] = []
    for r in ordered:
        e = by_id.get(r["ekey"])
        if e is not None:
            result.append(e)
    return result


def _build_pending_entries(host_rows, scan_rows) -> list[dict]:
    """Build pending unified entries (hosts with no leaf cert) for given hosts."""
    if not host_rows:
        return []
    latest_scan: dict[tuple[str, int], dict] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }
    entries: list[dict] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
            "notes": dict(h).get("notes", ""),
        }
        entries.append({
            "id": h["id"],
            "host_id": h["id"],
            "kind": "pending",
            "name": host_key,
            "host": host_key,
            "tags": dict(h).get("tags", ""),
            "source": "scanned",
            "subject": None,
            "issuer": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "urgency": "gray",
            "leaf_urgency": "gray",
            "chain": [],
            "chain_valid": None,
            "chain_status": None,
            "replaces_cert_id": None,
            "notes": "",
            "fingerprint_sha256": None,
            "san_dns_names": [],
            "last_scanned_at": scan["scanned_at"] if scan else None,
            "scan_status": scan["status"] if scan else None,
            "scan_error": scan.get("error_message") if scan else None,
            "added_at": h["added_at"],
            **owner_info,
        })
    return entries


def list_dashboard_grouped_page(
    db_path: str | Path,
    *,
    urgency: str | None = None,
    source: str | None = None,
    q: str | None = None,
    sort_by: str = "days",
    sort_order: str = "asc",
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Return a SQL-grouped, filtered, sorted, paginated page of dashboard rows.

    Grouped dashboard path (BC-073).  Scanned entries sharing a leaf
    fingerprint collapse into a single row whose urgency is the worst urgency
    across the group and whose host count is the number of hosts in the group.
    Uploaded and pending entries pass through ungrouped.

    Scanned-entry grouping uses SQL ``GROUP BY`` so only the visible page of
    grouped rows is materialised with full cert/host/scan detail.  Ungrouped
    entries (uploaded, pending) are loaded and merged in Python.  Returns
    ``(rows, total)``.
    """
    init_schema(db_path)

    _URGENCY_SQL = {
        "expired": "WHEN julianday(c.not_after) - julianday('now') < 0 THEN 0",
        "critical": "WHEN julianday(c.not_after) - julianday('now') < 7 THEN 1",
        "warning": "WHEN julianday(c.not_after) - julianday('now') < 30 THEN 2",
        "healthy": "ELSE 3",
    }
    _URGENCY_ORDER_SQL = ("expired", "critical", "warning", "healthy")
    _URGENCY_RANK = {u: i for i, u in enumerate(_URGENCY_ORDER_SQL)}

    _SORT_COLS = {
        "name": "LOWER(COALESCE(c.subject, c.hostname || ':' || c.port))",
        "issue_date": "c.not_before",
        "last_scan": "COALESCE(last_scan_at, '0000-01-01T00:00:00')",
        "expiry": "c.not_after",
        "days": "c.not_after",
    }
    sort_col = _safe_col(_SORT_COLS.get(sort_by, _SORT_COLS["days"]), _SORT_COLUMNS_GROUPED)
    sql_dir = _safe_dir("DESC" if sort_order == "desc" else "ASC")

    like = f"%{_escape_like(q.lower())}%" if q else None

    with _connect(db_path) as conn:
        # Step 1: SQL GROUP BY fingerprint for scanned entries.
        grouped_sql = f"""
            SELECT
                c.fingerprint_sha256,
                COUNT(DISTINCT c.hostname || ':' || c.port) AS host_count,
                MIN(c.not_after) AS earliest_expiry,
                MIN(julianday(c.not_after) - julianday('now')) AS min_days_remaining,
                CASE
                    {_URGENCY_SQL['expired']}
                    {_URGENCY_SQL['critical']}
                    {_URGENCY_SQL['warning']}
                    {_URGENCY_SQL['healthy']}
                END AS worst_urgency_rank,
                {sort_col} AS sort_val
            FROM certificates c
            WHERE c.is_leaf = 1
              AND c.source = 'scanned'
              AND c.fingerprint_sha256 IS NOT NULL
              AND c.fingerprint_sha256 != ''
        """
        params: list = []

        if like:
            grouped_sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\')"
            )
            params.extend([like, like, like])

        grouped_sql += " GROUP BY c.fingerprint_sha256"

        if urgency:
            rank = _URGENCY_RANK.get(urgency)
            if rank is not None:
                grouped_sql += " HAVING worst_urgency_rank = ?"
                params.append(rank)

        grouped_sql += f" ORDER BY sort_val {sql_dir}"

        rows = conn.execute(grouped_sql, params).fetchall()

        fingerprints = [r["fingerprint_sha256"] for r in rows]

        # Step 2: Load full details for grouped scanned entries.
        cert_rows: list = []
        chain_rows: list = []
        if fingerprints:
            ph = ",".join("?" * len(fingerprints))
            cert_rows = conn.execute(
                f"SELECT * FROM certificates c"
                f" WHERE c.fingerprint_sha256 IN ({ph}) AND c.is_leaf = 1"
                f" ORDER BY c.hostname, c.port",
                fingerprints,
            ).fetchall()
            leaf_ids = [r["id"] for r in cert_rows]
            if leaf_ids:
                cph = ",".join("?" * len(leaf_ids))
                chain_rows = conn.execute(
                    f"SELECT * FROM certificates WHERE parent_cert_id IN ({cph})",
                    leaf_ids,
                ).fetchall()

        host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()
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

    # Step 3: Build rich dashboard rows for scanned entries and group them.
    all_rows = list(cert_rows) + list(chain_rows)
    dash = _build_dashboard_rows(all_rows, anchor_rows)
    entries = _build_unified_from_dash(dash, host_rows, scan_rows, include_uploaded=False)

    entries_by_fp: dict[str, list[dict]] = {}
    for e in entries:
        fp = e.get("fingerprint_sha256")
        if fp:
            entries_by_fp.setdefault(fp, []).append(e)

    grouped_entries: list[dict] = []
    group_idx = 0
    for row in rows:
        fp = row["fingerprint_sha256"]
        group = entries_by_fp.get(fp, [])
        if not group:
            continue
        group_idx += 1
        first = group[0]

        urgency_counts: dict[str, int] = {}
        for h in group:
            u = h["urgency"]
            urgency_counts[u] = urgency_counts.get(u, 0) + 1

        group_urgency = "healthy"
        for u in _URGENCY_ORDER:
            if urgency_counts.get(u, 0) > 0:
                group_urgency = u
                break

        grouped_entries.append({
            "id": first["id"],
            "fingerprint_sha256": fp,
            "group_id": group_idx,
            "kind": "grouped",
            "source": "scanned",
            "subject": first["subject"],
            "issuer": first["issuer"],
            "not_before": first["not_before"],
            "not_after": first["not_after"],
            "days_remaining": first["days_remaining"],
            "urgency": group_urgency,
            "leaf_urgency": first["leaf_urgency"],
            "chain": first["chain"],
            "chain_valid": first["chain_valid"],
            "chain_status": first["chain_status"],
            "san_dns_names": first.get("san_dns_names", []),
            "replaces_cert_id": first.get("replaces_cert_id"),
            "notes": first.get("notes", ""),
            "name": subject_cn(first["subject"] or "") or first["host"],
            "host": first["host"],
            "host_id": first.get("host_id"),
            "host_count": len(group),
            "healthy_count": sum(1 for h in group if h["urgency"] == "healthy"),
            "urgency_summary": urgency_counts,
            "hosts": group,
            "last_scanned_at": first.get("last_scanned_at"),
            "scan_status": first.get("scan_status"),
            "scan_error": first.get("scan_error"),
            "added_at": first.get("added_at"),
            "owner_name": first.get("owner_name", ""),
            "owner_email": first.get("owner_email", ""),
            "owner_slack": first.get("owner_slack", ""),
            "renewal_status": first.get("renewal_status", "pending"),
            "renewal_method": first.get("renewal_method", ""),
            "runbook_url": first.get("runbook_url", ""),
        })

    # Step 4: Load ungrouped entries (uploaded + pending) and merge.
    # Only fetch uploaded leaf certs (scanned entries are already grouped above).
    with _connect(db_path) as conn2:
        uploaded_leaves = conn2.execute(
            "SELECT * FROM certificates WHERE is_leaf = 1 AND source != 'scanned' "
            "ORDER BY created_at"
        ).fetchall()
        uploaded_leaf_ids = [r["id"] for r in uploaded_leaves]
        if uploaded_leaf_ids:
            uph = ",".join("?" * len(uploaded_leaf_ids))
            uploaded_chain = conn2.execute(
                f"SELECT * FROM certificates WHERE parent_cert_id IN ({uph})",
                uploaded_leaf_ids,
            ).fetchall()
        else:
            uploaded_chain = []
    uploaded_dash = _build_dashboard_rows(
        list(uploaded_leaves) + list(uploaded_chain), anchor_rows
    )
    # Mark uploaded entries directly
    for u in uploaded_dash:
        u["kind"] = "uploaded"
        u["name"] = subject_cn(u.get("subject", ""))
        u["last_scanned_at"] = None
        u["scan_status"] = None
        u["scan_error"] = None
        u["added_at"] = None
    ungrouped = list(uploaded_dash)

    # Pending hosts: hosts with no scanned leaf cert at all
    scanned_host_keys = {(r["hostname"], r["port"]) for r in cert_rows}
    pending_hosts = [
        h for h in host_rows
        if (h["hostname"], h["port"]) not in scanned_host_keys
    ]
    ungrouped.extend(_build_pending_entries(pending_hosts, scan_rows))

    all_entries = grouped_entries + ungrouped
    all_entries = _filter_unified(all_entries, q=q, urgency=urgency, source=source)
    all_entries = _sort_unified(all_entries, sort_by=sort_by, sort_order=sort_order)

    total = len(all_entries)
    if per_page > 0:
        start = max(0, (page - 1) * per_page)
        all_entries = all_entries[start : start + per_page]
    return all_entries, total


def get_cert_detail(db_path: str | Path, cert_id: str) -> dict | None:
    """Return a single leaf certificate's dashboard row with chain + posture.

    Targeted JOIN replacement for scanning the full unified list to find one
    cert.  Returns a rich dashboard dict (same shape as the dashboard rows)
    augmented with ``posture`` (latest posture evaluation or ``None``) and
    host context (owner/renewal fields) when the cert maps to a tracked host.
    Returns ``None`` if no leaf cert with that id exists.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        leaf = conn.execute(
            "SELECT * FROM certificates WHERE id = ? AND is_leaf = 1", (cert_id,)
        ).fetchone()
        if leaf is None:
            return None
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ?", (cert_id,)
        ).fetchall()
        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        host_rows = []
        scan_rows = []
        if leaf["hostname"]:
            host_rows = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (leaf["hostname"], leaf["port"]),
            ).fetchall()
            scan_rows = conn.execute(
                """
                SELECT hostname, port, status, scanned_at, error_message
                FROM scan_history sh1
                WHERE sh1.hostname = ? AND sh1.port = ?
                  AND scanned_at = (
                    SELECT MAX(scanned_at) FROM scan_history sh2
                    WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
                  )
                """,
                (leaf["hostname"], leaf["port"]),
            ).fetchall()

    dash = _build_dashboard_rows([leaf, *chain_rows], anchor_rows)
    if not dash:
        return None
    if host_rows:
        unified = _build_unified_from_dash(dash, host_rows, scan_rows)
        row = next((e for e in unified if e.get("id") == cert_id), dash[0])
    else:
        row = dash[0]
        row["kind"] = "uploaded" if leaf["source"] != "scanned" else "scanned"
    row["posture"] = get_posture_for_cert(db_path, cert_id)
    return row


def _build_unified_from_dash(
    dash: list[dict],
    host_rows: list,
    scan_rows: list,
    *,
    include_uploaded: bool = True,
) -> list[dict]:
    """Build unified entries from dashboard rows, host rows, and scan rows."""
    latest_scan: dict[tuple[str, int], dict] = {
        (r["hostname"], r["port"]): dict(r) for r in scan_rows
    }

    scanned_map: dict[str, dict] = {}
    uploaded: list[dict] = []
    for c in dash:
        if c["source"] == "scanned":
            scanned_map[c["host"]] = c
        else:
            uploaded.append(c)

    host_id_map: dict[tuple[str, int], str] = {
        (h["hostname"], h["port"]): h["id"] for h in host_rows
    }

    entries: list[dict] = []
    for h in host_rows:
        host_key = f"{h['hostname']}:{h['port']}"
        scan = latest_scan.get((h["hostname"], h["port"]))
        owner_info = {
            "owner_name": dict(h).get("owner_name", ""),
            "owner_email": dict(h).get("owner_email", ""),
            "owner_slack": dict(h).get("owner_slack", ""),
            "renewal_status": dict(h).get("renewal_status", "pending"),
            "renewal_method": dict(h).get("renewal_method", ""),
            "runbook_url": dict(h).get("runbook_url", ""),
            "notes": dict(h).get("notes", ""),
        }
        if host_key in scanned_map:
            row = scanned_map[host_key]
            row["kind"] = "scanned"
            row["host_id"] = host_id_map.get((h["hostname"], h["port"]))
            row["last_scanned_at"] = scan["scanned_at"] if scan else None
            row["scan_status"] = scan["status"] if scan else None
            row["scan_error"] = scan.get("error_message") if scan else None
            row["added_at"] = h["added_at"]
            row.update(owner_info)
            entries.append(row)
        else:
            entries.append(
                {
                    "id": h["id"],
                    "host_id": h["id"],
                    "kind": "pending",
                    "name": host_key,
                    "host": host_key,
                    "source": "scanned",
                    "subject": None,
                    "issuer": None,
                    "not_before": None,
                    "not_after": None,
                    "days_remaining": None,
                    "urgency": "gray",
                    "leaf_urgency": "gray",
                    "chain": [],
                    "chain_valid": None,
                    "chain_status": None,
                    "replaces_cert_id": None,
                    "notes": "",
                    "fingerprint_sha256": None,
                    "san_dns_names": [],
                    "last_scanned_at": scan["scanned_at"] if scan else None,
                    "scan_status": scan["status"] if scan else None,
                    "scan_error": scan.get("error_message") if scan else None,
                    "added_at": h["added_at"],
                    **owner_info,
                }
            )

    if include_uploaded:
        for u in uploaded:
            u["kind"] = "uploaded"
            u["name"] = subject_cn(u["subject"] or "")
            u["last_scanned_at"] = None
            u["scan_status"] = None
            u["scan_error"] = None
            u["added_at"] = None
            entries.append(u)

    return entries



def _build_host_filter(
    col: str,
    values: list[str] | tuple[str, ...],
    *,
    include_null: bool = False,
) -> tuple[str, tuple]:
    """Build a parameterised SQL WHERE clause for host filtering.

    *col* must be a bare column name (e.g. ``"owner_name"``) validated
    against a whitelist — never derived from user input.  The returned
    fragment is safe to interpolate into SQL via f-string because only the
    whitelisted column name and ``?`` placeholders are inserted.

    Returns ``(clause, params)`` ready for ``conn.execute(sql, params)``.
    """
    _ALLOWED = {"owner_name", "renewal_method"}
    if col not in _ALLOWED:
        raise ValueError(f"disallowed filter column: {col}")
    prefixed = f"h.{col}"
    if not values:
        if include_null:
            return f"{prefixed} IS NULL", ()
        return "1=0", ()
    if len(values) == 1:
        eq = f"{prefixed} = ?"
        if include_null:
            return f"COALESCE({prefixed}, '') = ? OR {prefixed} IS NULL", (values[0],)
        return eq, (values[0],)
    ph = ",".join("?" * len(values))
    clause = f"{prefixed} IN ({ph})"
    if include_null:
        clause = f"COALESCE({prefixed}, '') IN ({ph}) OR {prefixed} IS NULL"
    return clause, tuple(values)


def _load_unified_filtered(
    db_path: str | Path,
    *,
    filter_col: str | None = None,
    filter_values: list[str] | tuple[str, ...] | None = None,
    filter_include_null: bool = False,
    include_uploaded: bool = False,
) -> list[dict]:
    """Load unified entries for scanned/pending hosts, optionally filtered.

    Uses SQL-level filtering via an EXISTS subquery on the *hosts* table so
    only matching rows are materialised.

    Filtering is column-based: *filter_col* is validated against a whitelist,
    and *filter_values* are passed as parameterised ``?`` placeholders — no
    user input reaches the SQL text.

    When *include_uploaded* is True (and no *filter_col* is set), uploaded
    certificates (those without a matching host) are included in the result.
    This is the mode used by :func:`list_unified_entries`.  When False (the
    default), only certificates linked to a host row are returned.
    """
    if filter_col and filter_values is not None:
        host_where, host_params = _build_host_filter(
            filter_col, filter_values, include_null=filter_include_null,
        )
    else:
        host_where, host_params = None, ()

    init_schema(db_path)
    with _connect(db_path) as conn:
        if host_where:
            host_rows = conn.execute(
                f"SELECT * FROM hosts WHERE {host_where} ORDER BY added_at",
                host_params,
            ).fetchall()
        else:
            host_rows = conn.execute("SELECT * FROM hosts ORDER BY added_at").fetchall()

        if host_where:
            exists_clause = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = c.hostname "
                f"AND h.port = c.port AND {host_where})"
            )
        elif include_uploaded:
            exists_clause = "1=1"
        else:
            exists_clause = "c.hostname IS NOT NULL"

        cert_rows = conn.execute(
            f"SELECT * FROM certificates c WHERE c.is_leaf = 1 "
            f"AND {exists_clause} ORDER BY created_at",
            host_params,
        ).fetchall()
        leaf_ids = [r["id"] for r in cert_rows]
        if leaf_ids:
            ph = ",".join("?" * len(leaf_ids))
            chain_rows = conn.execute(
                f"SELECT * FROM certificates WHERE parent_cert_id IN ({ph})",
                leaf_ids,
            ).fetchall()
        else:
            chain_rows = []

        anchor_rows = conn.execute("SELECT * FROM trust_anchors").fetchall()

        if host_where:
            scan_exists = (
                f"EXISTS (SELECT 1 FROM hosts h WHERE h.hostname = sh1.hostname "
                f"AND h.port = sh1.port AND {host_where})"
            )
        else:
            scan_exists = "1=1"
        scan_rows = conn.execute(
            f"""
            SELECT hostname, port, status, scanned_at, error_message
            FROM scan_history sh1
            WHERE scanned_at = (
                SELECT MAX(scanned_at)
                FROM scan_history sh2
                WHERE sh2.hostname = sh1.hostname AND sh2.port = sh1.port
            )
            AND {scan_exists}
            """,
            host_params,
        ).fetchall()

    dash = _build_dashboard_rows(list(cert_rows) + list(chain_rows), anchor_rows)
    return _build_unified_from_dash(dash, host_rows, scan_rows, include_uploaded=include_uploaded)
