"""SQL-grouped fingerprint dashboard query path (BC-073)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import (
    _SORT_COLUMNS_GROUPED,
    _URGENCY_ORDER,
    _add_grouped_effective_tag_filter,
    _entry_matches_scope_tag,
    _escape_like,
    _filter_unified,
    _safe_col,
    _safe_dir,
    _sort_unified,
)
from cert_watch.database.dashboard_rows import _build_dashboard_rows
from cert_watch.database.dashboard_unified import (
    _build_pending_entries,
    _build_unified_from_dash,
)
from cert_watch.database.schema import init_schema
from cert_watch.filters import subject_cn
from cert_watch.tags import format_tags, merge_tags


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
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Return a SQL-grouped, filtered, sorted, paginated page of dashboard rows.

    Grouped dashboard path (BC-073).  Scanned entries sharing a leaf
    fingerprint collapse into a single row whose urgency is the worst urgency
    across the group and whose host count is the number of hosts in the group.
    Uploaded and pending entries pass through ungrouped.

    Scanned-entry grouping uses SQL ``GROUP BY`` so only the visible page of
    grouped rows is materialised with full cert/host/scan detail.  Ungrouped
    entries (uploaded, pending) are loaded and merged in Python.  Returns
    ``(rows, total)``.

    ``scope_tags`` restricts results to certificates/hosts whose effective tags
    (cert tags ∪ host tags) include at least one supplied tag (WI-051).
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
        params: list[Any] = []

        if like:
            grouped_sql += (
                " AND (LOWER(c.subject) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.issuer) LIKE ? ESCAPE '\\'"
                " OR LOWER(c.hostname || ':' || c.port) LIKE ? ESCAPE '\\')"
            )
            params.extend([like, like, like])

        grouped_sql, params = _add_grouped_effective_tag_filter(
            grouped_sql, params, scope_tags or ()
        )

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
        cert_rows: list[Any] = []
        chain_rows: list[Any] = []
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

    entries_by_fp: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        fp = e.get("fingerprint_sha256")
        if fp:
            entries_by_fp.setdefault(fp, []).append(e)

    grouped_entries: list[dict[str, Any]] = []
    group_idx = 0
    for row in rows:
        fp = row["fingerprint_sha256"]
        group = entries_by_fp.get(fp, [])
        if not group:
            continue
        group_idx += 1
        first = group[0]
        group_tags = format_tags(merge_tags(*[h.get("tags", "") for h in group]))

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
            "tags": group_tags,
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

    if scope_tags:
        ungrouped = [e for e in ungrouped if _entry_matches_scope_tag(e, scope_tags)]

    all_entries = grouped_entries + ungrouped
    all_entries = _filter_unified(all_entries, q=q, urgency=urgency, source=source)
    all_entries = _sort_unified(all_entries, sort_by=sort_by, sort_order=sort_order)

    total = len(all_entries)
    if per_page > 0:
        start = max(0, (page - 1) * per_page)
        all_entries = all_entries[start : start + per_page]
    return all_entries, total
