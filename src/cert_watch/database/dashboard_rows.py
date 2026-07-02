"""Dashboard row building — rich dict construction from raw certificate rows."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect, _parse_iso, _row_to_cert
from cert_watch.database.dashboard_helpers import _SORT_COLUMNS_BARE, _safe_col, _safe_dir
from cert_watch.database.schema import init_schema


def _build_dashboard_rows(
    cert_rows: list[Any],
    anchor_rows: list[Any],
) -> list[dict[str, Any]]:
    """Build rich dashboard rows from raw certificate and anchor rows."""
    from cert_watch.cert_chain import chain_status

    # anchor_rows come from trust_anchors, which lacks the certificate-only
    # columns (is_leaf, source, notes) that _row_to_cert reads — default them.
    anchors = [_row_to_cert({**dict(r), "is_leaf": 0}) for r in anchor_rows]

    leaf_rows: list[dict[str, Any]] = []
    children_by_leaf: dict[str, list[dict[str, Any]]] = {}
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

    dash: list[dict[str, Any]] = []
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
) -> list[dict[str, Any]]:
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
