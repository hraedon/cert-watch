"""SQL-paginated fingerprint-grouped Browse query (#120 / #126 S1)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cert_watch.database.chain_status_cache import StatusContext, prepare_status
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import _safe_dir
from cert_watch.database.dashboard_page import build_inventory_entries, inventory_candidates_sql

# Compatibility seam for the existing row-construction scaling counter. The
# implementation delegates through ``dashboard_unified``; the imported name
# remains patchable so the guard can count both legacy and current paths.
from cert_watch.database.dashboard_rows import (
    _build_dashboard_rows as _build_dashboard_rows,
)
from cert_watch.database.fleet import group_entries_by_fingerprint
from cert_watch.database.schema import init_schema
from cert_watch.status_model import (
    AxisSettings,
    StatusModelContext,
    attach_status_models,
    load_delivery_statuses,
    prepare_status_model_context,
    register_status_model_functions,
)


def _group_key_sql(alias: str = "inv") -> str:
    return (
        f"CASE WHEN {alias}.etype = 'leaf' AND {alias}.host_id IS NOT NULL"
        f" THEN 'scanned:' || COALESCE((SELECT c.fingerprint_sha256"
        f" FROM certificates c WHERE c.id = {alias}.ekey), {alias}.ekey)"
        f" ELSE {alias}.etype || ':' || {alias}.ekey END"
    )


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
    now: datetime | None = None,
    status: StatusContext | None = None,
    axes: StatusModelContext | None = None,
    axis_settings: AxisSettings | None = None,
    condition: str | None = None,
    monitoring: str | None = None,
    renewal: str | None = None,
    delivery: str | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """Select/order one page of groups in SQL, then build only its members.

    Filters select fingerprint groups in SQL. Once a group is selected, all
    of its in-scope endpoints are shown (the established grouped-search
    contract). Counts and LIMIT operate on group keys, so rows outside the
    requested page are never handed to the Python row builder.
    """
    init_schema(db_path)
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
    member_candidates = inventory_candidates_sql(
        source=source, q=None, scope_tags=scope_tags, status=status, axes=axes
    )
    assert member_candidates is not None
    member_base_sql, member_params = member_candidates

    if delivery:
        with _connect(db_path) as conn:
            register_status_model_functions(conn, axes)
            ids = tuple(
                row[0]
                for row in conn.execute(
                    f"SELECT ekey FROM ({base_sql}) WHERE etype = 'leaf'", params
                ).fetchall()
            )
        load_delivery_statuses(db_path, ids, axes)

    for column, value in (
        ("urgency", urgency),
        ("condition", condition),
        ("monitoring", monitoring),
        ("renewal", renewal),
        ("delivery", delivery),
    ):
        if value:
            base_sql = f"SELECT * FROM ({base_sql}) WHERE {column} = ?"
            params = [*params, value]

    sort_column = {
        "name": "sort_name",
        "issue_date": "sort_issue",
        "last_scan": "sort_scan",
        "expiry": "sort_expiry",
        "days": "sort_expiry",
    }.get(sort_by, "sort_expiry")
    direction = _safe_dir("DESC" if sort_order == "desc" else "ASC")
    key = _group_key_sql()
    groups_sql = (
        f"SELECT {key} AS group_key, MIN({sort_column}) AS sort_val"
        f" FROM ({base_sql}) inv GROUP BY group_key"
    )

    with _connect(db_path) as conn:
        register_status_model_functions(conn, axes)
        total = conn.execute(f"SELECT COUNT(*) FROM ({groups_sql})", params).fetchone()[0]
        last_page = max((total + per_page - 1) // per_page, 1) if per_page > 0 else 1
        clamped = max(1, min(page, last_page))
        page_groups_sql = f"{groups_sql} ORDER BY sort_val {direction}, group_key ASC"
        page_params = list(params)
        if per_page > 0:
            page_groups_sql += " LIMIT ? OFFSET ?"
            page_params += [per_page, (clamped - 1) * per_page]
        group_rows = conn.execute(page_groups_sql, page_params).fetchall()
        group_keys = [row["group_key"] for row in group_rows]
        if not group_keys:
            return [], int(total)
        placeholders = ",".join("?" for _ in group_keys)
        member_sql = (
            f"SELECT inv.*, {_group_key_sql()} AS group_key FROM ({member_base_sql}) inv"
            f" WHERE {_group_key_sql()} IN ({placeholders})"
        )
        members = conn.execute(member_sql, [*member_params, *group_keys]).fetchall()
        by_group: dict[str, list[Any]] = {value: [] for value in group_keys}
        for member in members:
            by_group.setdefault(member["group_key"], []).append(member)
        ordered = [
            member
            for group_key in group_keys
            for member in sorted(
                by_group.get(group_key, []),
                key=lambda row: (row[sort_column], row["ekey"]),
                reverse=direction == "DESC",
            )
        ]
        built = build_inventory_entries(conn, ordered, status=status, axes=axes)

    grouped = group_entries_by_fingerprint(built, force=True)
    attach_status_models(db_path, grouped, axes)
    return grouped, int(total)
