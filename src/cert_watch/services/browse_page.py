"""Read-side application service for the Browse page."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cert_watch.database import (
    dashboard_axis_stats,
    dashboard_urgency_stats,
    distinct_tags,
    get_posture_grades_for_certs,
    list_calendar,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_fleet_pivot,
    pivot_urgency_stats,
)
from cert_watch.database.chain_status_cache import prepare_status
from cert_watch.scan_freshness import ScanEvidence, load_scan_evidence
from cert_watch.status_model import AxisSettings, prepare_status_model_context

_GLOBAL_VIEWS = frozenset({"issuer", "owner", "renewal_method", "calendar"})


@dataclass(frozen=True)
class BrowsePageData:
    entries: list[dict[str, Any]]
    all_tags: list[str]
    pivot_groups: list[dict[str, Any]] | None
    pivot_stats: dict[str, int]
    pivot_view: str
    calendar_data: list[dict[str, Any]] | None
    filter_q: str
    filter_urgency: str
    filter_source: str
    sort_by: str
    sort_order: str
    page: int
    total_pages: int
    total_entries: int
    tracked_total: int
    grouped: int
    posture_grades: dict[str, str]
    scan_evidence: dict[str, ScanEvidence]
    axis_stats: dict[str, dict[str, int]] = field(default_factory=dict)
    filter_condition: str = ""
    filter_monitoring: str = ""
    filter_renewal: str = ""
    filter_delivery: str = ""


def load_browse_page(
    db_path: str | Path,
    *,
    q: str | None,
    urgency: str | None,
    source: str | None,
    condition: str | None = None,
    monitoring: str | None = None,
    renewal: str | None = None,
    delivery: str | None = None,
    sort_by: str,
    sort_order: str,
    page: int,
    grouped: int,
    view: str,
    scope_tags: tuple[str, ...],
    sched_hour: int,
    sched_min: int,
    axis_settings: AxisSettings | None = None,
) -> BrowsePageData:
    """Fetch all read models needed for one Browse render."""
    if view in _GLOBAL_VIEWS:
        q = urgency = source = condition = monitoring = renewal = delivery = None
    grouped = int(bool(grouped))
    # One status context for the whole render: every count, group, filter and
    # row below is judged at one instant with one chain status per row.
    status = prepare_status(db_path)
    axis_settings = axis_settings or AxisSettings(
        sched_hour=sched_hour, sched_min=sched_min,
    )
    axes = prepare_status_model_context(
        db_path, certificate_status=status, settings=axis_settings
    )

    pivot_groups = (
        list_fleet_pivot(
            db_path, view, scope_tags=scope_tags, status=status, axes=axes
        )
        if view in {"issuer", "owner", "renewal_method"}
        else None
    )
    calendar_data = (
        list_calendar(db_path, bucket="week", scope_tags=scope_tags) if view == "calendar" else None
    )

    per_page = 25
    entries: list[dict[str, Any]] = []
    pivot_stats: dict[str, int] | None = None
    if calendar_data is not None:
        total = sum(int(bucket.get("count", 0)) for bucket in calendar_data)
        total_pages = 1
        pivot_stats = dashboard_urgency_stats(db_path, scope_tags=scope_tags, status=status)
    elif pivot_groups is not None:
        total = sum(int(group["count"]) for group in pivot_groups)
        total_pages = 1
        pivot_stats = pivot_urgency_stats(db_path, scope_tags=scope_tags, status=status)
    elif grouped:
        entries, total = list_dashboard_grouped_page(
            db_path,
            q=q,
            urgency=urgency,
            source=source,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
            scope_tags=scope_tags,
            status=status,
            axes=axes,
            condition=condition,
            monitoring=monitoring,
            renewal=renewal,
            delivery=delivery,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
    else:
        entries, total = list_dashboard_page(
            db_path,
            q=q,
            urgency=urgency,
            source=source,
            sort_by=sort_by,
            sort_order=sort_order,
            page=page,
            per_page=per_page,
            scope_tags=scope_tags,
            status=status,
            axes=axes,
            condition=condition,
            monitoring=monitoring,
            renewal=renewal,
            delivery=delivery,
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    if pivot_stats is None:
        pivot_stats = dashboard_urgency_stats(
            db_path, q=q, source=source, scope_tags=scope_tags, status=status
        )

    axis_stats = dashboard_axis_stats(
        db_path, q=q, source=source, scope_tags=scope_tags, status=status, axes=axes
    )

    if pivot_groups is not None:
        tracked_total = total
    else:
        _, tracked_total = list_dashboard_page(
            db_path,
            q=q,
            source=source,
            per_page=1,
            scope_tags=scope_tags,
            status=status,
            axes=axes,
        )

    is_global_view = pivot_groups is not None or calendar_data is not None
    display_entries = [] if is_global_view else entries
    cert_ids = [entry["id"] for entry in display_entries if entry.get("id")]
    posture_grades = get_posture_grades_for_certs(db_path, cert_ids) if cert_ids else {}
    scan_evidence = (
        load_scan_evidence(
            db_path,
            scope_tags=scope_tags,
            hour=sched_hour,
            minute=sched_min,
        )
        if display_entries
        else {}
    )
    return BrowsePageData(
        entries=display_entries,
        all_tags=distinct_tags(db_path, scope_tags=scope_tags),
        pivot_groups=pivot_groups,
        pivot_stats=pivot_stats,
        axis_stats=axis_stats,
        pivot_view=view if is_global_view else "",
        calendar_data=calendar_data,
        filter_q=q or "",
        filter_urgency=urgency or "",
        filter_source=source or "",
        filter_condition=condition or "",
        filter_monitoring=monitoring or "",
        filter_renewal=renewal or "",
        filter_delivery=delivery or "",
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        total_pages=total_pages,
        total_entries=total,
        tracked_total=tracked_total,
        grouped=grouped,
        posture_grades=posture_grades,
        scan_evidence=scan_evidence,
    )
