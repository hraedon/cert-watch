"""Read-side application service for the Browse page."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cert_watch.database import (
    dashboard_urgency_stats,
    distinct_tags,
    get_posture_grades_for_certs,
    list_calendar,
    list_dashboard_grouped_page,
    list_dashboard_page,
    list_fleet_pivot,
    pivot_urgency_stats,
)
from cert_watch.scan_freshness import ScanEvidence, load_scan_evidence

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


def load_browse_page(
    db_path: str | Path,
    *,
    q: str | None,
    urgency: str | None,
    source: str | None,
    sort_by: str,
    sort_order: str,
    page: int,
    grouped: int,
    view: str,
    scope_tags: tuple[str, ...],
    sched_hour: int,
    sched_min: int,
) -> BrowsePageData:
    """Fetch all read models needed for one Browse render."""
    if view in _GLOBAL_VIEWS:
        q = urgency = source = None
    grouped = int(bool(grouped))

    pivot_groups = (
        list_fleet_pivot(db_path, view, scope_tags=scope_tags)
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
        pivot_stats = dashboard_urgency_stats(db_path, scope_tags=scope_tags)
    elif pivot_groups is not None:
        total = sum(int(group["count"]) for group in pivot_groups)
        total_pages = 1
        pivot_stats = pivot_urgency_stats(db_path, scope_tags=scope_tags)
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
        )
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))

    if pivot_stats is None:
        pivot_stats = dashboard_urgency_stats(db_path, q=q, source=source, scope_tags=scope_tags)

    if pivot_groups is not None:
        tracked_total = total
    else:
        _, tracked_total = list_dashboard_page(
            db_path, q=q, source=source, per_page=1, scope_tags=scope_tags
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
        pivot_view=view if is_global_view else "",
        calendar_data=calendar_data,
        filter_q=q or "",
        filter_urgency=urgency or "",
        filter_source=source or "",
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
