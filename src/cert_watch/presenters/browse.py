"""Typed, HTTP-free presentation model for the Browse page."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from cert_watch.filters import compute_urgency
from cert_watch.scan_freshness import ScanEvidence
from cert_watch.services.browse_page import BrowsePageData
from cert_watch.tags import parse_tags


@dataclass(frozen=True)
class BrowseEntryView:
    id: str
    host_id: str | None
    kind: str
    name: str
    host: str
    source: str
    subject: str | None
    issuer: str | None
    not_before: str | None
    not_after: str | None
    days_remaining: int | None
    urgency: str
    chain_status: str | None
    chain_valid: bool | None
    owner_name: str
    renewal_method: str
    notes: str
    group_id: int | None
    host_count: int
    hosts: tuple[BrowseEntryView, ...]
    tag_items: tuple[str, ...]
    renewal_is_manual: bool
    renewal_label: str
    expiry_bar_percent: int | None
    expiry_horizon_title: str
    visible_sans: tuple[str, ...]
    hidden_san_count: int
    posture_grade: str | None
    freshness_current: int
    freshness_total: int
    freshness_label: str
    freshness_tone: str
    scan_status: str | None
    scan_error: str | None
    last_scanned_at: str | None

    def __getitem__(self, key: str) -> Any:
        """Retain the prior read-only mapping access for route-level tests."""
        return getattr(self, key)


@dataclass(frozen=True)
class PivotGroupView:
    key: str
    count: int
    worst_urgency: str
    earliest_expiry: int | None


@dataclass(frozen=True)
class CalendarBucketView:
    bucket_start: str
    count: int
    tone: str
    is_empty: bool
    is_storm: bool


@dataclass(frozen=True)
class BrowseView:
    entries: tuple[BrowseEntryView, ...]
    all_tags: tuple[str, ...]
    pivot_groups: tuple[PivotGroupView, ...] | None
    pivot_stats: dict[str, int]
    pivot_view: str
    calendar_data: tuple[CalendarBucketView, ...] | None
    current_week_start: str
    calendar_storms: int
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

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages

    def browse_url(self, **changes: Any) -> str:
        """Build inventory links from only the supported table controls."""
        state: dict[str, Any] = {
            "q": self.filter_q or None,
            "urgency": self.filter_urgency or None,
            "source": self.filter_source or None,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order,
            "grouped": self.grouped,
        }
        state.update({key: value for key, value in changes.items() if key in state})
        return "/browse?" + urlencode(
            {key: value for key, value in state.items() if value is not None and value != ""}
        )

    def template_context(self) -> dict[str, Any]:
        return {
            "entries": list(self.entries),
            "all_tags": self.all_tags,
            "pivot_groups": (
                list(self.pivot_groups) if self.pivot_groups is not None else None
            ),
            "pivot_stats": self.pivot_stats,
            "pivot_view": self.pivot_view,
            "calendar_data": (
                list(self.calendar_data) if self.calendar_data is not None else None
            ),
            "current_week_start": self.current_week_start,
            "calendar_storms": self.calendar_storms,
            "filter_q": self.filter_q,
            "filter_urgency": self.filter_urgency,
            "filter_source": self.filter_source,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order,
            "page": self.page,
            "total_pages": self.total_pages,
            "total_entries": self.total_entries,
            "tracked_total": self.tracked_total,
            "browse_url": self.browse_url,
            "has_prev": self.has_prev,
            "has_next": self.has_next,
            "grouped": self.grouped,
        }


def _urgency(raw: dict[str, Any]) -> str:
    return str(raw.get("urgency") or compute_urgency(raw.get("days_remaining")))


def _expiry_percent(days_remaining: int | None) -> int | None:
    if days_remaining is None:
        return None
    if days_remaining < 0:
        return 100
    return max(2, min(100, int(days_remaining / 90 * 100)))


def _freshness(
    raw: dict[str, Any],
    children: tuple[BrowseEntryView, ...],
    evidence: dict[str, ScanEvidence],
) -> tuple[int, int, str, str]:
    if raw.get("kind") == "grouped":
        total = sum(child.freshness_total for child in children)
        current = sum(child.freshness_current for child in children)
        return (
            current,
            total,
            f"{current}/{total} current scans",
            ("t-warn" if current < total else "cw-muted"),
        )
    scan = evidence.get(str(raw.get("host_id") or ""))
    if scan is None:
        return 0, 0, "", ""
    return (
        int(scan.state == "current"),
        1,
        scan.label,
        "cw-muted" if scan.state == "current" else "t-warn",
    )


def _present_entry(
    raw: dict[str, Any],
    posture_grades: dict[str, str],
    evidence: dict[str, ScanEvidence],
) -> BrowseEntryView:
    children = tuple(
        _present_entry(child, posture_grades, evidence) for child in raw.get("hosts") or []
    )
    current, total, freshness_label, freshness_tone = _freshness(raw, children, evidence)
    name = str(raw.get("name") or "")
    host = str(raw.get("host") or "")
    sans = raw.get("san_dns_names")
    san_items = sans if isinstance(sans, list) else []
    deduped = tuple(str(san) for san in san_items if san != (name or host))
    renewal_method = str(raw.get("renewal_method") or "")
    days_remaining = raw.get("days_remaining")
    return BrowseEntryView(
        id=str(raw.get("id") or ""),
        host_id=raw.get("host_id"),
        kind=str(raw.get("kind") or ""),
        name=name,
        host=host,
        source=str(raw.get("source") or ""),
        subject=raw.get("subject"),
        issuer=raw.get("issuer"),
        not_before=raw.get("not_before"),
        not_after=raw.get("not_after"),
        days_remaining=days_remaining,
        urgency=_urgency(raw),
        chain_status=raw.get("chain_status"),
        chain_valid=raw.get("chain_valid"),
        owner_name=str(raw.get("owner_name") or ""),
        renewal_method=renewal_method,
        notes=str(raw.get("notes") or ""),
        group_id=raw.get("group_id"),
        host_count=int(raw.get("host_count") or len(children) or 1),
        hosts=children,
        tag_items=tuple(parse_tags(str(raw.get("tags") or ""))),
        renewal_is_manual=renewal_method in {"manual", ""},
        renewal_label=renewal_method or "no auto-renew",
        expiry_bar_percent=_expiry_percent(days_remaining),
        expiry_horizon_title=(
            f"{days_remaining} days of a 90-day horizon" if days_remaining is not None else ""
        ),
        visible_sans=deduped[:2],
        hidden_san_count=max(len(deduped) - 2, 0),
        posture_grade=posture_grades.get(str(raw.get("id") or "")),
        freshness_current=current,
        freshness_total=total,
        freshness_label=freshness_label,
        freshness_tone=freshness_tone,
        scan_status=raw.get("scan_status"),
        scan_error=raw.get("scan_error"),
        last_scanned_at=raw.get("last_scanned_at"),
    )


def present_browse(data: BrowsePageData, *, now: datetime | None = None) -> BrowseView:
    """Turn fetched Browse data into the sole template-facing model."""
    current = now or datetime.now(UTC)
    week_start = current - timedelta(days=current.weekday())
    current_week_start = week_start.strftime("%Y-%m-%d")
    next_week_start = (week_start + timedelta(days=7)).strftime("%Y-%m-%d")
    calendar = None
    storms = 0
    if data.calendar_data is not None:
        buckets: list[CalendarBucketView] = []
        for raw in data.calendar_data:
            bucket_start = str(raw.get("bucket_start", ""))
            if bucket_start <= current_week_start:
                tone = "t-crit"
            elif bucket_start <= next_week_start:
                tone = "t-warn"
            else:
                tone = ""
            count = int(raw.get("count", 0))
            storms += int(count >= 3)
            buckets.append(
                CalendarBucketView(
                    bucket_start=bucket_start,
                    count=count,
                    tone=tone,
                    is_empty=count == 0,
                    is_storm=count >= 3,
                )
            )
        calendar = tuple(buckets)

    pivot_groups = (
        tuple(
            PivotGroupView(
                key=str(group["key"]),
                count=int(group["count"]),
                worst_urgency=str(group["worst_urgency"]),
                earliest_expiry=group.get("earliest_expiry"),
            )
            for group in data.pivot_groups
        )
        if data.pivot_groups is not None
        else None
    )
    return BrowseView(
        entries=tuple(
            _present_entry(entry, data.posture_grades, data.scan_evidence) for entry in data.entries
        ),
        all_tags=tuple(data.all_tags),
        pivot_groups=pivot_groups,
        pivot_stats=data.pivot_stats,
        pivot_view=data.pivot_view,
        calendar_data=calendar,
        current_week_start=current_week_start,
        calendar_storms=storms,
        filter_q=data.filter_q,
        filter_urgency=data.filter_urgency,
        filter_source=data.filter_source,
        sort_by=data.sort_by,
        sort_order=data.sort_order,
        page=data.page,
        total_pages=data.total_pages,
        total_entries=data.total_entries,
        tracked_total=data.tracked_total,
        grouped=data.grouped,
    )
