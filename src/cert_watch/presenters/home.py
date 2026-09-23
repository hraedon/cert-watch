"""Typed presentation model for the operator home page."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any


class Tone(StrEnum):
    """Template-safe status tone names."""

    NEUTRAL = ""
    WARNING = "t-warn"
    CRITICAL = "t-crit"


@dataclass(frozen=True)
class AttentionItemView:
    severity: str
    kind: str
    cert_id: str | None
    detail_url: str | None
    endpoint: str
    host: str
    host_id: str | None
    days_remaining: int | None
    reasons: tuple[str, ...]
    owner_name: str
    confidence: str
    confidence_label: str
    host_count: int
    severity_label: str
    severity_tone: str


@dataclass(frozen=True)
class ScanCoverageView:
    total: int
    current: int
    overdue: int
    unobserved: int
    failed: int
    unknown: int


@dataclass(frozen=True)
class HorizonBucketView:
    bucket_start: str
    count: int
    tone: str
    is_empty: bool
    is_storm: bool

    def __getitem__(self, key: str) -> Any:
        """Retain the prior read-only mapping access for route-level tests."""
        return getattr(self, key)


@dataclass(frozen=True)
class HomeView:
    queue: tuple[AttentionItemView, ...]
    stats: dict[str, int]
    tracked_total: int
    scan_coverage: ScanCoverageView
    horizon: tuple[HorizonBucketView, ...]
    current_week_start: str
    horizon_storms: int
    error: str | None
    warning: str | None
    saved: str | None

    def template_context(self) -> dict[str, Any]:
        """Return the stable template boundary for the page."""
        return {
            "queue": list(self.queue),
            "stats": self.stats,
            "tracked_total": self.tracked_total,
            "scan_coverage": self.scan_coverage,
            "horizon": list(self.horizon),
            "current_week_start": self.current_week_start,
            "horizon_storms": self.horizon_storms,
            "error": self.error,
            "warning": self.warning,
            "saved": self.saved,
        }


_SEVERITY_DISPLAY = {
    "expired": ("Expired", "expired"),
    "stalled": ("Renewal stalled", "critical"),
    "critical": ("Critical", "critical"),
    "failing": ("Scan failing", "warning"),
    "warning": ("Warning", "warning"),
}


def _present_attention_item(item: dict[str, Any]) -> AttentionItemView:
    label, tone = _SEVERITY_DISPLAY.get(str(item["severity"]), ("Info", "gray"))
    return AttentionItemView(
        severity=str(item["severity"]),
        kind=str(item["kind"]),
        cert_id=item.get("cert_id"),
        detail_url=item.get("detail_url"),
        endpoint=str(item["endpoint"]),
        host=str(item["host"]),
        host_id=item.get("host_id"),
        days_remaining=item.get("days_remaining"),
        reasons=tuple(item["reasons"]),
        owner_name=str(item["owner_name"]),
        confidence=str(item["confidence"]),
        confidence_label=str(item["confidence_label"]),
        host_count=int(item["host_count"]),
        severity_label=label,
        severity_tone=tone,
    )


def present_home(
    *,
    queue: list[dict[str, Any]],
    stats: dict[str, int],
    tracked_total: int,
    scan_coverage: dict[str, int],
    calendar: list[dict[str, Any]],
    now: datetime | None = None,
    error: str | None = None,
    warning: str | None = None,
    saved: str | None = None,
) -> HomeView:
    """Build the home view without HTTP, database, or template dependencies."""
    current = now or datetime.now(UTC)
    week_start = current - timedelta(days=current.weekday())
    current_week_start = week_start.strftime("%Y-%m-%d")
    next_week_start = (week_start + timedelta(days=7)).strftime("%Y-%m-%d")
    horizon_end = (week_start + timedelta(weeks=12)).strftime("%Y-%m-%d")

    horizon: list[HorizonBucketView] = []
    storms = 0
    for raw in calendar:
        bucket_start = str(raw["bucket_start"])
        if not current_week_start <= bucket_start < horizon_end:
            continue
        if bucket_start <= current_week_start:
            tone = Tone.CRITICAL
        elif bucket_start <= next_week_start:
            tone = Tone.WARNING
        else:
            tone = Tone.NEUTRAL
        count = int(raw.get("count", 0))
        storms += int(count >= 3)
        horizon.append(
            HorizonBucketView(
                bucket_start=bucket_start,
                count=count,
                tone=tone,
                is_empty=count == 0,
                is_storm=count >= 3,
            )
        )

    return HomeView(
        queue=tuple(_present_attention_item(item) for item in queue),
        stats=stats,
        tracked_total=tracked_total,
        scan_coverage=ScanCoverageView(**scan_coverage),
        horizon=tuple(horizon),
        current_week_start=current_week_start,
        horizon_storms=storms,
        error=error,
        warning=warning,
        saved=saved,
    )
