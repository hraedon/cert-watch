"""Shared operator-facing status labels.

Keep these rules free of Browse- or detail-page view models so every server
presenter can reuse them.  Browser-rendered lazy rows mirror this small
contract in ``static/js/dashboard.js`` and an e2e agreement test compares the
two paths.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class StatusDisplay:
    label: str
    tone: str


def condition_display(
    condition: str | None,
    days: int | None,
    monitoring: str,
) -> StatusDisplay:
    """Present certificate evidence without implying a stale scan is healthy."""
    if condition is None or days is None:
        return StatusDisplay("No certificate", "t-muted")

    stale = monitoring not in {"current", "not_monitored"}
    if condition == "expired":
        count = abs(days)
        label = f"Expired {count} day{'s' if count != 1 else ''} ago"
        return StatusDisplay(
            f"Last seen · {label.lower()}" if stale else label,
            "t-expired",
        )
    if days == 0:
        return StatusDisplay(
            "Last seen · expires today" if stale else "Expires today",
            "t-crit",
        )
    if condition == "ok" and stale:
        return StatusDisplay(
            f"Last seen OK · expires in {days} day{'s' if days != 1 else ''}",
            "t-muted",
        )

    tone = {"le7": "t-crit", "8to30": "t-warn", "ok": "t-ok"}.get(
        condition, "t-muted"
    )
    label = f"{days} day{'s' if days != 1 else ''} left"
    return StatusDisplay(f"Last seen · {label}" if stale else label, tone)
