"""Read complete seven-day expiry filters within Python's date range."""

from datetime import date, timedelta


def expiry_week_bounds(value: str) -> tuple[date, date] | None:
    """Return inclusive start/exclusive end, or None for an invalid window."""
    try:
        start = date.fromisoformat(value)
        return start, start + timedelta(days=7)
    except (ValueError, OverflowError):
        return None
