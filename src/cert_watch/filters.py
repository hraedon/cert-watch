"""Jinja template filters and DN parsing helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime


def humanize_expiry(dt) -> str:
    """Render a datetime (or ISO string) as 'YYYY-MM-DD (in 3 days)'."""
    if dt is None:
        return ""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    delta_days = (dt.date() - now.date()).days
    abs_str = dt.strftime("%Y-%m-%d")
    rel = _relative(delta_days)
    return f"{abs_str} ({rel})"


def _relative(days: int) -> str:
    if days == 0:
        return "today"
    past = days < 0
    n = abs(days)
    if n < 60:
        unit = "day" if n == 1 else "days"
        amount = f"{n} {unit}"
    elif n < 730:
        months = round(n / 30)
        unit = "month" if months == 1 else "months"
        amount = f"{months} {unit}"
    else:
        years = round(n / 365)
        unit = "year" if years == 1 else "years"
        amount = f"{years} {unit}"
    return f"expired {amount} ago" if past else f"in {amount}"


def compute_urgency(days_remaining: int | None) -> str:
    """Compute urgency bucket from days until expiry.

    Thresholds per wi_fr01_dashboard AC-02:
      Red    (< 7 days), Yellow (< 30 days), Green (>= 30 days).
    An explicit "expired" tier is added for already-expired certs.
    """
    if days_remaining is None:
        return "gray"
    if days_remaining < 0:
        return "expired"
    if days_remaining < 7:
        return "critical"
    if days_remaining < 30:
        return "warning"
    return "healthy"


def relative_short(days: int) -> str:
    """Short relative time string: 'in 4 days', '3 days ago', 'in 2 months'."""
    if days == 0:
        return "today"
    past = days < 0
    n = abs(days)
    if n < 45:
        unit = "day" if n == 1 else "days"
        amount = f"{n} {unit}"
    elif n < 365:
        months = round(n / 30)
        unit = "month" if months == 1 else "months"
        amount = f"{months} {unit}"
    else:
        years = round(n / 365)
        unit = "year" if years == 1 else "years"
        amount = f"{years} {unit}"
    return f"expired {amount} ago" if past else f"in {amount}"


def parse_dn_field(dn: str, field: str) -> str:
    """Extract a single RDN value from an RFC 4514 DN string.

    Handles escaped commas (\\,) per RFC 4514.
    """
    if not dn:
        return ""
    parts = re.split(r"(?<!\\),", dn)
    for part in parts:
        part = part.strip()
        if part.startswith(f"{field}="):
            value = part[len(field) + 1 :]
            value = value.replace("\\,", ",").replace("\\\\", "\\")
            return value
    return ""


def friendly_issuer(issuer_dn: str) -> str:
    """Extract a friendly issuer org name from the issuer DN.

    Tries O= first, falls back to CN=.
    """
    return parse_dn_field(issuer_dn, "O") or parse_dn_field(issuer_dn, "CN") or issuer_dn


def issuer_cn(issuer_dn: str) -> str:
    """Extract the issuer CN from the DN."""
    return parse_dn_field(issuer_dn, "CN") or issuer_dn


def subject_cn(subject_dn: str) -> str:
    """Extract the subject CN from the DN."""
    return parse_dn_field(subject_dn, "CN") or subject_dn


def register_filters(templates) -> None:
    """Register all filters on a Jinja2Templates instance."""
    templates.env.filters["humanize_expiry"] = humanize_expiry
    templates.env.filters["urgency"] = compute_urgency
    templates.env.filters["relative_short"] = relative_short
    templates.env.filters["friendly_issuer"] = friendly_issuer
    templates.env.filters["issuer_cn"] = issuer_cn
    templates.env.filters["subject_cn"] = subject_cn
