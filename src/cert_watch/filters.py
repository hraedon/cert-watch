"""Jinja template filters and DN parsing helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from fastapi.templating import Jinja2Templates


def humanize_expiry(dt: datetime | str | None) -> str:
    """Render a datetime (or ISO string) as 'YYYY-MM-DD (in 3 days)'."""
    if dt is None:
        return ""
    if isinstance(dt, str):
        parsed: datetime | None
        try:
            parsed = datetime.fromisoformat(dt)
        except ValueError:
            parsed = None
        if parsed is None:
            return dt
        dt = parsed
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


_URGENCY_LABELS = {
    "expired": "Expired",
    "critical": "Critical",
    "warning": "Warning",
    "healthy": "Healthy",
    "gray": "Unknown",
    "neutral": "—",
}

_URGENCY_TONES = {
    "expired": "var(--expired)",
    "critical": "var(--crit)",
    "warning": "var(--warn)",
    "healthy": "var(--ok)",
    "gray": "var(--text-3)",
    "neutral": "var(--text-2)",
}


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


def urgency_label(urgency: str) -> str:
    """Map an urgency bucket to its display label (WI-108).

    Single source of truth for the text rendered inside ``cw-pill`` —
    previously hand-duplicated as ``{% if urg == 'expired' %}Expired{% ... %}``
    chains across 7+ template sites.
    """
    return _URGENCY_LABELS.get(urgency, "Unknown")


def urgency_tone(urgency: str) -> str:
    """Map an urgency bucket to its CSS colour-variable (WI-108).

    Replaces the ``{% set _c = 'var(--expired)' if urg == 'expired' else ... %}``
    if-chain duplicated across dashboard.html, certificate_detail.html, and
    team_dashboard.html.
    """
    return _URGENCY_TONES.get(urgency, "var(--text-3)")


def compute_urgency_with_chain(
    leaf_days: int,
    min_chain_days: int | None = None,
    chain_status_val: str | None = None,
) -> str:
    """Compute urgency considering chain child expiry and chain status.

    Takes the minimum of leaf_days and min_chain_days (if present),
    then downgrades "healthy" to "warning" when chain_status is
    "incomplete" or "invalid".
    """
    all_days = [leaf_days]
    if min_chain_days is not None:
        all_days.append(int(min_chain_days))
    min_days = min(all_days)
    u = compute_urgency(min_days)
    if chain_status_val in ("incomplete", "invalid") and u == "healthy":
        u = "warning"
    return u


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


# Acronyms that should stay upper-case in humanized labels. Jinja's built-in
# `title` filter lower-cases them (hsts -> Hsts, ocsp -> Ocsp); this set restores
# the conventional casing for our domain terms.
_ACRONYMS = {
    "hsts": "HSTS",
    "ocsp": "OCSP",
    "tls": "TLS",
    "ssl": "SSL",
    "rsa": "RSA",
    "ec": "EC",
    "san": "SAN",
    "crl": "CRL",
    "caa": "CAA",
    "sni": "SNI",
    "dns": "DNS",
    "ca": "CA",
    "id": "ID",
}


def humanize_label(value: str) -> str:
    """Title-case an identifier for display, preserving known acronyms.

    ``hsts_required`` -> ``HSTS Required``; ``ocsp_must_staple`` ->
    ``OCSP Must Staple``. Words not in :data:`_ACRONYMS` are title-cased.
    """
    if not value:
        return ""
    words = str(value).replace("_", " ").replace("-", " ").split()
    return " ".join(_ACRONYMS.get(w.lower(), w.capitalize()) for w in words)


def register_filters(templates: Jinja2Templates) -> None:
    """Register all filters on a Jinja2Templates instance."""
    templates.env.filters["humanize_expiry"] = humanize_expiry
    templates.env.filters["urgency"] = compute_urgency
    templates.env.filters["urgency_label"] = urgency_label
    templates.env.filters["urgency_tone"] = urgency_tone
    templates.env.filters["relative_short"] = relative_short
    templates.env.filters["friendly_issuer"] = friendly_issuer
    templates.env.filters["issuer_cn"] = issuer_cn
    templates.env.filters["subject_cn"] = subject_cn
    templates.env.filters["humanize_label"] = humanize_label
