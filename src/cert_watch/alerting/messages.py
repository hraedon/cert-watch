"""Operator-facing text for individual alerts."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cert_watch.certificate_model import Certificate


def _format_renewal_message(
    leaf: Mapping[str, Any], days: int, window_days: int, owner: dict[str, Any]
) -> str:
    from cert_watch.filters import subject_cn

    raw_subject = leaf["subject"] or ""
    name = subject_cn(raw_subject) if raw_subject else (leaf["hostname"] or leaf["id"])
    target = leaf["hostname"] or "this certificate"
    msg = (
        f"Certificate '{name}' is inside its renewal window "
        f"({days} days remaining; window: {window_days}d) but no successor "
        f"certificate has appeared. Check the renewal automation "
        f"(Certbot / cert-manager / ACME client) for {target}."
    )
    if owner.get("owner_name"):
        msg += f" Owner: {owner['owner_name']}."
    return msg


def _format_message(
    cert: Certificate, days: int, threshold: int, *, owner_info: dict[str, Any] | None = None
) -> str:
    """See AC-05.

    Operator-facing text (email body, webhook payload, UI row): prefer the
    friendly CN over the raw X.509 DN, calendar dates over ISO-8601
    timestamps, and "expired N days ago" over negative "days remaining".
    """
    from cert_watch.filters import subject_cn

    action = (
        "Renew this certificate immediately."
        if days <= 7
        else "Plan a renewal soon."
    )
    name = subject_cn(cert.subject) if cert.subject else cert.display_name
    expiry_date = cert.not_after.date().isoformat()
    if days < 0:
        ago = -days
        timing = f"expired {ago} day{'s' if ago != 1 else ''} ago ({expiry_date})"
    else:
        timing = (
            f"expires {expiry_date} "
            f"({days} day{'s' if days != 1 else ''} remaining; threshold: <={threshold}d)"
        )
    msg = f"Certificate '{name}' {timing}. Recommended action: {action}"
    if owner_info:
        parts = []
        if owner_info.get("owner_name"):
            parts.append(f"Owner: {owner_info['owner_name']}")
        if owner_info.get("owner_email"):
            parts.append(f"Contact: {owner_info['owner_email']}")
        if owner_info.get("owner_slack"):
            parts.append(f"Slack: {owner_info['owner_slack']}")
        if parts:
            msg += " " + "; ".join(parts)
    if owner_info and owner_info.get("renewal_status") == "in_progress":
        msg += " (renewal in progress)"
    return msg
