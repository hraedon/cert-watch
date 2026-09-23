"""Renewal-window rule: leaves inside their window with no successor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.alerting.messages import _format_renewal_message
from cert_watch.alerting.routing import _load_host_owner_maps
from cert_watch.database import Alert, AlertRepository


def renewal_window_candidates(
    db_path: str | Path,
    window_days: int = 30,
) -> list[dict[str, Any]]:
    """Read current, unhandled renewal conditions without consulting alerts.

    Home and notification generation share this predicate: a leaf is inside
    the configured window, has no successor, and its host is not marked as
    renewed or in progress. Delivery success/failure does not resolve it.
    Each result contains the certificate fields, days_remaining, and owner.
    """
    if window_days <= 0:
        return []
    from cert_watch.database import _connect, _parse_iso

    now = datetime.now(UTC)
    with _connect(db_path) as conn:
        superseded = {
            r["replaces_cert_id"]
            for r in conn.execute(
                "SELECT DISTINCT replaces_cert_id FROM certificates "
                "WHERE replaces_cert_id IS NOT NULL"
            ).fetchall()
        }
        leaves = conn.execute(
            "SELECT id, subject, hostname, port, not_after "
            "FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    _host_thresholds, host_owners = _load_host_owner_maps(db_path)
    candidates: list[dict[str, Any]] = []
    for leaf in leaves:
        cid = leaf["id"]
        if cid in superseded:
            continue  # a successor cert already exists → renewal worked
        try:
            days = (_parse_iso(leaf["not_after"]) - now).days
        except (ValueError, TypeError):  # date parse
            continue
        if days < 0 or days > window_days:
            continue  # expired (expiry_warning owns it) or outside the window
        owner = host_owners.get((leaf["hostname"], leaf["port"]), {})
        if owner.get("renewal_status") in ("renewed", "in_progress"):
            continue  # operator has flagged renewal as handled
        candidates.append({**dict(leaf), "days_remaining": days, "owner": owner})
    return candidates


def evaluate_renewal_window(
    db_path: str | Path,
    alert_repo: AlertRepository,
    window_days: int = 30,
) -> list[Alert]:
    """Create notifications for the current renewal-window conditions.

    At most one pending ``renewal_stalled`` alert is created per certificate;
    notification status remains separate from the underlying condition.
    """
    created: list[Alert] = []
    for leaf in renewal_window_candidates(db_path, window_days):
        cid = leaf["id"]
        existing = alert_repo.list_for_cert(cid)
        if any(
            a.alert_type == "renewal_stalled" and a.status == "pending"
            for a in existing
        ):
            continue  # already flagged this window
        owner = leaf["owner"]
        alert = Alert(
            cert_id=cid,
            alert_type="renewal_stalled",
            status="pending",
            message=_format_renewal_message(leaf, leaf["days_remaining"], window_days, owner),
            threshold_days=window_days,
            extra_recipients=(
                [owner["owner_email"]] if owner.get("owner_email") else []
            ),
            hostname=leaf["hostname"] or "",
            subject=leaf["subject"] or "",
        )
        alert.id = alert_repo.create(alert)
        created.append(alert)
    return created
