"""Renewal-window rule: leaves inside their window with no successor."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.alerting.keys import certificate_alert_key
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
            "SELECT id, subject, hostname, port, not_after, fingerprint_sha256 "
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
    *,
    closed_sent: list[Alert] | None = None,
) -> list[Alert]:
    """Create one notification per fingerprint while its condition persists."""
    from cert_watch.alerting.routing import resolve_routing
    from cert_watch.database import AlertStore, _connect

    candidates = renewal_window_candidates(db_path, window_days)
    routing_map = resolve_routing(
        db_path, tuple(leaf["id"] for leaf in candidates)
    )
    active_keys = {
        certificate_alert_key(
            "renewal",
            cert_id=leaf["id"],
            fingerprint=leaf["fingerprint_sha256"],
            hostname=leaf["hostname"],
            port=leaf["port"],
        )
        for leaf in candidates
    }
    store = AlertStore(db_path)
    with _connect(db_path) as conn:
        open_keys = {
            row["dedupe_key"]
            for row in conn.execute(
                """SELECT dedupe_key FROM alerts
                   WHERE alert_type = 'renewal_stalled' AND closed_at IS NULL
                     AND dedupe_key IS NOT NULL"""
            ).fetchall()
        }
    closed = store.close_keys(open_keys - active_keys)
    if closed_sent is not None:
        closed_sent.extend(closed)

    created: list[Alert] = []
    for leaf in candidates:
        cid = leaf["id"]
        owner = leaf["owner"]
        routing = routing_map[cid]
        alert = Alert(
            cert_id=cid,
            alert_type="renewal_stalled",
            status="pending",
            message=_format_renewal_message(leaf, leaf["days_remaining"], window_days, owner),
            threshold_days=window_days,
            extra_recipients=list(routing["recipients"]),
            hostname=leaf["hostname"] or "",
            subject=leaf["subject"] or "",
            dedupe_key=certificate_alert_key(
                "renewal",
                cert_id=cid,
                fingerprint=leaf["fingerprint_sha256"],
                hostname=leaf["hostname"],
                port=leaf["port"],
            ),
            routing=routing,
        )
        alert_id = alert_repo.enqueue(alert, lifetime=True)
        if alert_id is None:
            continue
        alert.id = alert_id
        created.append(alert)
    return created
