"""Resolve open webhook incidents when a certificate is renewed."""

from __future__ import annotations

from pathlib import Path

from cert_watch.alerting.model import WebhookConfig
from cert_watch.alerting.transports.webhook import (
    _adapter_has_build_resolve,
    send_webhook_resolve,
)
from cert_watch.database import Alert


def resolve_webhook_for_renewed_cert(
    db_path: str | Path,
    old_cert_id: str,
    webhook_config: WebhookConfig | None = None,
    *,
    pending_alerts: list[Alert] | None = None,
) -> int:
    """Resolve all open incidents/alerts for a cert that has been renewed.

    Works for any webhook kind whose adapter exposes ``build_resolve``.
    Looks up alerts for the old cert and sends a resolve event for
    each unique (alert_type, threshold_days) combination. Returns the
    number of resolve events sent.

    When *pending_alerts* is provided (a pre-fetched list from
    :class:`SqliteAlertRepository`), uses that instead of querying the
    database — necessary when the caller knows the alert rows will be
    deleted before this function runs (e.g. ``replace_scanned``).
    """
    if webhook_config is None or not _adapter_has_build_resolve(webhook_config.kind):
        return 0
    if pending_alerts is None:
        from cert_watch.database import SqliteAlertRepository

        alert_repo = SqliteAlertRepository(db_path)
        cert_alerts = alert_repo.list_for_cert(old_cert_id)
    else:
        cert_alerts = pending_alerts
    seen: set[tuple[str, int | None]] = set()
    resolved = 0
    for alert in cert_alerts:
        if alert.status != "sent":
            continue
        key = (alert.alert_type, alert.threshold_days)
        if key in seen:
            continue
        seen.add(key)
        # Key the resolve on the row id the trigger was keyed on. A carried
        # alert may sit on a rewritten row id that PagerDuty never saw (#62);
        # pre-0034 rows were backfilled by the migration with the row id they
        # fired against; the fallback exists only for belt and braces.
        if send_webhook_resolve(
            alert.trigger_cert_id or old_cert_id, alert.alert_type, alert.threshold_days,
            webhook_config,
            summary=f"cert-watch: condition closed, resolving {alert.alert_type} alert",
            hostname=alert.hostname,
            subject=alert.subject,
            alert_created_at=alert.created_at,
        ):
            resolved += 1
    return resolved
