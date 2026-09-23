"""Pending-alert delivery cycle: waves, budget, and evidence-deferral settling."""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic

from cert_watch.alerting.evidence import DeliveryEvidenceUnavailable, attempt_delivery
from cert_watch.alerting.model import (
    ALERT_CYCLE_BUDGET_SECONDS,
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    EVIDENCE_DEFERRAL_GIVE_UP_HOURS,
    AlertConfig,
    OutboundMessage,
    WebhookConfig,
)
from cert_watch.alerting.transports.smtp import SmtpTransport, _smtp_recipients
from cert_watch.alerting.transports.webhook import WebhookTransport
from cert_watch.database import Alert, AlertRepository
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerts")


@dataclass
class _Delivery:
    """One alert's progress through the cycle. Mutable; one per pending alert."""

    alert: Alert
    delivered: bool = False
    last_error: str = ""
    attempts_made: int = 0
    # Whether the MOST RECENT wave reached a transport. Judged per wave, never
    # accumulated: an earlier wave may have reached the relay and failed, and if
    # the evidence store then becomes unwritable a stale "yes" would let a
    # database outage mark an alert failed that the relay might still accept.
    reached_transport: bool = False
    # Set when every configured channel refused before sending. Such an alert
    # leaves the cycle immediately -- further waves cannot help, because there
    # is nothing to back off from.
    evidence_unavailable: bool = False

    @property
    def done(self) -> bool:
        return self.delivered or self.evidence_unavailable


def _attempt_once(
    item: _Delivery,
    *,
    evidence_db: Path | None,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None,
) -> None:
    """One pass over every configured channel for a single alert."""
    alert = item.alert
    item.reached_transport = False
    if config is not None:
        smtp_transport = SmtpTransport(config)
        base_msg = OutboundMessage.from_alert(alert)
        recipients = tuple(_smtp_recipients(base_msg, config))
        global_recipients = tuple(address for address in recipients if address in config.recipients)
        smtp_msg = OutboundMessage.from_alert(
            alert,
            recipients=recipients,
            global_recipients=global_recipients,
        )
        try:
            result = attempt_delivery(evidence_db, alert.id, smtp_transport, smtp_msg)
            item.delivered = result.delivered
            if not item.delivered:
                item.last_error = result.operator_message or "unknown"
            item.reached_transport = True
            item.attempts_made += 1
        except DeliveryEvidenceUnavailable:
            # Guard this call only. A begin_attempt failure is per-statement --
            # typically a transient SQLITE_BUSY from a concurrent scan write --
            # so the webhook fallback below may well succeed.
            item.delivered = False
    if not item.delivered and webhook_config is not None:
        webhook_transport = WebhookTransport(webhook_config)
        webhook_msg = OutboundMessage.from_alert(alert)
        try:
            result = attempt_delivery(evidence_db, alert.id, webhook_transport, webhook_msg)
            item.delivered = result.delivered
            if not item.delivered:
                item.last_error = result.operator_message or "unknown"
            item.reached_transport = True
            item.attempts_made += 1
        except DeliveryEvidenceUnavailable:
            item.delivered = False
    if item.delivered:
        return
    item.evidence_unavailable = not item.reached_transport


def _settle_evidence_deferral(
    alert_repo: AlertRepository, item: _Delivery, *, now: datetime,
) -> str:
    """Persist a deferral, or give up on one that has outlived its bound.

    Returns ``"failed"`` or ``"deferred"``. Every write here targets the
    database that has just refused one, so each is tolerated: a failure is
    logged and the alert stays pending, which is the state it is already in.
    Nothing here may raise, or one refused UPDATE would abort the cycle and
    skip every alert after it (#38).
    """
    alert = item.alert
    # An attempt recorded in THIS cycle proves the store was writable more
    # recently than any earlier stamp, so the outage is younger than that stamp.
    restart = item.attempts_made > 0
    since = None if restart else alert.deferred_since
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=UTC)
    if since is not None and now - since >= timedelta(hours=EVIDENCE_DEFERRAL_GIVE_UP_HOURS):
        hours = int((now - since).total_seconds() // 3600)
        message = (
            f"delivery evidence could not be recorded since "
            f"{since.astimezone(UTC).isoformat(timespec='minutes')} ({hours}h); "
            "no transport was reached in that time"
        )
        try:
            alert_repo.mark_failed(alert.id, message)
        except (sqlite3.Error, OSError):
            logger.error(
                "Alert %s has been deferred for %dh and the failure could not be "
                "recorded either; leaving it pending", alert.id, hours, exc_info=True,
            )
            return "deferred"
        logger.error("Alert %s failed: %s", alert.id, message)
        return "failed"
    try:
        alert_repo.note_deferral(alert.id, now, restart=restart)
    except (sqlite3.Error, OSError):
        logger.warning(
            "Alert %s deferred (delivery evidence unavailable) and the deferral itself "
            "could not be recorded; leaving it pending", alert.id, exc_info=True,
        )
    else:
        logger.warning(
            "Alert %s deferred (delivery evidence unavailable), leaving it pending", alert.id,
        )
    return "deferred"


def process_pending(
    alert_repo: AlertRepository,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    budget_seconds: float = ALERT_CYCLE_BUDGET_SECONDS,
) -> dict[str, int]:
    """See AC-04. No-ops when both configs are None. Tries webhook if SMTP fails or is absent.

    Retries in **waves**: every alert is attempted once before any is attempted
    a second time. Each alert still gets ``ALERT_MAX_RETRIES`` attempts, but the
    backoff sleeps are shared by the queue instead of paid per alert -- the
    sleeps used to sit inside the per-alert loop, so a failing relay cost ~6s
    *each* and a 100-alert queue blocked the scheduler for ten minutes (#43).

    Waves alone do not bound that. An unreachable relay does not refuse, it
    hangs to the 15s socket timeout, and there is one connect per attempt: 100
    alerts x 3 attempts x 15s is 75 minutes of transport with no sleeping at
    all. So the cycle also carries a wall-clock ``budget_seconds``. When it is
    spent, the alerts not yet resolved stay ``pending`` and are counted as
    deferred -- the state #36 already defined for "nothing was dispatched and
    the alert is still deliverable", reused rather than reinvented.

    Breadth before depth is why the two belong together: spending a budget down
    the per-alert loop would give the first few alerts three attempts each and
    the rest none. Under an outage, having tried everything once is worth more
    than having tried three things thrice.
    """
    if config is None and webhook_config is None:
        return {"sent": 0, "failed": 0, "deferred": 0}

    repository_path = getattr(alert_repo, "db_path", None)
    evidence_db = Path(repository_path) if isinstance(repository_path, str | Path) else None
    queue = [_Delivery(alert=alert) for alert in alert_repo.list_pending()]
    started = monotonic()
    exhausted = False

    active = [item for item in queue if not item.done]
    for wave in backoff_range(ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"):
        for item in active:
            if monotonic() - started >= budget_seconds:
                exhausted = True
                logger.warning(
                    "Alert cycle budget of %.0fs spent during attempt %d; %d alert(s) "
                    "left pending for the next cycle",
                    budget_seconds, wave + 1,
                    sum(1 for entry in queue if not entry.done),
                )
                break
            _attempt_once(
                item, evidence_db=evidence_db, config=config, webhook_config=webhook_config,
            )
        # Decided here, at the END of the wave, so abandoning the generator
        # skips its sleep. Testing it at the top instead still pays one backoff
        # after the last useful wave -- a queue that delivered everything on the
        # first pass would sit there sleeping with nothing left to retry.
        active = [item for item in active if not item.done]
        if not active or exhausted:
            break

    sent = failed = deferred = 0
    now = datetime.now(UTC)
    for item in queue:
        alert = item.alert
        if item.delivered:
            alert.sent_at = now
            alert_repo.mark_sent(alert.id)
            sent += 1
        elif item.reached_transport and not exhausted and item.attempts_made:
            # A real delivery failure, and the alert had its full run of waves.
            plural = "attempt" if item.attempts_made == 1 else "attempts"
            alert_repo.mark_failed(
                alert.id, f"{item.last_error} (after {item.attempts_made} {plural})"
            )
            failed += 1
        elif item.evidence_unavailable:
            # No transport was reached: the database was unavailable, not the
            # destination. The alert stays deliverable, so it stays pending
            # rather than spending its retries on an outage that never reached
            # a destination. The deferral is stamped on the row (best effort --
            # the same database just refused a write) and, once it has outlived
            # EVIDENCE_DEFERRAL_GIVE_UP_HOURS on that persisted clock, the alert
            # is marked failed with a message that says since when (#38).
            if _settle_evidence_deferral(alert_repo, item, now=now) == "failed":
                failed += 1
            else:
                deferred += 1
        else:
            # The cycle ran out of budget before this alert had its full run.
            # It is still deliverable and goes out next cycle; the deferral
            # clock is for the evidence store, so it is not touched here.
            logger.warning("Alert %s deferred (cycle budget spent), leaving it pending", alert.id)
            deferred += 1
    return {"sent": sent, "failed": failed, "deferred": deferred}
