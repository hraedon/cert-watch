"""Claimed alert delivery with leases, bounded retries, and persisted backoff."""

from __future__ import annotations

import logging
import sqlite3
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import monotonic
from typing import Any

from cert_watch.alerting.evidence import DeliveryEvidenceUnavailable, attempt_delivery
from cert_watch.alerting.model import (
    ALERT_CYCLE_BUDGET_SECONDS,
    ALERT_MAX_ATTEMPTS,
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    ALERT_RETRY_ROUND_DELAYS,
    EVIDENCE_DEFERRAL_GIVE_UP_HOURS,
    AlertConfig,
    OutboundMessage,
    WebhookConfig,
)
from cert_watch.alerting.transports.base import Transport
from cert_watch.alerting.transports.smtp import SmtpTransport, _smtp_recipients
from cert_watch.alerting.transports.webhook import WebhookTransport
from cert_watch.database import Alert, AlertRepository, AlertStore
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerts")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


@dataclass
class _Delivery:
    """One claimed alert's mutable progress through the current cycle."""

    alert: Alert
    delivered: bool = False
    last_error: str = ""
    last_reason: str = ""
    attempts_made: int = 0  # channel attempts, retained for operator diagnostics
    waves_reached: int = 0  # persisted attempt_count unit
    reached_transport: bool = False
    evidence_recorded: bool = False
    evidence_unavailable: bool = False
    lease_lost: bool = False

    @property
    def done(self) -> bool:
        return self.delivered or self.evidence_unavailable or self.lease_lost

    @property
    def attempts_remaining(self) -> int:
        return max(ALERT_MAX_ATTEMPTS - self.alert.attempt_count - self.waves_reached, 0)


def _message_for_transport(
    alert: Alert, transport: Transport, config: AlertConfig | None
) -> OutboundMessage:
    if isinstance(transport, SmtpTransport) and config is not None:
        base_msg = OutboundMessage.from_alert(alert)
        recipients = tuple(_smtp_recipients(base_msg, config))
        global_recipients = tuple(
            address for address in recipients if address in config.recipients
        )
        return OutboundMessage.from_alert(
            alert,
            recipients=recipients,
            global_recipients=global_recipients,
        )
    return OutboundMessage.from_alert(alert)


def _attempt_once(
    item: _Delivery,
    *,
    evidence_db: Path | None,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None,
    transports: Sequence[Transport] | None = None,
    claim_owner: str = "",
) -> None:
    """One wave over configured channels, stopping after acceptance."""
    alert = item.alert
    item.reached_transport = False
    item.evidence_recorded = False
    configured: Sequence[Transport]
    if transports is not None:
        configured = transports
    else:
        built: list[Transport] = []
        if config is not None:
            built.append(SmtpTransport(config))
        if webhook_config is not None:
            built.append(WebhookTransport(webhook_config))
        configured = built

    for transport in configured:
        if item.delivered:
            break
        msg = _message_for_transport(alert, transport, config)
        try:
            result = attempt_delivery(
                evidence_db,
                alert.id,
                transport,
                msg,
                claim_owner=claim_owner,
            )
            item.evidence_recorded = True
            item.delivered = result.delivered
            item.reached_transport = item.reached_transport or result.reached_transport
            if result.reason:
                item.last_reason = result.reason
            if not item.delivered and result.operator_message:
                item.last_error = result.operator_message
            item.attempts_made += 1
        except DeliveryEvidenceUnavailable:
            # A later channel can still record evidence and deliver.
            item.delivered = False
    if item.reached_transport:
        item.waves_reached += 1
    if item.delivered:
        return
    item.evidence_unavailable = not item.evidence_recorded


def _settle_evidence_deferral(
    alert_repo: AlertRepository,
    item: _Delivery,
    *,
    now: datetime,
) -> str:
    """Backward-compatible unclaimed #38 helper; Dispatcher uses lease guards."""
    alert = item.alert
    restart = item.attempts_made > 0
    since = None if restart else alert.deferred_since
    if since is not None:
        since = _utc(since)
    if since is not None and now - since >= timedelta(hours=EVIDENCE_DEFERRAL_GIVE_UP_HOURS):
        hours = int((now - since).total_seconds() // 3600)
        message = (
            "delivery evidence could not be recorded since "
            f"{since.astimezone(UTC).isoformat(timespec='minutes')} ({hours}h); "
            "no transport was reached in that time"
        )
        try:
            alert_repo.mark_failed(alert.id, message)
        except (sqlite3.Error, OSError):
            logger.error(
                "Alert %s exceeded its evidence deferral bound but the failure "
                "could not be recorded; leaving it pending",
                alert.id,
                exc_info=True,
            )
            return "deferred"
        return "failed"
    try:
        alert_repo.note_deferral(alert.id, now, restart=restart)
    except (sqlite3.Error, OSError):
        logger.warning(
            "Alert %s evidence deferral could not be recorded", alert.id, exc_info=True
        )
    return "deferred"


class Dispatcher:
    """Claim and deliver one eligible alert queue under a unique lease owner."""

    def __init__(
        self,
        db_path: str | Path,
        config: AlertConfig | None = None,
        webhook_config: WebhookConfig | None = None,
        *,
        transports: Sequence[Transport] | None = None,
        budget_seconds: float = ALERT_CYCLE_BUDGET_SECONDS,
        scope_tags: tuple[str, ...] = (),
        ignore_backoff: bool = False,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        lease_owner: str | None = None,
        claim_limit: int = 1000,
        settlement_repo: AlertRepository | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.config = config
        self.webhook_config = webhook_config
        self.transports = tuple(transports) if transports is not None else None
        self.budget_seconds = budget_seconds
        self.scope_tags = scope_tags
        self.ignore_backoff = ignore_backoff
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic_clock = monotonic_clock
        self.lease_owner = lease_owner or uuid.uuid4().hex
        self.claim_limit = claim_limit
        self.settlement_repo = settlement_repo
        self.store = AlertStore(self.db_path)

    @property
    def lease_seconds(self) -> float:
        return max(self.budget_seconds, 0.0) + 120.0

    def _lease_expiry(self) -> datetime:
        return _utc(self.clock()) + timedelta(seconds=self.lease_seconds)

    def _configured(self) -> bool:
        if self.transports is not None:
            return bool(self.transports)
        return self.config is not None or self.webhook_config is not None

    def process_pending(self) -> dict[str, int]:
        if not self._configured():
            return {"sent": 0, "failed": 0, "deferred": 0}

        claimed_at = _utc(self.clock())
        alerts = self.store.claim(
            lease_owner=self.lease_owner,
            lease_expires_at=claimed_at + timedelta(seconds=self.lease_seconds),
            now=claimed_at,
            limit=self.claim_limit,
            scope_tags=self.scope_tags,
            ignore_backoff=self.ignore_backoff,
        )
        queue = [_Delivery(alert) for alert in alerts]
        started = self.monotonic_clock()
        exhausted = False

        active = [item for item in queue if item.attempts_remaining > 0]
        for wave in backoff_range(
            ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"
        ):
            for item in active:
                if self.monotonic_clock() - started >= self.budget_seconds:
                    exhausted = True
                    logger.warning(
                        "Alert cycle budget of %.0fs spent during attempt %d; %d "
                        "alert(s) left pending for the next cycle",
                        self.budget_seconds,
                        wave + 1,
                        sum(1 for entry in queue if not entry.done),
                    )
                    break
                _attempt_once(
                    item,
                    evidence_db=self.db_path,
                    config=self.config,
                    webhook_config=self.webhook_config,
                    transports=self.transports,
                    claim_owner=self.lease_owner,
                )

            active = [
                item
                for item in active
                if not item.done and item.attempts_remaining > 0
            ]
            if not active or exhausted:
                break

            # Extend every unsettled row before the shared inter-wave delay.
            unsettled = [item for item in queue if not item.done]
            renewed = self.store.renew_lease(
                [item.alert.id for item in unsettled],
                lease_owner=self.lease_owner,
                lease_expires_at=self._lease_expiry(),
            )
            for item in unsettled:
                if item.alert.id not in renewed:
                    item.lease_lost = True
                    logger.warning(
                        "Alert %s lease was lost between delivery waves; abandoning it",
                        item.alert.id,
                    )
            active = [item for item in active if not item.lease_lost]
            if not active:
                break

        return self._settle(queue, exhausted=exhausted)

    def _settle(self, queue: list[_Delivery], *, exhausted: bool) -> dict[str, int]:
        sent = failed = deferred = 0
        now = _utc(self.clock())
        for item in queue:
            alert = item.alert
            if item.lease_lost:
                continue
            if item.delivered:
                if self.store.complete_sent(
                    alert.id,
                    lease_owner=self.lease_owner,
                    attempts=item.waves_reached,
                    now=now,
                ):
                    sent += 1
                continue

            if item.evidence_unavailable:
                outcome = self._complete_evidence_deferral(item, now=now)
                failed += outcome == "failed"
                deferred += outcome == "deferred"
                continue

            new_attempt_count = alert.attempt_count + item.waves_reached
            error = item.last_error or "unknown"
            reason = item.last_reason or "unknown"
            if new_attempt_count >= ALERT_MAX_ATTEMPTS:
                message = f"{error} (gave up after {new_attempt_count} attempts)"
                if self.store.complete_failed(
                    alert.id,
                    lease_owner=self.lease_owner,
                    attempts=item.waves_reached,
                    now=now,
                    failure_reason=reason,
                    error_message=message,
                ):
                    failed += 1
                continue

            if exhausted:
                next_attempt_at = None
            else:
                round_index = min(
                    max(new_attempt_count - 1, 0) // ALERT_MAX_RETRIES,
                    len(ALERT_RETRY_ROUND_DELAYS) - 1,
                )
                next_attempt_at = now + timedelta(
                    seconds=ALERT_RETRY_ROUND_DELAYS[round_index]
                )
            message = (
                f"{error} (after {item.attempts_made} "
                f"{'attempt' if item.attempts_made == 1 else 'attempts'})"
                if item.attempts_made
                else error
            )
            if self.store.complete_pending(
                alert.id,
                lease_owner=self.lease_owner,
                attempts=item.waves_reached,
                now=now,
                next_attempt_at=next_attempt_at,
                error_message=message,
            ):
                deferred += 1
        return {"sent": sent, "failed": failed, "deferred": deferred}

    def _complete_evidence_deferral(self, item: _Delivery, *, now: datetime) -> str:
        alert = item.alert
        restart = item.attempts_made > 0
        since = None if restart else alert.deferred_since
        if since is not None:
            since = _utc(since)
        if since is not None and now - since >= timedelta(
            hours=EVIDENCE_DEFERRAL_GIVE_UP_HOURS
        ):
            hours = int((now - since).total_seconds() // 3600)
            message = (
                "delivery evidence could not be recorded since "
                f"{since.isoformat(timespec='minutes')} ({hours}h); "
                "no transport was reached in that time"
            )
            try:
                if self.settlement_repo is not None:
                    self._prepare_repo_settlement(
                        attempts=item.waves_reached,
                        now=now,
                        failure_reason="evidence_unavailable",
                    )
                    self.settlement_repo.mark_failed(alert.id, message)
                    completed = True
                else:
                    completed = self.store.complete_failed(
                        alert.id,
                        lease_owner=self.lease_owner,
                        attempts=item.waves_reached,
                        now=now,
                        failure_reason="evidence_unavailable",
                        error_message=message,
                    )
            except (sqlite3.Error, OSError):
                logger.error(
                    "Alert %s exceeded its evidence deferral bound but the failure "
                    "could not be recorded; leaving its lease to expire",
                    alert.id,
                    exc_info=True,
                )
                completed = self.store.complete_pending(
                    alert.id,
                    lease_owner=self.lease_owner,
                    attempts=item.waves_reached,
                    now=now,
                    next_attempt_at=None,
                )
                return "deferred" if completed else "lost"
            finally:
                self._clear_repo_settlement()
            return "failed" if completed else "lost"

        try:
            if self.settlement_repo is not None:
                self._prepare_repo_settlement(attempts=item.waves_reached, now=now)
                self.settlement_repo.note_deferral(alert.id, now, restart=restart)
                completed = True
            else:
                completed = self.store.complete_pending(
                    alert.id,
                    lease_owner=self.lease_owner,
                    attempts=item.waves_reached,
                    now=now,
                    next_attempt_at=None,
                    deferred_since=now,
                    preserve_deferral=not restart,
                )
        except (sqlite3.Error, OSError):
            logger.warning(
                "Alert %s evidence deferral could not be recorded; leaving its "
                "lease to expire",
                alert.id,
                exc_info=True,
            )
            completed = self.store.complete_pending(
                alert.id,
                lease_owner=self.lease_owner,
                attempts=item.waves_reached,
                now=now,
                next_attempt_at=None,
            )
            return "deferred" if completed else "lost"
        finally:
            self._clear_repo_settlement()
        return "deferred" if completed else "lost"

    def _prepare_repo_settlement(
        self,
        *,
        attempts: int,
        now: datetime,
        failure_reason: str = "unknown",
    ) -> None:
        if self.settlement_repo is None:
            return
        repo: Any = self.settlement_repo
        repo._dispatch_lease_owner = self.lease_owner
        repo._dispatch_attempts = attempts
        repo._dispatch_now = now
        repo._dispatch_failure_reason = failure_reason

    def _clear_repo_settlement(self) -> None:
        if self.settlement_repo is None:
            return
        for name in (
            "_dispatch_lease_owner",
            "_dispatch_attempts",
            "_dispatch_now",
            "_dispatch_failure_reason",
        ):
            if hasattr(self.settlement_repo, name):
                delattr(self.settlement_repo, name)


def process_pending(
    alert_repo: AlertRepository,
    config: AlertConfig | None,
    webhook_config: WebhookConfig | None = None,
    *,
    budget_seconds: float = ALERT_CYCLE_BUDGET_SECONDS,
    ignore_backoff: bool = False,
) -> dict[str, int]:
    """Compatibility entry point around :class:`Dispatcher`."""
    repository_path = getattr(alert_repo, "db_path", None)
    if not isinstance(repository_path, (str, Path)):
        raise TypeError("claimed alert dispatch requires a SQLite-backed repository")
    scope_tags = tuple(getattr(alert_repo, "_scope_tags", ()))
    return Dispatcher(
        repository_path,
        config,
        webhook_config,
        budget_seconds=budget_seconds,
        scope_tags=scope_tags,
        ignore_backoff=ignore_backoff,
        settlement_repo=alert_repo,
    ).process_pending()
