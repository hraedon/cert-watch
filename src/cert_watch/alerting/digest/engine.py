"""One claimed, budgeted delivery engine for every digest kind."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any, Literal, Protocol

from cert_watch.alerting.model import (
    ALERT_CYCLE_BUDGET_SECONDS,
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    OutboundMessage,
    SendResult,
)
from cert_watch.alerting.transports.base import Transport
from cert_watch.database.digest_deliveries import (
    DigestDeliveryClaim,
    claim_digest_delivery,
    complete_digest_delivery,
    digest_delivery_is_sent,
    renew_digest_delivery,
)
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerting.digest")


@dataclass(frozen=True)
class DigestTarget:
    """One rendered digest scope and its optional SMTP recipients."""

    key: str
    payload: Any
    smtp_recipients: tuple[str, ...] = ()
    is_global: bool = False
    webhook_eligible: bool = True
    webhook_subject: str | None = None


class DigestKind(Protocol):
    """Content and target selection supplied to :class:`DigestEngine`."""

    name: str
    webhook_fanout: Literal["global", "per_target"]

    def targets(
        self,
        db_path: str | Path,
        now: datetime,
        cadence_days: int,
    ) -> list[DigestTarget]: ...

    def render(self, target: DigestTarget) -> OutboundMessage: ...


@dataclass(frozen=True)
class DigestRunResult:
    """New claim outcomes from one synchronous digest run."""

    sent: int = 0
    failed: int = 0
    busy: int = 0
    skipped: int = 0
    attempts: int = 0
    budget_exhausted: bool = False
    cancelled: bool = False

    @property
    def succeeded(self) -> bool:
        return (
            self.failed == 0
            and self.busy == 0
            and not self.budget_exhausted
            and not self.cancelled
        )


@dataclass
class _Progress:
    sent: int = 0
    failed: int = 0
    busy: int = 0
    skipped: int = 0
    attempts: int = 0
    budget_exhausted: bool = False
    cancelled: bool = False

    def result(self) -> DigestRunResult:
        return DigestRunResult(
            sent=self.sent,
            failed=self.failed,
            busy=self.busy,
            skipped=self.skipped,
            attempts=self.attempts,
            budget_exhausted=self.budget_exhausted,
            cancelled=self.cancelled,
        )


def _claim_channel(transport: Transport) -> str:
    """Keep the endpoint-aware channel format used by the pre-engine senders."""
    if transport.channel == "smtp":
        return "smtp"
    destination = transport.destination_id
    return (
        transport.channel
        if not destination or transport.channel.endswith(f":{destination}")
        else f"{transport.channel}:{destination}"
    )


def _casefold_map(recipients: Sequence[str]) -> dict[str, str]:
    originals: dict[str, str] = {}
    for recipient in recipients:
        originals.setdefault(recipient.casefold(), recipient)
    return originals


class DigestEngine:
    """Deliver digest targets under durable per-channel leases.

    SMTP is attempted first and claimed per recipient. A webhook is a fallback
    only when SMTP failed (or was unavailable) and no SMTP claim was busy. Both
    channels use the same ``ALERT_MAX_RETRIES`` wave policy and run inline under
    one wall-clock budget.
    """

    def __init__(
        self,
        db_path: str | Path,
        transports: Sequence[Transport],
        budget_seconds: float = ALERT_CYCLE_BUDGET_SECONDS,
        *,
        clock: Callable[[], datetime] | None = None,
        monotonic_clock: Callable[[], float] = monotonic,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.transports = tuple(transports)
        self.budget_seconds = max(budget_seconds, 0.0)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.monotonic_clock = monotonic_clock
        self.stop_event = stop_event

    def run(self, kind: DigestKind, period_key: str) -> DigestRunResult:
        started = self.monotonic_clock()
        progress = _Progress()
        if self._stopped(progress):
            return progress.result()
        cadence_days = _cadence_from_period_key(period_key)
        targets = kind.targets(self.db_path, self.clock(), cadence_days)
        if not targets:
            return DigestRunResult()

        smtp = next((t for t in self.transports if t.channel == "smtp"), None)
        webhooks = tuple(t for t in self.transports if t.channel.startswith("webhook:"))
        webhook_targets = self._webhook_targets(kind, targets)

        # A prior successful fallback completes the period even though the
        # failed SMTP rows correctly remain failed observations. Without this
        # preflight, removing the scheduler-wide week key would retry SMTP on
        # every cycle and could later duplicate a digest already delivered by
        # webhook.
        webhook_identities = [
            (_claim_channel(transport), target.key)
            for transport in webhooks
            for target in webhook_targets
        ]
        if webhook_identities and all(
            digest_delivery_is_sent(self.db_path, period_key, channel, target)
            for channel, target in webhook_identities
        ):
            progress.skipped = len(webhook_identities)
            return progress.result()

        had_smtp_work = smtp is not None and any(t.smtp_recipients for t in targets)
        smtp_failed = False
        if had_smtp_work and smtp is not None:
            smtp_failed = self._deliver_smtp(
                kind, targets, period_key, smtp, started, progress
            )

        if progress.cancelled:
            return progress.result()
        if progress.busy:
            return progress.result()
        if had_smtp_work and not smtp_failed:
            return progress.result()

        if not webhooks or not webhook_targets:
            progress.failed += max(1, sum(bool(t.smtp_recipients) for t in targets))
            return progress.result()

        webhook_failed = self._deliver_webhooks(
            kind,
            webhook_targets,
            period_key,
            webhooks,
            started,
            progress,
        )
        if webhook_failed:
            progress.failed += webhook_failed
        return progress.result()

    def _stopped(self, progress: _Progress) -> bool:
        if self.stop_event is None or not self.stop_event.is_set():
            return False
        if not progress.cancelled:
            logger.info("Digest delivery stopped at scheduler shutdown")
        progress.cancelled = True
        return True

    def _within_budget(self, started: float, progress: _Progress) -> bool:
        if self.monotonic_clock() - started < self.budget_seconds:
            return True
        if not progress.budget_exhausted:
            logger.warning(
                "Digest cycle budget of %.0fs exhausted", self.budget_seconds
            )
        progress.budget_exhausted = True
        return False

    def _deliver_smtp(
        self,
        kind: DigestKind,
        targets: list[DigestTarget],
        period_key: str,
        transport: Transport,
        started: float,
        progress: _Progress,
    ) -> bool:
        pending = {
            target.key: _casefold_map(target.smtp_recipients)
            for target in targets
            if target.smtp_recipients
        }
        targets_by_key = {target.key: target for target in targets}

        for _wave in backoff_range(
            ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"
        ):
            if (
                not pending
                or self._stopped(progress)
                or not self._within_budget(started, progress)
            ):
                break
            next_pending: dict[str, dict[str, str]] = {}
            for key, recipients in pending.items():
                if self._stopped(progress):
                    return True
                if not self._within_budget(started, progress):
                    next_pending[key] = recipients
                    continue
                claims, live, retry = self._claim_smtp_recipients(
                    period_key, recipients, progress
                )
                if self._stopped(progress):
                    return True
                if not claims:
                    if retry:
                        next_pending[key] = retry
                    continue

                renewed_claims: list[DigestDeliveryClaim] = []
                renewed_recipients: list[str] = []
                for claim, recipient in zip(claims, live, strict=True):
                    if self._stopped(progress):
                        return True
                    if renew_digest_delivery(self.db_path, claim):
                        renewed_claims.append(claim)
                        renewed_recipients.append(recipient)
                    else:
                        progress.busy += 1
                if not renewed_claims:
                    continue
                if self._stopped(progress):
                    return True

                message = replace(
                    kind.render(targets_by_key[key]),
                    cert_id=renewed_claims[0].idempotency_key,
                    recipients=tuple(renewed_recipients),
                )
                result = transport.send(message)
                progress.attempts += 1
                accepted = self._accepted_recipients(result, renewed_recipients)
                for claim, recipient in zip(
                    renewed_claims, renewed_recipients, strict=True
                ):
                    succeeded = recipient.casefold() in accepted
                    recorded = complete_digest_delivery(
                        self.db_path, claim, succeeded=succeeded
                    )
                    if succeeded:
                        if recorded:
                            progress.sent += 1
                        else:
                            progress.busy += 1
                    else:
                        retry[claim.target] = recipient
                if retry:
                    next_pending[key] = retry
            pending = next_pending

        return bool(pending) or progress.budget_exhausted

    def _claim_smtp_recipients(
        self,
        period_key: str,
        recipients: dict[str, str],
        progress: _Progress,
    ) -> tuple[list[DigestDeliveryClaim], list[str], dict[str, str]]:
        claims: list[DigestDeliveryClaim] = []
        live: list[str] = []
        retry: dict[str, str] = {}
        for target, original in recipients.items():
            claim = claim_digest_delivery(
                self.db_path, period_key, "smtp", target
            )
            if claim.state == "sent":
                progress.skipped += 1
            elif claim.state == "busy":
                progress.busy += 1
            else:
                claims.append(claim)
                live.append(original)
        return claims, live, retry

    @staticmethod
    def _accepted_recipients(
        result: SendResult, recipients: Sequence[str]
    ) -> set[str]:
        if result.outcome == "accepted":
            return {recipient.casefold() for recipient in recipients}
        return {recipient.casefold() for recipient in result.accepted}

    @staticmethod
    def _webhook_targets(
        kind: DigestKind, targets: list[DigestTarget]
    ) -> list[DigestTarget]:
        eligible = [target for target in targets if target.webhook_eligible]
        if kind.webhook_fanout == "global":
            global_target = next((target for target in eligible if target.is_global), None)
            return [global_target] if global_target is not None else eligible[:1]
        per_target = [target for target in eligible if not target.is_global]
        return per_target or eligible

    def _deliver_webhooks(
        self,
        kind: DigestKind,
        targets: list[DigestTarget],
        period_key: str,
        transports: tuple[Transport, ...],
        started: float,
        progress: _Progress,
    ) -> int:
        pending = {
            (_claim_channel(transport), target.key): (transport, target)
            for transport in transports
            for target in targets
        }
        for _wave in backoff_range(
            ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"
        ):
            if (
                not pending
                or self._stopped(progress)
                or not self._within_budget(started, progress)
            ):
                break
            next_pending: dict[tuple[str, str], tuple[Transport, DigestTarget]] = {}
            for identity, (transport, target) in pending.items():
                if self._stopped(progress):
                    return len(pending)
                if not self._within_budget(started, progress):
                    next_pending[identity] = (transport, target)
                    continue
                channel, claim_target = identity
                claim = claim_digest_delivery(
                    self.db_path, period_key, channel, claim_target
                )
                if self._stopped(progress):
                    return len(pending)
                if claim.state == "sent":
                    progress.skipped += 1
                    continue
                if claim.state == "busy":
                    progress.busy += 1
                    continue
                if not renew_digest_delivery(self.db_path, claim):
                    progress.busy += 1
                    continue
                if self._stopped(progress):
                    return len(pending)

                rendered = kind.render(target)
                message = replace(
                    rendered,
                    subject=target.webhook_subject or rendered.subject,
                    cert_id=claim.idempotency_key,
                    recipients=(),
                )
                result = transport.send(message)
                progress.attempts += 1
                recorded = complete_digest_delivery(
                    self.db_path, claim, succeeded=result.delivered
                )
                if result.delivered:
                    if recorded:
                        progress.sent += 1
                    else:
                        progress.busy += 1
                else:
                    next_pending[identity] = (transport, target)
            pending = next_pending
        return len(pending)


def _cadence_from_period_key(period_key: str) -> int:
    """Read the cadence embedded by ``digest_period_key`` without changing it."""
    marker = ":cadence="
    try:
        cadence = int(period_key.rsplit(marker, 1)[1])
    except (IndexError, ValueError):
        raise ValueError(f"invalid digest period key: {period_key!r}") from None
    if cadence <= 0:
        raise ValueError("digest cadence must be positive")
    return cadence
