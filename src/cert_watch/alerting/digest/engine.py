"""Machinery shared by the digest kinds: claimed SMTP delivery.

Plan 058 PR 5 folds both digest senders into one ``DigestEngine``; until then
this module holds only the helpers that both senders already call.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
from collections.abc import Callable, Mapping
from email.message import EmailMessage
from pathlib import Path

from cert_watch.alerting.model import (
    ALERT_MAX_RETRIES,
    ALERT_RETRY_DELAY,
    AlertConfig,
    WebhookConfig,
)
from cert_watch.alerting.transports.smtp import _open_smtp_connection, _sanitize_smtp_error
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.alerts")


def _webhook_channel(config: WebhookConfig) -> str:
    endpoint = config.routing_key if config.kind == "pagerduty" else config.url
    endpoint_hash = hashlib.sha256(endpoint.encode()).hexdigest()[:16]
    return f"webhook:{config.kind}:{endpoint_hash}"


def _send_claimed_digest_smtp(
    db_path: str | Path,
    digest_key: str,
    recipients: list[str],
    config: AlertConfig,
    message_factory: Callable[[list[str]], EmailMessage],
    *,
    failure_label: str = "digest email",
) -> tuple[dict[str, bool], bool]:
    """Deliver a digest batch with per-recipient claims and refusal handling.

    A successful ``send_message`` may still return a mapping of refused
    recipients. Accepted recipients are committed immediately; refused ones
    release their claims and are the only addresses retried. Claims are taken
    (and renewed) immediately before each network attempt, never while waiting
    behind earlier owner deliveries.

    Returns ``(outcomes, busy)``. Outcome keys preserve input casing; ``busy``
    means another process held at least one live recipient lease.
    """
    from cert_watch.database.digest_deliveries import (
        claim_digest_delivery,
        complete_digest_delivery,
        renew_digest_delivery,
    )

    originals: dict[str, str] = {}
    for recipient in recipients:
        originals.setdefault(recipient.casefold(), recipient)
    pending = list(originals)
    outcomes: dict[str, bool] = {}
    busy = False

    for _ in backoff_range(ALERT_MAX_RETRIES - 1, ALERT_RETRY_DELAY, strategy="linear"):
        if not pending:
            break
        acquired = []
        attempt_recipients: list[str] = []
        for target in pending:
            claim = claim_digest_delivery(db_path, digest_key, "smtp", target)
            if claim.state == "sent":
                outcomes[target] = True
            elif claim.state == "busy":
                outcomes[target] = False
                busy = True
            else:
                acquired.append(claim)
                attempt_recipients.append(originals[target])
        pending = []
        if not acquired:
            continue

        # Renew as one tight pre-send step after all recipients have been
        # claimed, so even a deliberately short test lease cannot expire while
        # this batch was queued behind prior owner sends.
        live_claims = []
        live_recipients: list[str] = []
        for claim, recipient in zip(acquired, attempt_recipients, strict=True):
            if renew_digest_delivery(db_path, claim):
                live_claims.append(claim)
                live_recipients.append(recipient)
            else:
                outcomes[claim.target] = False
                busy = True
        if not live_claims:
            continue

        refused_targets: set[str] | None = None
        conn = _open_smtp_connection(config)
        if conn is not None:
            try:
                refused = conn.send_message(message_factory(live_recipients))
                if isinstance(refused, Mapping):
                    refused_targets = {str(address).casefold() for address in refused}
                else:
                    refused_targets = set()
            except Exception as exc:  # noqa: BLE001 — SMTP is an external service
                logger.warning(
                    "%s failed: %s",
                    failure_label,
                    _sanitize_smtp_error(str(exc), config),
                )
            finally:
                with contextlib.suppress(Exception):
                    conn.quit()

        for claim in live_claims:
            succeeded = (
                refused_targets is not None and claim.target not in refused_targets
            )
            recorded = complete_digest_delivery(db_path, claim, succeeded=succeeded)
            outcomes[claim.target] = succeeded and recorded
            if not outcomes[claim.target]:
                pending.append(claim.target)

    return ({originals[target]: outcomes.get(target, False) for target in originals}, busy)
