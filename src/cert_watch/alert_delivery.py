"""Observe individual alert attempts without storing transport secrets or payloads."""

from __future__ import annotations

import logging
import smtplib
import ssl
from collections.abc import Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from email.utils import getaddresses
from pathlib import Path
from typing import Any
from urllib.error import HTTPError

from cert_watch.database import Alert
from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

logger = logging.getLogger("cert_watch.alert_delivery")


REFUSED_NO_EVIDENCE = "Delivery attempt evidence could not be recorded"


class DeliveryEvidenceUnavailable(Exception):
    """The attempt could not be recorded, so nothing was sent.

    Distinct from a delivery that was attempted and failed: no transport was
    touched, the destination never saw a connection, and the alert is still
    deliverable. Callers must leave such an alert pending rather than spend a
    retry on it — the database, not the destination, was unavailable.
    """

FAILURE_LABELS = {
    "blocked": "Blocked by the destination policy before sending",
    "dns": "The SMTP destination could not be resolved",
    "tls": "TLS negotiation or certificate validation failed",
    "authentication": "The SMTP server rejected authentication",
    "no_recipients": "No valid email recipients were available",
    "recipients_refused": "The SMTP server refused recipients",
    "smtp_rejected": "The SMTP server rejected the request",
    "http_rejected": "The webhook returned an unsuccessful HTTP status",
    "timeout": "The transport timed out",
    "invalid_channel": "The webhook channel configuration was invalid",
    "transport": "The transport failed; sensitive diagnostic text is not retained",
    "unknown": "The transport reported failure without further safe details",
}


@dataclass
class _Observation:
    outcome: str = ""
    reason: str = ""
    accepted: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)
    http_status: int | None = None

    def details(self, delivered: bool) -> dict[str, Any]:
        return {
            "outcome": self.outcome or ("accepted" if delivered else "failed"),
            "reason": self.reason or ("" if delivered else "unknown"),
            "accepted": self.accepted, "refused": self.refused,
            "http_status": self.http_status,
        }


_active: ContextVar[_Observation | None] = ContextVar("alert_delivery_observation", default=None)


def observe_failure(reason: str, *, http_status: int | None = None) -> None:
    observation = _active.get()
    if observation is not None:
        observation.outcome = "failed"
        observation.reason = reason if reason in FAILURE_LABELS else "unknown"
        observation.http_status = http_status


def observe_exception(exc: Exception) -> None:
    """Persist an allowlisted category, never exception text or response bodies."""
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        observe_failure("authentication")
    elif isinstance(exc, ssl.SSLError):
        observe_failure("tls")
    elif isinstance(exc, smtplib.SMTPRecipientsRefused):
        observe_failure("recipients_refused")
    elif isinstance(exc, smtplib.SMTPResponseException):
        observe_failure("smtp_rejected")
    elif isinstance(exc, HTTPError):
        observe_failure("http_rejected", http_status=exc.code)
    elif isinstance(exc, TimeoutError):
        observe_failure("timeout")
    else:
        observe_failure("transport")


def observe_smtp(recipients: list[str], refused: dict[str, Any]) -> None:
    observation = _active.get()
    if observation is not None:
        envelope = [address for _, address in getaddresses(recipients)]
        observation.accepted = [address for address in envelope if address not in refused]
        observation.refused = [address for address in envelope if address in refused]
        observation.outcome = "partial" if observation.refused else "accepted"
        observation.reason = "recipients_refused" if observation.refused else ""


def observe_http(status: int, *, delivered: bool) -> None:
    observation = _active.get()
    if observation is not None:
        observation.http_status = status
        observation.outcome = "accepted" if delivered else "failed"
        observation.reason = "" if delivered else "http_rejected"


def _matching_groups(db_path: Path, cert_id: str) -> tuple[list[dict[str, str]], bool]:
    # This is a snapshot of configuration at attempt time, not an attribution
    # of queued addresses. The latter were resolved when the alert was queued.
    from cert_watch.alerts import _resolve_group_config
    from cert_watch.database.connection import _connect

    matches: dict[str, list[str]] = {}
    try:
        _resolve_group_config(db_path, matched_groups=matches, cert_ids=(cert_id,))
        with _connect(db_path) as conn:
            names = {
                row["id"]: row["name"] for row in conn.execute("SELECT id, name FROM alert_groups")
            }
        return [{"id": group_id, "name": names.get(group_id, "(deleted group)")}
                for group_id in matches.get(cert_id, [])], True
    except Exception:
        logger.warning("Matching-group snapshot unavailable for delivery evidence")
        return [], False


def attempt_delivery(
    db_path: Path | None,
    alert: Alert,
    channel: str,
    send: Callable[[], bool],
    *,
    recipients: list[str] | None = None,
    global_recipients: list[str] | None = None,
) -> bool:
    """Record before sending; a missing completion remains explicitly unknown.

    Non-SQLite repository adapters retain their existing behavior. A completion
    write failure cannot undo acceptance and must not provoke an extra send.

    Raises:
        DeliveryEvidenceUnavailable: the attempt could not be recorded, so no
            transport was touched. This is NOT a delivery failure and must not
            spend a retry -- see ``alerts.process_pending``, which keeps such an
            alert pending and still tries the other channel.
    """
    if db_path is None:
        return send()
    groups, groups_available = _matching_groups(db_path, alert.cert_id)
    actual_recipients = [address for _, address in getaddresses(recipients or [])]
    configured = [address for _, address in getaddresses(global_recipients or [])]
    queued = [address for _, address in getaddresses(alert.extra_recipients)]
    details = {
        "recipients": actual_recipients,
        "global_recipients": [address for address in actual_recipients if address in configured],
        "queued_recipients": [
            address for address in actual_recipients if address in queued
        ],
        "groups": groups, "groups_available": groups_available,
    }
    try:
        attempt_id = begin_attempt(db_path, alert.id, channel, details)
    except Exception as exc:
        # Deliberately does not set alert.error_message: the caller leaves the
        # alert pending and persists nothing, so an assignment here would only
        # suggest the reason was recorded somewhere. The caller owns the
        # operator-visible wording.
        logger.warning("Delivery refused because its attempt record could not be persisted")
        raise DeliveryEvidenceUnavailable(REFUSED_NO_EVIDENCE) from exc

    observation = _Observation()
    token = _active.set(observation)
    delivered = False
    try:
        delivered = send()
        return delivered
    except Exception as exc:
        observe_exception(exc)
        raise
    finally:
        _active.reset(token)
        try:
            complete_attempt(db_path, attempt_id, observation.details(delivered))
        except Exception:
            logger.warning("Delivery outcome could not be persisted; outcome remains unknown")
