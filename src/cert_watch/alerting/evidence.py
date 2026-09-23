"""Observe individual alert attempts without storing transport secrets or payloads."""

from __future__ import annotations

import logging
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from cert_watch.alerting.model import FAILURE_LABELS as FAILURE_LABELS
from cert_watch.alerting.model import OutboundMessage, SendResult
from cert_watch.alerting.routing import _resolve_group_config
from cert_watch.alerting.transports.base import Transport
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

def _matching_groups(db_path: Path, cert_id: str) -> tuple[list[dict[str, str]], bool]:
    # This is a snapshot of configuration at attempt time, not an attribution
    # of queued addresses. The latter were resolved when the alert was queued.
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
    except Exception:  # noqa: BLE001 — evidence enrichment is an optional snapshot
        logger.warning("Matching-group snapshot unavailable for delivery evidence")
        return [], False


def attempt_delivery(
    db_path: Path | None,
    alert_id: str,
    transport: Transport,
    msg: OutboundMessage,
    *,
    claim_owner: str = "",
) -> SendResult:
    """Record before sending; a missing completion remains explicitly unknown.

    Non-SQLite repository adapters retain their existing behavior. A completion
    write failure cannot undo acceptance and must not provoke an extra send.

    Raises:
        DeliveryEvidenceUnavailable: the attempt could not be recorded, so no
            transport was touched. This is NOT a delivery failure and must not
            spend a retry -- see ``dispatch.process_pending``, which keeps such an
            alert pending and still tries the other channel.
    """
    if db_path is None:
        return transport.send(msg)
    groups, groups_available = _matching_groups(db_path, msg.cert_id)
    actual_recipients = [address for _, address in getaddresses(msg.recipients)]
    configured = {address for _, address in getaddresses(msg.global_recipients)}
    queued = {address for _, address in getaddresses(msg.queued_recipients)}
    details = {
        "recipients": actual_recipients,
        "global_recipients": [address for address in actual_recipients if address in configured],
        "queued_recipients": [address for address in actual_recipients if address in queued],
        "groups": groups, "groups_available": groups_available,
        "claim_owner": claim_owner,
    }
    try:
        attempt_id = begin_attempt(db_path, alert_id, transport.channel, details)
    except Exception as exc:
        # The caller leaves the alert pending and persists nothing, so this
        # path does not manufacture an operator-visible transport failure.
        logger.warning("Delivery refused because its attempt record could not be persisted")
        raise DeliveryEvidenceUnavailable(REFUSED_NO_EVIDENCE) from exc

    result: SendResult
    try:
        result = transport.send(msg)
    except Exception:
        result = SendResult("failed", "transport")
        try:
            complete_attempt(db_path, attempt_id, _result_details(result))
        except Exception:  # noqa: BLE001 — completion remains best-effort
            logger.warning("Delivery outcome could not be persisted; outcome remains unknown")
        raise
    try:
        complete_attempt(db_path, attempt_id, _result_details(result))
    except Exception:  # noqa: BLE001 — completion evidence is best-effort after delivery
        logger.warning("Delivery outcome could not be persisted; outcome remains unknown")
    return result


def _result_details(result: SendResult) -> dict[str, Any]:
    """Keep the append-only ledger schema byte-compatible with prior attempts."""
    return {
        # The ledger historically represented policy blocks as failed. Preserve
        # that vocabulary while SendResult gives dispatchers the richer outcome.
        "outcome": "failed" if result.outcome == "blocked" else result.outcome,
        "reason": result.reason or ("" if result.delivered else "unknown"),
        "accepted": list(result.accepted),
        "refused": list(result.refused),
        "http_status": result.http_status,
    }
