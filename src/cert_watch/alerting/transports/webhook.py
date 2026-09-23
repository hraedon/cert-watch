"""Webhook transport: sends alerts and resolves through the channel adapters."""

from __future__ import annotations

import hashlib
import logging
import socket
from datetime import datetime
from typing import Any
from urllib.error import HTTPError, URLError

from cert_watch.alerting.model import OutboundMessage, SendResult, WebhookConfig
from cert_watch.alerting.transports.adapters import get_adapter
from cert_watch.alerting.transports.base import _redact_secret
from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen

logger = logging.getLogger("cert_watch.alerts")


def _sanitize_webhook_error(msg: str, config: WebhookConfig | None) -> str:
    """Strip webhook URL, header values, and routing key from error messages.

    The routing key (PagerDuty) is always redacted regardless of length (B4);
    header values keep the ``>= 4`` gate because short values like ``yes`` /
    ``true`` are common non-secret config flags that would corrupt diagnostic
    text if treated as secrets.
    """
    if config and config.url:
        msg = msg.replace(config.url, "***")
    if config and config.routing_key:
        msg = _redact_secret(msg, config.routing_key)
    if config and config.headers:
        for val in config.headers.values():
            if len(val) >= 4:
                msg = msg.replace(val, "***")
    return msg


_WEBHOOK_KINDS = {"generic", "slack", "discord", "teams", "pagerduty", "alertmanager"}


class WebhookTransport:
    def __init__(self, config: WebhookConfig) -> None:
        self.config = config
        kind = config.kind if config.kind in _WEBHOOK_KINDS else "generic"
        self.channel = f"webhook:{kind}"
        endpoint = config.routing_key if config.kind == "pagerduty" else config.url
        self.destination_id = hashlib.sha256(endpoint.encode()).hexdigest()[:16]

    def send(self, msg: OutboundMessage) -> SendResult:
        return send_webhook(msg, self.config)


def send_webhook(msg: OutboundMessage | Any, config: WebhookConfig | None) -> SendResult:
    """Send a message via the configured channel and return a sanitized result.

    Dispatches to the adapter matching ``config.kind`` and sends the resulting
    request through ``ssrf_safe_urlopen``. PagerDuty returns HTTP 202 on success;
    all other providers return 2xx.
    """
    if not isinstance(msg, OutboundMessage):
        # Compatibility for deprecated direct callers while plan 058's shims
        # remain. WebhookTransport itself accepts OutboundMessage only.
        msg = OutboundMessage.from_alert(msg)
    if config is None:
        return SendResult(
            "failed", "invalid_channel", reached_transport=False,
            operator_message="Webhook is not configured",
        )
    try:
        adapter = get_adapter(config.kind)
        req = adapter.build(msg, config)
        resp = ssrf_safe_urlopen(
            req.url,
            data=req.body,
            timeout=config.timeout,
            method=req.method,
            headers=req.headers,
            allow_private=config.allow_private,
            allowed_subnets=config.allowed_subnets,
        )
        with resp:
            delivered = (
                resp.status == 202 if config.kind == "pagerduty" else 200 <= resp.status < 300
            )
            return SendResult(
                "accepted" if delivered else "failed",
                "" if delivered else "http_rejected",
                http_status=resp.status,
            )
    except SSRFBlockedError as exc:
        return SendResult(
            "blocked",
            "blocked",
            reached_transport=False,
            operator_message=_sanitize_webhook_error(
                f"webhook URL blocked by SSRF policy: {exc}", config
            ),
        )
    except ValueError as exc:
        return SendResult(
            "failed",
            "invalid_channel",
            reached_transport=False,
            operator_message=_sanitize_webhook_error(str(exc), config),
        )
    except Exception as exc:  # noqa: BLE001 — webhook is an external service with unpredictable failure modes
        if isinstance(exc, HTTPError):
            reason = "http_rejected"
            http_status = exc.code
            reached_transport = True
        elif isinstance(exc, TimeoutError):
            reason = "timeout"
            http_status = None
            reached_transport = True
        else:
            reason = "transport"
            http_status = None
            reached_transport = not (
                isinstance(exc, URLError) and isinstance(exc.reason, socket.gaierror)
            )
        return SendResult(
            "failed",
            reason,
            reached_transport=reached_transport,
            http_status=http_status,
            operator_message=_sanitize_webhook_error(str(exc), config),
        )


def _adapter_has_build_resolve(kind: str) -> bool:
    """True when the adapter for *kind* exposes a ``build_resolve`` method."""
    try:
        adapter = get_adapter(kind)
    except ValueError:
        return False
    return hasattr(adapter, "build_resolve")


def send_webhook_resolve(
    cert_id: str,
    alert_type: str,
    threshold_days: int | None,
    config: WebhookConfig,
    *,
    summary: str = "",
    hostname: str = "",
    subject: str = "",
    alert_created_at: datetime | None = None,
) -> bool:
    """Send a resolve event through the appropriate adapter.

    Dispatches ``build_resolve`` on the adapter matching ``config.kind``.
    Returns False if the adapter has no ``build_resolve`` method.
    """
    try:
        adapter = get_adapter(config.kind)
    except ValueError:
        return False

    build_resolve = getattr(adapter, "build_resolve", None)
    if build_resolve is None:
        return False

    try:
        req = build_resolve(
            cert_id, alert_type, threshold_days, config,
            summary=summary, hostname=hostname, subject=subject,
            alert_created_at=alert_created_at,
        )
        resp = ssrf_safe_urlopen(
            req.url,
            data=req.body,
            timeout=config.timeout,
            method=req.method,
            headers=req.headers,
            allow_private=config.allow_private,
            allowed_subnets=config.allowed_subnets,
        )
        with resp:
            if config.kind == "pagerduty":
                return resp.status == 202
            return 200 <= resp.status < 300
    except SSRFBlockedError as exc:
        logger.warning(
            "%s resolve blocked by SSRF policy: %s",
            config.kind,
            _sanitize_webhook_error(str(exc), config),
        )
        return False
    except Exception as exc:  # noqa: BLE001 — webhook resolve is an external service with unpredictable failure modes
        logger.warning(
            "%s resolve failed for cert %s: %s",
            config.kind,
            cert_id,
            _sanitize_webhook_error(str(exc), config),
        )
        return False
