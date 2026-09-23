"""Webhook transport: sends alerts and resolves through the channel adapters."""

from __future__ import annotations

import logging
from datetime import datetime

from cert_watch.alerting.evidence import observe_exception, observe_failure, observe_http
from cert_watch.alerting.model import WebhookConfig
from cert_watch.alerting.transports.adapters import get_adapter
from cert_watch.alerting.transports.base import _redact_secret
from cert_watch.database import Alert
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


def send_webhook(alert: Alert, config: WebhookConfig | None) -> bool:
    """Send alert via the configured channel adapter. Returns True on success.

    Dispatches to the adapter matching ``config.kind`` and sends the resulting
    request through ``ssrf_safe_urlopen``. PagerDuty returns HTTP 202 on success;
    all other providers return 2xx.
    """
    if config is None:
        return False
    try:
        adapter = get_adapter(config.kind)
        req = adapter.build(alert, config)
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
            observe_http(resp.status, delivered=delivered)
            return delivered
    except SSRFBlockedError as exc:
        alert.error_message = f"webhook URL blocked by SSRF policy: {exc}"
        observe_failure("blocked")
        return False
    except Exception as exc:  # noqa: BLE001 — webhook is an external service with unpredictable failure modes
        alert.error_message = _sanitize_webhook_error(str(exc), config)
        observe_exception(exc)
        return False


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
