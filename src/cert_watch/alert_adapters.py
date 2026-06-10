"""Alert channel adapters — pure functions that build provider-specific HTTP requests.

Each adapter's ``build()`` is a pure function (no I/O), making them trivially
golden-testable. Delivery is handled by ``send_webhook`` in ``alerts.py``, which
dispatches to the right adapter and sends the result through ``ssrf_safe_urlopen``.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cert_watch.alerts import WebhookConfig
    from cert_watch.database import Alert


@dataclass(frozen=True)
class AlertRequest:
    url: str
    body: bytes
    headers: dict[str, str]
    method: str = "POST"


class AlertAdapter(Protocol):
    kind: str

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest: ...

def _status_color(alert_type: str) -> int:
    if alert_type == "expired":
        return 0xCC0000
    if alert_type in ("expiry_warning", "drift", "renewal_stalled", "policy_violation"):
        return 0xE0A800
    return 0x808080


def _status_urgency(alert_type: str) -> str:
    if alert_type == "expired":
        return "attention"
    if alert_type in ("expiry_warning", "renewal_stalled", "policy_violation"):
        return "warning"
    return "default"


def _pd_severity(alert_type: str, threshold_days: int | None) -> str:
    if alert_type == "expired":
        return "critical"
    if alert_type in ("expiry_warning", "drift"):
        if threshold_days is not None and threshold_days <= 3:
            return "error"
        return "warning"
    if alert_type == "mis_issuance":
        return "error"
    if alert_type == "renewal_stalled":
        return "warning"
    if alert_type == "policy_violation":
        return "warning"
    return "info"


def _pd_dedup_key(cert_id: str, alert_type: str, threshold_days: int | None) -> str:
    raw = f"{cert_id}:{alert_type}:{threshold_days}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


_ALERT_NAMES = {
    "expired": "CertExpired",
    "expiry_warning": "CertExpiry",
    "drift": "CertDrift",
    "mis_issuance": "CertMisIssued",
    "renewal_stalled": "CertRenewalStalled",
    "scan_failure": "CertScanFailure",
    "policy_violation": "CertPolicyViolation",
}


def _alertname(alert_type: str) -> str:
    return _ALERT_NAMES.get(alert_type, "CertAlert")


# ---------------------------------------------------------------------------
# Generic adapter — preserves existing behaviour exactly
# ---------------------------------------------------------------------------

class GenericAdapter:
    kind = "generic"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        if config.template:
            payload = config.template
            for key in ("alert_type", "cert_id", "message", "threshold_days", "status"):
                value = str(getattr(alert, key, ""))
                payload = payload.replace("{{" + key + "}}", value)
            content_type = "text/plain"
            if payload.lstrip().startswith("{"):
                content_type = "application/json"
        else:
            payload_dict: dict[str, Any] = {
                "alert_type": alert.alert_type,
                "cert_id": alert.cert_id,
                "message": alert.message,
                "threshold_days": alert.threshold_days,
                "status": alert.status,
            }
            if alert.extra_recipients:
                payload_dict["extra_recipients"] = alert.extra_recipients
            payload = json.dumps(payload_dict)
            content_type = "application/json"
        headers = {"Content-Type": content_type, **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# Discord adapter — incoming webhook with embeds
# ---------------------------------------------------------------------------

class DiscordAdapter:
    kind = "discord"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        color = _status_color(alert.alert_type)
        threshold_str = f"{alert.threshold_days}d" if alert.threshold_days is not None else "—"
        fields = [
            {"name": "Alert Type", "value": alert.alert_type, "inline": True},
            {"name": "Threshold", "value": threshold_str, "inline": True},
            {"name": "Status", "value": alert.status, "inline": True},
        ]
        if alert.cert_id:
            fields.append({"name": "Cert ID", "value": str(alert.cert_id), "inline": False})
        embed = {
            "title": f"cert-watch: {alert.alert_type.replace('_', ' ').title()}",
            "description": alert.message,
            "color": color,
            "fields": fields,
        }
        payload = json.dumps({"username": "cert-watch", "embeds": [embed]})
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# Microsoft Teams adapter — Adaptive Card via Workflows webhook
# ---------------------------------------------------------------------------

class TeamsAdapter:
    kind = "teams"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        urgency = _status_urgency(alert.alert_type)
        threshold_str = f"{alert.threshold_days}d" if alert.threshold_days is not None else "—"
        facts = [
            {"title": "Alert Type", "value": alert.alert_type},
            {"title": "Threshold", "value": threshold_str},
            {"title": "Status", "value": alert.status},
        ]
        if alert.cert_id:
            facts.append({"title": "Cert ID", "value": str(alert.cert_id)})
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": f"cert-watch: {alert.alert_type.replace('_', ' ').title()}",
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": urgency,
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                            {
                                "type": "TextBlock",
                                "text": alert.message,
                                "wrap": True,
                            },
                        ],
                    },
                }
            ],
        }
        payload = json.dumps(card)
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# PagerDuty adapter — Events API v2
# ---------------------------------------------------------------------------

_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyAdapter:
    kind = "pagerduty"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        severity = _pd_severity(alert.alert_type, alert.threshold_days)
        dedup_key = _pd_dedup_key(alert.cert_id, alert.alert_type, alert.threshold_days)
        summary = alert.message
        if len(summary) > 1024:
            summary = summary[:1021] + "..."
        payload_dict = {
            "routing_key": config.routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary,
                "source": "cert-watch",
                "severity": severity,
                "component": str(alert.cert_id),
                "class": "cert-expiry",
            },
        }
        payload = json.dumps(payload_dict)
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(
            url=_PAGERDUTY_EVENTS_URL,
            body=payload.encode("utf-8"),
            headers=headers,
        )

    def build_resolve(
        self,
        cert_id: str,
        alert_type: str,
        threshold_days: int | None,
        config: WebhookConfig,
        *,
        summary: str = "",
        hostname: str = "",
        subject: str = "",
        alert_created_at: datetime | None = None,
    ) -> AlertRequest:
        dedup_key = _pd_dedup_key(cert_id, alert_type, threshold_days)
        if not summary:
            summary = f"cert-watch: certificate {cert_id} renewed, {alert_type} resolved"
        if len(summary) > 1024:
            summary = summary[:1021] + "..."
        payload_dict = {
            "routing_key": config.routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
            "payload": {
                "summary": summary,
                "source": "cert-watch",
                "severity": "info",
                "component": str(cert_id),
                "class": "cert-expiry",
            },
        }
        payload = json.dumps(payload_dict)
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(
            url=_PAGERDUTY_EVENTS_URL,
            body=payload.encode("utf-8"),
            headers=headers,
        )


def _slack_color(alert_type: str) -> str:
    if alert_type == "expired":
        return "danger"
    if alert_type in ("expiry_warning", "renewal_stalled"):
        return "warning"
    return "good"


class SlackAdapter:
    kind = "slack"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        color = _slack_color(alert.alert_type)
        threshold_str = f"{alert.threshold_days}d" if alert.threshold_days is not None else "—"
        fields = [
            {"title": "Expires", "value": threshold_str, "short": True},
            {"title": "Urgency", "value": alert.alert_type, "short": True},
        ]
        if alert.cert_id:
            fields.append({"title": "Cert ID", "value": str(alert.cert_id), "short": False})
        attachment = {
            "color": color,
            "title": f"cert-watch: {alert.alert_type.replace('_', ' ').title()}",
            "text": alert.message,
            "fields": fields,
            "footer": "cert-watch",
        }
        payload = json.dumps({"attachments": [attachment]})
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


class AlertmanagerAdapter:
    kind = "alertmanager"

    def build(self, alert: Alert, config: WebhookConfig) -> AlertRequest:
        now = datetime.now(UTC).isoformat()
        alert_entry = {
            "status": "firing",
            "labels": {
                "alertname": _alertname(alert.alert_type),
                "host": alert.hostname or str(alert.cert_id),
                "cert_subject": alert.subject or str(alert.cert_id),
                "urgency": alert.alert_type,
            },
            "annotations": {
                "summary": alert.message,
                "expires": str(alert.threshold_days) if alert.threshold_days is not None else "",
            },
            "startsAt": now,
            "generatorURL": config.url,
        }
        payload = json.dumps({"alerts": [alert_entry]})
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)

    def build_resolve(
        self,
        cert_id: str,
        alert_type: str,
        threshold_days: int | None,
        config: WebhookConfig,
        *,
        summary: str = "",
        hostname: str = "",
        subject: str = "",
        alert_created_at: datetime | None = None,
    ) -> AlertRequest:
        if not summary:
            summary = f"cert-watch: certificate {cert_id} renewed, {alert_type} resolved"
        now = datetime.now(UTC)
        if alert_created_at is not None:
            starts_at = alert_created_at.isoformat()
        else:
            starts_at = (now - timedelta(milliseconds=1)).isoformat()
        ends_at = now.isoformat()
        alert_entry = {
            "status": "resolved",
            "labels": {
                "alertname": _alertname(alert_type),
                "host": hostname or str(cert_id),
                "cert_subject": subject or str(cert_id),
                "urgency": alert_type,
            },
            "annotations": {
                "summary": summary,
                "expires": str(threshold_days) if threshold_days is not None else "",
            },
            "startsAt": starts_at,
            "endsAt": ends_at,
            "generatorURL": config.url,
        }
        payload = json.dumps({"alerts": [alert_entry]})
        headers = {"Content-Type": "application/json", **config.headers}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_ADAPTERS: dict[str, AlertAdapter] = {
    "generic": GenericAdapter(),
    "discord": DiscordAdapter(),
    "teams": TeamsAdapter(),
    "pagerduty": PagerDutyAdapter(),
    "slack": SlackAdapter(),
    "alertmanager": AlertmanagerAdapter(),
}


def get_adapter(kind: str) -> AlertAdapter:
    adapter = _ADAPTERS.get(kind)
    if adapter is None:
        raise ValueError(f"unknown alert adapter kind: {kind!r}")
    return adapter
