"""Alert channel adapters — pure functions that build provider-specific HTTP requests.

Each adapter's ``build()`` is a pure function (no I/O), making them trivially
golden-testable. Delivery is handled by ``send_webhook`` in ``transports/webhook.py``,
which dispatches to the right adapter and sends the result through
``ssrf_safe_urlopen``.
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from cert_watch.alerting.model import OutboundMessage, WebhookConfig


@dataclass(frozen=True)
class AlertRequest:
    url: str
    body: bytes
    headers: dict[str, str]
    method: str = "POST"


class InvalidWebhookTemplateError(ValueError):
    """Rendered generic webhook template is not valid for its declared format."""


class AlertAdapter(Protocol):
    kind: str

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest: ...

def _status_color(alert_type: str) -> int:
    if alert_type in ("expired", "renewal_failed"):
        return 0xCC0000
    if alert_type in (
        "expiry_warning", "drift", "renewal_stalled", "renewal_not_deployed",
        "policy_violation",
    ):
        return 0xE0A800
    return 0x808080


def _status_urgency(alert_type: str) -> str:
    if alert_type == "expired":
        return "attention"
    if alert_type in (
        "expiry_warning", "renewal_stalled", "renewal_not_deployed", "renewal_failed",
        "policy_violation",
    ):
        return "warning"
    return "default"


def _pd_severity(alert_type: str, threshold_days: int | None) -> str:
    if alert_type == "expired":
        return "critical"
    if alert_type in ("expiry_warning", "drift"):
        if threshold_days is not None and threshold_days <= 3:
            return "error"
        return "warning"
    if alert_type == "renewal_failed":
        return "error"
    if alert_type in ("renewal_stalled", "renewal_not_deployed"):
        return "warning"
    if alert_type == "policy_violation":
        return "warning"
    return "info"


def _pd_dedup_key(cert_id: str, alert_type: str, threshold_days: int | None) -> str:
    """Key a PagerDuty incident by the certificate row the alert fired on.

    Callers must pass the alert's ``trigger_cert_id`` (falling back to
    ``cert_id``): an unchanged rescan rewrites the leaf row under a new id
    and carries the alert with it (#57), so keying resolves on the current
    row id would never match the incident the trigger opened (#62).
    """
    raw = f"{cert_id}:{alert_type}:{threshold_days}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


_ALERT_NAMES = {
    "expired": "CertExpired",
    "expiry_warning": "CertExpiry",
    "drift": "CertDrift",
    "renewal_stalled": "CertRenewalStalled",
    "renewal_not_deployed": "CertRenewalNotDeployed",
    "renewal_failed": "CertRenewalFailed",
    "scan_failure": "CertScanFailure",
    "policy_violation": "CertPolicyViolation",
}


def _alertname(alert_type: str) -> str:
    return _ALERT_NAMES.get(alert_type, "CertAlert")


# ---------------------------------------------------------------------------
# Generic adapter
# ---------------------------------------------------------------------------


def _strip_control_characters(value: str) -> str:
    return "".join(
        character for character in value
        if unicodedata.category(character) != "Cc"
    )


def _escape_slack_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_DISCORD_MARKDOWN = re.compile(r"([\\[\]()*_~`>|])")
_TEAMS_MARKDOWN = re.compile(r"([\\[\]*])")


def _escape_discord_text(value: str) -> str:
    return _DISCORD_MARKDOWN.sub(r"\\\1", value)


def _escape_teams_text(value: str) -> str:
    # Teams documents only bold, italic, lists, and links for Adaptive Card
    # TextBlock Markdown. Mentions additionally require an msteams.entities
    # entry, which this adapter never supplies. Break angle-bracket and entity
    # tokens invisibly, and escape only link/emphasis delimiters. Punctuation
    # used in hostnames and subjects remains visible verbatim.
    escaped = (
        value.replace("&", "&\u200b")
        .replace("<", "<\u200b")
        .replace(">", "\u200b>")
    )
    return _TEAMS_MARKDOWN.sub(r"\\\1", escaped)


_TEMPLATE_VALUES = frozenset(
    {"alert_type", "cert_id", "message", "threshold_days", "status"}
)
_TEMPLATE_PLACEHOLDER = re.compile(
    r"{{(" + "|".join(sorted(_TEMPLATE_VALUES)) + r")}}"
)
# Starts with a non-hex letter so a placeholder completing a "\uXXXX" escape
# cannot parse by accident.
_JSON_SAMPLE_MARKER = "zz_cert_watch_template_sample"
# Placeholders whose value is always a JSON number or null.
_BARE_TEMPLATE_KEYS = frozenset({"threshold_days"})
_INVALID_JSON = object()


def _strip_template_prefix(template: str) -> str:
    """Remove every leading BOM and whitespace character."""
    position = 0
    while position < len(template):
        character = template[position]
        if character != "\ufeff" and not character.isspace():
            break
        position += 1
    return template[position:]


def _placeholder_is_in_string(template: str, position: int) -> bool:
    """Return whether *position* is inside a JSON-style quoted string."""
    in_string = False
    escaped = False
    for character in template[:position]:
        if escaped:
            escaped = False
        elif character == "\\" and in_string:
            escaped = True
        elif character == '"':
            in_string = not in_string
    return in_string


def _template_probe(template: str) -> tuple[str, Any]:
    """Strip the prefix and parse neutral, non-secret renderings.

    Unquoted placeholders are rendered both as ``0`` and as ``null`` (the two
    shapes ``{{threshold_days}}`` takes), and the template counts as valid
    JSON only if both parse, so ``-{{threshold_days}}`` is refused at save
    rather than failing each send that has no threshold.
    """
    template = _strip_template_prefix(template)
    parsed: Any = _INVALID_JSON
    for bare in ("0", "null"):

        def neutral(match: re.Match[str], bare: str = bare) -> str:
            if _placeholder_is_in_string(template, match.start()):
                return f"{_JSON_SAMPLE_MARKER}_{match.group(1)}"
            return bare

        rendered = _TEMPLATE_PLACEHOLDER.sub(neutral, template)
        try:
            parsed = json.loads(rendered)
        except json.JSONDecodeError:
            return template, _INVALID_JSON
    return template, parsed


def validate_generic_webhook_template(template: str) -> bool:
    """Validate *template* and return whether it is a JSON template.

    Text templates are deliberately accepted. A template is JSON only when it
    starts with ``{`` and a neutral rendering parses as a JSON object.
    Malformed object-looking templates are rejected so an operator sees the
    error while saving Settings.
    """
    template, parsed = _template_probe(template)
    if not template.startswith("{") or template.startswith("{{"):
        return False
    if parsed is _INVALID_JSON or not isinstance(parsed, dict):
        raise InvalidWebhookTemplateError(
            "Webhook template starts with '{' but is not a valid JSON object "
            "after placeholder substitution."
        )
    for match in _TEMPLATE_PLACEHOLDER.finditer(template):
        key = match.group(1)
        if key not in _BARE_TEMPLATE_KEYS and not _placeholder_is_in_string(
            template, match.start()
        ):
            raise InvalidWebhookTemplateError(
                f"Webhook JSON template placeholder {{{{{key}}}}} must be inside quotes; "
                "only {{threshold_days}} may appear unquoted."
            )
    return True

class GenericAdapter:
    kind = "generic"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        if config.template:
            template = _strip_template_prefix(config.template)
            is_json = validate_generic_webhook_template(template)
            values = {
                "alert_type": msg.severity,
                "cert_id": msg.cert_id,
                "message": msg.body,
                "threshold_days": msg.threshold_days,
                "status": msg.status,
            }

            def substitute(match: re.Match[str]) -> str:
                key = match.group(1)
                raw_value = values[key]
                if is_json:
                    if _placeholder_is_in_string(template, match.start()):
                        return json.dumps(str(raw_value))[1:-1]
                    if raw_value is None:
                        return "null"
                    if (
                        isinstance(raw_value, (int, float))
                        and not isinstance(raw_value, bool)
                        and isfinite(raw_value)
                    ):
                        return json.dumps(raw_value)
                    raise InvalidWebhookTemplateError(
                        f"generic webhook JSON placeholder {{{{{key}}}}} is bare, "
                        "but its value is not a JSON number or null"
                    )
                value = _strip_control_characters(str(raw_value))
                return value

            # One pass over the original template: placeholder-looking text in
            # a substituted certificate value remains literal.
            payload = _TEMPLATE_PLACEHOLDER.sub(substitute, template)
            content_type = "text/plain"
            if is_json:
                try:
                    json.loads(payload)
                except json.JSONDecodeError as exc:
                    raise InvalidWebhookTemplateError(
                        "generic webhook JSON template is invalid after substitution"
                    ) from exc
                content_type = "application/json"
        else:
            payload_dict: dict[str, Any] = {
                "alert_type": msg.severity,
                "cert_id": msg.cert_id,
                "message": msg.body,
                "threshold_days": msg.threshold_days,
                "status": msg.status,
            }
            if msg.queued_recipients:
                payload_dict["extra_recipients"] = list(msg.queued_recipients)
            payload = json.dumps(payload_dict)
            content_type = "application/json"
        # Adapter Content-Type is security-critical: custom headers must not be
        # allowed to override it (L11), so the adapter's value is applied last.
        headers = {**config.headers, "Content-Type": content_type}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# Discord adapter — incoming webhook with embeds
# ---------------------------------------------------------------------------

class DiscordAdapter:
    kind = "discord"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        color = _status_color(msg.severity)
        threshold_str = f"{msg.threshold_days}d" if msg.threshold_days is not None else "—"
        fields = [
            {"name": "Alert Type", "value": msg.severity, "inline": True},
            {"name": "Threshold", "value": threshold_str, "inline": True},
            {"name": "Status", "value": msg.status, "inline": True},
        ]
        if msg.cert_id:
            fields.append({"name": "Cert ID", "value": str(msg.cert_id), "inline": False})
        embed = {
            "title": f"cert-watch: {msg.severity.replace('_', ' ').title()}",
            "description": _escape_discord_text(msg.body),
            "color": color,
            "fields": fields,
        }
        payload = json.dumps(
            {
                "username": "cert-watch",
                "embeds": [embed],
                "allowed_mentions": {"parse": []},
            }
        )
        headers = {**config.headers, "Content-Type": "application/json"}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# Microsoft Teams adapter — Adaptive Card via Workflows webhook
# ---------------------------------------------------------------------------

class TeamsAdapter:
    kind = "teams"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        urgency = _status_urgency(msg.severity)
        threshold_str = f"{msg.threshold_days}d" if msg.threshold_days is not None else "—"
        facts = [
            {"title": "Alert Type", "value": msg.severity},
            {"title": "Threshold", "value": threshold_str},
            {"title": "Status", "value": msg.status},
        ]
        if msg.cert_id:
            facts.append({"title": "Cert ID", "value": str(msg.cert_id)})
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
                                "text": f"cert-watch: {msg.severity.replace('_', ' ').title()}",
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
                                "text": _escape_teams_text(msg.body),
                                "wrap": True,
                            },
                        ],
                    },
                }
            ],
        }
        payload = json.dumps(card)
        headers = {**config.headers, "Content-Type": "application/json"}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


# ---------------------------------------------------------------------------
# PagerDuty adapter — Events API v2
# ---------------------------------------------------------------------------

_PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"


class PagerDutyAdapter:
    kind = "pagerduty"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        severity = _pd_severity(msg.severity, msg.threshold_days)
        dedup_key = msg.incident_key or _pd_dedup_key(
            msg.trigger_cert_id or msg.cert_id, msg.severity, msg.threshold_days,
        )
        summary = msg.body
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
                "component": str(msg.cert_id),
                "class": "cert-expiry",
            },
        }
        payload = json.dumps(payload_dict)
        headers = {**config.headers, "Content-Type": "application/json"}
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
        incident_key: str = "",
    ) -> AlertRequest:
        dedup_key = incident_key or _pd_dedup_key(cert_id, alert_type, threshold_days)
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
        headers = {**config.headers, "Content-Type": "application/json"}
        return AlertRequest(
            url=_PAGERDUTY_EVENTS_URL,
            body=payload.encode("utf-8"),
            headers=headers,
        )


def _slack_color(alert_type: str) -> str:
    if alert_type in ("expired", "renewal_failed"):
        return "danger"
    if alert_type in ("expiry_warning", "renewal_stalled", "renewal_not_deployed"):
        return "warning"
    return "good"


class SlackAdapter:
    kind = "slack"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        color = _slack_color(msg.severity)
        threshold_str = f"{msg.threshold_days}d" if msg.threshold_days is not None else "—"
        fields = [
            {"title": "Expires", "value": threshold_str, "short": True},
            {"title": "Urgency", "value": msg.severity, "short": True},
        ]
        if msg.cert_id:
            fields.append({"title": "Cert ID", "value": str(msg.cert_id), "short": False})
        attachment = {
            "color": color,
            "title": f"cert-watch: {msg.severity.replace('_', ' ').title()}",
            "text": _escape_slack_text(msg.body),
            "fields": fields,
            "footer": "cert-watch",
        }
        payload = json.dumps({"attachments": [attachment]})
        headers = {**config.headers, "Content-Type": "application/json"}
        return AlertRequest(url=config.url, body=payload.encode("utf-8"), headers=headers)


class AlertmanagerAdapter:
    kind = "alertmanager"

    def build(self, msg: OutboundMessage, config: WebhookConfig) -> AlertRequest:
        now = datetime.now(UTC).isoformat()
        labels = {
            "alertname": _alertname(msg.severity),
            "host": msg.hostname or str(msg.cert_id),
            "cert_subject": msg.cert_subject or str(msg.cert_id),
            "urgency": msg.severity,
        }
        if msg.incident_key:
            labels["cert_watch_dedupe_key"] = msg.incident_key
        alert_entry = {
            "status": "firing",
            "labels": labels,
            "annotations": {
                "summary": msg.body,
                "expires": str(msg.threshold_days) if msg.threshold_days is not None else "",
            },
            "startsAt": now,
            "generatorURL": config.url,
        }
        payload = json.dumps({"alerts": [alert_entry]})
        headers = {**config.headers, "Content-Type": "application/json"}
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
        incident_key: str = "",
    ) -> AlertRequest:
        if not summary:
            summary = f"cert-watch: certificate {cert_id} renewed, {alert_type} resolved"
        now = datetime.now(UTC)
        if alert_created_at is not None:
            starts_at = alert_created_at.isoformat()
        else:
            starts_at = (now - timedelta(milliseconds=1)).isoformat()
        ends_at = now.isoformat()
        labels = {
            "alertname": _alertname(alert_type),
            "host": hostname or str(cert_id),
            "cert_subject": subject or str(cert_id),
            "urgency": alert_type,
        }
        if incident_key:
            labels["cert_watch_dedupe_key"] = incident_key
        alert_entry = {
            "status": "resolved",
            "labels": labels,
            "annotations": {
                "summary": summary,
                "expires": str(threshold_days) if threshold_days is not None else "",
            },
            "startsAt": starts_at,
            "endsAt": ends_at,
            "generatorURL": config.url,
        }
        payload = json.dumps({"alerts": [alert_entry]})
        headers = {**config.headers, "Content-Type": "application/json"}
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


_WEBHOOK_KIND_LABELS: dict[str, str] = {
    "generic": "Generic",
    "discord": "Discord",
    "teams": "Teams",
    "slack": "Slack",
    "pagerduty": "PagerDuty",
    "alertmanager": "Alertmanager",
}

WEBHOOK_KIND_OPTIONS: list[tuple[str, str]] = [
    (kind, _WEBHOOK_KIND_LABELS[kind]) for kind in _ADAPTERS
]
