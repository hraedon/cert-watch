"""Golden-payload unit tests for alert channel adapters (Plan 022).

Each adapter's ``build()`` is a pure function — these tests assert the exact
JSON payload, headers, and URL for different alert scenarios, plus delivery
integration via ``send_webhook``.
"""
from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.alert_adapters import (
    _PAGERDUTY_EVENTS_URL,
    AlertmanagerAdapter,
    DiscordAdapter,
    GenericAdapter,
    PagerDutyAdapter,
    SlackAdapter,
    TeamsAdapter,
    _pd_dedup_key,
    _pd_severity,
    _slack_color,
    _status_color,
    _status_urgency,
    get_adapter,
)
from cert_watch.alerts import WebhookConfig, send_webhook
from cert_watch.database import Alert


def _alert(
    alert_type: str = "expiry_warning",
    threshold_days: int = 7,
    cert_id: str = "cert-abc123",
    message: str = "Certificate 'web.example.com' expires in 5 days.",
    hostname: str = "",
    subject: str = "",
) -> Alert:
    return Alert(
        cert_id=cert_id,
        alert_type=alert_type,
        status="pending",
        message=message,
        threshold_days=threshold_days,
        hostname=hostname,
        subject=subject,
    )


def _config(kind: str = "generic", **kw) -> WebhookConfig:
    defaults = {
        "url": "https://hooks.example.com/alert",
        "kind": kind,
    }
    defaults.update(kw)
    return WebhookConfig(**defaults)


# ---------------------------------------------------------------------------
# Generic adapter — backward-compatible behaviour
# ---------------------------------------------------------------------------


class TestGenericAdapter:
    def test_default_json_payload(self):
        adapter = GenericAdapter()
        alert = _alert()
        config = _config()
        req = adapter.build(alert, config)
        assert req.url == "https://hooks.example.com/alert"
        assert req.method == "POST"
        assert req.headers["Content-Type"] == "application/json"
        body = json.loads(req.body)
        assert body["alert_type"] == "expiry_warning"
        assert body["cert_id"] == "cert-abc123"
        assert body["threshold_days"] == 7
        assert body["status"] == "pending"

    def test_template_substitution(self):
        adapter = GenericAdapter()
        config = _config(
            template='{"text":"[{{alert_type}}] {{message}}"}',
        )
        alert = _alert(message="Cert expires soon")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["text"] == "[expiry_warning] Cert expires soon"

    def test_template_non_json(self):
        adapter = GenericAdapter()
        config = _config(template="Alert: {{alert_type}}")
        alert = _alert()
        req = adapter.build(alert, config)
        assert req.headers["Content-Type"] == "text/plain"

    def test_extra_recipients_in_payload(self):
        adapter = GenericAdapter()
        alert = _alert()
        alert.extra_recipients = ["team@example.com"]
        config = _config()
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["extra_recipients"] == ["team@example.com"]

    def test_custom_headers_merged(self):
        adapter = GenericAdapter()
        config = _config(headers={"X-Custom": "yes"})
        alert = _alert()
        req = adapter.build(alert, config)
        assert req.headers["X-Custom"] == "yes"
        assert "Content-Type" in req.headers


# ---------------------------------------------------------------------------
# Discord adapter
# ---------------------------------------------------------------------------


class TestDiscordAdapter:
    def test_embed_payload(self):
        adapter = DiscordAdapter()
        alert = _alert()
        config = _config(kind="discord")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["username"] == "cert-watch"
        assert len(body["embeds"]) == 1
        embed = body["embeds"][0]
        assert "expiry warning" in embed["title"].lower()
        assert embed["description"] == alert.message
        assert isinstance(embed["color"], int)

    def test_expired_color_red(self):
        assert _status_color("expired") == 0xCC0000

    def test_expiry_warning_color_amber(self):
        assert _status_color("expiry_warning") == 0xE0A800

    def test_drift_color_amber(self):
        assert _status_color("drift") == 0xE0A800

    def test_default_color_grey(self):
        assert _status_color("scan_failure") == 0x808080

    def test_fields_include_threshold(self):
        adapter = DiscordAdapter()
        alert = _alert(threshold_days=3)
        config = _config(kind="discord")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        fields = body["embeds"][0]["fields"]
        threshold_field = next(f for f in fields if f["name"] == "Threshold")
        assert threshold_field["value"] == "3d"

    def test_null_threshold_shows_dash(self):
        adapter = DiscordAdapter()
        alert = _alert(threshold_days=None)
        config = _config(kind="discord")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        fields = body["embeds"][0]["fields"]
        threshold_field = next(f for f in fields if f["name"] == "Threshold")
        assert threshold_field["value"] == "—"


# ---------------------------------------------------------------------------
# Teams adapter — Adaptive Card
# ---------------------------------------------------------------------------


class TestTeamsAdapter:
    def test_adaptive_card_structure(self):
        adapter = TeamsAdapter()
        alert = _alert()
        config = _config(kind="teams")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["type"] == "message"
        assert len(body["attachments"]) == 1
        attachment = body["attachments"][0]
        assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
        card = attachment["content"]
        assert card["type"] == "AdaptiveCard"
        assert card["version"] == "1.4"
        assert len(card["body"]) == 3  # title, factset, message

    def test_expired_urgency_attention(self):
        assert _status_urgency("expired") == "attention"

    def test_expiry_warning_urgency_warning(self):
        assert _status_urgency("expiry_warning") == "warning"

    def test_title_text_block_color(self):
        adapter = TeamsAdapter()
        alert = _alert(alert_type="expired")
        config = _config(kind="teams")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        title_block = body["attachments"][0]["content"]["body"][0]
        assert title_block["color"] == "attention"
        assert title_block["weight"] == "Bolder"

    def test_factset_contains_threshold(self):
        adapter = TeamsAdapter()
        alert = _alert(threshold_days=14)
        config = _config(kind="teams")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        factset = body["attachments"][0]["content"]["body"][1]
        facts = factset["facts"]
        threshold_fact = next(f for f in facts if f["title"] == "Threshold")
        assert threshold_fact["value"] == "14d"


# ---------------------------------------------------------------------------
# PagerDuty adapter
# ---------------------------------------------------------------------------


class TestPagerDutyAdapter:
    def test_events_api_v2_payload(self):
        adapter = PagerDutyAdapter()
        alert = _alert()
        config = _config(kind="pagerduty", routing_key="0123456789abcdef0123456789abcdef")
        req = adapter.build(alert, config)
        assert req.url == _PAGERDUTY_EVENTS_URL
        body = json.loads(req.body)
        assert body["routing_key"] == "0123456789abcdef0123456789abcdef"
        assert body["event_action"] == "trigger"
        assert "dedup_key" in body
        assert body["payload"]["source"] == "cert-watch"
        assert body["payload"]["class"] == "cert-expiry"
        assert body["payload"]["component"] == "cert-abc123"

    def test_dedup_key_deterministic(self):
        key1 = _pd_dedup_key("cert-1", "expiry_warning", 7)
        key2 = _pd_dedup_key("cert-1", "expiry_warning", 7)
        assert key1 == key2

    def test_dedup_key_differs_for_different_inputs(self):
        key1 = _pd_dedup_key("cert-1", "expiry_warning", 7)
        key2 = _pd_dedup_key("cert-1", "expired", 7)
        assert key1 != key2

    def test_severity_expired_critical(self):
        assert _pd_severity("expired", None) == "critical"

    def test_severity_warning_low_threshold_error(self):
        assert _pd_severity("expiry_warning", 3) == "error"

    def test_severity_warning_higher_threshold_warning(self):
        assert _pd_severity("expiry_warning", 14) == "warning"

    def test_severity_drift_warning(self):
        assert _pd_severity("drift", None) == "warning"

    def test_severity_info(self):
        assert _pd_severity("scan_failure", None) == "info"

    def test_summary_truncated_at_1024(self):
        adapter = PagerDutyAdapter()
        long_msg = "x" * 2000
        alert = _alert(message=long_msg)
        config = _config(kind="pagerduty", routing_key="rk")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert len(body["payload"]["summary"]) <= 1024
        assert body["payload"]["summary"].endswith("...")

    def test_url_ignores_config_url(self):
        adapter = PagerDutyAdapter()
        config = _config(
            kind="pagerduty",
            url="https://custom.example.com/should-be-ignored",
            routing_key="rk",
        )
        alert = _alert()
        req = adapter.build(alert, config)
        assert req.url == _PAGERDUTY_EVENTS_URL


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestGetAdapter:
    @pytest.mark.parametrize(
        "kind",
        ["generic", "discord", "teams", "pagerduty", "slack", "alertmanager"],
    )
    def test_known_kinds(self, kind):
        adapter = get_adapter(kind)
        assert adapter.kind == kind

    def test_unknown_kind_raises(self):
        with pytest.raises(ValueError, match="unknown alert adapter kind"):
            get_adapter("unknown_channel")


# ---------------------------------------------------------------------------
# Delivery integration (send_webhook with adapters)
# ---------------------------------------------------------------------------


class TestSendWebhookWithAdapters:
    def test_discord_delivery(self):
        config = _config(kind="discord")
        alert = _alert()
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook(alert, config)
        assert ok is True
        call_kwargs = mock_urlopen.call_args
        body = json.loads(call_kwargs.kwargs["data"])
        assert body["username"] == "cert-watch"

    def test_teams_delivery(self):
        config = _config(kind="teams")
        alert = _alert()
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook(alert, config)
        assert ok is True
        call_kwargs = mock_urlopen.call_args
        body = json.loads(call_kwargs.kwargs["data"])
        assert body["type"] == "message"

    def test_pagerduty_delivery_202(self):
        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        alert = _alert()
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 202
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook(alert, config)
        assert ok is True
        assert mock_urlopen.call_args[0][0] == _PAGERDUTY_EVENTS_URL

    def test_pagerduty_delivery_non_202_is_failure(self):
        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        alert = _alert()
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook(alert, config)
        assert ok is False

    def test_generic_delivery_still_works(self):
        config = _config(kind="generic")
        alert = _alert()
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook(alert, config)
        assert ok is True
        call_kwargs = mock_urlopen.call_args
        body = json.loads(call_kwargs.kwargs["data"])
        assert body["alert_type"] == "expiry_warning"

    def test_routing_key_sanitized_from_error(self):
        config = _config(
            kind="pagerduty",
            routing_key="super-secret-key-1234567890",
        )
        alert = _alert()
        with patch(
            "cert_watch.alerts.ssrf_safe_urlopen",
            side_effect=Exception("POST failed: routing_key=super-secret-key-1234567890"),
        ):
            ok = send_webhook(alert, config)
        assert ok is False
        assert "super-secret-key-1234567890" not in (alert.error_message or "")
        assert "***" in (alert.error_message or "")

    def test_ssrf_blocked(self):
        from cert_watch.http_client import SSRFBlockedError

        config = _config(kind="discord")
        alert = _alert()
        with patch(
            "cert_watch.alerts.ssrf_safe_urlopen",
            side_effect=SSRFBlockedError("blocked IP: 127.0.0.1"),
        ):
            ok = send_webhook(alert, config)
        assert ok is False
        assert "blocked" in (alert.error_message or "")


# ---------------------------------------------------------------------------
# PagerDuty resolve-on-renewal (Slice 4)
# ---------------------------------------------------------------------------


class TestPagerDutyResolve:
    def test_build_resolve_payload(self):

        adapter = PagerDutyAdapter()
        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        req = adapter.build_resolve("cert-1", "expiry_warning", 7, config)
        body = json.loads(req.body)
        assert body["routing_key"] == "rk1234567890abcdef1234567890abcdef"
        assert body["event_action"] == "resolve"
        assert body["dedup_key"] == _pd_dedup_key("cert-1", "expiry_warning", 7)
        assert body["payload"]["severity"] == "info"
        assert body["payload"]["source"] == "cert-watch"

    def test_build_resolve_custom_summary(self):
        adapter = PagerDutyAdapter()
        config = _config(kind="pagerduty", routing_key="rk")
        req = adapter.build_resolve("c", "expired", None, config, summary="Custom resolve msg")
        body = json.loads(req.body)
        assert body["payload"]["summary"] == "Custom resolve msg"

    def test_build_resolve_summary_truncated(self):
        adapter = PagerDutyAdapter()
        config = _config(kind="pagerduty", routing_key="rk")
        req = adapter.build_resolve("c", "expired", None, config, summary="x" * 2000)
        body = json.loads(req.body)
        assert len(body["payload"]["summary"]) <= 1024

    def test_build_resolve_same_dedup_key_as_trigger(self):
        adapter = PagerDutyAdapter()
        config = _config(kind="pagerduty", routing_key="rk")
        alert = _alert(cert_id="cert-1", threshold_days=7)
        trigger_req = adapter.build(alert, config)
        resolve_req = adapter.build_resolve("cert-1", "expiry_warning", 7, config)
        trigger_body = json.loads(trigger_req.body)
        resolve_body = json.loads(resolve_req.body)
        assert trigger_body["dedup_key"] == resolve_body["dedup_key"]

    def test_send_webhook_resolve_pagerduty(self):
        from cert_watch.alerts import send_webhook_resolve

        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 202
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook_resolve("cert-1", "expiry_warning", 7, config)
        assert ok is True
        body = json.loads(mock_urlopen.call_args[1]["data"])
        assert body["event_action"] == "resolve"

    def test_send_webhook_resolve_non_202_is_failure(self):
        from cert_watch.alerts import send_webhook_resolve

        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook_resolve("cert-1", "expiry_warning", 7, config)
        assert ok is False

    def test_resolve_webhook_for_renewed_cert_pagerduty(self, tmp_path):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert
        from cert_watch.database import SqliteAlertRepository, init_schema

        db = tmp_path / "cw_resolve.sqlite3"
        init_schema(db)
        alert_repo = SqliteAlertRepository(db)
        alert_repo.create(Alert(
            cert_id="old-cert-1", alert_type="expiry_warning", status="pending",
            message="expiring", threshold_days=7,
        ))
        alert_repo.create(Alert(
            cert_id="old-cert-1", alert_type="expiry_warning", status="pending",
            message="expiring", threshold_days=3,
        ))
        config = _config(kind="pagerduty", routing_key="rk1234567890abcdef1234567890abcdef")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 202
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            resolved = resolve_webhook_for_renewed_cert(db, "old-cert-1", config)
        assert resolved == 2

    def test_resolve_webhook_noops_for_non_pagerduty(self):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert

        config = _config(kind="discord")
        resolved = resolve_webhook_for_renewed_cert(None, "cert-1", config)
        assert resolved == 0

    def test_resolve_webhook_noops_for_none_config(self):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert

        resolved = resolve_webhook_for_renewed_cert(None, "cert-1", None)
        assert resolved == 0


# ---------------------------------------------------------------------------
# Slack adapter
# ---------------------------------------------------------------------------


class TestSlackAdapter:
    def test_attachments_payload(self):
        adapter = SlackAdapter()
        alert = _alert()
        config = _config(kind="slack")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert "attachments" in body
        assert len(body["attachments"]) == 1
        att = body["attachments"][0]
        assert att["footer"] == "cert-watch"
        assert att["text"] == alert.message

    def test_expired_color_danger(self):
        assert _slack_color("expired") == "danger"

    def test_expiry_warning_color_warning(self):
        assert _slack_color("expiry_warning") == "warning"

    def test_renewal_stalled_color_warning(self):
        assert _slack_color("renewal_stalled") == "warning"

    def test_default_color_good(self):
        assert _slack_color("scan_failure") == "good"

    def test_fields_include_expires_and_urgency(self):
        adapter = SlackAdapter()
        alert = _alert(threshold_days=7)
        config = _config(kind="slack")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        fields = body["attachments"][0]["fields"]
        expires_field = next(f for f in fields if f["title"] == "Expires")
        urgency_field = next(f for f in fields if f["title"] == "Urgency")
        assert expires_field["value"] == "7d"
        assert urgency_field["value"] == "expiry_warning"

    def test_null_threshold_shows_dash(self):
        adapter = SlackAdapter()
        alert = _alert(threshold_days=None)
        config = _config(kind="slack")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        fields = body["attachments"][0]["fields"]
        expires_field = next(f for f in fields if f["title"] == "Expires")
        assert expires_field["value"] == "—"

    def test_custom_headers_merged(self):
        adapter = SlackAdapter()
        config = _config(kind="slack", headers={"X-Custom": "yes"})
        alert = _alert()
        req = adapter.build(alert, config)
        assert req.headers["X-Custom"] == "yes"
        assert req.headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# Alertmanager adapter
# ---------------------------------------------------------------------------


class TestAlertmanagerAdapter:
    def test_firing_payload(self):
        adapter = AlertmanagerAdapter()
        alert = _alert(hostname="web.example.com", subject="CN=web.example.com")
        config = _config(kind="alertmanager")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert "alerts" in body
        assert len(body["alerts"]) == 1
        entry = body["alerts"][0]
        assert entry["status"] == "firing"
        assert entry["labels"]["alertname"] == "CertExpiry"
        assert entry["labels"]["host"] == "web.example.com"
        assert entry["labels"]["cert_subject"] == "CN=web.example.com"
        assert entry["labels"]["urgency"] == "expiry_warning"
        assert entry["annotations"]["summary"] == alert.message
        assert entry["generatorURL"] == config.url

    def test_url_uses_config_url(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager", url="https://am.example.com/api/v1/alerts")
        alert = _alert()
        req = adapter.build(alert, config)
        assert req.url == "https://am.example.com/api/v1/alerts"

    def test_threshold_days_in_annotations(self):
        adapter = AlertmanagerAdapter()
        alert = _alert(threshold_days=3)
        config = _config(kind="alertmanager")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["alerts"][0]["annotations"]["expires"] == "3"

    def test_null_threshold_expires_empty(self):
        adapter = AlertmanagerAdapter()
        alert = _alert(threshold_days=None)
        config = _config(kind="alertmanager")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        assert body["alerts"][0]["annotations"]["expires"] == ""

    def test_labels_fallback_to_cert_id_when_empty(self):
        adapter = AlertmanagerAdapter()
        alert = _alert()
        config = _config(kind="alertmanager")
        req = adapter.build(alert, config)
        body = json.loads(req.body)
        entry = body["alerts"][0]
        assert entry["labels"]["host"] == "cert-abc123"
        assert entry["labels"]["cert_subject"] == "cert-abc123"

    def test_build_resolve_payload(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        req = adapter.build_resolve(
            "cert-1", "expiry_warning", 7, config,
            hostname="web.example.com", subject="CN=web.example.com",
        )
        body = json.loads(req.body)
        entry = body["alerts"][0]
        assert entry["status"] == "resolved"
        assert entry["labels"]["alertname"] == "CertExpiry"
        assert entry["labels"]["host"] == "web.example.com"
        assert entry["labels"]["cert_subject"] == "CN=web.example.com"
        assert "renewed" in entry["annotations"]["summary"]

    def test_build_resolve_custom_summary(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        req = adapter.build_resolve("c", "expired", None, config, summary="Custom resolve msg")
        body = json.loads(req.body)
        assert body["alerts"][0]["annotations"]["summary"] == "Custom resolve msg"

    def test_build_resolve_null_threshold(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        req = adapter.build_resolve("c", "expired", None, config)
        body = json.loads(req.body)
        assert body["alerts"][0]["annotations"]["expires"] == ""

    def test_build_resolve_starts_at_from_created_at(self):
        from datetime import UTC, datetime

        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        created = datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC)
        req = adapter.build_resolve(
            "cert-1", "expiry_warning", 7, config, alert_created_at=created,
        )
        body = json.loads(req.body)
        entry = body["alerts"][0]
        assert entry["startsAt"] == "2025-01-15T10:30:00+00:00"
        assert entry["endsAt"] != entry["startsAt"]

    def test_build_resolve_starts_at_defaults_to_now(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        req = adapter.build_resolve("c", "expired", None, config)
        body = json.loads(req.body)
        entry = body["alerts"][0]
        assert entry["startsAt"] != entry["endsAt"]
        # startsAt should be slightly before endsAt when created_at is missing
        starts = datetime.fromisoformat(entry["startsAt"])
        ends = datetime.fromisoformat(entry["endsAt"])
        assert starts < ends

    def test_build_resolve_labels_fallback_to_cert_id(self):
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        req = adapter.build_resolve("cert-xyz", "expired", None, config)
        body = json.loads(req.body)
        entry = body["alerts"][0]
        assert entry["labels"]["host"] == "cert-xyz"
        assert entry["labels"]["cert_subject"] == "cert-xyz"

    def test_resolve_labels_match_trigger_labels(self):
        """Round-trip: trigger and resolve payloads must share labels for correlation."""
        adapter = AlertmanagerAdapter()
        config = _config(kind="alertmanager")
        alert = _alert(
            cert_id="cert-1",
            alert_type="expiry_warning",
            threshold_days=7,
            hostname="web.example.com",
            subject="CN=web.example.com",
        )
        trigger_req = adapter.build(alert, config)
        resolve_req = adapter.build_resolve(
            "cert-1", "expiry_warning", 7, config,
            hostname="web.example.com", subject="CN=web.example.com",
        )
        trigger_labels = json.loads(trigger_req.body)["alerts"][0]["labels"]
        resolve_labels = json.loads(resolve_req.body)["alerts"][0]["labels"]
        assert resolve_labels == trigger_labels

    def test_send_webhook_resolve_alertmanager(self):
        from cert_watch.alerts import send_webhook_resolve

        config = _config(kind="alertmanager")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook_resolve(
                "cert-1", "expiry_warning", 7, config,
                hostname="web.example.com", subject="CN=web.example.com",
            )
        assert ok is True
        body = json.loads(mock_urlopen.call_args[1]["data"])
        assert body["alerts"][0]["status"] == "resolved"
        assert body["alerts"][0]["labels"]["host"] == "web.example.com"

    def test_send_webhook_resolve_alertmanager_non_2xx_is_failure(self):
        from cert_watch.alerts import send_webhook_resolve

        config = _config(kind="alertmanager")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 500
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            ok = send_webhook_resolve("cert-1", "expired", None, config)
        assert ok is False

    def test_send_webhook_resolve_no_build_resolve_returns_false(self):
        from cert_watch.alerts import send_webhook_resolve

        config = _config(kind="discord")
        ok = send_webhook_resolve("cert-1", "expiry_warning", 7, config)
        assert ok is False

    def test_resolve_webhook_for_renewed_cert_alertmanager(self, tmp_path):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert
        from cert_watch.database import SqliteAlertRepository, init_schema

        db = tmp_path / "cw_resolve_am.sqlite3"
        init_schema(db)
        alert_repo = SqliteAlertRepository(db)
        alert_repo.create(Alert(
            cert_id="old-cert-1", alert_type="expiry_warning", status="pending",
            message="expiring", threshold_days=7,
        ))
        alert_repo.create(Alert(
            cert_id="old-cert-1", alert_type="expiry_warning", status="pending",
            message="expiring", threshold_days=3,
        ))
        config = _config(kind="alertmanager")
        with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp
            resolved = resolve_webhook_for_renewed_cert(db, "old-cert-1", config)
        assert resolved == 2

    def test_resolve_webhook_noops_for_unsupported_kind(self):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert

        config = _config(kind="discord")
        resolved = resolve_webhook_for_renewed_cert(None, "cert-1", config)
        assert resolved == 0

    def test_resolve_webhook_noops_for_none_config(self):
        from cert_watch.alerts import resolve_webhook_for_renewed_cert

        resolved = resolve_webhook_for_renewed_cert(None, "cert-1", None)
        assert resolved == 0
