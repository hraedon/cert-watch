"""Plan 058 transport/result contracts independent of delivery dispatch."""

from __future__ import annotations

import smtplib
import socket
from dataclasses import FrozenInstanceError, dataclass
from unittest.mock import Mock
from urllib.error import URLError

import pytest

from cert_watch.alerting.evidence import attempt_delivery
from cert_watch.alerting.model import (
    AlertConfig,
    OutboundMessage,
    SendResult,
    WebhookConfig,
    normalize_channel,
)
from cert_watch.alerting.transports.smtp import SmtpTransport
from cert_watch.alerting.transports.webhook import WebhookTransport
from cert_watch.database import Alert, SqliteAlertRepository, init_schema
from cert_watch.database.delivery_evidence import list_attempts
from cert_watch.http_client import SSRFBlockedError


@dataclass(frozen=True)
class _Contract:
    outcome: str
    reason: str
    reached_transport: bool
    http_status: int | None = None
    accepted: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()


_CONTRACTS = {
    "smtp_ssrf_block": _Contract("blocked", "blocked", False),
    "smtp_dns_failure": _Contract("failed", "dns", False),
    "smtp_starttls_failure": _Contract("failed", "tls", True),
    "smtp_auth_failure": _Contract("failed", "authentication", True),
    "smtp_all_recipients_refused": _Contract(
        "failed",
        "recipients_refused",
        True,
        refused=("global@example.invalid", "queued@example.invalid"),
    ),
    "smtp_partial_refusal": _Contract(
        "partial",
        "recipients_refused",
        True,
        accepted=("global@example.invalid",),
        refused=("queued@example.invalid",),
    ),
    "smtp_timeout": _Contract("failed", "timeout", True),
    "smtp_connection_refused": _Contract("failed", "transport", True),
    "webhook_ssrf_block": _Contract("blocked", "blocked", False),
    "webhook_dns_failure": _Contract("failed", "transport", False),
    "webhook_http_4xx": _Contract("failed", "http_rejected", True, http_status=400),
    "webhook_http_5xx": _Contract("failed", "http_rejected", True, http_status=503),
    "webhook_timeout": _Contract("failed", "timeout", True),
    "webhook_connection_refused": _Contract("failed", "transport", True),
}


def _message() -> OutboundMessage:
    return OutboundMessage(
        subject="[cert-watch] expiry warning",
        body="Certificate expires within seven days",
        severity="expiry_warning",
        cert_id="contract-cert",
        threshold_days=7,
        recipients=("global@example.invalid", "queued@example.invalid"),
        global_recipients=("global@example.invalid",),
        queued_recipients=("queued@example.invalid",),
    )


def _smtp_config() -> AlertConfig:
    return AlertConfig(
        smtp_host="smtp.example",
        smtp_user="synthetic-user",
        smtp_password="synthetic-password",
        from_addr="watch@example.invalid",
        recipients=["global@example.invalid"],
    )


def _smtp_connection(monkeypatch) -> Mock:
    connection = Mock()
    connection.send_message.return_value = {}
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection",
        Mock(return_value=connection),
    )
    return connection


def _response(status: int) -> Mock:
    response = Mock(status=status)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    return response


def _arrange(monkeypatch, case: str):
    if case.startswith("smtp_"):
        config = _smtp_config()
        if case == "smtp_ssrf_block":
            monkeypatch.setattr(
                "cert_watch.alerting.transports.smtp.resolve_smtp_host",
                Mock(return_value=("blocked", None)),
            )
        elif case == "smtp_dns_failure":
            monkeypatch.setattr(
                "cert_watch.alerting.transports.smtp.resolve_smtp_host",
                Mock(return_value=(None, None)),
            )
        elif case in {"smtp_starttls_failure", "smtp_auth_failure", "smtp_connection_refused"}:
            connection = Mock()
            monkeypatch.setattr(
                "cert_watch.alerting.transports.smtp.resolve_smtp_host",
                Mock(return_value=(None, "203.0.113.10")),
            )
            if case == "smtp_connection_refused":
                monkeypatch.setattr(
                    "cert_watch.alerting.transports.smtp.connect_smtp_transport",
                    Mock(side_effect=ConnectionRefusedError(111, "connection refused")),
                )
            else:
                monkeypatch.setattr(
                    "cert_watch.alerting.transports.smtp.connect_smtp_transport",
                    Mock(return_value=connection),
                )
                monkeypatch.setattr(
                    "cert_watch.alerting.transports.smtp.negotiate_starttls",
                    Mock(return_value=case != "smtp_starttls_failure"),
                )
                if case == "smtp_auth_failure":
                    connection.login.side_effect = smtplib.SMTPAuthenticationError(
                        535, b"synthetic-password rejected"
                    )
        else:
            connection = _smtp_connection(monkeypatch)
            if case == "smtp_all_recipients_refused":
                connection.send_message.side_effect = smtplib.SMTPRecipientsRefused(
                    {
                        "global@example.invalid": (550, b"rejected"),
                        "queued@example.invalid": (550, b"rejected"),
                    }
                )
            elif case == "smtp_partial_refusal":
                connection.send_message.return_value = {
                    "queued@example.invalid": (550, b"rejected")
                }
            elif case == "smtp_timeout":
                connection.send_message.side_effect = TimeoutError("timed out")
        return SmtpTransport(config)

    config = WebhookConfig(url="https://hooks.example.invalid/alert")
    if case == "webhook_ssrf_block":
        effect: Exception | None = SSRFBlockedError("blocked 127.0.0.1")
        response = None
    elif case == "webhook_dns_failure":
        effect = URLError(socket.gaierror(-2, "name resolution failed"))
        response = None
    elif case == "webhook_http_4xx":
        effect = None
        response = _response(400)
    elif case == "webhook_http_5xx":
        effect = None
        response = _response(503)
    elif case == "webhook_timeout":
        effect = TimeoutError("timed out")
        response = None
    else:
        effect = URLError(ConnectionRefusedError(111, "connection refused"))
        response = None
    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen",
        Mock(side_effect=effect, return_value=response),
    )
    return WebhookTransport(config)


@pytest.mark.parametrize("case", _CONTRACTS)
def test_transport_failure_mode_contract(monkeypatch, case):
    expected = _CONTRACTS[case]
    result = _arrange(monkeypatch, case).send(_message())

    assert result.outcome == expected.outcome
    assert result.reason == expected.reason
    assert result.reached_transport is expected.reached_transport
    assert result.http_status == expected.http_status
    assert result.accepted == expected.accepted
    assert result.refused == expected.refused
    assert "synthetic-password" not in result.operator_message


@pytest.mark.parametrize(
    ("legacy", "normalized"),
    [
        ("smtp", "smtp"),
        ("generic", "webhook:generic"),
        ("slack", "webhook:slack"),
        ("discord", "webhook:discord"),
        ("teams", "webhook:teams"),
        ("pagerduty", "webhook:pagerduty"),
        ("alertmanager", "webhook:alertmanager"),
        ("webhook", "webhook:unspecified"),
        ("webhook:teams", "webhook:teams"),
    ],
)
def test_normalize_channel_maps_legacy_ledger_names(legacy, normalized):
    assert normalize_channel(legacy) == normalized


def test_alertmanager_transport_uses_unified_channel_name():
    url = "https://alertmanager.example.invalid/secret-hook"
    transport = WebhookTransport(
        WebhookConfig(url=url, kind="alertmanager")
    )
    assert transport.channel == "webhook:alertmanager"
    assert len(transport.destination_id) == 16
    assert transport.destination_id not in url


def test_unknown_webhook_kind_has_distinct_ledger_channel():
    transport = WebhookTransport(
        WebhookConfig(url="https://hooks.example.invalid/path", kind="typo")
    )

    assert transport.channel == "webhook:unknown"


@pytest.mark.parametrize(
    "message",
    [
        "Invalid header value b'bad\\r\\nvalue'",
        "'latin-1' codec can't encode character '\u2603'",
        "unknown url type: 'not-a-url'",
    ],
)
def test_webhook_value_errors_after_adapter_selection_are_transport_failures(
    monkeypatch, message,
):
    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen",
        Mock(side_effect=ValueError(message)),
    )

    result = WebhookTransport(
        WebhookConfig(url="https://hooks.example.invalid/path", kind="generic")
    ).send(_message())

    assert result.reason == "transport"
    assert result.operator_message == message


def test_unknown_webhook_kind_is_the_only_invalid_channel_failure():
    result = WebhookTransport(
        WebhookConfig(url="https://hooks.example.invalid/path", kind="typo")
    ).send(_message())

    assert result.reason == "invalid_channel"
    assert result.reached_transport is False


def test_deprecated_observation_names_are_not_silently_exported():
    import cert_watch.alert_delivery as shim

    for name in (
        "_Observation",
        "_active",
        "observe_exception",
        "observe_failure",
        "observe_http",
        "observe_smtp",
    ):
        assert not hasattr(shim, name)


def test_send_result_is_frozen_and_rejects_unknown_labels():
    result = SendResult("accepted")
    with pytest.raises(FrozenInstanceError):
        result.outcome = "failed"
    with pytest.raises(ValueError, match="unknown delivery failure reason"):
        SendResult("failed", "raw exception text")


def test_attempt_delivery_ledger_details_match_pre_refactor_golden(
    tmp_path, fake_transport
):
    db = tmp_path / "golden.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    alert = Alert(
        cert_id="golden-cert",
        alert_type="expiry_warning",
        status="pending",
        message="expiring",
        extra_recipients=["queued@example.invalid"],
    )
    alert.id = repo.create(alert)
    msg = OutboundMessage.from_alert(
        alert,
        recipients=("global@example.invalid", "queued@example.invalid"),
        global_recipients=("global@example.invalid",),
    )
    transport = fake_transport(
        SendResult(
            "partial",
            "recipients_refused",
            accepted=("global@example.invalid",),
            refused=("queued@example.invalid",),
            operator_message="must not enter the ledger",
        ),
        channel="webhook:slack",
    )

    result = attempt_delivery(db, alert.id, transport, msg)

    assert result.outcome == "partial"
    [attempt] = list_attempts(db, [alert.id])[alert.id]
    assert attempt["channel"] == "webhook:slack"
    assert attempt["routing"] == {
        "recipients": ["global@example.invalid", "queued@example.invalid"],
        "global_recipients": ["global@example.invalid"],
        "queued_recipients": ["queued@example.invalid"],
        "groups": [],
        "groups_available": True,
    }
    assert attempt["result"] == {
        "outcome": "partial",
        "reason": "recipients_refused",
        "accepted": ["global@example.invalid"],
        "refused": ["queued@example.invalid"],
        "http_status": None,
    }


def test_sanitizer_redacts_escaped_header_values() -> None:
    """urllib reports an invalid header value in repr-escaped form; the secret
    must be redacted in that form too, not only verbatim."""
    from cert_watch.alerting.model import WebhookConfig
    from cert_watch.alerting.transports.webhook import _sanitize_webhook_error

    secret = "secret-token\r\nX-Injected: 1"
    config = WebhookConfig(url="https://hooks.example.test/x", headers={"Authorization": secret})
    message = f"Invalid header value {secret.encode()!r}"

    sanitized = _sanitize_webhook_error(message, config)

    assert "secret-token" not in sanitized
