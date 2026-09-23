"""Characterize delivery observables before plan 058 replaces side channels.

These assertions intentionally cover the database row and immutable evidence
ledger together.  Transport internals may change, but operators must see the
same terminal state and the ledger must retain the same sanitized facts.
"""

from __future__ import annotations

import smtplib
import socket
from dataclasses import dataclass
from typing import Any
from unittest.mock import Mock
from urllib.error import HTTPError, URLError

import pytest

from cert_watch.alerting.dispatch import process_pending
from cert_watch.alerting.model import ALERT_MAX_RETRIES, AlertConfig, WebhookConfig
from cert_watch.database import Alert, SqliteAlertRepository, init_schema
from cert_watch.database.delivery_evidence import list_attempts
from cert_watch.http_client import SSRFBlockedError


@dataclass(frozen=True)
class _Expected:
    channel: str
    outcome: str
    reason: str
    error_contains: str
    http_status: int | None = None
    accepted: tuple[str, ...] = ()
    refused: tuple[str, ...] = ()
    sent: bool = False


_CASES = {
    "smtp_ssrf_block": _Expected(
        "smtp", "failed", "blocked", "smtp host blocked by SSRF policy"
    ),
    "smtp_dns_failure": _Expected(
        "smtp", "failed", "dns", "SMTP host could not be resolved"
    ),
    "smtp_starttls_failure": _Expected(
        "smtp", "failed", "tls", "STARTTLS not supported by SMTP server"
    ),
    "smtp_auth_failure": _Expected(
        "smtp", "failed", "authentication", "authentication rejected"
    ),
    "smtp_all_recipients_refused": _Expected(
        "smtp",
        "failed",
        "recipients_refused",
        "global@example.invalid",
        refused=("global@example.invalid", "queued@example.invalid"),
    ),
    "smtp_partial_refusal": _Expected(
        "smtp",
        "partial",
        "recipients_refused",
        "",
        accepted=("global@example.invalid",),
        refused=("queued@example.invalid",),
        sent=True,
    ),
    "smtp_timeout": _Expected("smtp", "failed", "timeout", "transport timed out"),
    "smtp_connection_refused": _Expected(
        "smtp", "failed", "transport", "connection refused"
    ),
    "webhook_ssrf_block": _Expected(
        "webhook:generic", "failed", "blocked", "webhook URL blocked by SSRF policy"
    ),
    "webhook_dns_failure": _Expected(
        "webhook:generic", "failed", "transport", "name resolution failed"
    ),
    "webhook_http_4xx": _Expected(
        "webhook:generic", "failed", "http_rejected", "HTTP Error 400", http_status=400
    ),
    "webhook_http_5xx": _Expected(
        "webhook:generic", "failed", "http_rejected", "HTTP Error 503", http_status=503
    ),
    "webhook_timeout": _Expected(
        "webhook:generic", "failed", "timeout", "webhook timed out"
    ),
    "webhook_connection_refused": _Expected(
        "webhook:generic", "failed", "transport", "connection refused"
    ),
}


def _pending(tmp_path) -> tuple[SqliteAlertRepository, Alert]:
    db = tmp_path / "characterization.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    alert = Alert(
        cert_id="characterization-cert",
        alert_type="expiry_warning",
        status="pending",
        message="Certificate expires within seven days",
        threshold_days=7,
        extra_recipients=["queued@example.invalid"],
    )
    alert.id = repo.create(alert)
    return repo, alert


def _smtp_config() -> AlertConfig:
    return AlertConfig(
        smtp_host="smtp.example",
        smtp_user="synthetic-user",
        smtp_password="synthetic-password",
        from_addr="watch@example.invalid",
        recipients=["global@example.invalid"],
    )


def _webhook_config() -> WebhookConfig:
    return WebhookConfig(url="https://hooks.example.invalid/alert", kind="generic")


def _response(status: int) -> Mock:
    response = Mock(status=status)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    return response


def _smtp_connection(monkeypatch, *, refused: dict[str, Any] | None = None) -> Mock:
    connection = Mock()
    connection.send_message.return_value = refused or {}
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection",
        Mock(return_value=connection),
    )
    return connection


def _arrange(monkeypatch, case: str) -> tuple[AlertConfig | None, WebhookConfig | None]:
    if case == "smtp_ssrf_block":
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.resolve_smtp_host",
            Mock(return_value=("blocked by policy", None)),
        )
    elif case == "smtp_dns_failure":
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.resolve_smtp_host",
            Mock(return_value=(None, None)),
        )
    elif case == "smtp_starttls_failure":
        connection = Mock()
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.resolve_smtp_host",
            Mock(return_value=(None, "203.0.113.10")),
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.connect_smtp_transport",
            Mock(return_value=connection),
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.negotiate_starttls", Mock(return_value=False)
        )
    elif case == "smtp_auth_failure":
        connection = Mock()
        connection.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"authentication rejected"
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.resolve_smtp_host",
            Mock(return_value=(None, "203.0.113.10")),
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.connect_smtp_transport",
            Mock(return_value=connection),
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.negotiate_starttls", Mock(return_value=True)
        )
    elif case == "smtp_all_recipients_refused":
        connection = _smtp_connection(monkeypatch)
        connection.send_message.side_effect = smtplib.SMTPRecipientsRefused(
            {
                "global@example.invalid": (550, b"recipient rejected"),
                "queued@example.invalid": (550, b"recipient rejected"),
            }
        )
    elif case == "smtp_partial_refusal":
        _smtp_connection(
            monkeypatch,
            refused={"queued@example.invalid": (550, b"recipient rejected")},
        )
    elif case == "smtp_timeout":
        connection = _smtp_connection(monkeypatch)
        connection.send_message.side_effect = TimeoutError("transport timed out")
    elif case == "smtp_connection_refused":
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.resolve_smtp_host",
            Mock(return_value=(None, "203.0.113.10")),
        )
        monkeypatch.setattr(
            "cert_watch.alerting.transports.smtp.connect_smtp_transport",
            Mock(side_effect=ConnectionRefusedError(111, "connection refused")),
        )
    else:
        if case == "webhook_ssrf_block":
            failure: Exception = SSRFBlockedError("blocked 127.0.0.1")
        elif case == "webhook_dns_failure":
            failure = URLError(socket.gaierror(-2, "name resolution failed"))
        elif case == "webhook_http_4xx":
            failure = HTTPError(
                "https://hooks.example.invalid/alert", 400, "rejected", {}, None
            )
        elif case == "webhook_http_5xx":
            failure = HTTPError(
                "https://hooks.example.invalid/alert", 503, "unavailable", {}, None
            )
        elif case == "webhook_timeout":
            failure = TimeoutError("webhook timed out")
        elif case == "webhook_connection_refused":
            failure = URLError(ConnectionRefusedError(111, "connection refused"))
        else:  # pragma: no cover - guarded by the parametrization
            raise AssertionError(case)
        monkeypatch.setattr(
            "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen",
            Mock(side_effect=failure),
        )
        return None, _webhook_config()
    return _smtp_config(), None


@pytest.mark.parametrize("case", _CASES)
def test_delivery_failure_observables_are_characterized(monkeypatch, tmp_path, case):
    expected = _CASES[case]
    repo, alert = _pending(tmp_path)
    smtp_config, webhook_config = _arrange(monkeypatch, case)

    summary = process_pending(repo, smtp_config, webhook_config)

    stored = repo.list_for_cert(alert.cert_id)[0]
    attempts = list_attempts(repo.db_path, [alert.id])[alert.id]
    expected_attempts = 1 if expected.sent else ALERT_MAX_RETRIES
    assert summary == (
        {"sent": 1, "failed": 0, "deferred": 0}
        if expected.sent
        else {"sent": 0, "failed": 1, "deferred": 0}
    )
    assert stored.status == ("sent" if expected.sent else "failed")
    if expected.sent:
        assert stored.error_message is None
    else:
        assert expected.error_contains in (stored.error_message or "")
        assert stored.error_message.endswith(f"(after {ALERT_MAX_RETRIES} attempts)")
    assert len(attempts) == expected_attempts
    for attempt in attempts:
        assert attempt["channel"] == expected.channel
        assert attempt["routing"] == {
            "recipients": (
                ["global@example.invalid", "queued@example.invalid"]
                if expected.channel == "smtp"
                else []
            ),
            "global_recipients": (
                ["global@example.invalid"] if expected.channel == "smtp" else []
            ),
            "queued_recipients": (
                ["queued@example.invalid"] if expected.channel == "smtp" else []
            ),
            "groups": [],
            "groups_available": True,
        }
        assert attempt["result"] == {
            "outcome": expected.outcome,
            "reason": expected.reason,
            "accepted": list(expected.accepted),
            "refused": list(expected.refused),
            "http_status": expected.http_status,
        }
