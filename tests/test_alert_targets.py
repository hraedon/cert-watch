"""Real transport qualification for the routing matrix's local delivery oracles."""

from __future__ import annotations

import json

import pytest

from cert_watch.alerts import AlertConfig, WebhookConfig, process_pending, send_alert, send_webhook
from cert_watch.database import Alert, SqliteAlertRepository, init_schema
from cert_watch.database.delivery_evidence import list_attempts
from tests._integration_servers import allow_loopback_transport
from tests._mock_targets import capturing_http_target, smtp_target

pytestmark = pytest.mark.integration


def _alert() -> Alert:
    return Alert(
        cert_id="transport-cert", alert_type="expiry_warning", status="pending",
        threshold_days=7, hostname="service.invalid", subject="CN=service.invalid",
        message="Certificate service.invalid expires in seven days.",
        extra_recipients=["specific@example.invalid", "global@example.invalid"],
    )


def _config(target, **overrides) -> AlertConfig:
    fields = {
        "smtp_host": target.host,
        "smtp_port": target.port,
        "smtp_user": target.username,
        "smtp_password": target.password,
        "from_addr": "sender@example.invalid",
        "recipients": ["global@example.invalid"],
    }
    return AlertConfig(**(fields | overrides))


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_send_alert_reaches_authenticated_tls_receiver(tmp_path, monkeypatch, mode):
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch, mode=mode) as target,
    ):
        alert = _alert()
        assert send_alert(alert, _config(target)) is True
        assert target.connection_addresses == [("127.0.0.1", 465 if mode == "implicit" else 587)]
        assert target.listening_port not in {465, 587}
        assert len(target.messages) == 1
        receipt = target.messages[0]
        assert receipt.mail_from == "sender@example.invalid"
        assert receipt.recipients == ("global@example.invalid", "specific@example.invalid")
        assert receipt.tls and receipt.authenticated
        assert receipt.message["To"] == "global@example.invalid, specific@example.invalid"
        assert "expiry_warning" in receipt.message["Subject"]
        assert alert.message in receipt.message.get_content()
        assert len(target.auth_attempts) == 1
        assert target.auth_attempts[0].success and target.auth_attempts[0].tls


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_bad_smtp_credentials_cannot_deliver(tmp_path, monkeypatch, mode):
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch, mode=mode) as target,
    ):
        alert = _alert()
        assert send_alert(alert, _config(target, smtp_password="wrong-synthetic-password")) is False
        assert target.auth_attempts
        assert all(attempt.tls and not attempt.success for attempt in target.auth_attempts)
        assert target.messages == []
        assert "535" in alert.error_message
        assert "wrong-synthetic-password" not in alert.error_message


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
@pytest.mark.parametrize("refusal", ["untrusted-ca", "wrong-host"])
def test_invalid_smtp_certificate_refuses_before_auth(
    tmp_path, monkeypatch, mode, refusal,
):
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(
            tmp_path, monkeypatch, mode=mode,
            trusted=refusal != "untrusted-ca", valid_hostname=refusal != "wrong-host",
        ) as target,
    ):
        alert = _alert()
        assert send_alert(alert, _config(target)) is False
        assert "certificate verify failed" in alert.error_message.casefold()
        assert target.messages == []
        assert target.auth_attempts == []


def test_plaintext_smtp_refuses_credentials(tmp_path, monkeypatch):
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch, mode="plaintext") as target,
    ):
        alert = _alert()
        assert send_alert(alert, _config(target)) is False
        assert "STARTTLS not supported" in alert.error_message
        assert target.auth_attempts == []
        assert target.messages == []


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_smtp_receiver_requires_authentication(tmp_path, monkeypatch, mode):
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch, mode=mode) as target,
    ):
        alert = _alert()
        assert send_alert(alert, _config(target, smtp_user="", smtp_password="")) is False
        assert "530" in alert.error_message
        assert target.messages == []
        assert target.auth_attempts == []


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_smtp_target_does_not_bypass_loopback_policy(tmp_path, monkeypatch, mode):
    with smtp_target(tmp_path, monkeypatch, mode=mode) as target:
        alert = _alert()
        assert send_alert(alert, _config(target)) is False
        assert alert.error_message == "smtp host blocked by SSRF policy"
        assert target.connection_addresses == []
        assert target.auth_attempts == []
        assert target.messages == []


def test_http_receiver_records_exact_destination_and_negative_paths(monkeypatch):
    with (
        allow_loopback_transport(monkeypatch),
        capturing_http_target("/team-a", "/team-b", "/never") as target,
    ):
        for path in ("/team-a", "/team-b"):
            assert send_webhook(_alert(), WebhookConfig(
                url=target.url(path), headers={"X-Routing-Test": path}, allow_private=True,
            )) is True
        assert [request.path for request in target.requests] == ["/team-a", "/team-b"]
        for path in ("/team-a", "/team-b"):
            [request] = target.received(path)
            assert request.method == "POST"
            assert request.headers["X-Routing-Test"] == path
            assert json.loads(request.body)["cert_id"] == "transport-cert"
        assert target.received("/never") == []


def test_http_receiver_captures_rejected_delivery(monkeypatch):
    with (
        allow_loopback_transport(monkeypatch),
        capturing_http_target("/reject", "/never", statuses={"/reject": 503}) as target,
    ):
        assert send_webhook(_alert(), WebhookConfig(
            url=target.url("/reject"), allow_private=True,
        )) is False
        assert len(target.received("/reject")) == 1
        assert target.received("/never") == []


@pytest.mark.parametrize("mode", ["starttls", "implicit"])
def test_recorded_smtp_acceptance_matches_real_receiver(tmp_path, monkeypatch, mode):
    db = tmp_path / "evidence.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    alert = _alert()
    alert.id = repo.create(alert)
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch, mode=mode) as target,
    ):
        assert process_pending(repo, _config(target)) == {"sent": 1, "failed": 0}
        [receipt] = target.messages
        [attempt] = list_attempts(db, [alert.id])[alert.id]
        assert attempt["routing"]["recipients"] == list(receipt.recipients)
        assert attempt["result"]["accepted"] == list(receipt.recipients)
        assert attempt["result"]["outcome"] == "accepted"
        assert receipt.tls and receipt.authenticated


def test_recorded_smtp_failure_and_webhook_success_match_receivers(tmp_path, monkeypatch):
    db = tmp_path / "evidence.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    alert = _alert()
    alert.id = repo.create(alert)
    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch) as smtp,
        capturing_http_target("/fallback") as http,
    ):
        assert process_pending(
            repo, _config(smtp, smtp_password="wrong-test-password"),
            WebhookConfig(url=http.url("/fallback"), allow_private=True),
        ) == {"sent": 1, "failed": 0}
        assert smtp.messages == []
        assert smtp.auth_attempts and not smtp.auth_attempts[0].success
        assert len(http.received("/fallback")) == 1
        attempts = list_attempts(db, [alert.id])[alert.id]
        assert [item["channel"] for item in attempts] == ["generic", "smtp"]
        assert attempts[0]["result"]["outcome"] == "accepted"
        assert attempts[0]["result"]["http_status"] == 200
        assert attempts[1]["result"]["reason"] == "authentication"
