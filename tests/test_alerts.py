from unittest.mock import MagicMock, patch

import pytest

from cert_watch.alerts import (
    AlertConfig,
    WebhookConfig,
    evaluate_thresholds,
    process_pending,
    send_alert,
    send_webhook,
)
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import Alert, SqliteAlertRepository


@pytest.fixture
def alert_repo(tmp_path):
    from cert_watch.database.schema import init_schema
    init_schema(tmp_path / "cw.sqlite3")
    return SqliteAlertRepository(tmp_path / "cw.sqlite3")


@pytest.fixture
def expiring_cert(expiring_soon_leaf) -> Certificate:
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    return cert


def test_evaluate_thresholds_creates_alerts(alert_repo, expiring_cert):
    # Cert expires in ~5 days; should create alerts for 14 and 7 (leaf thresholds).
    alerts = evaluate_thresholds(expiring_cert, alert_repo)
    days = expiring_cert.days_until_expiry()
    expected_count = sum(1 for t in (14, 7, 3, 1) if days <= t)
    assert len(alerts) == expected_count


def test_evaluate_thresholds_no_duplicates(alert_repo, expiring_cert):
    evaluate_thresholds(expiring_cert, alert_repo)
    second = evaluate_thresholds(expiring_cert, alert_repo)
    assert second == []


def test_evaluate_thresholds_uses_days_until_expiry(alert_repo, expiring_soon_leaf):
    """AC-02: must call days_until_expiry on a real parsed Certificate."""
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    # Verify days_until_expiry is non-zero and used.
    days = cert.days_until_expiry()
    assert days >= 0
    alerts = evaluate_thresholds(cert, alert_repo)
    # Threshold count for ~5 days should be > 0.
    assert len(alerts) > 0


def test_evaluate_thresholds_chain_cert(alert_repo, chain_triplet):
    inter = parse_certificate(chain_triplet["intermediate"].der)
    assert isinstance(inter, Certificate)
    inter.is_leaf = False
    # Intermediate has 1825 days; no chain thresholds should fire.
    alerts = evaluate_thresholds(inter, alert_repo)
    assert alerts == []


def test_send_alert_smtp_success(monkeypatch):
    config = AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="a@b",
        recipients=["c@d"],
    )
    alert = Alert(
        cert_id="c", alert_type="expiry_warning", status="pending", message="msg"
    )
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
        ok = send_alert(alert, config)
    assert ok is True
    smtp_mock.send_message.assert_called_once()


def test_send_alert_smtp_failure_returns_false():
    config = AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="a@b",
        recipients=["c@d"],
    )
    alert = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    with patch(
        "cert_watch.alerts.smtplib.SMTP", side_effect=ConnectionRefusedError("nope")
    ):
        ok = send_alert(alert, config)
    assert ok is False
    assert alert.error_message and "nope" in alert.error_message


def test_send_alert_none_config_returns_false():
    alert = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    assert send_alert(alert, None) is False


def test_process_pending_no_config(alert_repo):
    counts = process_pending(alert_repo, None)
    assert counts == {"sent": 0, "failed": 0}


def test_process_pending_sends_and_marks(alert_repo, expiring_cert):
    evaluate_thresholds(expiring_cert, alert_repo)
    config = AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="a@b",
        recipients=["c@d"],
    )
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
        counts = process_pending(alert_repo, config)
    assert counts["sent"] > 0
    assert counts["failed"] == 0
    assert alert_repo.list_pending() == []


def test_alert_formatting_includes_required_fields(alert_repo, expiring_cert):
    alerts = evaluate_thresholds(expiring_cert, alert_repo)
    assert alerts
    msg = alerts[0].message
    assert expiring_cert.display_name in msg or expiring_cert.subject in msg
    assert "days remaining" in msg
    assert "Recommended action" in msg


def test_send_webhook_success():
    config = WebhookConfig(url="https://hooks.example.com/alert")
    alert = Alert(cert_id="c", alert_type="expiry_warning", status="pending", message="msg")
    with patch("cert_watch.alerts.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ok = send_webhook(alert, config)
    assert ok is True
    mock_urlopen.assert_called_once()


def test_send_webhook_failure():
    config = WebhookConfig(url="https://hooks.example.com/alert")
    alert = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    with patch(
        "cert_watch.alerts.urllib.request.urlopen",
        side_effect=Exception("connection refused"),
    ):
        ok = send_webhook(alert, config)
    assert ok is False
    assert "connection refused" in (alert.error_message or "")


def test_send_webhook_none_config():
    alert = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    assert send_webhook(alert, None) is False


def test_send_webhook_template():
    """FEAT-005: custom template should substitute {{variables}}."""
    config = WebhookConfig(
        url="https://hooks.example.com/alert",
        template='{"text":"[{{alert_type}}] {{message}} (cert: {{cert_id}})"}',
    )
    alert = Alert(
        cert_id="abc123",
        alert_type="expiry_warning",
        status="pending",
        message="Cert expiring soon",
    )
    with patch("cert_watch.alerts.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ok = send_webhook(alert, config)
    assert ok is True
    req = mock_urlopen.call_args[0][0]
    body = req.data.decode("utf-8")
    assert "expiry_warning" in body
    assert "Cert expiring soon" in body
    assert "abc123" in body


def test_send_webhook_template_non_json():
    """FEAT-005: non-JSON template should use text/plain content type."""
    config = WebhookConfig(
        url="https://hooks.example.com/alert",
        template="Alert: {{alert_type}} - {{message}}",
    )
    alert = Alert(
        cert_id="c",
        alert_type="expired",
        status="pending",
        message="Cert has expired",
    )
    with patch("cert_watch.alerts.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ok = send_webhook(alert, config)
    assert ok is True
    req = mock_urlopen.call_args[0][0]
    assert req.headers.get("Content-type") == "text/plain"


def test_process_pending_webhook_fallback(alert_repo, expiring_cert):
    evaluate_thresholds(expiring_cert, alert_repo)
    smtp_config = AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="a@b",
        recipients=["c@d"],
    )
    webhook_config = WebhookConfig(url="https://hooks.example.com/alert")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    smtp_mock.send_message.side_effect = Exception("smtp down")
    with (
        patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock),
        patch("cert_watch.alerts.urllib.request.urlopen") as mock_urlopen,
    ):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        counts = process_pending(alert_repo, smtp_config, webhook_config=webhook_config)
    assert counts["sent"] > 0
    assert counts["failed"] == 0


def test_process_pending_webhook_only(alert_repo, expiring_cert):
    evaluate_thresholds(expiring_cert, alert_repo)
    webhook_config = WebhookConfig(url="https://hooks.example.com/alert")
    with patch("cert_watch.alerts.urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        counts = process_pending(alert_repo, None, webhook_config=webhook_config)
    assert counts["sent"] > 0
    assert counts["failed"] == 0


def test_delete_certificate_cascades_alerts(tmp_path, expiring_soon_leaf):
    """Deleting a cert must also delete its alerts."""
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import (
        SqliteCertificateRepository,
        delete_certificate_cascade,
        init_schema,
    )

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    repo = SqliteCertificateRepository(db, source="scanned", hostname="h.example.com", port=443)
    cert_id = repo.add(cert)

    alert_repo = SqliteAlertRepository(db)
    evaluate_thresholds(cert, alert_repo, cert_id=cert_id)
    assert len(alert_repo.list_for_cert(cert_id)) > 0

    delete_certificate_cascade(db, cert_id)
    assert alert_repo.list_for_cert(cert_id) == []


def test_delete_host_cascades_alerts(tmp_path, expiring_soon_leaf):
    """Deleting a host must also delete alerts for its scanned certs."""
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import (
        SqliteCertificateRepository,
        SqliteHostRepository,
        init_schema,
    )

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    cert_repo = SqliteCertificateRepository(
        db, source="scanned", hostname="hostdel.example.com", port=443
    )
    cert_id = cert_repo.add(cert)

    host_repo = SqliteHostRepository(db)
    host_id = host_repo.add("hostdel.example.com", 443)

    alert_repo = SqliteAlertRepository(db)
    evaluate_thresholds(cert, alert_repo, cert_id=cert_id)
    assert len(alert_repo.list_for_cert(cert_id)) > 0

    host_repo.delete(host_id)
    assert alert_repo.list_for_cert(cert_id) == []


def test_evaluate_thresholds_escalation_after_cooldown(alert_repo, expiring_cert):
    """FEAT-004: alerts should re-fire after cooldown period expires."""
    # First call — creates alerts
    first = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert len(first) > 0
    first_ids = {a.id for a in first}

    # Second call immediately — no new alerts (within cooldown)
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert second == []

    # Third call with cooldown=0 — should create escalation alerts
    third = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    assert len(third) > 0
    # New alerts should have different IDs
    third_ids = {a.id for a in third}
    assert third_ids.isdisjoint(first_ids)


def test_evaluate_thresholds_no_escalation_within_cooldown(alert_repo, expiring_cert):
    """FEAT-004: alerts should NOT re-fire within cooldown window."""
    evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    # Immediate re-evaluation should produce no new alerts
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert second == []


def test_evaluate_thresholds_custom_cooldown(alert_repo, expiring_cert):
    """FEAT-004: cooldown_hours parameter should be respected."""
    # With very short cooldown, re-evaluation can produce new alerts
    evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    # All thresholds already have alerts, but cooldown=0 means they're eligible
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    assert len(second) > 0
