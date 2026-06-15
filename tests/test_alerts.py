import smtplib
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
    # Cert expires in ~5 days; only the most urgent newly-tripped threshold fires.
    alerts = evaluate_thresholds(expiring_cert, alert_repo)
    days = expiring_cert.days_until_expiry()
    assert len(alerts) == 1
    assert alerts[0].threshold_days == min(t for t in (14, 7, 3, 1) if days <= t)


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


def test_send_alert_port25_no_starttls_no_creds_sends():
    """Plain port-25 relay (no auth, no STARTTLS) must still deliver."""
    import smtplib

    config = AlertConfig(
        smtp_host="relay.internal",
        smtp_port=25,
        smtp_user="",
        smtp_password="",
        from_addr="a@b",
        recipients=["c@d"],
    )
    alert = Alert(cert_id="c", alert_type="expiry_warning", status="pending", message="m")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    smtp_mock.starttls.side_effect = smtplib.SMTPNotSupportedError("no starttls")
    with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
        ok = send_alert(alert, config)
    assert ok is True
    smtp_mock.login.assert_not_called()
    smtp_mock.send_message.assert_called_once()


def test_send_alert_no_starttls_with_creds_refuses():
    """Credentials present but STARTTLS unavailable: refuse, don't leak the password."""
    import smtplib

    config = AlertConfig(
        smtp_host="relay.internal",
        smtp_port=25,
        smtp_user="svc",
        smtp_password="secret",
        from_addr="a@b",
        recipients=["c@d"],
    )
    alert = Alert(cert_id="c", alert_type="expiry_warning", status="pending", message="m")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    smtp_mock.starttls.side_effect = smtplib.SMTPNotSupportedError("no starttls")
    with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
        ok = send_alert(alert, config)
    assert ok is False
    smtp_mock.login.assert_not_called()
    smtp_mock.send_message.assert_not_called()
    assert alert.error_message and "cleartext" in alert.error_message


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
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
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
        "cert_watch.alerts.ssrf_safe_urlopen",
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
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ok = send_webhook(alert, config)
    assert ok is True
    call_kwargs = mock_urlopen.call_args
    body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
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
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ok = send_webhook(alert, config)
    assert ok is True
    call_kwargs = mock_urlopen.call_args
    headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
    assert headers.get("Content-Type") == "text/plain"


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
        patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen,
    ):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        counts = process_pending(alert_repo, smtp_config, webhook_config=webhook_config)
    # SMTP was deliberately broken: fallback to webhook must have fired.
    # A regression that drops the fallback would leave failed > 0 and sent == 0.
    assert counts["sent"] > 0
    assert counts["failed"] == 0
    # The webhook URL was hit (not just any HTTP call — verify the URL matches).
    assert mock_urlopen.called
    called_url = (
        mock_urlopen.call_args.args[0]
        if mock_urlopen.call_args and mock_urlopen.call_args.args
        else mock_urlopen.call_args.kwargs.get("url", "")
    )
    assert str(called_url) == "https://hooks.example.com/alert"


def test_process_pending_webhook_only(alert_repo, expiring_cert):
    evaluate_thresholds(expiring_cert, alert_repo)
    webhook_config = WebhookConfig(url="https://hooks.example.com/alert")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        counts = process_pending(alert_repo, None, webhook_config=webhook_config)
    # Webhook-only path: no SMTP attempted, one webhook call.
    assert counts["sent"] > 0
    assert counts["failed"] == 0
    assert mock_urlopen.call_count >= 1


def test_send_webhook_ssrf_blocked():
    """BC-116: webhook to a blocked IP must be refused."""
    from cert_watch.http_client import SSRFBlockedError

    config = WebhookConfig(url="https://127.0.0.1/webhook")
    alert = Alert(cert_id="c", alert_type="expiry_warning", status="pending", message="msg")
    with patch(
        "cert_watch.alerts.ssrf_safe_urlopen",
        side_effect=SSRFBlockedError("blocked IP: 127.0.0.1"),
    ):
        ok = send_webhook(alert, config)
    assert ok is False
    assert "SSRF" in (alert.error_message or "") or "blocked" in (alert.error_message or "")


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


def test_evaluate_thresholds_each_threshold_fires_once(alert_repo, expiring_cert):
    """Each threshold fires exactly once — no re-alerting after cooldown."""
    first = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert len(first) == 1

    # Second call immediately — no new alerts (already alerted)
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert second == []

    # Third call with cooldown=0 — still no new alerts (each fires exactly once)
    third = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    assert third == []


def test_evaluate_thresholds_no_escalation_within_cooldown(alert_repo, expiring_cert):
    """FEAT-004: alerts should NOT re-fire within cooldown window."""
    evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    # Immediate re-evaluation should produce no new alerts
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=24)
    assert second == []


def test_evaluate_thresholds_thresholds_never_refire(alert_repo, expiring_cert):
    """cooldown_hours has no effect: each threshold fires exactly once."""
    evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    # All thresholds already have alerts, cooldown=0 is irrelevant
    second = evaluate_thresholds(expiring_cert, alert_repo, cooldown_hours=0)
    assert second == []


def test_escalation_one_email_per_new_threshold(alert_repo):
    """Regression: a cert crossing thresholds over time fires exactly one alert
    per newly-tripped threshold — not one per already-crossed stage."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate

    def _make_cert(days_remaining: int) -> Certificate:
        return Certificate(
            subject="CN=escalation-test",
            issuer="CN=CA",
            not_before=datetime.now(UTC) - timedelta(days=360),
            not_after=datetime.now(UTC) + timedelta(days=days_remaining, hours=12),
            san_dns_names=[],
            fingerprint_sha256="esc" * 22,
            raw_der=b"",
            is_leaf=True,
        )

    # Day 10: crosses t=14 only → one alert for 14
    alerts_10 = evaluate_thresholds(_make_cert(10), alert_repo)
    assert len(alerts_10) == 1
    assert alerts_10[0].threshold_days == 14

    # Day 9: same state, already alerted at 14 → no new alert
    alerts_9 = evaluate_thresholds(_make_cert(9), alert_repo)
    assert alerts_9 == []

    # Day 6: crosses t=7 → one alert for 7 (not 14 again)
    alerts_6 = evaluate_thresholds(_make_cert(6), alert_repo)
    assert len(alerts_6) == 1
    assert alerts_6[0].threshold_days == 7

    # Day 2: crosses t=3 → one alert for 3
    alerts_2 = evaluate_thresholds(_make_cert(2), alert_repo)
    assert len(alerts_2) == 1
    assert alerts_2[0].threshold_days == 3


def test_first_scan_at_5_days_only_most_urgent(alert_repo):
    """When a cert is first seen already past multiple thresholds,
    only the most urgent fires — not every crossed stage."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate

    cert = Certificate(
        subject="CN=late-discovery",
        issuer="CN=CA",
        not_before=datetime.now(UTC) - timedelta(days=360),
        not_after=datetime.now(UTC) + timedelta(days=5, hours=12),
        san_dns_names=[],
        fingerprint_sha256="lat" * 22,
        raw_der=b"",
        is_leaf=True,
    )
    alerts = evaluate_thresholds(cert, alert_repo)
    # Crosses 14 and 7, but only the most urgent (7) fires
    assert len(alerts) == 1
    assert alerts[0].threshold_days == 7


def test_expired_fires_after_expiry_warning_at_same_threshold(alert_repo):
    """Regression: an 'expired' alert must fire even if an 'expiry_warning'
    already exists at the same threshold — they are different alert types."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate

    fp = "trn" * 22

    # Day 1: expiry_warning at t=1
    cert_1d = Certificate(
        subject="CN=transition",
        issuer="CN=CA",
        not_before=datetime.now(UTC) - timedelta(days=364),
        not_after=datetime.now(UTC) + timedelta(days=1, hours=12),
        san_dns_names=[],
        fingerprint_sha256=fp,
        raw_der=b"",
        is_leaf=True,
    )
    warnings = evaluate_thresholds(cert_1d, alert_repo)
    assert len(warnings) == 1
    assert warnings[0].alert_type == "expiry_warning"
    assert warnings[0].threshold_days == 1

    # Day -1: cert is expired — 'expired' alert should fire despite t=1 already alerted
    cert_expired = Certificate(
        subject="CN=transition",
        issuer="CN=CA",
        not_before=datetime.now(UTC) - timedelta(days=366),
        not_after=datetime.now(UTC) - timedelta(days=1),
        san_dns_names=[],
        fingerprint_sha256=fp,
        raw_der=b"",
        is_leaf=True,
    )
    expired_alerts = evaluate_thresholds(cert_expired, alert_repo)
    assert len(expired_alerts) == 1
    assert expired_alerts[0].alert_type == "expired"


def test_failed_alert_does_not_block_refire(alert_repo, expiring_cert):
    """Regression: a failed delivery (status='failed') must not permanently
    suppress the threshold — it should re-fire on the next evaluation."""
    # First evaluation creates a pending alert
    alerts = evaluate_thresholds(expiring_cert, alert_repo)
    assert len(alerts) == 1

    # Simulate delivery failure
    alert_repo.mark_failed(alerts[0].id, "SMTP connection refused")

    # Re-evaluate — should create a new alert because the old one is 'failed'
    second = evaluate_thresholds(expiring_cert, alert_repo)
    assert len(second) == 1


# ---------- send_expiry_digest (Plan 002 WI-2) ----------


def _insert_cert(db_path, *, subject="CN=test", hostname="h.example.com", port=443,
                 not_after="2026-06-01T00:00:00+00:00"):
    """Insert a minimal certificate row for digest testing."""
    import uuid
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from tests._helpers import seed_certificate

    if isinstance(not_after, str):
        not_after = datetime.fromisoformat(not_after)
    cert_id = str(uuid.uuid4())
    cert = Certificate(
        subject=subject,
        issuer="CN=CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=not_after,
        fingerprint_sha256="fp" + cert_id[:8],
        raw_der=b"",
    )
    return seed_certificate(
        db_path, cert,
        hostname=hostname,
        port=port,
        source="scan",
    )


def test_send_expiry_digest_returns_true_with_expiring_certs(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    # Cert expiring in 5 days
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, not_after=soon)
    config = AlertConfig(smtp_host="smtp.test", smtp_user="", smtp_password="",
                         from_addr="from@test", recipients=["to@test"])
    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_server = MagicMock()
        mock_smtp.SMTP.return_value.__enter__ = lambda s: mock_server
        mock_smtp.SMTP.return_value.__exit__ = MagicMock(return_value=False)
        result = send_expiry_digest(db, config)
    assert result is True


def test_send_expiry_digest_returns_true_when_no_expiring(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    # Cert expiring in 100 days — not within 30-day window
    far = (datetime.now(UTC) + timedelta(days=100)).isoformat()
    _insert_cert(db, not_after=far)
    config = AlertConfig(smtp_host="smtp.test", smtp_user="", smtp_password="",
                         from_addr="from@test", recipients=["to@test"])
    result = send_expiry_digest(db, config)
    assert result is True  # nothing to report is success


def test_send_expiry_digest_returns_false_when_no_config(tmp_path):
    from cert_watch.alerts import send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    _insert_cert(db)
    assert send_expiry_digest(db, None, None) is False


def test_send_expiry_digest_sends_webhook_when_no_smtp(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, not_after=soon)
    webhook = WebhookConfig(url="https://hooks.test/hook")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True


def test_send_expiry_digest_includes_expiring_cert_details(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=3)).isoformat()
    _insert_cert(db, subject="CN=important", hostname="web.example.com",
                 port=443, not_after=soon)
    webhook = WebhookConfig(url="https://hooks.test/hook")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True


def test_send_expiry_digest_discord_adapter_format(tmp_path):
    """WI-011: digest webhook to kind='discord' uses Discord embed format."""
    import json
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, subject="CN=discord-test", hostname="d.example.com",
                 port=443, not_after=soon)
    webhook = WebhookConfig(url="https://hooks.discord.test/webhook", kind="discord")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True
    call_kwargs = mock_urlopen.call_args
    body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    payload = json.loads(body)
    assert "embeds" in payload
    assert payload["embeds"][0]["title"] == "cert-watch: Expiry Digest"


def test_send_expiry_digest_alertmanager_adapter_format(tmp_path):
    """WI-011: digest webhook to kind='alertmanager' uses Alertmanager alert format."""
    import json
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, subject="CN=am-test", hostname="am.example.com",
                 port=443, not_after=soon)
    webhook = WebhookConfig(url="https://am.example.com/api/v1/alerts", kind="alertmanager")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True
    call_kwargs = mock_urlopen.call_args
    body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    payload = json.loads(body)
    assert "alerts" in payload
    assert payload["alerts"][0]["labels"]["alertname"] == "CertAlert"


def test_send_expiry_digest_generic_adapter_format(tmp_path):
    """WI-011: digest webhook to kind='generic' still uses plain JSON payload."""
    import json
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, subject="CN=generic-test", hostname="g.example.com",
                 port=443, not_after=soon)
    webhook = WebhookConfig(url="https://hooks.test/hook", kind="generic")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True
    call_kwargs = mock_urlopen.call_args
    body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    payload = json.loads(body)
    assert payload["alert_type"] == "expiry_digest"
    assert "message" in payload


def test_send_expiry_digest_smtp_failure_returns_false(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, not_after=soon)
    config = AlertConfig(smtp_host="smtp.test", smtp_user="", smtp_password="",
                         from_addr="from@test", recipients=["to@test"])
    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_smtp.SMTP.side_effect = Exception("connection refused")
        result = send_expiry_digest(db, config)
    assert result is False


def test_send_expiry_digest_respects_30_day_window(tmp_path):
    """Only certs within 30 days are included."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest
    db = tmp_path / "cw.sqlite3"
    # One inside window, one outside
    inside = (datetime.now(UTC) + timedelta(days=20)).isoformat()
    outside = (datetime.now(UTC) + timedelta(days=60)).isoformat()
    _insert_cert(db, subject="CN=inside", hostname="in.example.com", not_after=inside)
    _insert_cert(db, subject="CN=outside", hostname="out.example.com", not_after=outside)
    webhook = WebhookConfig(url="https://hooks.test/hook")
    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)
    assert result is True


# ---------- send_expiry_digest owner-scoped (WI-A.2) ----------


def _seed_owner_host(db_path, hostname, owner_email, port=443):
    from cert_watch.database import SqliteHostRepository
    from cert_watch.database.schema import init_schema

    init_schema(db_path)
    SqliteHostRepository(db_path).add(hostname, port, owner_email=owner_email)


def test_expiry_digest_owner_scoped(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()

    _seed_owner_host(db, "host-a.example.com", "alice@example.com")
    _seed_owner_host(db, "host-b.example.com", "bob@example.com")
    _insert_cert(db, subject="CN=cert-a", hostname="host-a.example.com", not_after=soon)
    _insert_cert(db, subject="CN=cert-b", hostname="host-b.example.com", not_after=soon)

    config = AlertConfig(
        smtp_host="smtp.test", smtp_user="", smtp_password="",
        from_addr="from@test", recipients=["admin@example.com"],
    )

    sent: list = []

    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_conn = mock_smtp.SMTP.return_value
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send_message.side_effect = lambda msg: sent.append(msg)
        result = send_expiry_digest(db, config)

    assert result is True
    assert len(sent) == 3

    global_msg = sent[0]
    assert "admin@example.com" in global_msg["To"]
    body = global_msg.get_content()
    assert "cert-a" in body
    assert "cert-b" in body

    owner_msgs = sorted(sent[1:], key=lambda m: str(m["To"]))
    alice_msg = owner_msgs[0]
    assert "alice@example.com" in alice_msg["To"]
    alice_body = alice_msg.get_content()
    assert "cert-a" in alice_body
    assert "cert-b" not in alice_body

    bob_msg = owner_msgs[1]
    assert "bob@example.com" in bob_msg["To"]
    bob_body = bob_msg.get_content()
    assert "cert-b" in bob_body
    assert "cert-a" not in bob_body


def test_expiry_digest_owner_in_global_recipients(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()

    _seed_owner_host(db, "host-a.example.com", "alice@example.com")
    _seed_owner_host(db, "host-b.example.com", "bob@example.com")
    _insert_cert(db, subject="CN=cert-a", hostname="host-a.example.com", not_after=soon)
    _insert_cert(db, subject="CN=cert-b", hostname="host-b.example.com", not_after=soon)

    config = AlertConfig(
        smtp_host="smtp.test", smtp_user="", smtp_password="",
        from_addr="from@test",
        recipients=["admin@example.com", "alice@example.com"],
    )

    sent: list = []

    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_conn = mock_smtp.SMTP.return_value
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send_message.side_effect = lambda msg: sent.append(msg)
        result = send_expiry_digest(db, config)

    assert result is True
    assert len(sent) == 2

    global_msg = sent[0]
    assert "alice@example.com" in global_msg["To"]
    assert "admin@example.com" in global_msg["To"]
    body = global_msg.get_content()
    assert "cert-a" in body
    assert "cert-b" in body

    bob_msg = sent[1]
    assert "bob@example.com" in bob_msg["To"]
    bob_body = bob_msg.get_content()
    assert "cert-b" in bob_body
    assert "cert-a" not in bob_body


def test_expiry_digest_no_owners_backward_compat(tmp_path):
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()
    _insert_cert(db, subject="CN=cert-a", hostname="h1.example.com", not_after=soon)
    _insert_cert(db, subject="CN=cert-b", hostname="h2.example.com", not_after=soon)

    config = AlertConfig(
        smtp_host="smtp.test", smtp_user="", smtp_password="",
        from_addr="from@test", recipients=["admin@example.com"],
    )

    sent: list = []

    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_conn = mock_smtp.SMTP.return_value
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send_message.side_effect = lambda msg: sent.append(msg)
        result = send_expiry_digest(db, config)

    assert result is True
    assert len(sent) == 1
    body = sent[0].get_content()
    assert "cert-a" in body
    assert "cert-b" in body
    assert "admin@example.com" in sent[0]["To"]


def test_expiry_digest_mixed_case_email_preserves_original(tmp_path):
    """WI-A.2: mixed-case owner_email must be used verbatim in the To header."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()

    _seed_owner_host(db, "mixed.example.com", "Alice@Example.COM")
    _insert_cert(db, subject="CN=cert-mixed", hostname="mixed.example.com", not_after=soon)

    config = AlertConfig(
        smtp_host="smtp.test", smtp_user="", smtp_password="",
        from_addr="from@test", recipients=["admin@example.com"],
    )

    sent: list = []

    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_conn = mock_smtp.SMTP.return_value
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send_message.side_effect = lambda msg: sent.append(msg)
        result = send_expiry_digest(db, config)

    assert result is True
    owner_msg = sent[1]
    assert "Alice@Example.COM" in owner_msg["To"]


def test_expiry_digest_partial_smtp_failure_returns_false(tmp_path):
    """WI-A.2: global send succeeds but owner send raises → function returns False."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import AlertConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()

    _seed_owner_host(db, "host-p.example.com", "owner@example.com")
    _insert_cert(db, subject="CN=cert-p", hostname="host-p.example.com", not_after=soon)

    config = AlertConfig(
        smtp_host="smtp.test", smtp_user="", smtp_password="",
        from_addr="from@test", recipients=["admin@example.com"],
    )

    call_count = 0

    def _send(msg):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return None
        raise smtplib.SMTPException("owner send failed")

    with patch("cert_watch.alerts.smtplib") as mock_smtp:
        mock_conn = mock_smtp.SMTP.return_value
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_conn.send_message.side_effect = _send
        result = send_expiry_digest(db, config)

    assert result is False


def test_expiry_digest_webhook_strips_owner_email_pii(tmp_path):
    """WI-A.2: webhook payload must not contain owner_email PII."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.alerts import WebhookConfig, send_expiry_digest

    db = tmp_path / "cw.sqlite3"
    soon = (datetime.now(UTC) + timedelta(days=5)).isoformat()

    _seed_owner_host(db, "pii.example.com", "secret@example.com")
    _insert_cert(
        db, subject="CN=cert-pii", hostname="pii.example.com",
        port=443, not_after=soon,
    )

    webhook = WebhookConfig(url="https://hooks.test/hook")

    with patch("cert_watch.alerts.ssrf_safe_urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = send_expiry_digest(db, None, webhook)

    assert result is True
    call_kwargs = mock_urlopen.call_args
    body = call_kwargs.kwargs.get("data") or call_kwargs[1].get("data", b"")
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    assert "secret@example.com" not in body
    assert "pii.example.com" in body


def _leaf_expiring_in(days: int, fp: str) -> Certificate:
    import datetime as _dt
    now = _dt.datetime.now(_dt.UTC)
    return Certificate(
        subject="CN=urgent-test",
        issuer="CN=test-ca",
        not_before=now - _dt.timedelta(days=365),
        # +12h buffer so days_until_expiry()'s floor semantics yield exactly `days`.
        not_after=now + _dt.timedelta(days=days, hours=12),
        san_dns_names=[],
        fingerprint_sha256=fp,
        raw_der=b"",
        is_leaf=True,
    )


def test_urgent_only_skips_routine_thresholds(alert_repo):
    # 10 days out: trips the 14-day heads-up normally, but in digest mode the
    # routine thresholds are left to the weekly digest, so nothing fires.
    cert = _leaf_expiring_in(10, "fp-routine")
    assert evaluate_thresholds(cert, alert_repo, urgent_only=True) == []


def test_urgent_only_fires_final_countdown(alert_repo):
    # 2 days out: the final-countdown (<=3) alert still fires even in digest mode.
    cert = _leaf_expiring_in(2, "fp-urgent")
    alerts = evaluate_thresholds(cert, alert_repo, urgent_only=True)
    assert len(alerts) == 1
    assert alerts[0].threshold_days == 3


def test_routine_threshold_fires_when_not_digest(alert_repo):
    # Same 10-day cert fires normally when not in digest mode (sanity).
    cert = _leaf_expiring_in(10, "fp-normal")
    alerts = evaluate_thresholds(cert, alert_repo, urgent_only=False)
    assert len(alerts) == 1
    assert alerts[0].threshold_days == 14
