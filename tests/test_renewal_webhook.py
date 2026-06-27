import json
from unittest.mock import MagicMock, patch

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database.schema import init_schema
from cert_watch.renewal_analytics import RenewalOverdueSignal
from cert_watch.renewal_webhook import (
    RenewalWebhookConfig,
    build_renewal_payload,
    load_renewal_webhook_config,
    send_renewal_webhook,
)
from tests._helpers import seed_certificate


def test_load_renewal_webhook_config_returns_none_when_no_url():
    assert load_renewal_webhook_config(env_url="") is None
    assert load_renewal_webhook_config(env_url="   ") is None


def test_load_renewal_webhook_config_with_url():
    cfg = load_renewal_webhook_config(env_url="https://example.com/hook")
    assert isinstance(cfg, RenewalWebhookConfig)
    assert cfg.url == "https://example.com/hook"
    assert cfg.headers == {}
    assert cfg.allow_private is True


def test_load_renewal_webhook_config_with_headers():
    cfg = load_renewal_webhook_config(
        env_url="https://example.com/hook",
        env_headers='{"Authorization": "Bearer token", "X-Custom": "1"}',
    )
    assert cfg.headers == {"Authorization": "Bearer token", "X-Custom": "1"}


def test_load_renewal_webhook_config_invalid_headers(caplog):
    with caplog.at_level("WARNING", logger="cert_watch.renewal_webhook"):
        cfg = load_renewal_webhook_config(
            env_url="https://example.com/hook",
            env_headers="not-json",
        )
    assert cfg.headers == {}
    assert any(
        "CERT_WATCH_RENEWAL_WEBHOOK_HEADERS" in r.message for r in caplog.records
    )


def _make_signal(hostname="host.example.com", fingerprint="abc123") -> RenewalOverdueSignal:
    return RenewalOverdueSignal(
        hostname=hostname,
        cert_fingerprint=fingerprint,
        days_remaining=7.0,
        expected_renewal_at_days=30.0,
        days_overdue=23.0,
        confidence="low",
    )


def _cert_from_der(der: bytes) -> Certificate:
    parsed = parse_certificate(der)
    assert isinstance(parsed, Certificate)
    return parsed


def test_build_renewal_payload(tmp_path, self_signed_leaf):
    cert = _cert_from_der(self_signed_leaf.der)
    db = tmp_path / "cw.sqlite3"
    seed_certificate(
        db,
        cert,
        hostname="host.example.com",
        port=443,
    )
    signal = _make_signal(
        hostname="host.example.com",
        fingerprint=cert.fingerprint_sha256,
    )

    payload = build_renewal_payload(signal, db)

    assert payload["event"] == "renewal_needed"
    assert payload["hostname"] == "host.example.com"
    assert payload["port"] == 443
    assert payload["cert_fingerprint"] == cert.fingerprint_sha256
    assert payload["subject_cn"] == cert.subject
    assert '"leaf.example.com"' in json.dumps(payload["san_names"])
    assert payload["issuer"] == cert.issuer
    assert payload["expiry"] == cert.not_after.isoformat()
    assert payload["days_remaining"] == 7.0
    assert payload["expected_renewal_at_days"] == 30.0
    assert payload["days_overdue"] == 23.0
    assert payload["confidence"] == "low"
    assert "automation_hint" in payload
    assert "cert_watch_url" not in payload


def test_build_renewal_payload_with_base_url(tmp_path, self_signed_leaf):
    cert = _cert_from_der(self_signed_leaf.der)
    db = tmp_path / "cw.sqlite3"
    seed_certificate(
        db,
        cert,
        hostname="host.example.com",
        port=443,
    )
    signal = _make_signal(
        hostname="host.example.com",
        fingerprint=cert.fingerprint_sha256,
    )

    payload = build_renewal_payload(signal, db, base_url="https://cw.example.com")

    from cert_watch.database.connection import _connect
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND is_leaf = 1",
            ("host.example.com",),
        ).fetchone()
    cert_id = dict(row)["id"]
    assert payload["cert_watch_url"] == (
        f"https://cw.example.com/certificates/{cert_id}"
    )


def test_build_renewal_payload_no_cert_in_db(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    signal = _make_signal(hostname="missing.example.com", fingerprint="deadbeef")

    payload = build_renewal_payload(signal, db)

    assert payload["event"] == "renewal_needed"
    assert payload["hostname"] == "missing.example.com"
    assert payload["cert_fingerprint"] == "deadbeef"
    assert payload["subject_cn"] == ""
    assert payload["san_names"] == []
    assert payload["issuer"] == ""
    assert payload["expiry"] == ""
    assert payload["automation_hint"] == "unknown"


def test_send_renewal_webhook_success():
    config = RenewalWebhookConfig(url="https://example.com/hook")
    payload = {"event": "renewal_needed", "hostname": "h.example.com"}
    fake_resp = MagicMock()
    fake_resp.status = 200
    with patch(
        "cert_watch.renewal_webhook.ssrf_safe_urlopen",
        return_value=fake_resp,
    ) as mock_open:
        assert send_renewal_webhook(payload, config) is True
    mock_open.assert_called_once()
    call_kwargs = mock_open.call_args.kwargs
    assert call_kwargs["data"] == b'{"event": "renewal_needed", "hostname": "h.example.com"}'
    assert call_kwargs["headers"]["Content-Type"] == "application/json"
    assert call_kwargs["timeout"] == 15
    fake_resp.read.assert_called_once_with(1)
    fake_resp.close.assert_called_once()


def test_send_renewal_webhook_failure():
    config = RenewalWebhookConfig(url="https://example.com/hook")
    payload = {"event": "renewal_needed", "hostname": "h.example.com"}
    with patch(
        "cert_watch.renewal_webhook.ssrf_safe_urlopen",
        side_effect=OSError("boom"),
    ):
        assert send_renewal_webhook(payload, config) is False


def test_send_renewal_webhook_ssrf_blocked():
    from cert_watch.http_client import SSRFBlockedError

    config = RenewalWebhookConfig(url="https://example.com/hook")
    payload = {"event": "renewal_needed", "hostname": "h.example.com"}
    with patch(
        "cert_watch.renewal_webhook.ssrf_safe_urlopen",
        side_effect=SSRFBlockedError("blocked"),
    ):
        assert send_renewal_webhook(payload, config) is False


def test_send_renewal_webhook_http_error_status():
    config = RenewalWebhookConfig(url="https://example.com/hook")
    payload = {"event": "renewal_needed", "hostname": "h.example.com"}
    fake_resp = MagicMock()
    fake_resp.status = 500
    with patch(
        "cert_watch.renewal_webhook.ssrf_safe_urlopen",
        return_value=fake_resp,
    ):
        assert send_renewal_webhook(payload, config) is False


def test_send_renewal_webhook_unexpected_exception():
    config = RenewalWebhookConfig(url="https://example.com/hook")
    payload = {"event": "renewal_needed", "hostname": "h.example.com"}
    with patch(
        "cert_watch.renewal_webhook.ssrf_safe_urlopen",
        side_effect=RuntimeError("unexpected"),
    ):
        assert send_renewal_webhook(payload, config) is False
