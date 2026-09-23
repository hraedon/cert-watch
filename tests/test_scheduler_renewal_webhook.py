"""Integration tests for the renewal-webhook wiring in the scheduler.

The renewal_webhook module's primitives (build/send/load) are unit-tested in
test_renewal_webhook.py. This file covers the *wiring* that those tests left
uncovered: the scheduler path that detects an overdue cert, emits the event, and
delivers the webhook — including the retry-on-transient-failure behaviour.
"""
from unittest.mock import patch

import pytest

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.config import Settings
from cert_watch.database import init_schema
from cert_watch.renewal_analytics import RenewalOverdueSignal
from cert_watch.scheduler import Scheduler
from cert_watch.scheduler_context import SchedulerContext
from tests._helpers import seed_certificate


def _signal(hostname="host.example.com", fingerprint="abc123") -> RenewalOverdueSignal:
    return RenewalOverdueSignal(
        hostname=hostname,
        cert_fingerprint=fingerprint,
        days_remaining=7.0,
        expected_renewal_at_days=30.0,
        days_overdue=23.0,
        confidence="low",
    )


@pytest.fixture
def runtime(tmp_path):
    """Each test gets an independently owned webhook executor."""
    db = tmp_path / "scheduler.sqlite3"
    init_schema(db)
    settings = Settings(db_path=db, data_dir=tmp_path)
    scheduler = Scheduler(SchedulerContext(settings, None, None))
    scheduler.start()
    with patch("cert_watch.retry.time.sleep"):
        yield scheduler
    scheduler.stop(timeout=1)


@pytest.fixture
def seeded_db(tmp_path, self_signed_leaf):
    parsed = parse_certificate(self_signed_leaf.der)
    assert isinstance(parsed, Certificate)
    db = tmp_path / "cw.sqlite3"
    seed_certificate(db, parsed, hostname="host.example.com", port=443)
    return db, parsed


def test_not_configured_does_not_send(runtime, seeded_db, monkeypatch):
    db, _ = seeded_db
    monkeypatch.delenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", raising=False)
    with patch("cert_watch.renewal_webhook.send_renewal_webhook") as send:
        runtime._send_renewal_webhook_if_configured(
            _signal(), "host.example.com", 443, db
        )
    send.assert_not_called()


def test_configured_sends_built_payload(runtime, seeded_db, monkeypatch):
    db, parsed = seeded_db
    monkeypatch.setenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", "https://hook.example.com/r")
    signal = _signal(fingerprint=parsed.fingerprint_sha256)
    with patch(
        "cert_watch.renewal_webhook.send_renewal_webhook", return_value=True
    ) as send:
        runtime._send_renewal_webhook_if_configured(
            signal, "host.example.com", 443, db
        )
    assert runtime.wait_for_webhooks()
    send.assert_called_once()
    payload, config = send.call_args.args
    assert payload["event"] == "renewal_needed"
    assert payload["hostname"] == "host.example.com"
    assert payload["cert_fingerprint"] == parsed.fingerprint_sha256
    assert config.url == "https://hook.example.com/r"


def test_retries_then_succeeds(runtime, seeded_db, monkeypatch):
    db, parsed = seeded_db
    monkeypatch.setenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", "https://hook.example.com/r")
    signal = _signal(fingerprint=parsed.fingerprint_sha256)
    with patch(
        "cert_watch.renewal_webhook.send_renewal_webhook",
        side_effect=[False, True],
    ) as send:
        runtime._send_renewal_webhook_if_configured(
            signal, "host.example.com", 443, db
        )
    assert runtime.wait_for_webhooks()
    assert send.call_count == 2  # stops as soon as one attempt succeeds


def test_retry_exhausted_is_logged(runtime, seeded_db, monkeypatch, caplog):
    db, parsed = seeded_db
    monkeypatch.setenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", "https://hook.example.com/r")
    signal = _signal(fingerprint=parsed.fingerprint_sha256)
    with patch(
        "cert_watch.renewal_webhook.send_renewal_webhook", return_value=False
    ) as send, caplog.at_level("WARNING", logger="cert_watch.scheduler"):
        runtime._send_renewal_webhook_if_configured(
            signal, "host.example.com", 443, db
        )
    assert runtime.wait_for_webhooks()
    assert send.call_count == 3  # three attempts: 0, +1s, +2s
    assert any("failed after retries" in r.message for r in caplog.records)


def test_shutdown_rejects_new_renewal_webhook(runtime, seeded_db, monkeypatch):
    db, parsed = seeded_db
    monkeypatch.setenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", "https://hook.example.com/r")
    runtime.stop(timeout=1)
    with patch("cert_watch.renewal_webhook.send_renewal_webhook") as send:
        runtime._send_renewal_webhook_if_configured(
            _signal(fingerprint=parsed.fingerprint_sha256),
            "host.example.com",
            443,
            db,
        )
    send.assert_not_called()


def test_check_renewal_overdue_fires_webhook_once_and_dedupes(
    runtime, seeded_db, monkeypatch
):
    """Full wiring: detect → emit event → deliver, and the 24h dedup guard."""
    db, parsed = seeded_db
    monkeypatch.setenv("CERT_WATCH_RENEWAL_WEBHOOK_URL", "https://hook.example.com/r")
    signal = _signal(fingerprint=parsed.fingerprint_sha256)
    hosts = [("host.example.com", 443)]

    with patch(
        "cert_watch.renewal_analytics.detect_renewal_overdue", return_value=signal
    ), patch(
        "cert_watch.renewal_webhook.send_renewal_webhook", return_value=True
    ) as send:
        runtime._check_renewal_overdue(db, hosts)
        # Second cycle: the event was already emitted within 24h, so no resend.
        runtime._check_renewal_overdue(db, hosts)

    assert runtime.wait_for_webhooks()
    send.assert_called_once()


def test_check_renewal_overdue_records_cooldown_only_after_event_is_persisted(
    runtime, seeded_db, monkeypatch,
):
    db, parsed = seeded_db
    signal = _signal(fingerprint=parsed.fingerprint_sha256)
    hosts = [("host.example.com", 443)]
    monkeypatch.setattr(
        "cert_watch.renewal_analytics.detect_renewal_overdue", lambda *a, **k: signal,
    )
    monkeypatch.setattr("cert_watch.events.emit_event", lambda *a, **k: None)

    runtime._check_renewal_overdue(db, hosts)

    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM rule_firings").fetchone()[0] == 0


def test_check_renewal_overdue_no_signal_no_send(runtime, seeded_db):
    db, _ = seeded_db
    with patch(
        "cert_watch.renewal_analytics.detect_renewal_overdue", return_value=None
    ), patch(
        "cert_watch.renewal_webhook.send_renewal_webhook"
    ) as send:
        runtime._check_renewal_overdue(db, [("host.example.com", 443)])
    send.assert_not_called()


def test_check_renewal_overdue_db_path_none_is_noop(runtime):
    with patch("cert_watch.renewal_webhook.send_renewal_webhook") as send:
        runtime._check_renewal_overdue(None, [("host.example.com", 443)])
    send.assert_not_called()
