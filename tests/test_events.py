"""Tests for cert_watch.events (Plan 044)."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from cert_watch.database import init_schema
from cert_watch.events import (
    ALL_EVENT_TYPES,
    Event,
    EventStreamConfig,
    _deliver_webhook,
    emit_event,
    emit_scan_failed,
    get_events,
    get_failed_deliveries,
    load_event_config,
    purge_old_events,
    reset_pool,
    save_event_config,
)


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_schema(db_path)
    return db_path


@pytest.fixture(autouse=True)
def _reset():
    yield
    reset_pool()


class TestEvent:
    def test_creation(self):
        e = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={"cert_id": "1"},
            source="scan",
        )
        assert e.event_type == "cert_added"
        assert e.source == "scan"

    def test_to_dict(self):
        ts = datetime(2026, 1, 1, tzinfo=UTC)
        e = Event(
            event_type="scan_failed",
            timestamp=ts,
            payload={"hostname": "a"},
            source="scan",
        )
        d = e.to_dict()
        assert d["event_type"] == "scan_failed"
        assert d["source"] == "scan"
        assert d["payload"]["hostname"] == "a"
        assert d["timestamp"] == ts.isoformat()


class TestEventStreamConfig:
    def test_defaults(self):
        c = EventStreamConfig()
        assert c.enabled_event_types == list(ALL_EVENT_TYPES)
        assert c.webhook_url is None
        assert c.webhook_kind == "generic"
        assert c.pagerduty_routing_key == ""
        assert c.rate_limit_per_second == 100

    def test_round_trip(self, db):
        c = EventStreamConfig(
            enabled_event_types=["cert_added", "scan_failed"],
            webhook_url="https://example.com/hook",
            webhook_kind="discord",
            pagerduty_routing_key="abc123",
            rate_limit_per_second=5,
        )
        save_event_config(db, c)
        loaded = load_event_config(db)
        assert loaded.enabled_event_types == ["cert_added", "scan_failed"]
        assert loaded.webhook_url == "https://example.com/hook"
        assert loaded.webhook_kind == "discord"
        assert loaded.pagerduty_routing_key == "abc123"
        assert loaded.rate_limit_per_second == 5

    def test_load_default_when_missing(self, db):
        c = load_event_config(db)
        assert c.enabled_event_types == list(ALL_EVENT_TYPES)
        assert c.webhook_url is None

    def test_json_round_trip(self):
        c = EventStreamConfig(webhook_url="https://x", rate_limit_per_second=3)
        raw = c.to_json()
        c2 = EventStreamConfig.from_json(raw)
        assert c2.webhook_url == "https://x"
        assert c2.rate_limit_per_second == 3

    def test_pagerduty_routing_key_excluded_from_json(self):
        # WI-065: the routing key is stored as a separate enc:v1: secret, not
        # in the EventStreamConfig JSON blob (so it is not plaintext at rest).
        c = EventStreamConfig(pagerduty_routing_key="rk-123")
        raw = c.to_json()
        assert "pagerduty_routing_key" not in json.loads(raw)
        c2 = EventStreamConfig.from_json(raw)
        assert c2.pagerduty_routing_key == ""

    def test_pagerduty_routing_key_legacy_plaintext_compat(self):
        # WI-065: pre-WI-065 blobs stored the key as plaintext in the JSON;
        # from_json still reads it so existing deployments don't lose their key
        # on upgrade (it migrates to the encrypted secret on the next save).
        legacy = json.dumps({
            "enabled_event_types": ["cert_added"],
            "webhook_url": None,
            "webhook_kind": "generic",
            "pagerduty_routing_key": "legacy-rk",
            "rate_limit_per_second": 100,
        })
        c = EventStreamConfig.from_json(legacy)
        assert c.pagerduty_routing_key == "legacy-rk"

    def test_pagerduty_routing_key_encrypted_round_trip(self, db):
        # WI-065: with an encryption key, the routing key is stored as enc:v1:
        # in a dedicated kv key (not in the JSON blob) and decrypts on load.
        from cert_watch.database.encryption import derive_encryption_key
        from cert_watch.database.kv_store import kv_get

        enc_key = derive_encryption_key("test-signing-key")
        save_event_config(
            db, EventStreamConfig(pagerduty_routing_key="secret-rk"), encryption_key=enc_key
        )
        blob = kv_get(db, "event_stream_config") or ""
        assert "secret-rk" not in blob  # not in the JSON blob
        raw_secret = kv_get(db, "event_stream_pagerduty_routing_key")
        assert raw_secret is not None
        assert raw_secret.startswith("enc:v1:")  # encrypted at rest
        assert "secret-rk" not in raw_secret
        loaded = load_event_config(db, encryption_key=enc_key)
        assert loaded.pagerduty_routing_key == "secret-rk"

    def test_pagerduty_routing_key_blank_preserve(self, db):
        # WI-065: the route's blank-skip preserves the existing key. Here we
        # emulate that flow at the save/load layer: save a key, then re-save a
        # config whose routing key was loaded-back (preserved), and confirm it
        # survives (would be wiped if blank meant clear).
        from cert_watch.database.encryption import derive_encryption_key

        enc_key = derive_encryption_key("test-signing-key")
        save_event_config(
            db, EventStreamConfig(pagerduty_routing_key="keep-me"), encryption_key=enc_key
        )
        existing = load_event_config(db, encryption_key=enc_key)
        # Route passes the preserved value through on a blank submission.
        preserved = EventStreamConfig(
            webhook_url="https://example.com/hook",
            pagerduty_routing_key=existing.pagerduty_routing_key,
        )
        save_event_config(db, preserved, encryption_key=enc_key)
        assert load_event_config(db, encryption_key=enc_key).pagerduty_routing_key == "keep-me"

    def test_pagerduty_routing_key_no_decrypt_without_key(self, db):
        # When the signing key is absent (encryption_key resolves to None) and
        # the stored value is enc:v1: ciphertext, load_event_config must NOT
        # load the raw ciphertext as the routing key (which would corrupt on
        # re-save). The key should appear unset.
        from cert_watch.database.encryption import derive_encryption_key
        from cert_watch.database.kv_store import kv_set_secret

        enc_key = derive_encryption_key("test-signing-key")
        # Write an encrypted secret directly (simulates a save that happened
        # when the signing key was available).
        kv_set_secret(db, "event_stream_pagerduty_routing_key", "real-key", enc_key)
        # Now load without an encryption key — signing key absent.
        cfg = load_event_config(db, encryption_key=None)
        # Must NOT be the raw ciphertext.
        assert not cfg.pagerduty_routing_key.startswith("enc:v1:")
        # Must be empty (key is undecryptable).
        assert cfg.pagerduty_routing_key == ""


class TestEmitEvent:
    def test_writes_to_event_log(self, db):
        e = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={"cert_id": "1"},
            source="scan",
        )
        row_id = emit_event(e, db)
        assert row_id is not None
        events = get_events(db)
        assert len(events) == 1
        assert events[0]["event_type"] == "cert_added"
        assert events[0]["delivery_status"] == "delivered"

    def test_skips_disabled_event_type(self, db):
        c = EventStreamConfig(enabled_event_types=["scan_failed"])
        e = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={},
            source="scan",
        )
        result = emit_event(e, db, config=c)
        assert result is None
        assert get_events(db) == []

    def test_webhook_sets_pending(self, db):
        c = EventStreamConfig(webhook_url="https://example.com/hook")
        e = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={"cert_id": "1"},
            source="scan",
        )
        row_id = emit_event(e, db, config=c)
        assert row_id is not None
        events = get_events(db)
        assert events[0]["delivery_status"] == "pending"

    def test_fail_open_on_error(self, db):
        e = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={"cert_id": "1"},
            source="scan",
        )
        with patch("cert_watch.events._write_event_log", side_effect=sqlite3.DatabaseError("boom")):
            result = emit_event(e, db)
        assert result is None

    def test_rate_limiting(self, db):
        c = EventStreamConfig(rate_limit_per_second=1, webhook_url="https://example.com/hook")
        from cert_watch.events import _rate_lock, _rate_timestamps

        with _rate_lock:
            _rate_timestamps.clear()
        results = []
        for i in range(5):
            e = Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"i": i},
                source="scan",
            )
            results.append(emit_event(e, db, config=c))
        accepted = sum(1 for r in results if r is not None)
        assert accepted >= 1
        assert None in results

    def test_no_rate_limit_without_webhook(self, db):
        c = EventStreamConfig(rate_limit_per_second=2, webhook_url=None)
        from cert_watch.events import _rate_lock, _rate_timestamps

        with _rate_lock:
            _rate_timestamps.clear()
        results = []
        for i in range(10):
            e = Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"i": i},
                source="scan",
            )
            results.append(emit_event(e, db, config=c))
        assert all(r is not None for r in results)


class TestGetEvents:
    def test_filter_by_event_type(self, db):
        for et in ("cert_added", "scan_failed", "cert_added"):
            e = Event(
                event_type=et,
                timestamp=datetime.now(UTC),
                payload={},
                source="scan",
            )
            emit_event(e, db)
        events = get_events(db, event_type="cert_added")
        assert all(ev["event_type"] == "cert_added" for ev in events)

    def test_filter_by_source(self, db):
        e1 = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={},
            source="scan",
        )
        e2 = Event(
            event_type="cert_added",
            timestamp=datetime.now(UTC),
            payload={},
            source="upload",
        )
        emit_event(e1, db)
        emit_event(e2, db)
        events = get_events(db, source="upload")
        assert len(events) == 1
        assert events[0]["source"] == "upload"

    def test_pagination(self, db):
        for i in range(5):
            e = Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"i": i},
                source="scan",
            )
            emit_event(e, db)
        page1 = get_events(db, limit=2, offset=0)
        page2 = get_events(db, limit=2, offset=2)
        assert len(page1) == 2
        assert len(page2) == 2

    def test_filter_by_since(self, db):
        e1 = Event(
            event_type="cert_added",
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            payload={},
            source="scan",
        )
        e2 = Event(
            event_type="cert_added",
            timestamp=datetime(2026, 6, 1, tzinfo=UTC),
            payload={},
            source="scan",
        )
        emit_event(e1, db)
        emit_event(e2, db)
        events = get_events(db, since="2026-05-01")
        assert len(events) == 1


class TestGetFailedDeliveries:
    def test_returns_failed(self, db):
        from cert_watch.database.connection import _connect

        now = datetime.now(UTC).isoformat()
        with _connect(db) as conn:
            conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("cert_added", now, "scan", "{}", "failed", now),
            )
            conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("cert_added", now, "scan", "{}", "delivered", now),
            )
            conn.commit()
        failures = get_failed_deliveries(db)
        assert len(failures) == 1
        assert failures[0]["delivery_status"] == "failed"


class TestEmitScanFailed:
    def test_convenience(self, db):
        result = emit_scan_failed(
            db, "host.example.com", 443, "connection refused", source="scan",
        )
        assert result is not None
        events = get_events(db, event_type="scan_failed")
        assert len(events) == 1
        payload = json.loads(events[0]["payload"])
        assert payload["hostname"] == "host.example.com"
        assert payload["error_message"] == "connection refused"


class TestPurgeOldEvents:
    def test_purge_removes_old_events(self, db):
        from cert_watch.database.connection import _connect

        now = datetime.now(UTC)
        old_ts = (now - timedelta(days=60)).isoformat()
        new_ts = (now - timedelta(days=5)).isoformat()
        with _connect(db) as conn:
            conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("cert_added", old_ts, "scan", "{}", "delivered", old_ts),
            )
            conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("cert_added", new_ts, "scan", "{}", "delivered", new_ts),
            )
            conn.commit()
        count = purge_old_events(db, 30)
        assert count == 1
        remaining = get_events(db)
        assert len(remaining) == 1

    def test_purge_zero_retention_is_noop(self, db):
        from cert_watch.database.connection import _connect

        now = datetime.now(UTC).isoformat()
        with _connect(db) as conn:
            conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("cert_added", now, "scan", "{}", "delivered", now),
            )
            conn.commit()
        count = purge_old_events(db, 0)
        assert count == 0
        assert len(get_events(db)) == 1


class TestDeliverWebhookSSRFPolicy:
    """WI-063: event-stream webhook delivery honors CERT_WATCH_ALLOW_PRIVATE_IPS
    and CERT_WATCH_ALLOWED_SUBNETS (env wins, else the kv allowlist set by the
    setup wizard), so internal event webhooks are not silently blocked."""

    def _capture(self, monkeypatch, db):
        captured: dict = {}

        def _fake_send(alert, wc):  # noqa: ANN001
            captured["allow_private"] = wc.allow_private
            captured["allowed_subnets"] = wc.allowed_subnets
            return True

        monkeypatch.setattr("cert_watch.alerts.send_webhook", _fake_send)
        return captured

    def _emit(self, db):
        _deliver_webhook(
            Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"cert_id": "1"},
                source="scan",
            ),
            EventStreamConfig(webhook_url="https://mattermost.internal/hook"),
            db,
            row_id=1,
        )

    def test_allow_private_false_when_env_disabled(self, db, monkeypatch):
        monkeypatch.setenv("CERT_WATCH_ALLOW_PRIVATE_IPS", "0")
        monkeypatch.delenv("CERT_WATCH_ALLOWED_SUBNETS", raising=False)
        captured = self._capture(monkeypatch, db)
        self._emit(db)
        assert captured["allow_private"] is False

    def test_allow_private_true_by_default(self, db, monkeypatch):
        monkeypatch.delenv("CERT_WATCH_ALLOW_PRIVATE_IPS", raising=False)
        monkeypatch.delenv("CERT_WATCH_ALLOWED_SUBNETS", raising=False)
        captured = self._capture(monkeypatch, db)
        self._emit(db)
        assert captured["allow_private"] is True

    def test_allowed_subnets_from_kv_when_env_unset(self, db, monkeypatch):
        from cert_watch.database import kv_set

        monkeypatch.delenv("CERT_WATCH_ALLOWED_SUBNETS", raising=False)
        kv_set(db, "allowed_subnets", "10.0.0.0/8,172.16.0.0/12")
        captured = self._capture(monkeypatch, db)
        self._emit(db)
        assert captured["allowed_subnets"] == ("10.0.0.0/8", "172.16.0.0/12")

    def test_env_allowed_subnets_wins_over_kv(self, db, monkeypatch):
        from cert_watch.database import kv_set

        kv_set(db, "allowed_subnets", "10.0.0.0/8")
        monkeypatch.setenv("CERT_WATCH_ALLOWED_SUBNETS", "192.168.0.0/16")
        captured = self._capture(monkeypatch, db)
        self._emit(db)
        assert captured["allowed_subnets"] == ("192.168.0.0/16",)


class TestDeliverWebhookErrorHandling:
    """_deliver_webhook must catch exceptions and mark the event as failed
    rather than leaving it stuck in 'pending' status forever."""

    def test_exception_in_delivery_marks_event_failed(self, db, monkeypatch):
        from cert_watch.database.connection import _connect

        # Write the event row so the UPDATE at the end has something to update.
        with _connect(db) as conn:
            cur = conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "cert_added",
                    datetime.now(UTC).isoformat(),
                    "scan",
                    '{"cert_id": "1"}',
                    "pending",
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            row_id = cur.lastrowid

        # Force _resolve_ssrf_policy to raise.
        monkeypatch.setattr(
            "cert_watch.events._resolve_ssrf_policy",
            lambda db_path: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        _deliver_webhook(
            Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"cert_id": "1"},
                source="scan",
            ),
            EventStreamConfig(webhook_url="https://example.com/hook"),
            db,
            row_id=row_id,
        )
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT delivery_status, error_message FROM event_log WHERE id = ?",
                (row_id,),
            ).fetchone()
        assert row["delivery_status"] == "failed"
        assert "boom" in (row["error_message"] or "")