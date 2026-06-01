"""Tests for Plan 016 Slice 2 — drift detection and alerting."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.queries import (
    DriftEvent,
    _compute_drift_events,
    _drift_summary,
    create_drift_alert,
    detect_drift,
)


def _make_leaf(
    issuer: str = "CN=Test CA",
    days_valid: int = 90,
    sans: list[str] | None = None,
    fingerprint: str = "abc123",
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject="CN=test.example.com",
        issuer=issuer,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days_valid),
        san_dns_names=sans or ["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=b"",
    )


def _old_row(**overrides) -> dict:
    """Build a minimal cert_history-like dict for drift tests."""
    base = {
        "issuer": "",
        "key_algo": "",
        "sig_algo": "",
        "posture_grade": "",
        "protocol_version": "",
        "san_count": 1,
        "not_after": "",
    }
    base.update(overrides)
    return base


def _seed_history(
    db,
    hostname: str = "h.example.com",
    port: int = 443,
    *,
    issuer: str = "CN=Old CA",
    not_after_days: int = 90,
    key_algo: str = "RSA-2048",
    sig_algo: str = "SHA-256",
    posture_grade: str = "A",
    protocol_version: str = "TLSv1.3",
    san_count: int = 1,
    fingerprint: str = "old_fp",
) -> None:
    """Insert a cert_history row directly."""
    now = datetime.now(UTC)
    ts = (now - timedelta(hours=1)).isoformat()
    not_after = (now + timedelta(days=not_after_days)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"hist-{hostname}-{port}",
                hostname, port, fingerprint, issuer, not_after,
                key_algo, sig_algo, posture_grade, protocol_version, san_count, ts,
            ),
        )
        conn.commit()


# ---------- _compute_drift_events ----------


class TestComputeDriftEvents:
    def test_no_changes_returns_empty(self):
        old = _old_row(
            issuer="CN=CA", key_algo="RSA-2048", sig_algo="SHA-256",
            posture_grade="A", protocol_version="TLSv1.3", san_count=2,
            not_after=(datetime.now(UTC) + timedelta(days=90)).isoformat(),
        )
        leaf = _make_leaf(issuer="CN=CA", days_valid=90, sans=["a.com", "b.com"])
        events = _compute_drift_events(
            old, leaf, "A", "TLSv1.3", "RSA-2048", "SHA-256",
        )
        assert events == []

    def test_issuer_change_is_high(self):
        old = _old_row(issuer="CN=Old CA")
        leaf = _make_leaf(issuer="CN=New CA")
        events = _compute_drift_events(old, leaf)
        assert len(events) == 1
        assert events[0].field == "issuer"
        assert events[0].severity == "high"
        assert events[0].old == "CN=Old CA"
        assert events[0].new == "CN=New CA"

    def test_key_size_drop_is_high(self):
        old = _old_row(key_algo="RSA-4096")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_key_algo="RSA-2048")
        key_events = [e for e in events if e.field == "key_algo"]
        assert len(key_events) == 1
        assert key_events[0].severity == "high"

    def test_key_algo_change_same_size_is_info(self):
        old = _old_row(key_algo="RSA-2048")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_key_algo="EC-P256")
        key_events = [e for e in events if e.field == "key_algo"]
        assert len(key_events) == 1
        assert key_events[0].severity == "info"

    def test_sha1_sig_downgrade_is_high(self):
        old = _old_row(sig_algo="SHA-256")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_sig_algo="SHA-1")
        sig_events = [e for e in events if e.field == "sig_algo"]
        assert len(sig_events) == 1
        assert sig_events[0].severity == "high"

    def test_grade_drop_is_high(self):
        old = _old_row(posture_grade="A")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_posture_grade="B")
        grade_events = [e for e in events if e.field == "posture_grade"]
        assert len(grade_events) == 1
        assert grade_events[0].severity == "high"

    def test_grade_improvement_is_info(self):
        old = _old_row(posture_grade="B")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_posture_grade="A")
        grade_events = [e for e in events if e.field == "posture_grade"]
        assert len(grade_events) == 1
        assert grade_events[0].severity == "info"

    def test_tls_downgrade_is_high(self):
        old = _old_row(protocol_version="TLSv1.3")
        leaf = _make_leaf()
        events = _compute_drift_events(old, leaf, new_protocol_version="TLSv1.2")
        proto_events = [e for e in events if e.field == "protocol_version"]
        assert len(proto_events) == 1
        assert proto_events[0].severity == "high"

    def test_san_count_change_is_info(self):
        old = _old_row()
        leaf = _make_leaf(sans=["a.com", "b.com"])
        events = _compute_drift_events(old, leaf)
        san_events = [e for e in events if e.field == "san_count"]
        assert len(san_events) == 1
        assert san_events[0].severity == "info"

    def test_benign_renewal_same_issuer_later_expiry_is_info(self):
        now = datetime.now(UTC)
        old_not_after = (now + timedelta(days=30)).isoformat()
        old = _old_row(issuer="CN=CA", not_after=old_not_after)
        leaf = _make_leaf(issuer="CN=CA", days_valid=90)
        events = _compute_drift_events(old, leaf)
        expiry_events = [e for e in events if e.field == "not_after"]
        assert len(expiry_events) == 1
        assert expiry_events[0].severity == "info"

    def test_multiple_events_mixed_severity(self):
        old = _old_row(
            issuer="CN=Old CA", key_algo="RSA-4096", sig_algo="SHA-256",
            posture_grade="A", protocol_version="TLSv1.3",
        )
        leaf = _make_leaf(issuer="CN=New CA")
        events = _compute_drift_events(
            old, leaf, "B", "TLSv1.2", "RSA-2048", "SHA-1",
        )
        high = [e for e in events if e.severity == "high"]
        assert len(high) >= 3  # issuer, key drop, sha1, grade drop, tls downgrade


# ---------- detect_drift ----------


class TestDetectDrift:
    def test_no_history_returns_empty(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        leaf = _make_leaf()
        events = detect_drift(db, "h.example.com", 443, leaf)
        assert events == []

    def test_detects_issuer_change(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _seed_history(db, issuer="CN=Old CA")
        leaf = _make_leaf(issuer="CN=New CA")
        events = detect_drift(db, "h.example.com", 443, leaf)
        issuer_events = [e for e in events if e.field == "issuer"]
        assert len(issuer_events) == 1
        assert issuer_events[0].severity == "high"

    def test_detects_grade_drop(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _seed_history(db, posture_grade="A")
        leaf = _make_leaf()
        events = detect_drift(db, "h.example.com", 443, leaf, posture_grade="B")
        grade_events = [e for e in events if e.field == "posture_grade"]
        assert len(grade_events) == 1
        assert grade_events[0].severity == "high"

    def test_no_drift_when_unchanged(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _seed_history(
            db, issuer="CN=CA",
            posture_grade="A", protocol_version="TLSv1.3",
        )
        leaf = _make_leaf(issuer="CN=CA")
        events = detect_drift(
            db, "h.example.com", 443, leaf,
            posture_grade="A", protocol_version="TLSv1.3",
        )
        assert events == []

    def test_isolates_host_port(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        _seed_history(db, hostname="h1.example.com", port=443, issuer="CN=CA1")
        _seed_history(db, hostname="h2.example.com", port=443, issuer="CN=CA2")
        leaf = _make_leaf(issuer="CN=CA1")
        # h1 should have no drift (same issuer)
        assert detect_drift(db, "h1.example.com", 443, leaf) == []
        # h2 should detect issuer change
        events = detect_drift(db, "h2.example.com", 443, leaf)
        assert any(e.field == "issuer" for e in events)


# ---------- _drift_summary ----------


class TestDriftSummary:
    def test_empty_returns_empty_string(self):
        assert _drift_summary([]) == ""

    def test_high_events_prefixed_with_drift(self):
        events = [DriftEvent("issuer", "CN=Old", "CN=New", "high")]
        s = _drift_summary(events)
        assert s.startswith("DRIFT")
        assert "issuer" in s

    def test_info_events_lowercase_prefix(self):
        events = [DriftEvent("san_count", "1", "2", "info")]
        s = _drift_summary(events)
        assert s.startswith("drift")


# ---------- create_drift_alert ----------


class TestCreateDriftAlert:
    def test_high_events_creates_alert(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        events = [DriftEvent("issuer", "CN=Old", "CN=New", "high")]
        alert_id = create_drift_alert(db, "cert-1", "h.example.com", 443, events)
        assert alert_id is not None
        with _connect(db) as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        assert row is not None
        assert row["alert_type"] == "drift"
        assert "h.example.com" in row["message"]

    def test_info_only_events_returns_none(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        events = [DriftEvent("san_count", "1", "2", "info")]
        alert_id = create_drift_alert(db, "cert-1", "h.example.com", 443, events)
        assert alert_id is None

    def test_no_events_returns_none(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        alert_id = create_drift_alert(db, "cert-1", "h.example.com", 443, [])
        assert alert_id is None

    def test_extra_recipients_passed_through(self, tmp_path):
        db = tmp_path / "cw.sqlite3"
        init_schema(db)
        events = [DriftEvent("issuer", "CN=Old", "CN=New", "high")]
        alert_id = create_drift_alert(
            db, "cert-1", "h.example.com", 443, events,
            extra_recipients=["team@example.com"],
        )
        assert alert_id is not None
        with _connect(db) as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        assert row is not None


# ---------- Config ----------


class TestDriftAlertsConfig:
    def test_default_enabled(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CERT_WATCH_DRIFT_ALERTS", raising=False)
        import importlib

        import cert_watch.config as cfg
        importlib.reload(cfg)
        s = cfg.Settings.from_env()
        assert s.drift_alerts is True

    def test_disabled_via_env(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CERT_WATCH_DRIFT_ALERTS", "0")
        import importlib

        import cert_watch.config as cfg
        importlib.reload(cfg)
        s = cfg.Settings.from_env()
        assert s.drift_alerts is False
