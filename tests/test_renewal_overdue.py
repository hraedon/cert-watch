"""Tests for renewal-overdue detection (WI-1.2)."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.database.schema import init_schema
from cert_watch.renewal_analytics import (
    RenewalOverdueSignal,
    detect_renewal_overdue,
)
from cert_watch.scheduler import run_scan_now


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _insert_history_row(
    conn,
    hostname: str,
    fingerprint: str,
    issuer: str,
    not_after: str,
    scanned_at: str,
    not_before: str | None = None,
    port: int = 443,
) -> None:
    conn.execute(
        """INSERT INTO cert_history
        (id, hostname, port, fingerprint_sha256, issuer, not_after,
         key_algo, sig_algo, posture_grade, protocol_version, san_count,
         scanned_at, not_before)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()),
            hostname,
            port,
            fingerprint,
            issuer,
            not_after,
            "RSA-2048",
            "SHA-256",
            "A",
            "TLSv1.3",
            1,
            scanned_at,
            not_before,
        ),
    )
    conn.commit()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


class TestDetectRenewalOverdue:
    def test_no_history_returns_none(self, db_path: Path):
        result = detect_renewal_overdue(db_path, "no-such-host.example.com")
        assert result is None

    def test_single_cert_returns_none(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=89)
        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "single.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after),
                _iso(now),
                not_before=_iso(not_before),
            )

        result = detect_renewal_overdue(db_path, "single.example.com")
        assert result is None

    def test_past_expected_renewal_triggers_overdue(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)

        scan_a = now - timedelta(days=185)
        scan_b = now - timedelta(days=125)
        scan_c = now - timedelta(days=65)

        not_after_a = scan_a + timedelta(days=90)
        not_after_b = scan_b + timedelta(days=90)
        not_after_c = scan_c + timedelta(days=90)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "overdue.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after_a),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "overdue.example.com",
                "fp-B",
                "Let's Encrypt Authority X3",
                _iso(not_after_b),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )
            _insert_history_row(
                conn,
                "overdue.example.com",
                "fp-C",
                "Let's Encrypt Authority X3",
                _iso(not_after_c),
                _iso(scan_c),
                not_before=_iso(scan_c),
            )

        result = detect_renewal_overdue(db_path, "overdue.example.com")
        assert result is not None
        assert isinstance(result, RenewalOverdueSignal)
        assert result.hostname == "overdue.example.com"
        assert result.cert_fingerprint == "fp-C"
        assert result.confidence == "low"
        assert result.days_overdue > 0
        assert result.expected_renewal_at_days == 30.0
        assert result.days_remaining < 30

    def test_high_confidence_with_5_plus_renewals(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)

        with sqlite3.connect(str(db_path)) as conn:
            for i in range(7):
                scan_time = now - timedelta(days=425 - i * 60)
                not_after = scan_time + timedelta(days=90)
                _insert_history_row(
                    conn,
                    "high.example.com",
                    f"fp-{i}",
                    "Let's Encrypt Authority X3",
                    _iso(not_after),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        result = detect_renewal_overdue(db_path, "high.example.com")
        assert result is not None
        assert result.confidence == "high"
        assert result.cert_fingerprint == "fp-6"

    def test_medium_confidence_with_3_to_4_renewals(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)

        with sqlite3.connect(str(db_path)) as conn:
            for i in range(5):
                scan_time = now - timedelta(days=305 - i * 60)
                not_after = scan_time + timedelta(days=90)
                _insert_history_row(
                    conn,
                    "medium.example.com",
                    f"fp-{i}",
                    "Let's Encrypt Authority X3",
                    _iso(not_after),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        result = detect_renewal_overdue(db_path, "medium.example.com")
        assert result is not None
        assert result.confidence == "medium"
        assert result.cert_fingerprint == "fp-4"

    def test_renewed_cert_returns_none(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)

        scan_a = now - timedelta(days=100)
        scan_b = now - timedelta(days=40)

        not_after_a = scan_a + timedelta(days=90)
        not_after_b = scan_b + timedelta(days=90)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "renewed.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after_a),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "renewed.example.com",
                "fp-B",
                "Let's Encrypt Authority X3",
                _iso(not_after_b),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )

        result = detect_renewal_overdue(db_path, "renewed.example.com")
        assert result is None

    def test_not_past_expected_renewal_returns_none(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)

        scan_a = now - timedelta(days=80)
        scan_b = now - timedelta(days=20)

        not_after_a = scan_a + timedelta(days=90)
        not_after_b = scan_b + timedelta(days=90)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "fresh.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after_a),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "fresh.example.com",
                "fp-B",
                "Let's Encrypt Authority X3",
                _iso(not_after_b),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )

        result = detect_renewal_overdue(db_path, "fresh.example.com")
        assert result is None


class TestSchedulerRenewalOverdue:
    def test_run_scan_now_emits_renewal_overdue_event(self, db_path: Path):
        import sqlite3

        from cert_watch.database import SqliteHostRepository

        SqliteHostRepository(db_path).add("overdue.example.com", 443)

        now = datetime.now(UTC)

        scan_a = now - timedelta(days=185)
        scan_b = now - timedelta(days=125)
        scan_c = now - timedelta(days=65)

        with sqlite3.connect(str(db_path)) as conn:
            for scan_time, fp in [
                (scan_a, "fp-A"),
                (scan_b, "fp-B"),
                (scan_c, "fp-C"),
            ]:
                _insert_history_row(
                    conn,
                    "overdue.example.com",
                    fp,
                    "Let's Encrypt Authority X3",
                    _iso(scan_time + timedelta(days=90)),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        def scan_fn(hostname, port):
            from dataclasses import dataclass

            @dataclass
            class FakeResult:
                host: str
                port: int

            return FakeResult(host=hostname, port=port)

        def store_fn(result):
            pass

        def alert_fn():
            return {"sent": 0, "failed": 0}

        run_scan_now(
            scan_fn,
            alert_fn,
            db_path=db_path,
            host_provider=lambda: [("overdue.example.com", 443)],
            store_fn=store_fn,
        )

        import json

        from cert_watch.events import get_events

        evts = get_events(db_path, event_type="renewal_overdue")
        assert len(evts) == 1
        payload = json.loads(evts[0]["payload"])
        assert payload["hostname"] == "overdue.example.com"
        assert payload["cert_fingerprint"] == "fp-C"
        assert payload["confidence"] == "low"

    def test_run_scan_now_no_event_when_not_overdue(self, db_path: Path):
        from cert_watch.database import SqliteHostRepository

        SqliteHostRepository(db_path).add("fresh.example.com", 443)

        now = datetime.now(UTC)
        scan_a = now - timedelta(days=80)
        scan_b = now - timedelta(days=20)

        import sqlite3

        with sqlite3.connect(str(db_path)) as conn:
            for scan_time, fp in [(scan_a, "fp-A"), (scan_b, "fp-B")]:
                _insert_history_row(
                    conn,
                    "fresh.example.com",
                    fp,
                    "Let's Encrypt Authority X3",
                    _iso(scan_time + timedelta(days=90)),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        def scan_fn(hostname, port):
            from dataclasses import dataclass

            @dataclass
            class FakeResult:
                host: str
                port: int

            return FakeResult(host=hostname, port=port)

        def alert_fn():
            return {"sent": 0, "failed": 0}

        run_scan_now(
            scan_fn,
            alert_fn,
            db_path=db_path,
            host_provider=lambda: [("fresh.example.com", 443)],
        )

        from cert_watch.events import get_events

        evts = get_events(db_path, event_type="renewal_overdue")
        assert len(evts) == 0

    def test_run_scan_no_db_path_skips_overdue(self):
        def scan_fn(hostname, port):
            from dataclasses import dataclass

            @dataclass
            class FakeResult:
                host: str
                port: int

            return FakeResult(host=hostname, port=port)

        def alert_fn():
            return {"sent": 0, "failed": 0}

        result = run_scan_now(
            scan_fn,
            alert_fn,
            host_provider=lambda: [("any.example.com", 443)],
        )
        assert result["scanned"] == 1

    def test_check_renewal_overdue_failure_isolated(self, db_path: Path):
        from cert_watch.scheduler import _check_renewal_overdue

        _check_renewal_overdue(db_path, [("invalid!", 443)])
