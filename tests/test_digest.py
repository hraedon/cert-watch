"""Tests for renewal digest (WI-3.1 / Plan 048)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.digest import (
    build_renewal_digest,
    send_renewal_digest,
)
from cert_watch.events import Event, emit_event


def _add_host(db: Path, hostname: str, owner_email: str = ""):
    repo = SqliteHostRepository(db)
    repo.add(hostname, owner_name="Owner", owner_email=owner_email)


def _emit_renewal(db: Path, hostname: str, cert_id: str = "c1"):
    emit_event(
        Event(
            event_type="cert_renewed",
            timestamp=datetime.now(UTC),
            payload={"hostname": hostname, "cert_id": cert_id},
            source="scan",
        ),
        db,
    )


def _emit_overdue(db: Path, hostname: str, cert_id: str = "c1"):
    emit_event(
        Event(
            event_type="renewal_overdue",
            timestamp=datetime.now(UTC),
            payload={
                "hostname": hostname,
                "cert_fingerprint": "aa" * 32,
                "days_remaining": 3,
                "expected_renewal_at_days": 7,
                "days_overdue": 4,
                "confidence": "medium",
            },
            source="scheduler",
        ),
        db,
    )


@pytest.fixture
def empty_db(tmp_path) -> str:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)
    return str(db)


class TestBuildRenewalDigest:
    def test_zero_activity_returns_empty(self, empty_db):
        result = build_renewal_digest(empty_db, days=7)
        assert result == []

    def test_mixed_week_produces_digest(self, empty_db):
        db = empty_db
        _add_host(db, "host-a.example.com")
        _add_host(db, "host-b.example.com")
        _emit_renewal(db, "host-a.example.com")
        _emit_overdue(db, "host-b.example.com")
        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.renewed_count == 1
        assert "host-a.example.com" in digest.renewed_hosts
        assert digest.overdue_count == 1
        assert "host-b.example.com" in digest.overdue_hosts

    def test_per_owner_routing(self, empty_db):
        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@example.com")
        _add_host(db, "host-b.example.com", owner_email="bob@example.com")
        _emit_renewal(db, "host-a.example.com")
        _emit_overdue(db, "host-b.example.com")
        result = build_renewal_digest(db, days=7)
        by_owner = {d.owner_email: d for d in result}
        assert "alice@example.com" in by_owner
        assert "bob@example.com" in by_owner
        assert by_owner["alice@example.com"].renewed_count == 1
        assert by_owner["bob@example.com"].overdue_count == 1

    def test_events_outside_window_ignored(self, empty_db):
        db = empty_db
        _add_host(db, "host-old.example.com")
        old = datetime.now(UTC) - timedelta(days=10)
        emit_event(
            Event(
                event_type="cert_renewed",
                timestamp=old,
                payload={"hostname": "host-old.example.com", "cert_id": "old"},
                source="scan",
            ),
            db,
        )
        result = build_renewal_digest(db, days=7)
        assert result == []

    def test_multiple_renewals_same_host_aggregated(self, empty_db):
        db = empty_db
        _add_host(db, "host-multi.example.com")
        _emit_renewal(db, "host-multi.example.com", "c1")
        _emit_renewal(db, "host-multi.example.com", "c2")
        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        assert result[0].renewed_count == 2
        assert result[0].renewed_hosts == ["host-multi.example.com"]


class TestSendRenewalDigest:
    def test_no_configs_returns_false(self, empty_db):
        result = send_renewal_digest(empty_db, None, None, days=7)
        assert result is False

    def test_zero_activity_returns_true(self, empty_db):
        from cert_watch.alerts import AlertConfig

        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["c@d"],
        )
        result = send_renewal_digest(empty_db, config, None, days=7)
        assert result is True

    def test_with_activity_sends_smtp(self, empty_db):
        from unittest.mock import MagicMock, patch

        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
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
            result = send_renewal_digest(db, config, None, days=7)
        assert result is True
        smtp_mock.send_message.assert_called()
