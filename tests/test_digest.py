"""Tests for renewal digest (WI-3.1 / Plan 048)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.alerting.digest.renewal import build_renewal_digest
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.events import Event, emit_event


def _add_host(db: Path, hostname: str, owner_email: str = ""):
    repo = SqliteHostRepository(db)
    repo.add(hostname, owner_name="Owner", owner_email=owner_email)


def _emit_renewal(db: Path, hostname: str, cert_id: str = "c1"):
    emit_event(
        Event(
            event_type="cert_renewed",
            timestamp=datetime.now(UTC),
            payload={"hostname": hostname, "port": 443, "cert_id": cert_id},
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
                "port": 443,
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


class TestDigestExpiry:
    """The digest body shows each host's current cert expiry (not_after)."""

    def test_message_includes_expiry_per_host(self, empty_db):
        from cert_watch.alerting.digest.renewal import _build_digest_message
        from cert_watch.certificate_model import Certificate
        from cert_watch.database import record_cert_history
        from tests._helpers import seed_certificate

        db = empty_db
        _add_host(db, "host-renewed.example.com")
        _add_host(db, "host-overdue.example.com")

        def _seed(hostname: str, not_after: datetime, fp: str) -> None:
            cert = Certificate(
                subject=f"CN={hostname}", issuer="CN=CA",
                not_before=datetime(2026, 1, 1, tzinfo=UTC), not_after=not_after,
                san_dns_names=[hostname], fingerprint_sha256=fp, raw_der=b"", is_leaf=True,
            )
            seed_certificate(db, cert, hostname=hostname, port=443)
            record_cert_history(
                db, hostname, 443, cert,
                scanned_at=datetime.now(UTC).isoformat(),
            )

        _seed("host-renewed.example.com", datetime(2026, 12, 31, tzinfo=UTC), "fp1")
        _seed("host-overdue.example.com", datetime(2026, 8, 20, tzinfo=UTC), "fp2")

        _emit_renewal(db, "host-renewed.example.com")
        _emit_overdue(db, "host-overdue.example.com")

        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.host_expiry.get("host-renewed.example.com") is not None
        assert digest.host_expiry.get("host-overdue.example.com") is not None

        msg = _build_digest_message(digest)
        assert "expires 2026-12-31" in msg  # renewed host
        assert "expires 2026-08-20" in msg  # overdue host

    def test_message_without_history_omits_expiry(self, empty_db):
        from cert_watch.alerting.digest.renewal import _build_digest_message

        db = empty_db
        _add_host(db, "host-nohistory.example.com")
        _emit_renewal(db, "host-nohistory.example.com")

        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.host_expiry.get("host-nohistory.example.com") is None

        msg = _build_digest_message(digest)
        assert "expires" not in msg
