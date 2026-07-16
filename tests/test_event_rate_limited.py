"""Tests for rate_limited event delivery status visibility."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cert_watch.database import init_schema
from cert_watch.events import get_events, get_failed_deliveries


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_schema(db_path)
    return db_path


def _insert_event(db, delivery_status):
    from cert_watch.database.connection import _connect

    now = datetime.now(UTC).isoformat()
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO event_log"
            " (event_type, timestamp, source, payload,"
            " delivery_status, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            ("cert_added", now, "scan", "{}", delivery_status, now),
        )
        conn.commit()


class TestRateLimitedVisibility:
    def test_rate_limited_events_included_in_failed_deliveries(self, db):
        _insert_event(db, "failed")
        _insert_event(db, "rate_limited")
        failures = get_failed_deliveries(db)
        assert len(failures) == 2
        statuses = {f["delivery_status"] for f in failures}
        assert statuses == {"failed", "rate_limited"}

    def test_rate_limited_status_in_get_events(self, db):
        _insert_event(db, "rate_limited")
        events = get_events(db)
        assert len(events) == 1
        assert events[0]["delivery_status"] == "rate_limited"

    def test_delivered_events_excluded_from_failed(self, db):
        _insert_event(db, "delivered")
        _insert_event(db, "failed")
        _insert_event(db, "rate_limited")
        failures = get_failed_deliveries(db)
        assert len(failures) == 2
        statuses = {f["delivery_status"] for f in failures}
        assert "delivered" not in statuses
        assert statuses == {"failed", "rate_limited"}

    def test_pending_events_excluded_from_failed(self, db):
        _insert_event(db, "pending")
        _insert_event(db, "failed")
        failures = get_failed_deliveries(db)
        assert len(failures) == 1
        assert failures[0]["delivery_status"] == "failed"
