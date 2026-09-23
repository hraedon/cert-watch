"""Persisted alert claims, leases, backoff, and give-up (plan 058 PR 3)."""

from __future__ import annotations

import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.alerting import Dispatcher
from cert_watch.alerting.model import ALERT_MAX_ATTEMPTS, SendResult
from cert_watch.database import Alert, AlertStore, SqliteAlertRepository, init_schema
from cert_watch.database.connection import close_connections
from cert_watch.database.delivery_evidence import list_attempts


class CountingTransport:
    channel = "webhook:generic"
    destination_id = "counting"

    def __init__(self, result: SendResult | None = None) -> None:
        self.result = result if result is not None else SendResult("accepted")
        self._lock = threading.Lock()
        self.counts: dict[str, int] = {}

    def send(self, message):
        with self._lock:
            self.counts[message.cert_id] = self.counts.get(message.cert_id, 0) + 1
        return self.result


def _alert(db: Path, cert_id: str = "cert-1", *, status: str = "pending") -> str:
    return SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status=status,
            message="expires soon",
            threshold_days=7,
        )
    )


def test_two_thread_dispatchers_send_every_alert_exactly_once(tmp_path: Path) -> None:
    db = tmp_path / "claims.sqlite3"
    init_schema(db)
    for number in range(40):
        _alert(db, f"cert-{number}")
    transport = CountingTransport()
    barrier = threading.Barrier(2)
    results: list[dict[str, int]] = []

    def run() -> None:
        try:
            barrier.wait()
            results.append(Dispatcher(db, transports=[transport]).process_pending())
        finally:
            close_connections()

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sum(result["sent"] for result in results) == 40
    assert transport.counts == {f"cert-{number}": 1 for number in range(40)}
    assert {alert.status for alert in SqliteAlertRepository(db).list_all()} == {"sent"}


def test_expired_lease_is_reclaimed_and_old_owner_cannot_complete(tmp_path: Path) -> None:
    db = tmp_path / "reclaim.sqlite3"
    init_schema(db)
    alert_id = _alert(db)
    store = AlertStore(db)
    now = datetime(2026, 9, 22, tzinfo=UTC)

    first = store.claim(
        lease_owner="old",
        lease_expires_at=now + timedelta(seconds=30),
        now=now,
    )
    assert [alert.id for alert in first] == [alert_id]
    assert store.claim(
        lease_owner="early",
        lease_expires_at=now + timedelta(minutes=1),
        now=now + timedelta(seconds=10),
    ) == []

    second = store.claim(
        lease_owner="new",
        lease_expires_at=now + timedelta(minutes=2),
        now=now + timedelta(seconds=31),
    )
    assert [alert.id for alert in second] == [alert_id]
    assert not store.complete_sent(
        alert_id, lease_owner="old", attempts=1, now=now + timedelta(seconds=32)
    )
    stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
    assert stored.status == "sending"
    assert stored.lease_owner == "new"


def test_backoff_schedule_and_give_up_use_injected_clock(tmp_path: Path) -> None:
    db = tmp_path / "backoff.sqlite3"
    init_schema(db)
    _alert(db)
    current = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)
    transport = CountingTransport(
        SendResult("failed", "transport", operator_message="relay unavailable")
    )

    def clock() -> datetime:
        return current

    expected_delays = (timedelta(hours=1), timedelta(hours=4), timedelta(hours=12))
    for round_number, delay in enumerate(expected_delays, start=1):
        result = Dispatcher(db, transports=[transport], clock=clock).process_pending()
        assert result == {"sent": 0, "failed": 0, "deferred": 1}
        stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
        assert stored.status == "pending"
        assert stored.attempt_count == round_number * 3
        assert stored.next_attempt_at == current + delay
        assert Dispatcher(db, transports=[transport], clock=clock).process_pending() == {
            "sent": 0,
            "failed": 0,
            "deferred": 0,
        }
        current += delay

    result = Dispatcher(db, transports=[transport], clock=clock).process_pending()
    assert result == {"sent": 0, "failed": 1, "deferred": 0}
    stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
    assert stored.status == "failed"
    assert stored.attempt_count == ALERT_MAX_ATTEMPTS
    assert stored.failure_reason == "transport"
    assert stored.next_attempt_at is None


@pytest.mark.parametrize(
    "result",
    [
        SendResult(
            "blocked",
            "blocked",
            reached_transport=False,
            operator_message="destination blocked by policy",
        ),
        SendResult(
            "failed",
            "invalid_channel",
            reached_transport=False,
            operator_message="unknown webhook channel",
        ),
    ],
    ids=("ssrf-blocked", "invalid-channel"),
)
def test_pre_transport_policy_failures_reach_give_up(
    tmp_path: Path, result: SendResult
) -> None:
    db = tmp_path / "pre-transport.sqlite3"
    init_schema(db)
    _alert(db)
    current = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)
    transport = CountingTransport(result)

    def clock() -> datetime:
        return current

    for delay in (timedelta(hours=1), timedelta(hours=4), timedelta(hours=12)):
        assert Dispatcher(db, transports=[transport], clock=clock).process_pending() == {
            "sent": 0,
            "failed": 0,
            "deferred": 1,
        }
        current += delay

    assert Dispatcher(db, transports=[transport], clock=clock).process_pending() == {
        "sent": 0,
        "failed": 1,
        "deferred": 0,
    }
    stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
    assert stored.status == "failed"
    assert stored.attempt_count == ALERT_MAX_ATTEMPTS
    assert transport.counts == {"cert-1": ALERT_MAX_ATTEMPTS}


def test_unconfigured_delivery_backs_off_without_spending_attempts(
    tmp_path: Path,
) -> None:
    db = tmp_path / "unconfigured.sqlite3"
    init_schema(db)
    _alert(db)
    current = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)

    def clock() -> datetime:
        return current

    assert Dispatcher(db, transports=[], clock=clock).process_pending() == {
        "sent": 0,
        "failed": 0,
        "deferred": 1,
    }
    stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
    assert stored.status == "pending"
    assert stored.attempt_count == 0
    assert stored.next_attempt_at == current + timedelta(hours=1)

    configured = CountingTransport()
    assert Dispatcher(db, transports=[configured], clock=clock).process_pending() == {
        "sent": 0,
        "failed": 0,
        "deferred": 0,
    }
    current += timedelta(hours=1)
    assert Dispatcher(db, transports=[configured], clock=clock).process_pending() == {
        "sent": 1,
        "failed": 0,
        "deferred": 0,
    }
    assert configured.counts == {"cert-1": 1}


def test_cycle_budget_backs_off_attempted_rows_and_preserves_diagnostics(
    tmp_path: Path,
) -> None:
    db = tmp_path / "cycle-budget.sqlite3"
    init_schema(db)
    first_id = _alert(db, "first")
    second_id = _alert(db, "second")
    with sqlite3.connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET error_message = 'relay timed out' WHERE id = ?",
            (first_id,),
        )
        conn.execute(
            "UPDATE alerts SET error_message = 'waiting for first attempt' WHERE id = ?",
            (second_id,),
        )
        conn.commit()
    times = iter((0.0, 0.0, 2.0))
    now = datetime(2026, 9, 22, 10, 0, tzinfo=UTC)
    transport = CountingTransport(
        SendResult("failed", "transport", operator_message="")
    )

    result = Dispatcher(
        db,
        transports=[transport],
        budget_seconds=1.0,
        clock=lambda: now,
        monotonic_clock=lambda: next(times),
    ).process_pending()

    assert result == {"sent": 0, "failed": 0, "deferred": 2}
    stored = {
        alert.cert_id: alert for alert in SqliteAlertRepository(db).list_all()
    }
    assert stored["first"].attempt_count == 1
    assert stored["first"].next_attempt_at == now + timedelta(hours=1)
    assert stored["first"].error_message == "relay timed out (after 1 attempt)"
    assert stored["second"].attempt_count == 0
    assert stored["second"].next_attempt_at is None
    assert stored["second"].error_message == "waiting for first attempt"


def test_operator_flush_records_evidence_without_spending_give_up_budget(
    tmp_path: Path,
) -> None:
    db = tmp_path / "operator-flush.sqlite3"
    init_schema(db)
    alert_id = _alert(db)
    transport = CountingTransport(
        SendResult(
            "failed", "transport", operator_message="relay unavailable"
        )
    )

    for _ in range(4):
        assert Dispatcher(
            db, transports=[transport], ignore_backoff=True
        ).process_pending() == {"sent": 0, "failed": 0, "deferred": 1}

    stored = SqliteAlertRepository(db).list_for_cert("cert-1")[0]
    assert stored.status == "pending"
    assert stored.attempt_count == 0
    assert len(list_attempts(db, [alert_id])[alert_id]) == 12

    assert Dispatcher(
        db, transports=[transport], ignore_backoff=False
    ).process_pending() == {"sent": 0, "failed": 0, "deferred": 0}


def test_flush_and_scheduler_dispatchers_still_send_once(tmp_path: Path) -> None:
    db = tmp_path / "flush-scheduler.sqlite3"
    init_schema(db)
    _alert(db)
    transport = CountingTransport()
    barrier = threading.Barrier(2)

    def run(ignore_backoff: bool) -> None:
        try:
            barrier.wait()
            Dispatcher(
                db, transports=[transport], ignore_backoff=ignore_backoff
            ).process_pending()
        finally:
            close_connections()

    scheduler = threading.Thread(target=run, args=(False,))
    flush = threading.Thread(target=run, args=(True,))
    scheduler.start()
    flush.start()
    scheduler.join()
    flush.join()

    assert transport.counts == {"cert-1": 1}


def test_migration_0036_upgrades_rows_and_backfills_last_attempt(tmp_path: Path) -> None:
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "pre-0036.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    cases = (
        ("pending-expiry", "pending", "expiry_warning"),
        ("sent-expiry", "sent", "expiry_warning"),
        ("failed-expiry", "failed", "expiry_warning"),
        ("failed-expired", "failed", "expired"),
        ("failed-drift", "failed", "drift"),
    )
    ids = {
        name: repo.create(
            Alert(
                cert_id=f"cert-{name}",
                alert_type=alert_type,
                status=status,
                message=name,
            )
        )
        for name, status, alert_type in cases
    }
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO alert_delivery_events "
            "(attempt_id, alert_id, occurred_at, event_kind, channel, details) "
            "VALUES ('attempt-1', ?, '2026-09-20T10:00:00+00:00', 'started', "
            "'smtp', '{}')",
            (ids["sent-expiry"],),
        )
        conn.execute("DROP INDEX idx_alerts_dispatch")
        for column in (
            "failure_reason",
            "lease_expires_at",
            "lease_owner",
            "last_attempt_at",
            "next_attempt_at",
            "attempt_count",
        ):
            conn.execute(f"ALTER TABLE alerts DROP COLUMN {column}")
        conn.execute("DELETE FROM schema_version WHERE id = '0036'")
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0036"]
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        rows = {
            row["message"]: row
            for row in conn.execute(
                "SELECT message, status, attempt_count, next_attempt_at, "
                "last_attempt_at FROM alerts"
            )
        }
        indexes = {
            row[1] for row in conn.execute("PRAGMA index_list('alerts')")
        }
    assert set(rows) == {name for name, _, _ in cases}
    assert all(row["attempt_count"] == 0 for row in rows.values())
    assert rows["failed-expiry"]["status"] == "pending"
    assert rows["failed-expired"]["status"] == "pending"
    assert rows["failed-drift"]["status"] == "failed"
    assert rows["failed-expiry"]["next_attempt_at"] is None
    assert rows["sent-expiry"]["last_attempt_at"] == "2026-09-20T10:00:00+00:00"
    assert rows["pending-expiry"]["last_attempt_at"] is None
    assert "idx_alerts_dispatch" in indexes
