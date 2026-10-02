"""Delivery deadlines wake the scheduler independently of host scan cadence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest

from cert_watch.alerting import Dispatcher
from cert_watch.config import Settings
from cert_watch.database import Alert, AlertStore, SqliteAlertRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.scheduler import Scheduler
from cert_watch.scheduler_context import SchedulerContext

NOW = datetime(2026, 10, 2, 6, 0, 1, tzinfo=UTC)


def _seed_alert(db, state, *, due_at=None):
    store = AlertStore(db)
    alert_id = SqliteAlertRepository(db).create(Alert(
        cert_id="delivery-cert", alert_type="expiry_warning", message="expires soon",
        threshold_days=7, status="pending",
    ))
    if state == "pending" and due_at is None:
        return alert_id
    store.claim(
        lease_owner="previous-worker", now=NOW - timedelta(hours=1),
        lease_expires_at=due_at or NOW + timedelta(minutes=5),
    )
    if state == "pending":
        store.complete_pending(
            alert_id, lease_owner="previous-worker", attempts=3,
            now=NOW - timedelta(hours=1), next_attempt_at=due_at,
        )
    elif state == "sent":
        store.complete_sent(
            alert_id, lease_owner="previous-worker", attempts=1, now=NOW,
        )
    return alert_id


def _run_scheduler(settings, on_wait, delivery):
    """Drive the real loop synchronously with bounded, deterministic clock steps."""
    waits = []
    cycles = []

    class Clock:
        current = NOW

        def now(self):
            return self.current

        def monotonic(self):
            return (self.current - NOW).total_seconds()

        def wait(self, event, timeout):
            waits.append(timeout)
            self.current += timedelta(seconds=timeout)
            on_wait(len(waits), timeout, runtime)
            return event.is_set()

    clock = Clock()
    context = SchedulerContext(settings, None, None)
    context.scan_all = Mock(return_value={})
    context.maybe_run_weekly_digest = Mock(return_value={})
    context.maintenance = Mock()

    def run_delivery():
        cycles.append(clock.now())
        return delivery(clock.now, runtime)

    context.run_alerts = run_delivery
    runtime = Scheduler(context, clock=clock)
    runtime._run_loop(runtime.stop_event)
    return waits, cycles


@pytest.mark.parametrize("state,delay", [
    ("pending", timedelta(minutes=30)),
    ("sending", timedelta(minutes=20)),
])
def test_delivery_runs_when_due_without_due_hosts(tmp_path, fake_transport, state, delay):
    settings = Settings(db_path=tmp_path / "queue.sqlite3", data_dir=tmp_path)
    init_schema(settings.db_path)
    due_at = NOW + delay if delay is not None else None
    alert_id = _seed_alert(settings.db_path, state, due_at=due_at)
    transport = fake_transport()

    def on_wait(number, _timeout, runtime):
        if number == 3:
            runtime.stop_event.set()

    def deliver(clock, runtime):
        result = Dispatcher(
            settings.db_path, transports=[transport], clock=clock,
        ).process_pending()
        if result["sent"]:
            runtime.stop_event.set()
        return result

    waits, cycles = _run_scheduler(settings, on_wait, deliver)

    assert len(transport.messages) == 1
    assert SqliteAlertRepository(settings.db_path).list_all()[0].id == alert_id
    assert SqliteAlertRepository(settings.db_path).list_all()[0].status == "sent"
    # A sending lease is reclaimable strictly after its expiry. An exact
    # boundary wake may take the loop's existing one-minute follow-up.
    expected_due = due_at or NOW
    assert expected_due <= cycles[-1] <= expected_due + timedelta(minutes=1)
    assert waits[0] <= (expected_due - NOW).total_seconds()


def test_disabled_delivery_keeps_hourly_backoff(tmp_path):
    settings = Settings(db_path=tmp_path / "queue.sqlite3", data_dir=tmp_path)
    init_schema(settings.db_path)
    _seed_alert(settings.db_path, "pending")
    Dispatcher(
        settings.db_path, transports=[], clock=lambda: NOW,
    ).process_pending()

    def on_wait(number, _timeout, runtime):
        if number == 3:
            runtime.stop_event.set()

    def deliver(clock, _runtime):
        return Dispatcher(settings.db_path, transports=[], clock=clock).process_pending()

    waits, cycles = _run_scheduler(settings, on_wait, deliver)

    assert cycles == [NOW + timedelta(hours=1), NOW + timedelta(hours=2)]
    assert waits == [3600, 3600, 3600]
    alert = SqliteAlertRepository(settings.db_path).list_all()[0]
    assert alert.status == "pending"
    assert alert.attempt_count == 0
    assert alert.next_attempt_at == NOW + timedelta(hours=3)


def test_new_pending_alert_preserves_first_delivery_cadence(tmp_path):
    settings = Settings(db_path=tmp_path / "queue.sqlite3", data_dir=tmp_path)
    init_schema(settings.db_path)
    _seed_alert(settings.db_path, "pending")
    delivery = Mock(return_value={})

    def on_wait(number, _timeout, runtime):
        if number == 2:
            runtime.stop_event.set()

    waits, cycles = _run_scheduler(settings, on_wait, delivery)

    assert waits == [3600, 3600]
    assert cycles == []
    delivery.assert_not_called()


def test_completed_alert_does_not_request_delivery_cycle(tmp_path):
    settings = Settings(db_path=tmp_path / "queue.sqlite3", data_dir=tmp_path)
    init_schema(settings.db_path)
    _seed_alert(settings.db_path, "sent")
    delivery = Mock()

    def on_wait(number, _timeout, runtime):
        if number == 2:
            runtime.stop_event.set()

    waits, cycles = _run_scheduler(settings, on_wait, delivery)

    assert waits == [3600, 3600]
    assert cycles == []
    delivery.assert_not_called()


@pytest.mark.parametrize("due_hint", ["scan", "rule_pass"])
def test_malformed_delivery_deadline_preserves_other_due_work(tmp_path, monkeypatch, due_hint):
    settings = Settings(db_path=tmp_path / "queue.sqlite3", data_dir=tmp_path)
    init_schema(settings.db_path)
    alert_id = _seed_alert(settings.db_path, "pending")
    with _connect(settings.db_path) as conn:
        conn.execute(
            "UPDATE alerts SET next_attempt_at = ? WHERE id = ?",
            ("!malformed", alert_id),
        )
        conn.commit()
    due_at = NOW + timedelta(minutes=2)
    monkeypatch.setattr(
        f"cert_watch.scheduler._seconds_until_next_{due_hint}",
        lambda *args, now, **kwargs: max(0, (due_at - now).total_seconds()),
    )

    def on_wait(number, _timeout, runtime):
        if number == 2:
            runtime.stop_event.set()

    def deliver(_clock, runtime):
        runtime.stop_event.set()
        return {}

    waits, cycles = _run_scheduler(settings, on_wait, deliver)

    assert waits[0] == 120
    assert cycles == [due_at]
