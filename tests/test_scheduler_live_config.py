"""Regressions for effective settings and host cadence at real job boundaries."""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from starlette.testclient import TestClient

import cert_watch.scheduler as scheduler
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema, kv_set
from cert_watch.routes.hosts import _scan_and_store
from cert_watch.routes.settings.core import _rebuild_settings
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.scheduler_context import SchedulerContext


def _settings(tmp_path, **kwargs):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    return Settings(db_path=db, data_dir=tmp_path, **kwargs)


def test_saved_settings_reach_existing_scheduler_job(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    context = SchedulerContext(settings, None, None)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(
        settings=settings, scheduler_context=context,
    )))
    for key, value in {
        "smtp_host": "new-relay.example.invalid", "alert_from": "watch@example.invalid",
        "alert_recipients": "operator@example.invalid", "sched_hour": "20",
        "renewal_window_days": "17",
    }.items():
        kv_set(settings.db_path, key, value)
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    delivered = Mock(return_value={"sent": 0, "failed": 0})
    renewal = Mock()
    monkeypatch.setattr("cert_watch.alerts.process_pending", delivered)
    monkeypatch.setattr("cert_watch.alerts.evaluate_all_certs", Mock())
    monkeypatch.setattr("cert_watch.alerts.evaluate_renewal_window", renewal)

    _rebuild_settings(request, settings.db_path)
    context.run_alerts()

    assert delivered.call_args.args[1].smtp_host == "new-relay.example.invalid"
    assert renewal.call_args.args[2] == 17
    assert context.settings.sched_hour == 20


def test_scheduled_scan_selects_due_hosts_only(monkeypatch, tmp_path):
    settings = _settings(tmp_path)
    repo = SqliteHostRepository(settings.db_path)
    now = datetime.now(UTC)
    for hostname, interval, age in [("due.example.invalid", 1, 2),
                                    ("fresh.example.invalid", 72, 0)]:
        repo.add(hostname, 443, scan_interval_hours=interval)
        record_scan_history(settings.db_path, ScanHistory(
            hostname, 443, "success", scanned_at=now - timedelta(hours=age),
        ))
    scan = Mock(return_value=object())
    monkeypatch.setattr("cert_watch.scheduler_context.scan_host", scan)
    monkeypatch.setattr("cert_watch.scheduler_context._evaluate_posture", Mock())
    monkeypatch.setattr("cert_watch.scheduler_context.store_scanned", Mock(return_value="leaf"))
    monkeypatch.setattr("cert_watch.scan._execute_deferred_post_commit", Mock())
    monkeypatch.setattr("cert_watch.scheduler._check_renewal_overdue", Mock())

    result = SchedulerContext(settings, None, None).scan_all()

    assert [call.args[:2] for call in scan.call_args_list] == [("due.example.invalid", 443)]
    assert result["scanned"] == 1


def test_explicit_scan_honors_tls_and_drift_settings(monkeypatch, tmp_path):
    settings = _settings(tmp_path, tls_verify=True, drift_alerts=False)
    scan = AsyncMock(return_value=object())
    store = AsyncMock(return_value="leaf")
    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", scan)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", store)

    result = asyncio.run(_scan_and_store(
        "manual.example.invalid", 443, settings.db_path, settings,
        pinned_ip=None, starttls_mode="", source="manual",
    ))

    assert result == ("success", None)
    assert scan.call_args.kwargs.get("verify", False) is True
    assert store.call_args.kwargs.get("drift_alerts", True) is False


@pytest.mark.parametrize("from_environment", [True, False])
def test_renewal_zero_disables_from_env_and_saved_settings(monkeypatch, tmp_path, from_environment):
    settings = _settings(tmp_path)
    if from_environment:
        monkeypatch.setenv("CERT_WATCH_RENEWAL_WINDOW_DAYS", "0")
    else:
        monkeypatch.delenv("CERT_WATCH_RENEWAL_WINDOW_DAYS", raising=False)
        kv_set(settings.db_path, "renewal_window_days", "0")
    assert Settings.from_env_with_kv(settings.db_path).renewal_window_days == 0


@pytest.mark.parametrize("key,value,default", [("sched_hour", "24", 6),
                                              ("sched_min", "-1", 0)])
def test_invalid_saved_schedule_cannot_kill_timer(monkeypatch, tmp_path, key, value, default):
    settings = _settings(tmp_path)
    monkeypatch.delenv("CERT_WATCH_SCHED_HOUR", raising=False)
    monkeypatch.delenv("CERT_WATCH_SCHED_MIN", raising=False)
    kv_set(settings.db_path, key, value)
    assert getattr(Settings.from_env_with_kv(settings.db_path), key) == default


@pytest.mark.parametrize("environment_hour", [None, "3"])
def test_lifespan_jobs_use_saved_configuration_without_restart(
    monkeypatch, reload_app, environment_hour,
):
    if environment_hour:
        monkeypatch.setenv("CERT_WATCH_SCHED_HOUR", environment_hour)
    jobs = {}
    monkeypatch.setattr("cert_watch.app.start_scheduler", lambda **kwargs: jobs.update(kwargs))
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    wake = Mock()
    monkeypatch.setattr("cert_watch.scheduler_context.wake_scheduler", wake)
    delivered = Mock(return_value={"sent": 0, "failed": 0})
    monkeypatch.setattr("cert_watch.alerts.process_pending", delivered)
    app = reload_app().app
    with TestClient(app) as client:
        smtp = client.post("/settings/smtp", data={
            "smtp_host": "saved.example.invalid", "smtp_port": "587",
            "alert_from": "watch@example.invalid", "alert_recipients": "ops@example.invalid",
        }, follow_redirects=False)
        alerts = client.post("/settings/alerts", data={
            "sched_hour": "20", "sched_min": "15", "renewal_window_days": "0",
        }, follow_redirects=False)
        assert smtp.status_code == alerts.status_code == 303
        assert "saved=1" in smtp.headers["location"]
        assert "saved=1" in alerts.headers["location"]
        assert jobs["scan_fn"].__self__ is app.state.scheduler_context
        assert jobs["schedule_provider"]() == (int(environment_hour or "20"), 15)
        assert app.state.scheduler_context.settings.renewal_window_days == 0
        jobs["alert_fn"]()
    assert delivered.call_args.args[1].smtp_host == "saved.example.invalid"
    assert wake.call_count == 2


class _Clock(datetime):
    current = datetime(2026, 9, 12, 12, tzinfo=UTC)

    @classmethod
    def now(cls, tz=None):
        return cls.current if tz is None else cls.current.astimezone(tz)


def _freeze(monkeypatch):
    _Clock.current = datetime(2026, 9, 12, 12, tzinfo=UTC)
    monkeypatch.setattr(scheduler, "datetime", _Clock)


def _history(settings, hostname, status="success", *, age=timedelta()):
    record_scan_history(settings.db_path, ScanHistory(
        hostname, 443, status, scanned_at=_Clock.current - age,
    ))


@pytest.mark.parametrize("interval", [None, 0, -1])
def test_default_daily_host_waits_for_boundary_even_during_interval_cycles(
    monkeypatch, tmp_path, interval,
):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)
    SqliteHostRepository(settings.db_path).add("daily.example.invalid", 443,
                                            scan_interval_hours=interval)
    _history(settings, "daily.example.invalid", age=timedelta(hours=1))

    assert scheduler.get_hosts_due_for_scan(settings.db_path) == []
    assert scheduler._seconds_until_next_scan(settings.db_path, 6, 0) == 18 * 3600
    _Clock.current += timedelta(hours=18)
    assert scheduler.get_hosts_due_for_scan(settings.db_path) == [("daily.example.invalid", 443)]


def test_failed_interval_scan_retries_after_one_hour_without_spinning(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)
    SqliteHostRepository(settings.db_path).add("retry.example.invalid", 443,
                                            scan_interval_hours=1)
    _history(settings, "retry.example.invalid", age=timedelta(hours=2))
    _history(settings, "retry.example.invalid", "failure", age=timedelta(minutes=10))

    assert scheduler.get_hosts_due_for_scan(settings.db_path) == []
    assert scheduler._seconds_until_next_scan(settings.db_path, 6, 0) == 50 * 60
    _Clock.current += timedelta(minutes=50)
    assert scheduler.get_hosts_due_for_scan(settings.db_path) == [("retry.example.invalid", 443)]


def test_never_attempted_host_keeps_hourly_wakeup_and_is_eligible_in_any_cycle(
    monkeypatch, tmp_path,
):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)
    SqliteHostRepository(settings.db_path).add("new.example.invalid", 443)
    assert scheduler.get_hosts_due_for_scan(settings.db_path) == [("new.example.invalid", 443)]
    assert scheduler._seconds_until_next_scan(settings.db_path, 6, 0) == 3600


def test_explicit_scan_bypasses_cadence(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)
    SqliteHostRepository(settings.db_path).add("manual.example.invalid", 443,
                                            scan_interval_hours=72)
    _history(settings, "manual.example.invalid")
    assert scheduler.get_hosts_due_for_scan(settings.db_path) == []
    scan = AsyncMock(return_value=object())
    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", scan)
    monkeypatch.setattr(
        "cert_watch.routes.hosts.store_scanned_async", AsyncMock(return_value="leaf"),
    )
    assert asyncio.run(_scan_and_store(
        "manual.example.invalid", 443, settings.db_path, settings,
        pinned_ip=None, starttls_mode="", source="manual",
    )) == ("success", None)
    scan.assert_awaited_once()


def _drive_timer(monkeypatch, settings, on_wait, *, scan_fn=None, schedule_provider=None):
    """Run the real scheduler loop with a deterministic clock/event, no sleeping."""
    stop = threading.Event()
    waits = []

    class Wake:
        signalled = False

        def clear(self):
            self.signalled = False

        def set(self):
            self.signalled = True

        def wait(self, timeout):
            waits.append(timeout)
            on_wait(len(waits), timeout, stop)
            return self.signalled

    wake = Wake()
    monkeypatch.setattr(scheduler, "_scheduler_stop", stop)
    monkeypatch.setattr(scheduler, "_scheduler_wake", wake)
    monkeypatch.setattr(scheduler, "_scheduler_thread", None)
    monkeypatch.setattr(scheduler, "_start_renewal_webhook_pool", Mock())
    monkeypatch.setattr("cert_watch.digest.start_digest_pool", Mock())
    monkeypatch.setattr(scheduler, "_detach_renewal_webhook_pool", Mock(return_value=None))
    monkeypatch.setattr("cert_watch.digest._detach_digest_pool", Mock(return_value=None))
    monkeypatch.setattr(scheduler.threading, "Thread", lambda **kwargs: SimpleNamespace(
        start=kwargs["target"], is_alive=lambda: False, join=Mock(),
    ))
    scheduler.start_scheduler(
        scan_fn=scan_fn or Mock(return_value={}), alert_fn=Mock(return_value={}),
        db_path=settings.db_path, hour=settings.sched_hour, minute=settings.sched_min,
        schedule_provider=schedule_provider,
    )
    return waits


def test_scheduler_wakes_when_hourly_host_becomes_due(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)
    SqliteHostRepository(settings.db_path).add("hourly.example.invalid", 443,
                                            scan_interval_hours=1)
    _history(settings, "hourly.example.invalid", age=timedelta(minutes=30))
    scanned = []

    def on_wait(number, timeout, stop):
        assert number == 1
        assert timeout == 1800
        _Clock.current += timedelta(seconds=timeout)

    def scan():
        scanned.extend(scheduler.get_hosts_due_for_scan(settings.db_path))
        scheduler._scheduler_stop.set()
        return {}

    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan)
    assert scanned == [("hourly.example.invalid", 443)]


@pytest.mark.parametrize("settings_wakeup", [False, True])
def test_hourly_recheck_crossing_daily_deadline_runs_cycle_once(
    monkeypatch, tmp_path, settings_wakeup,
):
    _freeze(monkeypatch)
    _Clock.current = datetime(2026, 9, 12, 11, 59, 59, 999999, tzinfo=UTC)
    settings = _settings(tmp_path, sched_hour=13)
    context = SchedulerContext(settings, None, None)

    def on_wait(number, timeout, stop):
        if number == 1:
            assert timeout == 3600
            # OS scheduling need only overshoot by a millisecond to cross the
            # daily boundary. This matters even with no live-scanned hosts.
            _Clock.current += timedelta(seconds=timeout, milliseconds=1)
            if settings_wakeup:
                context.update_settings(replace(settings, renewal_window_days=17))
        elif number == 2 and settings_wakeup:
            assert timeout == 0
        else:
            assert number == (3 if settings_wakeup else 2)
            stop.set()

    scan = Mock(return_value={})
    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan,
                 schedule_provider=context.schedule_time)
    scan.assert_called_once()


@pytest.mark.parametrize("old_time,new_time,old_wait,new_wait", [
    ((20, 0), (12, 15), 3600, 900), ((12, 15), (20, 0), 900, 3600),
])
def test_settings_save_interrupts_timer_and_reads_new_schedule(
    monkeypatch, tmp_path, old_time, new_time, old_wait, new_wait,
):
    _freeze(monkeypatch)
    settings = _settings(tmp_path, sched_hour=old_time[0], sched_min=old_time[1])
    context = SchedulerContext(settings, None, None)

    def on_wait(number, timeout, stop):
        if number == 1:
            assert timeout == old_wait
            context.update_settings(replace(
                settings, sched_hour=new_time[0], sched_min=new_time[1],
            ))
        else:
            assert number == 2
            assert timeout == new_wait
            stop.set()

    scan = Mock(return_value={})
    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan,
                 schedule_provider=context.schedule_time)
    scan.assert_not_called()


def test_early_interval_cycle_preserves_future_daily_cycle(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path, sched_hour=13)
    SqliteHostRepository(settings.db_path).add("hourly.example.invalid", 443,
                                            scan_interval_hours=1)
    _history(settings, "hourly.example.invalid", age=timedelta(minutes=30))
    cycles = []

    def on_wait(number, timeout, stop):
        if number < 3:
            assert timeout == 1800
            _Clock.current += timedelta(seconds=timeout)
        else:
            assert number == 3
            stop.set()

    def scan():
        due = scheduler.get_hosts_due_for_scan(settings.db_path, hour=13)
        cycles.append(due)
        for hostname, _ in due:
            _history(settings, hostname)
        return {}

    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan)
    assert cycles == [[("hourly.example.invalid", 443)], []]


def test_actual_schedule_change_replaces_elapsed_daily_target(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path, sched_hour=13)
    context = SchedulerContext(settings, None, None)

    def on_wait(number, timeout, stop):
        if number == 1:
            _Clock.current += timedelta(seconds=timeout, milliseconds=1)
            context.update_settings(replace(settings, sched_hour=14))
        else:
            assert number == 2
            assert 3500 < timeout < 3600
            stop.set()

    scan = Mock(return_value={})
    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan,
                 schedule_provider=context.schedule_time)
    scan.assert_not_called()


def test_timer_stop_interrupts_wait_without_running_jobs(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    settings = _settings(tmp_path)

    def on_wait(number, timeout, stop):
        assert number == 1
        scheduler.stop_scheduler()

    scan = Mock(return_value={})
    _drive_timer(monkeypatch, settings, on_wait, scan_fn=scan)
    scan.assert_not_called()


def test_scan_keeps_one_snapshot_through_mid_job_settings_update(monkeypatch, tmp_path):
    _freeze(monkeypatch)
    monkeypatch.setattr("cert_watch.http_client.validate_webhook_url", lambda *a, **kw: None)
    settings = _settings(tmp_path, tls_verify=True, drift_alerts=False,
                         webhook_url="https://old.example.invalid")
    context = SchedulerContext(settings, None, settings.build_webhook_config())
    for hostname in ["a.example.invalid", "b.example.invalid"]:
        SqliteHostRepository(settings.db_path).add(hostname, 443)
    updated = replace(settings, tls_verify=False, drift_alerts=True,
                      webhook_url="https://new.example.invalid")

    def scan(host, port, **kwargs):
        context.update_settings(updated)
        return object()

    scan_spy = Mock(side_effect=scan)
    store = Mock(return_value="leaf")
    monkeypatch.setattr("cert_watch.scheduler_context.scan_host", scan_spy)
    monkeypatch.setattr("cert_watch.scheduler_context.store_scanned", store)
    monkeypatch.setattr("cert_watch.scheduler_context._evaluate_posture", Mock())
    monkeypatch.setattr("cert_watch.scan._execute_deferred_post_commit", Mock())
    monkeypatch.setattr("cert_watch.scheduler._check_renewal_overdue", Mock())

    assert context.scan_all()["scanned"] == 2
    assert len(scan_spy.call_args_list) == len(store.call_args_list) == 2
    assert all(call.kwargs["verify"] is True for call in scan_spy.call_args_list)
    assert all(call.kwargs["drift_alerts"] is False for call in store.call_args_list)
    assert all(call.kwargs["webhook_config"].url == "https://old.example.invalid"
               for call in store.call_args_list)
    assert context.settings is updated


def test_alert_job_keeps_matching_transports_through_mid_job_update(monkeypatch, tmp_path):
    monkeypatch.setattr("cert_watch.http_client.validate_webhook_url", lambda *a, **kw: None)
    settings = _settings(
        tmp_path, alert_digest_only=True, smtp_host="old.example.invalid",
        alert_from="watch@example.invalid", alert_recipients=("old@example.invalid",),
        webhook_url="https://old.example.invalid",
    )
    context = SchedulerContext(
        settings, settings.build_alert_config(), settings.build_webhook_config(),
    )
    updated = replace(settings, smtp_host="new.example.invalid",
                      webhook_url="https://new.example.invalid")

    def pending(*args, **kwargs):
        context.update_settings(updated)
        return {"sent": 0, "failed": 0}

    pending_spy = Mock(side_effect=pending)
    digest = Mock(return_value=False)
    monkeypatch.setattr("cert_watch.alerts.evaluate_all_certs", Mock())
    monkeypatch.setattr("cert_watch.alerts.evaluate_renewal_window", Mock())
    monkeypatch.setattr("cert_watch.alerts.process_pending", pending_spy)
    monkeypatch.setattr("cert_watch.alerts.send_expiry_digest", digest)

    context.run_alerts()
    context.run_alerts()

    for spy in (pending_spy, digest):
        assert [call.args[1].smtp_host for call in spy.call_args_list] == [
            "old.example.invalid", "new.example.invalid",
        ]
        assert [call.kwargs["webhook_config"].url for call in spy.call_args_list] == [
            "https://old.example.invalid", "https://new.example.invalid",
        ]
