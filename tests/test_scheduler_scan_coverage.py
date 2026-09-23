"""Coverage tests for scheduler.py and scan.py error paths.

Plan 024 Slice 4 — scheduled-job failure handling, next-run math, scan error paths.
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.config import Settings
from cert_watch.database import init_schema
from cert_watch.scheduler import Scheduler
from cert_watch.scheduler_context import SchedulerContext


def _scheduler(db) -> Scheduler:
    init_schema(db)
    settings = Settings(db_path=db, data_dir=db.parent)
    return Scheduler(SchedulerContext(settings, None, None))


def run_scan_now(scan_fn, alert_fn, **kwargs):
    """Exercise immediate scans through a Scheduler instance."""
    return _scheduler(kwargs["db_path"]).run_scan_now(scan_fn, alert_fn, **kwargs)

# ---------- _seconds_until ----------


def test_seconds_until_future():
    from cert_watch.scheduler import _seconds_until

    now = datetime.now(UTC)
    future_hour = (now.hour + 1) % 24
    secs = _seconds_until(future_hour, now.minute)
    assert secs > 0


def test_seconds_until_past_wraps():
    from cert_watch.scheduler import _seconds_until

    now = datetime.now(UTC)
    past_hour = (now.hour - 1) % 24
    secs = _seconds_until(past_hour, now.minute)
    assert secs > 0  # wraps to next day


# ---------- record_scan_history ----------


def test_record_scan_history(tmp_path):
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "test.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    entry = ScanHistory(hostname="h.example.com", port=443, status="success")
    eid = record_scan_history(db, entry)
    assert eid


def test_record_scan_history_with_error(tmp_path):
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "test.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    entry = ScanHistory(
        hostname="h.example.com", port=443, status="failure", error_message="timeout"
    )
    eid = record_scan_history(db, entry)
    assert eid


def test_record_scan_history_custom_id(tmp_path):
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "test.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    entry = ScanHistory(hostname="h.example.com", port=443, status="success", id="custom-id")
    eid = record_scan_history(db, entry)
    assert eid == "custom-id"


# ---------- start/stop scheduler ----------


def test_scheduler_starts_thread(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime.start()

    assert runtime.is_running
    assert runtime.stop()


def test_scheduler_start_is_idempotent(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime.start()
    first_thread = runtime._thread
    runtime.start()

    assert runtime._thread is first_thread
    assert runtime.stop()


def test_scheduler_loop_failure_backs_off_and_recovers(
    tmp_path, monkeypatch, caplog,
):
    import cert_watch.scheduler as scheduler_module

    runtime = _scheduler(tmp_path / "test.sqlite3")
    original_schedule_time = runtime.context.schedule_time
    fault_active = threading.Event()
    fault_active.set()
    attempts = 0

    def failing_schedule_time():
        nonlocal attempts
        attempts += 1
        if fault_active.is_set():
            raise RuntimeError("schedule unavailable")
        return original_schedule_time()

    monkeypatch.setattr(runtime.context, "schedule_time", failing_schedule_time)
    monkeypatch.setattr(scheduler_module, "LOOP_RESTART_BACKOFF_INITIAL", 0.01)
    monkeypatch.setattr(scheduler_module, "LOOP_RESTART_BACKOFF_MAX", 0.04)

    runtime.start()
    deadline = time.monotonic() + 1
    while attempts < 3 and time.monotonic() < deadline:
        time.sleep(0.002)

    while (
        caplog.text.count("scheduler loop failed; retrying") < attempts
        and time.monotonic() < deadline
    ):
        time.sleep(0.002)

    assert 3 <= attempts <= 4
    assert not runtime.is_running
    assert runtime.loop_failure_count == attempts
    assert runtime.last_loop_error == "RuntimeError"
    assert caplog.text.count("scheduler loop failed; retrying") == attempts

    fault_active.clear()
    deadline = time.monotonic() + 1
    while not runtime.is_running and time.monotonic() < deadline:
        time.sleep(0.002)

    assert runtime.is_running
    assert runtime.loop_failure_count == 0
    assert runtime.last_loop_error is None
    assert runtime.stop(timeout=1)


# The exception tests below drive the cycle directly via `_run_cycle` rather than
# starting the thread at hour=23:59 (where the timer never fires in-test). What the
# scheduler promises is *failure isolation*: one stage raising must not stop the
# others or escape the cycle. We assert that by tracking which stages ran.


def _boom(msg):
    def _f():
        raise RuntimeError(msg)

    return _f


def test_scheduler_scan_fn_exception_does_not_block_alerts(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    # scan_fn raises; alert_fn must still run and the cycle must not propagate.
    runtime.run_cycle(
        scan_fn=_boom("scan failed"),
        alert_fn=lambda: ran.append("alert") or {},
        digest_fn=lambda: {},
        maintenance_fn=lambda: None,
    )
    assert ran == ["alert"]


def test_scheduler_scan_system_exit_isolated_and_next_cycle_runs(
    tmp_path, monkeypatch,
):
    import cert_watch.scheduler as scheduler_module

    settings = Settings(
        db_path=tmp_path / "test.sqlite3",
        data_dir=tmp_path,
        sched_hour=6,
    )
    init_schema(settings.db_path)
    context = SchedulerContext(settings, None, None)
    second_cycle = threading.Event()
    release_second_cycle = threading.Event()
    scans = 0
    alerts = []

    class Clock:
        current = datetime(2026, 9, 23, 5, 59, tzinfo=UTC)

        def now(self):
            return self.current

        def monotonic(self):
            return self.current.timestamp()

        def wait(self, _event, timeout):
            self.current += timedelta(seconds=timeout)
            return False

    def scan():
        nonlocal scans
        scans += 1
        if scans == 1:
            raise SystemExit("scan library called sys.exit")
        second_cycle.set()
        release_second_cycle.wait(1)
        return {}

    context.scan_all = scan
    context.run_alerts = lambda: alerts.append("alert") or {}
    context.maybe_run_weekly_digest = lambda: {}
    context.maintenance = lambda: None
    monkeypatch.setattr(
        scheduler_module, "_seconds_until_next_scan", lambda *args, **kwargs: 0,
    )
    runtime = Scheduler(context, clock=Clock())

    runtime.start()
    try:
        assert second_cycle.wait(1), "SystemExit killed the scheduler before cycle two"
        assert alerts == ["alert"]
        assert runtime.is_running
        assert runtime.loop_failure_count == 0
        assert runtime.last_loop_error is None
    finally:
        release_second_cycle.set()
        assert runtime.stop(timeout=1)


def test_scheduler_scan_system_exit_propagates_during_shutdown(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    stopped = threading.Event()

    def scan():
        stopped.set()
        raise SystemExit("shutdown")

    with pytest.raises(SystemExit, match="shutdown"):
        runtime.run_cycle(
            scan_fn=scan,
            alert_fn=lambda: {},
            digest_fn=lambda: {},
            maintenance_fn=lambda: None,
            stop_event=stopped,
        )


def test_scheduler_alert_fn_exception_is_swallowed(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    # alert_fn raises after scan ran; the cycle must complete without raising.
    runtime.run_cycle(
        scan_fn=lambda: ran.append("scan") or {},
        alert_fn=_boom("alert failed"),
        digest_fn=lambda: {},
        maintenance_fn=lambda: None,
    )
    assert ran == ["scan"]


def test_scheduler_runs_all_stages_in_order(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    runtime.run_cycle(
        scan_fn=lambda: ran.append("scan") or {},
        alert_fn=lambda: ran.append("alert") or {},
        ct_fn=lambda: ran.append("ct") or {},
        maintenance_fn=lambda: ran.append("maint"),
    )
    assert ran == ["scan", "ct", "alert", "maint"]


def test_scheduler_stop_during_scan_skips_remaining_stages(tmp_path):
    import threading

    runtime = _scheduler(tmp_path / "test.sqlite3")
    stopped = threading.Event()
    ran = []

    def scan():
        ran.append("scan")
        stopped.set()
        return {}

    runtime.run_cycle(
        scan_fn=scan,
        alert_fn=lambda: ran.append("alert") or {},
        ct_fn=lambda: ran.append("ct") or {},
        digest_fn=lambda: ran.append("digest") or {},
        maintenance_fn=lambda: ran.append("maintenance"),
        stop_event=stopped,
    )
    assert ran == ["scan"]


def test_scheduler_ct_fn_exception_does_not_block_alerts(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    # ct_fn raises between scan and alert; alert + maintenance must still run.
    runtime.run_cycle(
        scan_fn=lambda: ran.append("scan") or {},
        alert_fn=lambda: ran.append("alert") or {},
        ct_fn=_boom("ct failed"),
        maintenance_fn=lambda: ran.append("maint"),
    )
    assert ran == ["scan", "alert", "maint"]


def test_scheduler_maintenance_fn_exception_is_swallowed(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    # maintenance_fn is the last stage; its failure must not escape the cycle.
    runtime.run_cycle(
        scan_fn=lambda: ran.append("scan") or {},
        alert_fn=lambda: ran.append("alert") or {},
        digest_fn=lambda: {},
        maintenance_fn=_boom("maint failed"),
    )
    assert ran == ["scan", "alert"]


def test_stop_scheduler_when_not_started(tmp_path):
    assert _scheduler(tmp_path / "test.sqlite3").stop()


def test_stop_scheduler_cancels_queued_webhook_work(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime.start()
    assert runtime.stop()
    assert runtime._webhook_pool is None


def test_stop_scheduler_cancels_queued_webhook_future(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime._webhook_pool = ThreadPoolExecutor(max_workers=1)
    entered = threading.Event()
    release = threading.Event()
    queued_ran = threading.Event()

    def blocker():
        entered.set()
        release.wait(1)

    assert runtime._submit_renewal_webhook(blocker)
    assert entered.wait(1)
    assert runtime._submit_renewal_webhook(queued_ran.set)
    queued = next(future for future in runtime._webhook_futures if not future.running())

    runtime.stop(timeout=0.03)

    release.set()
    assert queued.cancelled()
    assert not queued_ran.is_set()


def test_restart_after_bounded_stop_hands_off_to_one_new_loop(tmp_path):
    settings = Settings(
        db_path=tmp_path / "test.sqlite3",
        data_dir=tmp_path,
        sched_hour=6,
    )
    init_schema(settings.db_path)
    context = SchedulerContext(settings, None, None)
    entered = threading.Event()
    release = threading.Event()

    class Clock:
        current = datetime(2026, 9, 23, 5, 59, tzinfo=UTC)
        waits = 0

        def now(self):
            return self.current

        def monotonic(self):
            return self.current.timestamp()

        def wait(self, event, timeout):
            self.waits += 1
            if self.waits == 1:
                self.current += timedelta(seconds=timeout)
                return False
            return event.wait(1)

    def scan():
        entered.set()
        release.wait(1)
        return {}

    context.scan_all = scan
    context.run_alerts = lambda: {}
    context.maybe_run_weekly_digest = lambda: {}
    context.maintenance = lambda: None
    runtime = Scheduler(context, clock=Clock(), shutdown_timeout=0.01)
    runtime.start()
    assert entered.wait(1)
    old_thread = runtime._thread

    assert not runtime.stop()
    runtime.start()
    release.set()

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if runtime._thread is not old_thread and runtime.is_running:
            break
        time.sleep(0.005)
    if old_thread is not None:
        old_thread.join(0.2)
    assert old_thread is not None and not old_thread.is_alive()
    assert runtime._thread is not old_thread
    assert runtime.is_running
    assert runtime.stop(timeout=1)


def test_stop_is_bounded_when_webhook_is_hung(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime.start()
    entered = threading.Event()
    release = threading.Event()

    def hung_webhook():
        entered.set()
        release.wait(1)

    assert runtime._submit_renewal_webhook(hung_webhook)
    assert entered.wait(1)
    started = time.monotonic()

    runtime.stop(timeout=0.03)

    elapsed = time.monotonic() - started
    release.set()
    assert elapsed < 0.2


def test_malformed_last_scan_timestamp_is_not_exported(tmp_path, caplog):
    from cert_watch.database import _connect

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO scan_history "
            "(id, hostname, port, status, scanned_at) VALUES (?, ?, ?, ?, ?)",
            ("bad-time", "bad.example.test", 443, "failure", "not-a-timestamp"),
        )
        conn.commit()

    runtime = _scheduler(db)

    assert runtime.last_scan_timestamp is None
    assert "latest scan timestamp is malformed" in caplog.text


def test_last_scan_timestamp_is_cached_after_recorded_scan(tmp_path, monkeypatch):
    db = tmp_path / "test.sqlite3"
    scanned_at = datetime(2026, 9, 23, 12, 34, tzinfo=UTC)

    class Clock:
        def now(self):
            return scanned_at

        def monotonic(self):
            return scanned_at.timestamp()

        def wait(self, event, timeout):
            return event.wait(timeout)

    init_schema(db)
    settings = Settings(db_path=db, data_dir=tmp_path)
    runtime = Scheduler(SchedulerContext(settings, None, None), clock=Clock())
    runtime.run_scan_now(
        scan_fn=lambda hostname, port: object(),
        alert_fn=lambda: {},
        db_path=db,
        host_provider=lambda: [("cached.example.com", 443)],
        store_fn=lambda result: "leaf-id",
    )
    monkeypatch.setattr(
        runtime,
        "_load_last_scan_timestamp",
        lambda: pytest.fail("cached property queried the database"),
    )

    assert runtime.last_scan_timestamp == scanned_at.timestamp()
    assert runtime.last_scan_timestamp == scanned_at.timestamp()


# ---------- run_scan_now ----------


def test_internal_run_scan_requires_renewal_check():
    from inspect import Parameter, signature

    from cert_watch.scheduler import _run_scan_now

    renewal_check = signature(_run_scan_now).parameters["renewal_check"]
    assert renewal_check.kind is Parameter.KEYWORD_ONLY
    assert renewal_check.default is Parameter.empty


def test_run_scan_now_basic(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("h1.example.com", 443), ("h2.example.com", 443)]
    scanned = []

    def scan_fn(hostname, port):
        scanned.append((hostname, port))
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            host: str
            port: int

        return FakeResult(host=hostname, port=port)

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
    )
    assert result["scanned"] == 2
    assert result["failures"] == 0
    assert len(scanned) == 2


def test_run_scan_now_without_provider_scans_all_hosts(tmp_path):
    from cert_watch.database import SqliteHostRepository
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(
        "fresh.example.com", 443, scan_interval_hours=24,
    )
    record = ScanHistory(
        hostname="fresh.example.com",
        port=443,
        status="success",
        scanned_at=datetime.now(UTC),
    )
    record_scan_history(db, record)
    scanned = []

    result = _scheduler(db).run_scan_now(
        lambda hostname, port: scanned.append((hostname, port)) or object(),
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
    )

    assert scanned == [("fresh.example.com", 443)]
    assert result["scanned"] == 1


def test_run_scan_now_with_scan_error(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("fail.example.com", 443)]

    def scan_fn(hostname, port):
        from cert_watch.scan import ScanError

        return ScanError(hostname=hostname, port=port, error_message="connection refused")

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
    )
    assert result["scanned"] == 0
    assert result["failures"] == 1


def test_run_scan_now_with_exception(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("err.example.com", 443)]

    def scan_fn(hostname, port):
        raise RuntimeError("network error")

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
    )
    assert result["scanned"] == 0
    assert result["failures"] == 1


@pytest.mark.parametrize("failure_kind", ["exception", "scan_error"])
def test_run_scan_now_history_write_failure_does_not_stop_hosts(
    tmp_path, monkeypatch, failure_kind
):
    import sqlite3

    from cert_watch.database import init_schema
    from cert_watch.scan import ScanError

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("one.example.com", 443), ("two.example.com", 443)]
    attempted = []

    def scan_fn(hostname, port):
        attempted.append((hostname, port))
        if failure_kind == "exception":
            raise RuntimeError("scan failed")
        return ScanError(hostname=hostname, port=port, error_message="scan failed")

    monkeypatch.setattr(
        "cert_watch.scheduler.record_scan_history",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("locked")),
    )
    try:
        result = run_scan_now(
            scan_fn,
            lambda: {"sent": 0, "failed": 0},
            db_path=db,
            host_provider=lambda: hosts,
        )
    except sqlite3.Error:
        result = None

    assert result == {"scanned": 0, "alerts_sent": 0, "failures": 2}
    assert attempted == hosts


def test_run_scan_now_with_store_fn(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("store.example.com", 443)]
    stored = []

    def scan_fn(hostname, port):
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            host: str
            port: int

        return FakeResult(host=hostname, port=port)

    def store_fn(result):
        stored.append(result)
        return "leaf-id-1"  # contract: non-empty leaf id on success (WI-142)

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
        store_fn=store_fn,
    )
    assert result["scanned"] == 1
    assert len(stored) == 1


def test_run_scan_now_store_fn_exception(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("store-err.example.com", 443)]

    def scan_fn(hostname, port):
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            host: str
            port: int

        return FakeResult(host=hostname, port=port)

    def store_fn(result):
        raise RuntimeError("store failed")

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
        store_fn=store_fn,
    )
    # A failed store is NOT a successful scan: the cert was never persisted.
    # Regression (WI-142 sibling): scanned was incremented before store_fn ran,
    # inflating the success count and hiding the failure.
    assert result["scanned"] == 0
    assert result["failures"] == 1


def test_run_scan_now_store_fn_exception_records_failure_status(tmp_path):
    from cert_watch.database import _connect, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("store-err-status.example.com", 443)]

    def scan_fn(hostname, port):
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            host: str
            port: int

        return FakeResult(host=hostname, port=port)

    def store_fn(result):
        raise RuntimeError("store failed")

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
        store_fn=store_fn,
    )
    assert result["scanned"] == 0

    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT status, error_message FROM scan_history WHERE hostname=? AND port=?",
            (hosts[0][0], hosts[0][1]),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "failure"
    assert rows[0][1] and "store failed" in rows[0][1]


def test_run_scan_now_store_fn_returns_none_records_failure(tmp_path):
    """A store_fn that returns an empty leaf id is a failure, not a silent
    success (WI-142). store_scanned's contract is "return non-empty leaf id
    on success, raise on failure"; the scheduler defends against a future
    contract violation that silently returns "" by recording failure too.
    """
    from cert_watch.database import _connect, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    hosts = [("store-none.example.com", 443)]

    def scan_fn(hostname, port):
        from dataclasses import dataclass

        @dataclass
        class FakeResult:
            host: str
            port: int

        return FakeResult(host=hostname, port=port)

    def store_fn(result):
        return None  # contract violation — empty leaf id

    result = run_scan_now(
        scan_fn,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: hosts,
        store_fn=store_fn,
    )
    # An empty leaf id is a failure: nothing was persisted, so the scan
    # must not count as successful and must trigger fast-retry.
    assert result["scanned"] == 0
    assert result["failures"] == 1

    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT status FROM scan_history WHERE hostname=? AND port=?",
            (hosts[0][0], hosts[0][1]),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "failure"


def test_run_scan_now_alert_counts(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)

    result = run_scan_now(
        lambda h, p: None,
        lambda: {"sent": 3, "failed": 1},
        db_path=db,
        host_provider=lambda: [],
    )
    assert result["alerts_sent"] == 3
    assert result["failures"] == 1


def test_run_scan_now_no_hosts(tmp_path):
    from cert_watch.database import init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)

    result = run_scan_now(
        lambda h, p: None,
        lambda: {"sent": 0, "failed": 0},
        db_path=db,
        host_provider=lambda: [],
    )
    assert result["scanned"] == 0


# ---------- get_hosts_due_for_scan ----------


def test_get_hosts_due_for_scan_no_interval(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("daily.example.com", 443)
    due = get_hosts_due_for_scan(db)
    assert ("daily.example.com", 443) in due


def test_get_hosts_due_for_scan_never_scanned(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("new.example.com", 443, scan_interval_hours=6)
    due = get_hosts_due_for_scan(db)
    assert ("new.example.com", 443) in due


def test_get_hosts_due_for_scan_interval_passed(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import ScanHistory, get_hosts_due_for_scan, record_scan_history

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("int.example.com", 443, scan_interval_hours=1)
    # Record a scan from 2 hours ago
    entry = ScanHistory(
        hostname="int.example.com",
        port=443,
        status="success",
        scanned_at=datetime.now(UTC) - timedelta(hours=2),
    )
    record_scan_history(db, entry)
    due = get_hosts_due_for_scan(db)
    assert ("int.example.com", 443) in due


def test_get_hosts_due_for_scan_interval_not_passed(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import ScanHistory, get_hosts_due_for_scan, record_scan_history

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("fresh.example.com", 443, scan_interval_hours=24)
    entry = ScanHistory(
        hostname="fresh.example.com",
        port=443,
        status="success",
        scanned_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    record_scan_history(db, entry)
    due = get_hosts_due_for_scan(db)
    assert ("fresh.example.com", 443) not in due


# ---------- _has_pending_hosts ----------


def test_has_pending_hosts_true(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import _has_pending_hosts

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("pending.example.com", 443)
    assert _has_pending_hosts(db) is True


def test_has_pending_hosts_false(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import ScanHistory, _has_pending_hosts, record_scan_history

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("done.example.com", 443)
    record_scan_history(db, ScanHistory(hostname="done.example.com", port=443, status="success"))
    assert _has_pending_hosts(db) is False


# ---------- ScanError ----------


def test_scan_error_dataclass():
    from cert_watch.scan import ScanError

    err = ScanError(hostname="h.example.com", port=443, error_message="timeout")
    assert err.hostname == "h.example.com"
    assert err.error_message == "timeout"


# ---------- _scan_error_reason ----------


def test_scan_error_reason_variants():
    from cert_watch.routes.metrics import _scan_error_reason

    assert _scan_error_reason("connection refused") == "connection_refused"
    assert _scan_error_reason("Connection Refused") == "connection_refused"
    assert _scan_error_reason("timed out") == "timeout"
    assert _scan_error_reason("Timeout occurred") == "timeout"
    assert _scan_error_reason("DNS resolve failed") == "dns_failure"
    assert _scan_error_reason("dns error") == "dns_failure"
    assert _scan_error_reason("blocked by SSRF policy") == "blocked"
    assert _scan_error_reason("something else") == "unknown"
    assert _scan_error_reason(None) == "unknown"
    assert _scan_error_reason("") == "unknown"


# ---------- cycle overlap protection (WI-022) ----------


def test_cycle_lock_prevents_concurrent_delivery(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    entered = runtime._cycle_lock.acquire(blocking=False)
    try:
        assert entered
        assert runtime.try_run_alert_delivery(lambda: {"sent": 1}) is None
    finally:
        runtime._cycle_lock.release()


def test_cycle_lock_available_after_delivery(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    assert runtime.try_run_alert_delivery(lambda: {"sent": 1}) == {"sent": 1}
    assert runtime.try_run_alert_delivery(lambda: {"sent": 2}) == {"sent": 2}


def test_stop_scheduler_does_not_release_active_cycle_lock(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime._cycle_lock.acquire(blocking=False)
    assert runtime._cycle_lock.locked()

    runtime.stop()

    assert runtime._cycle_lock.locked()
    runtime._cycle_lock.release()


def test_manual_delivery_skips_when_cycle_lock_held(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    runtime._cycle_lock.acquire(blocking=False)
    ran = []
    try:
        assert runtime.try_run_alert_delivery(
            lambda: ran.append("delivery") or {"sent": 1}
        ) is None
    finally:
        runtime._cycle_lock.release()
    assert ran == []


def test_run_cycle_runs_when_lock_free(tmp_path):
    runtime = _scheduler(tmp_path / "test.sqlite3")
    ran = []
    runtime.run_cycle(
        scan_fn=lambda: ran.append("scan") or {},
        alert_fn=lambda: ran.append("alert") or {},
        digest_fn=lambda: {},
        maintenance_fn=lambda: None,
    )

    assert ran == ["scan", "alert"]
    assert not runtime._cycle_lock.locked()
