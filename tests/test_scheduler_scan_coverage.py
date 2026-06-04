"""Coverage tests for scheduler.py and scan.py error paths.

Plan 024 Slice 4 — scheduled-job failure handling, next-run math, scan error paths.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

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


def test_start_scheduler_starts_thread():
    from cert_watch.scheduler import start_scheduler, stop_scheduler

    stop_scheduler()  # ensure clean state
    start_scheduler(lambda: {}, lambda: {}, hour=23, minute=59)
    from cert_watch.scheduler import _scheduler_thread as t

    assert t is not None
    assert t.is_alive()
    stop_scheduler()


def test_start_scheduler_idempotent():
    from cert_watch.scheduler import start_scheduler, stop_scheduler

    stop_scheduler()
    start_scheduler(lambda: {}, lambda: {}, hour=23, minute=59)
    start_scheduler(lambda: {}, lambda: {}, hour=23, minute=59)  # no-op
    from cert_watch.scheduler import _scheduler_thread as t

    assert t is not None
    stop_scheduler()


# The exception tests below drive the cycle directly via `_run_cycle` rather than
# starting the thread at hour=23:59 (where the timer never fires in-test). What the
# scheduler promises is *failure isolation*: one stage raising must not stop the
# others or escape the cycle. We assert that by tracking which stages ran.


def _boom(msg):
    def _f():
        raise RuntimeError(msg)

    return _f


def test_scheduler_scan_fn_exception_does_not_block_alerts():
    from cert_watch.scheduler import _run_cycle

    ran = []
    # scan_fn raises; alert_fn must still run and the cycle must not propagate.
    _run_cycle(_boom("scan failed"), lambda: ran.append("alert") or {})
    assert ran == ["alert"]


def test_scheduler_alert_fn_exception_is_swallowed():
    from cert_watch.scheduler import _run_cycle

    ran = []
    # alert_fn raises after scan ran; the cycle must complete without raising.
    _run_cycle(lambda: ran.append("scan") or {}, _boom("alert failed"))
    assert ran == ["scan"]


def test_scheduler_runs_all_stages_in_order():
    from cert_watch.scheduler import _run_cycle

    ran = []
    _run_cycle(
        lambda: ran.append("scan") or {},
        lambda: ran.append("alert") or {},
        ct_fn=lambda: ran.append("ct") or {},
        maintenance_fn=lambda: ran.append("maint"),
    )
    assert ran == ["scan", "ct", "alert", "maint"]


def test_scheduler_ct_fn_exception_does_not_block_alerts():
    from cert_watch.scheduler import _run_cycle

    ran = []
    # ct_fn raises between scan and alert; alert + maintenance must still run.
    _run_cycle(
        lambda: ran.append("scan") or {},
        lambda: ran.append("alert") or {},
        ct_fn=_boom("ct failed"),
        maintenance_fn=lambda: ran.append("maint"),
    )
    assert ran == ["scan", "alert", "maint"]


def test_scheduler_maintenance_fn_exception_is_swallowed():
    from cert_watch.scheduler import _run_cycle

    ran = []
    # maintenance_fn is the last stage; its failure must not escape the cycle.
    _run_cycle(
        lambda: ran.append("scan") or {},
        lambda: ran.append("alert") or {},
        maintenance_fn=_boom("maint failed"),
    )
    assert ran == ["scan", "alert"]


def test_stop_scheduler_when_not_started():
    from cert_watch.scheduler import stop_scheduler

    stop_scheduler()  # should not raise


# ---------- run_scan_now ----------


def test_run_scan_now_basic(tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.scheduler import run_scan_now

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


def test_run_scan_now_with_scan_error(tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.scheduler import run_scan_now

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
    from cert_watch.scheduler import run_scan_now

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


def test_run_scan_now_with_store_fn(tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.scheduler import run_scan_now

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
    from cert_watch.scheduler import run_scan_now

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
    assert result["scanned"] == 1


def test_run_scan_now_alert_counts(tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.scheduler import run_scan_now

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
    from cert_watch.scheduler import run_scan_now

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
    from cert_watch.routes.views import _scan_error_reason

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
