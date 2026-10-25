"""Recover unusable persisted timing data without weakening scan leases."""

import multiprocessing
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch import scheduler
from cert_watch.database import SqliteHostRepository, _connect, init_schema
from cert_watch.scan_freshness import load_scan_evidence
from cert_watch.scheduler import ScanHistory, record_scan_history

NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
ENDPOINT = ("recovery.example.test", 443)
HEALTHY = ("healthy.example.test", 443)
MAX_TIME = datetime.max.replace(tzinfo=UTC)


def _host(db, *, interval=None):
    init_schema(db)
    return SqliteHostRepository(db).add(*ENDPOINT, scan_interval_hours=interval)


def _claim(db, host_id, expiry, *, owner="old-worker"):
    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO host_scan_claims (host_id, claimed_by, claimed_at, claim_expires_at) "
            "VALUES (?, ?, ?, ?)",
            (host_id, owner, NOW.isoformat(), expiry),
        )


@pytest.mark.parametrize("operation", ["selection", "wakeup"])
@pytest.mark.parametrize(
    ("status", "interval"), [("success", None), ("success", 1), ("failure", None)]
)
def test_extreme_history_cannot_stop_healthy_hosts(tmp_path, status, interval, operation):
    db = tmp_path / "extreme.sqlite3"
    host_id = _host(db, interval=interval)
    SqliteHostRepository(db).add(*HEALTHY)
    record_scan_history(db, ScanHistory(*ENDPOINT, status, scanned_at=MAX_TIME))
    record_scan_history(db, ScanHistory(*HEALTHY, "success", scanned_at=NOW - timedelta(days=2)))

    if operation == "selection":
        assert scheduler.get_hosts_due_for_scan(db, now=NOW) == [HEALTHY]
    else:
        assert scheduler._seconds_until_next_scan(db, 6, 0, now=NOW) == 0
    # A future observation never becomes "current" merely because its deadline
    # was bounded. It still needs an operator's attention.
    evidence = load_scan_evidence(db, now=NOW)[host_id]
    assert evidence.state == "unknown"
    assert evidence.due_at is None


def test_legacy_unusable_interval_still_falls_back_to_daily(tmp_path):
    db = tmp_path / "legacy.sqlite3"
    host_id = _host(db)
    record_scan_history(db, ScanHistory(*ENDPOINT, "success", scanned_at=NOW - timedelta(days=2)))
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET scan_interval_hours=? WHERE id=?", (2**63 - 1, host_id))
        conn.commit()
    assert scheduler.get_hosts_due_for_scan(db, now=NOW) == [ENDPOINT]


@pytest.mark.parametrize("expiry", ["not-a-date", "tomorrow", "9999-12-31T23:59:59.999999-14:00"])
def test_unusable_claim_can_be_replaced_atomically(tmp_path, expiry):
    db = tmp_path / "claim.sqlite3"
    host_id = _host(db)
    _claim(db, host_id, expiry)
    assert scheduler.claim_hosts_due_for_scan(db, owner="new-worker", now=NOW) == [ENDPOINT]
    assert scheduler.get_hosts_due_for_scan(db, now=NOW) == []
    with _connect(db) as conn:
        row = conn.execute("SELECT * FROM host_scan_claims WHERE host_id=?", (host_id,)).fetchone()
    assert row["claimed_by"] == "new-worker"
    assert datetime.fromisoformat(row["claim_expires_at"]) == NOW + timedelta(minutes=15)


def test_writer_honors_offset_lease_acquired_after_selection(tmp_path, monkeypatch):
    db = tmp_path / "race.sqlite3"
    host_id = _host(db)
    original = scheduler.get_hosts_due_for_scan

    def select_then_other_worker_claims(*args, **kwargs):
        due = original(*args, **kwargs)
        # This separate connection commits between the due read and the write
        # transaction. The local text sorts before NOW, but the instant is later.
        _claim(db, host_id, "2026-09-12T11:30:00-01:00", owner="other-worker")
        return due

    monkeypatch.setattr(scheduler, "get_hosts_due_for_scan", select_then_other_worker_claims)
    assert scheduler.claim_hosts_due_for_scan(db, owner="late-worker", now=NOW) == []
    with _connect(db) as conn:
        owner = conn.execute(
            "SELECT claimed_by FROM host_scan_claims WHERE host_id=?", (host_id,)
        ).fetchone()[0]
    assert owner == "other-worker"


def _competing_worker(db, owner, barrier, results):
    original = scheduler.get_hosts_due_for_scan

    def select_before_both_transactions(*args, **kwargs):
        due = original(*args, **kwargs)
        barrier.wait(timeout=30)
        return due

    scheduler.get_hosts_due_for_scan = select_before_both_transactions
    results.put(scheduler.claim_hosts_due_for_scan(db, owner=owner, now=NOW))


def test_only_one_process_claims_a_due_host(tmp_path):
    db = tmp_path / "processes.sqlite3"
    _host(db)
    context = multiprocessing.get_context("spawn")
    barrier = context.Barrier(2)
    results = context.Queue()
    children = [
        context.Process(target=_competing_worker, args=(db, owner, barrier, results))
        for owner in ("worker-a", "worker-b")
    ]
    try:
        for child in children:
            child.start()
        claims = [results.get(timeout=30), results.get(timeout=30)]
        for child in children:
            child.join(timeout=30)
            assert child.exitcode == 0
        assert sorted(len(value) for value in claims) == [0, 1]
        assert [endpoint for value in claims for endpoint in value] == [ENDPOINT]
    finally:
        for child in children:
            if child.is_alive():
                child.terminate()
                child.join(timeout=10)
        results.close()
        results.join_thread()


@pytest.mark.parametrize(
    ("value", "wait"),
    [
        ("0001-01-01T00:00:00+14:00", 0),
        ("9999-12-31T23:59:59.999999-14:00", 0),
        ("not-a-date", 0),
        ("2026-09-12T18:00:00+05:30", 1800),
        (None, float("inf")),
    ],
)
def test_rule_wake_recovers_bad_utc_values_and_preserves_valid_times(tmp_path, value, wait):
    db = tmp_path / "rules.sqlite3"
    host_id = _host(db)
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO renewal_attempts "
            "(attempt_id, host_id, source, state, opened_seq, received_at, rule_due_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("rule-wake", host_id, "manual", "verifying", 1, NOW.isoformat(), value),
        )
        conn.commit()
    assert scheduler._seconds_until_next_rule_pass(db, now=NOW) == wait
