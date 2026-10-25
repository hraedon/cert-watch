"""One unusable stored UTC conversion must not stop estate scan selection."""

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.database import SqliteHostRepository, _connect, init_schema
from cert_watch.scheduler import (
    ScanHistory,
    _seconds_until_next_scan,
    get_hosts_due_for_scan,
    record_scan_history,
)

NOW = datetime(2026, 9, 12, 12, tzinfo=UTC)
ENDPOINT = ("timestamp.example.test", 443)
HEALTHY = ("healthy.example.test", 443)
FIELDS = ("successful", "attempt", "renewal verification", "scan claim")


def _seed(db, field, value, *, healthy):
    init_schema(db)
    hosts = SqliteHostRepository(db)
    host_id = hosts.add(*ENDPOINT)
    if healthy:
        hosts.add(*HEALTHY)
        record_scan_history(
            db, ScanHistory(*HEALTHY, "success", scanned_at=NOW - timedelta(days=2))
        )
    with _connect(db) as conn:
        if field in ("successful", "attempt"):
            conn.execute(
                "INSERT INTO scan_history (id, hostname, port, status, scanned_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "boundary-history",
                    *ENDPOINT,
                    "success" if field == "successful" else "failure",
                    value,
                ),
            )
        elif field == "renewal verification":
            conn.execute(
                "INSERT INTO renewal_attempts "
                "(attempt_id, host_id, source, state, opened_seq, received_at, next_check_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("boundary-renewal", host_id, "manual", "verifying", 1, NOW.isoformat(), value),
            )
        else:
            conn.execute(
                "INSERT INTO host_scan_claims (host_id, claimed_by, claimed_at, claim_expires_at) "
                "VALUES (?, ?, ?, ?)",
                (host_id, "test-worker", NOW.isoformat(), value),
            )
        conn.commit()


@pytest.mark.parametrize("operation", ["selection", "wakeup"])
@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize(
    "value",
    [
        "0001-01-01T00:00:00+14:00",
        "9999-12-31T23:59:59.999999-14:00",
    ],
)
def test_unrepresentable_utc_timestamp_is_isolated(tmp_path, caplog, field, value, operation):
    db = tmp_path / "boundary.sqlite3"
    _seed(db, field, value, healthy=True)

    if operation == "selection":
        assert set(get_hosts_due_for_scan(db, now=NOW)) == {ENDPOINT, HEALTHY}
    else:
        assert _seconds_until_next_scan(db, 6, 0, now=NOW) == 0

    assert f"malformed {field} scan timestamp" in caplog.text
    assert value in caplog.text


@pytest.mark.parametrize("operation", ["selection", "wakeup"])
@pytest.mark.parametrize(
    ("field", "value", "due", "wait"),
    [
        ("successful", "2026-09-12T16:30:00+05:30", False, 18 * 3600),
        ("attempt", "2026-09-12T16:45:00+05:30", False, 15 * 60),
        ("renewal verification", "2026-09-12T17:00:00+05:30", True, 0),
        ("scan claim", "2026-09-12T18:00:00+05:30", False, 3600),
    ],
)
def test_representable_offsets_keep_existing_deadlines(
    tmp_path, field, value, due, wait, operation
):
    db = tmp_path / "normal.sqlite3"
    _seed(db, field, value, healthy=False)

    if operation == "selection":
        assert get_hosts_due_for_scan(db, now=NOW) == ([ENDPOINT] if due else [])
    else:
        assert _seconds_until_next_scan(db, 6, 0, now=NOW) == wait
