"""A per-host scan cadence must be storable, and one bad row must not stop the estate.

Every write path used to accept any integer. `last_success + timedelta(hours=N)`
leaves the representable date range long before N does, so a single such row
aborted scan selection for the **whole** estate — while the dashboards, which
already caught the error, kept rendering green. A certificate monitor that has
silently stopped monitoring is the worst shape this could take, so the two
halves are tested separately: new values are refused, and old ones are survived.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cert_watch.database import SqliteHostRepository, _connect, init_schema
from cert_watch.scan_freshness import (
    MAX_SCAN_INTERVAL_HOURS,
    MIN_SCAN_INTERVAL_HOURS,
    cadence_due_at,
)

UNUSABLE = 10**9


def _estate(tmp_path, *, bad_interval=UNUSABLE):
    """One ordinary host and one carrying an interval the arithmetic cannot use."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    ids = {
        "good": repo.add("good.example.invalid", 443, scan_interval_hours=24),
        "bad": repo.add("bad.example.invalid", 443, scan_interval_hours=bad_interval),
    }
    stale = (datetime.now(UTC) - timedelta(days=2)).isoformat()
    with _connect(db) as conn:
        for key, hostname in (("good", "good.example.invalid"), ("bad", "bad.example.invalid")):
            conn.execute(
                "INSERT INTO scan_history (id, hostname, port, status, scanned_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (ids[key] + "-scan", hostname, 443, "success", stale),
            )
        conn.commit()
    return db


def test_one_unusable_interval_does_not_stop_the_whole_estate_scanning(tmp_path):
    """The bug that mattered: selection is estate-wide, so a raise stopped everything."""
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = _estate(tmp_path)

    due = dict(get_hosts_due_for_scan(db))

    assert "good.example.invalid" in due, "an unrelated host must still be scanned"
    assert "bad.example.invalid" in due, "the affected host falls back to the daily cadence"


def test_the_scheduler_still_computes_a_wakeup_with_an_unusable_interval(tmp_path):
    """`_seconds_until_next_scan` drives the loop; raising here stops the scheduler."""
    from cert_watch.scheduler import _seconds_until_next_scan

    db = _estate(tmp_path)

    assert _seconds_until_next_scan(db, 6, 0) >= 0


def test_the_fallback_is_the_daily_cadence_not_a_skip(tmp_path):
    """Never scanning the affected host would be the same silence, one host wide."""
    from cert_watch.scheduler import _host_scan_deadlines

    db = _estate(tmp_path)
    now = datetime.now(UTC)
    last = now - timedelta(days=2)

    deadlines = {host: due for host, _, due, _ in _host_scan_deadlines(db, 6, 0, now)}

    assert deadlines["bad.example.invalid"] == cadence_due_at(last, None, 6, 0)


def test_an_unusable_interval_is_reported_not_swallowed(tmp_path, caplog):
    """Falling back quietly would leave the operator's configured cadence a lie."""
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = _estate(tmp_path)
    with caplog.at_level("WARNING", logger="cert_watch.scheduler"):
        get_hosts_due_for_scan(db)

    assert any("unusable scan_interval_hours" in r.message for r in caplog.records)


def test_malformed_scan_timestamp_does_not_poison_estate_deadlines(tmp_path):
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = tmp_path / "malformed-history.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("malformed.example.invalid", 443)
    repo.add("unobserved.example.invalid", 443)
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO scan_history (id, hostname, port, status, scanned_at) "
            "VALUES ('bad-scan', 'malformed.example.invalid', 443, 'success', 'not-a-date')"
        )
        conn.commit()

    try:
        due = set(get_hosts_due_for_scan(db))
    except ValueError:
        due = set()

    assert {
        ("malformed.example.invalid", 443),
        ("unobserved.example.invalid", 443),
    } <= due


@pytest.mark.parametrize("interval", [MIN_SCAN_INTERVAL_HOURS, 24, MAX_SCAN_INTERVAL_HOURS])
def test_add_host_accepts_a_storable_cadence(interval, tmp_path, reload_app):
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts",
            data={"hostname": "ok.example.invalid", "port": "443",
                  "scan_interval_hours": str(interval)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "error" not in response.headers["location"]
    hosts = SqliteHostRepository(tmp_path / "cert-watch.sqlite3").list_all()
    assert [h.scan_interval_hours for h in hosts] == [interval]


@pytest.mark.parametrize(
    "interval",
    [0, -1, MIN_SCAN_INTERVAL_HOURS - 1, MAX_SCAN_INTERVAL_HOURS + 1, UNUSABLE],
)
def test_add_host_refuses_a_cadence_it_cannot_store(interval, tmp_path, reload_app):
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts",
            data={"hostname": "bad.example.invalid", "port": "443",
                  "scan_interval_hours": str(interval)},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "error" in response.headers["location"]
    assert SqliteHostRepository(tmp_path / "cert-watch.sqlite3").list_all() == []


def test_add_host_still_accepts_a_blank_cadence_as_the_daily_default(tmp_path, reload_app):
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts", data={"hostname": "daily.example.invalid", "port": "443"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    hosts = SqliteHostRepository(tmp_path / "cert-watch.sqlite3").list_all()
    assert [h.scan_interval_hours for h in hosts] == [None]


def test_csv_import_refuses_an_out_of_range_cadence_and_names_the_row(tmp_path, reload_app):
    csv_content = (
        "hostname,port,scan_interval_hours\n"
        "fine.example.invalid,443,24\n"
        f"huge.example.invalid,443,{UNUSABLE}\n"
    )
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )

    assert response.status_code == 303
    location = response.headers["location"]
    assert "scan_interval_hours" in location and "row" in location, (
        "a partial import used to redirect to a bare '/', dropping the row in silence"
    )
    stored = {h.hostname for h in SqliteHostRepository(tmp_path / "cert-watch.sqlite3").list_all()}
    assert stored == {"fine.example.invalid"}, "the good row still imports"


def test_a_clean_csv_import_says_nothing(tmp_path, reload_app):
    """The partial-import warning must not fire when every row landed."""
    csv_content = "hostname,port,scan_interval_hours\nfine.example.invalid,443,24\n"
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content, "text/csv")},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_settings_edit_preserves_a_legacy_value_it_would_now_refuse(tmp_path, reload_app):
    """An operator editing the threshold must not be blocked by history.

    Rows predating the bound exist. Refusing every submission that carries one
    would make the *other* fields on the form uneditable, which is a worse
    outcome than an out-of-range cadence the scheduler already tolerates.
    """
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("legacy.example.invalid", 443,
                                           scan_interval_hours=UNUSABLE)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/settings",
            data={"scan_interval_hours": str(UNUSABLE), "threshold_days": "14",
                  "renewal_status": "pending"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "error" not in response.headers["location"]
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    assert host.threshold_days == 14, "the edit the operator actually came to make"


def test_settings_edit_refuses_changing_a_legacy_value_to_another_bad_one(tmp_path, reload_app):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("legacy.example.invalid", 443,
                                           scan_interval_hours=UNUSABLE)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/settings",
            data={"scan_interval_hours": "0", "threshold_days": "14",
                  "renewal_status": "pending"},
            follow_redirects=False,
        )

    assert response.status_code == 303
    assert "error" in response.headers["location"]
