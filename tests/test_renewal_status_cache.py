"""Persisted Browse renewal evidence stays identical to the Python classifier."""

from __future__ import annotations

import random
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteHostRepository,
    init_schema,
    purge_old_history,
    record_cert_history,
    replace_scanned,
)
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_axes import dashboard_axis_stats
from cert_watch.database.dashboard_page import list_dashboard_page
from cert_watch.renewal_analytics import (
    compute_endpoint_analytics,
    refresh_endpoint_analytics,
)

NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
_STATE = {
    "likely-automated": "automation_configured",
    "manual": "manual",
    "unknown": "unknown",
}


def _live_cert(hostname: str, fingerprint: str) -> Certificate:
    return Certificate(
        subject=f"CN={hostname}",
        issuer="CN=Example Test CA",
        not_before=NOW - timedelta(days=5),
        not_after=NOW + timedelta(days=200),
        fingerprint_sha256=fingerprint,
    )


def test_rounding_boundary_uses_persisted_python_result_for_rows_filters_and_counts(tmp_path):
    db = tmp_path / "rounding.sqlite3"
    init_schema(db)
    hostname = "rounding.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    replace_scanned(db, hostname, 443, _live_cert(hostname, "live"), [], True)

    base = NOW - timedelta(days=200)
    with _connect(db) as conn:
        for index in range(3):
            first_seen = base + timedelta(days=60 * index)
            next_seen = base + timedelta(days=60 * (index + 1))
            not_after = next_seen + timedelta(hours=1)
            conn.execute(
                """INSERT INTO cert_history
                   (id, hostname, port, fingerprint_sha256, issuer,
                    not_before, not_after, scanned_at)
                   VALUES (?, ?, 443, ?, ?, ?, ?, ?)""",
                (
                    f"history-{index}",
                    hostname,
                    f"fp-{index}",
                    "CN=R3, O=Let's Encrypt",
                    (not_after - timedelta(days=90)).isoformat(),
                    not_after.isoformat(),
                    first_seen.isoformat(),
                ),
            )
        refresh_endpoint_analytics(conn, hostname, 443)
        conn.commit()

    python = compute_endpoint_analytics(db, ((hostname, 443),))[0]
    assert python.renewal_lead_times == [0.0, 0.0]
    assert python.automation_classification == "manual"

    rows, total = list_dashboard_page(db, renewal="manual", per_page=0, now=NOW)
    assert total == 1
    assert rows[0]["renewal"] == "manual"
    assert list_dashboard_page(
        db, renewal="automation_configured", per_page=0, now=NOW
    )[1] == 0
    assert dashboard_axis_stats(db)["renewal"]["manual"] == 1


def test_out_of_band_history_change_invalidates_to_unknown_until_refreshed(tmp_path):
    db = tmp_path / "stale.sqlite3"
    init_schema(db)
    hostname = "stale.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    replace_scanned(db, hostname, 443, _live_cert(hostname, "live"), [], True)

    with _connect(db) as conn:
        refresh_endpoint_analytics(conn, hostname, 443)
        assert conn.execute(
            "SELECT classification FROM endpoint_renewal_analytics WHERE hostname = ?",
            (hostname,),
        ).fetchone() is not None
        conn.execute(
            """INSERT INTO cert_history
               (id, hostname, port, fingerprint_sha256, issuer,
                not_before, not_after, scanned_at)
               VALUES ('raw', ?, 443, 'raw-fp', 'CN=Example Test CA', ?, ?, ?)""",
            (
                hostname,
                (NOW - timedelta(days=1)).isoformat(),
                (NOW + timedelta(days=89)).isoformat(),
                NOW.isoformat(),
            ),
        )
        assert conn.execute(
            "SELECT classification FROM endpoint_renewal_analytics WHERE hostname = ?",
            (hostname,),
        ).fetchone() is None
        conn.commit()

    rows, total = list_dashboard_page(db, renewal="unknown", per_page=0, now=NOW)
    assert total == 1
    assert rows[0]["renewal"] == "unknown"


def test_history_writers_refresh_basis_and_host_delete_removes_cache(tmp_path):
    db = tmp_path / "writers.sqlite3"
    init_schema(db)
    hostname = "writers.example.test"
    host_id = SqliteHostRepository(db).add(hostname, 443)
    for index in range(3):
        first_seen = NOW - timedelta(days=180 - index * 60)
        record_cert_history(
            db,
            hostname,
            443,
            Certificate(
                subject=f"CN={hostname}",
                issuer="CN=R3, O=Let's Encrypt",
                not_before=first_seen,
                not_after=first_seen + timedelta(days=90),
                fingerprint_sha256=f"fp-{index}",
            ),
            scanned_at=first_seen.isoformat(),
        )

    with _connect(db) as conn:
        cached = conn.execute(
            """SELECT classification, deployment_count, basis_history_count,
                      basis_latest_fingerprint
               FROM endpoint_renewal_analytics
               WHERE hostname = ? AND port = 443""",
            (hostname,),
        ).fetchone()
    assert tuple(cached) == ("likely-automated", 3, 3, "fp-2")

    # Purging two old periods recomputes rather than leaving their classification.
    assert purge_old_history(db, retention_days=100) == 2
    with _connect(db) as conn:
        cached = conn.execute(
            """SELECT classification, deployment_count, basis_history_count
               FROM endpoint_renewal_analytics
               WHERE hostname = ? AND port = 443""",
            (hostname,),
        ).fetchone()
    assert tuple(cached) == ("unknown", 1, 1)

    assert SqliteHostRepository(db).delete(host_id)
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT 1 FROM endpoint_renewal_analytics WHERE hostname = ?",
            (hostname,),
        ).fetchone() is None


def test_migration_backfill_runs_the_python_classifier(tmp_path):
    from cert_watch.migrations.m0043_endpoint_renewal_analytics import upgrade

    db = tmp_path / "backfill.sqlite3"
    init_schema(db)
    hostname = "backfill.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    base = NOW - timedelta(days=180)
    with _connect(db) as conn:
        for index in range(3):
            first_seen = base + timedelta(days=index * 60)
            conn.execute(
                """INSERT INTO cert_history
                   (id, hostname, port, fingerprint_sha256, issuer,
                    not_before, not_after, scanned_at)
                   VALUES (?, ?, 443, ?, 'CN=ZeroSSL', ?, ?, ?)""",
                (
                    f"backfill-{index}",
                    hostname,
                    f"fp-{index}",
                    first_seen.isoformat(),
                    (first_seen + timedelta(days=90)).isoformat(),
                    first_seen.isoformat(),
                ),
            )
        assert conn.execute(
            "SELECT 1 FROM endpoint_renewal_analytics WHERE hostname = ?",
            (hostname,),
        ).fetchone() is None
        upgrade(conn)
        cached = conn.execute(
            """SELECT classification, basis_history_count, basis_latest_history_id
               FROM endpoint_renewal_analytics WHERE hostname = ?""",
            (hostname,),
        ).fetchone()
        conn.commit()
    assert tuple(cached) == ("likely-automated", 3, "backfill-2")


def test_renewal_classifier_fuzz_agrees_with_browse_filters_and_counts(tmp_path):
    """Fixed-seed differential regression for the two reviewer fuzz harnesses."""
    db = tmp_path / "fuzz.sqlite3"
    init_schema(db)
    randomizer = random.Random(126)
    endpoints: list[tuple[str, int]] = []
    histories: dict[str, list[tuple[datetime, float, float, bool]]] = {}

    hosts = SqliteHostRepository(db)
    for index in range(400):
        hostname = f"h{index}.fuzz.example.test"
        endpoints.append((hostname, 443))
        hosts.add(hostname, 443)
        replace_scanned(
            db, hostname, 443, _live_cert(hostname, f"live-{index}"), [], True
        )
        period_count = randomizer.choice([2, 3, 3, 4, 5])
        acme = randomizer.random() < 0.8
        first_seen = NOW - timedelta(days=400)
        cadence = randomizer.choice([30, 45, 60])
        periods: list[tuple[datetime, float, float, bool]] = []
        for period in range(period_count):
            lifetime = randomizer.choice([30, 60, 89.6, 90, 90.2, 397])
            if period:
                first_seen += timedelta(
                    days=cadence
                    + randomizer.choice([0, 0.04, 0.5, 2.9, 3.0, 3.1, 4.3, -2.95])
                )
            lead = randomizer.choice([30, 20, 1, 0.06, 0.051, 0.04, -0.04, 0])
            periods.append((first_seen, lifetime, lead, acme))
        histories[hostname] = periods

    with _connect(db) as conn:
        for endpoint_index, (hostname, periods) in enumerate(histories.items()):
            for period_index, (first_seen, lifetime, lead, acme) in enumerate(periods):
                next_seen = (
                    periods[period_index + 1][0]
                    if period_index + 1 < len(periods)
                    else first_seen + timedelta(days=lifetime)
                )
                not_after = (
                    next_seen + timedelta(days=lead)
                    if period_index + 1 < len(periods)
                    else first_seen + timedelta(days=lifetime)
                )
                scans = [first_seen]
                if randomizer.random() < 0.5:
                    scans.append(first_seen + timedelta(hours=randomizer.choice([1, 12])))
                if randomizer.random() < 0.05 and period_index:
                    scans.insert(0, periods[period_index - 1][0])
                for scan_index, scanned_at in enumerate(scans):
                    conn.execute(
                        """INSERT INTO cert_history
                           (id, hostname, port, fingerprint_sha256, issuer,
                            not_before, not_after, scanned_at)
                           VALUES (?, ?, 443, ?, ?, ?, ?, ?)""",
                        (
                            str(uuid.uuid5(
                                uuid.NAMESPACE_DNS,
                                f"{endpoint_index}:{period_index}:{scan_index}",
                            )),
                            hostname,
                            f"fp-{endpoint_index}-{period_index}",
                            "CN=R3, O=Let's Encrypt" if acme else "CN=Example Test CA",
                            (not_after - timedelta(days=lifetime)).isoformat()
                            if randomizer.random() > 0.03
                            else None,
                            not_after.isoformat(),
                            scanned_at.isoformat(),
                        ),
                    )
            refresh_endpoint_analytics(conn, hostname, 443)
        conn.commit()

    expected = {
        item.hostname: _STATE[item.automation_classification]
        for item in compute_endpoint_analytics(db, tuple(endpoints))
    }
    rows, _total = list_dashboard_page(db, per_page=0, now=NOW)
    displayed = {str(row["hostname"]): str(row["renewal"]) for row in rows}
    filtered: dict[str, str] = {}
    for state in _STATE.values():
        state_rows, state_total = list_dashboard_page(
            db, renewal=state, per_page=0, now=NOW
        )
        assert state_total == sum(value == state for value in expected.values())
        filtered.update({str(row["hostname"]): state for row in state_rows})

    assert displayed == expected
    assert filtered == expected
    stats = dashboard_axis_stats(db)["renewal"]
    assert stats == {
        "automation_configured": Counter(expected.values())["automation_configured"],
        "manual": Counter(expected.values())["manual"],
        "stalled": 0,
        "in_progress": 0,
        "unknown": Counter(expected.values())["unknown"],
    }
