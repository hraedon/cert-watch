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


# ---------------------------------------------------------------------------
# Write-path coverage: the scan store, per-port isolation, triggers, deletes.
# ---------------------------------------------------------------------------


def _seed_history(
    conn,
    hostname: str,
    port: int,
    *,
    issuer: str,
    lifetime_days: float,
    cadence_days: float,
    lead_days: float,
    periods: int,
    last_seen: datetime,
) -> None:
    """Insert *periods* prior fingerprint periods ending before *last_seen*.

    Raw SQL on purpose: the INSERT trigger invalidates the cache, so only a
    later sanctioned writer can make the endpoint read as anything but unknown.
    """
    for index in range(periods):
        first_seen = last_seen - timedelta(days=cadence_days * (periods - index))
        next_seen = first_seen + timedelta(days=cadence_days)
        not_after = next_seen + timedelta(days=lead_days)
        conn.execute(
            """INSERT INTO cert_history
               (id, hostname, port, fingerprint_sha256, issuer,
                not_before, not_after, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"seed-{hostname}-{port}-{index}",
                hostname,
                port,
                f"fp-{port}-{index}",
                issuer,
                (not_after - timedelta(days=lifetime_days)).isoformat(),
                not_after.isoformat(),
                first_seen.isoformat(),
            ),
        )


def _scan_cert(hostname: str, port: int, issuer: str, lifetime_days: float) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={hostname}",
        issuer=issuer,
        not_before=now - timedelta(hours=1),
        not_after=now - timedelta(hours=1) + timedelta(days=lifetime_days),
        fingerprint_sha256=f"fp-{port}-live",
    )


def _cached(db, hostname: str, port: int) -> str | None:
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT classification FROM endpoint_renewal_analytics "
            "WHERE hostname = ? AND port = ?",
            (hostname, port),
        ).fetchone()
    return None if row is None else str(row["classification"])


_ACME = "CN=R3, O=Let's Encrypt"
_PRIVATE = "CN=Example Test CA"


def _seed_acme(conn, hostname: str, port: int) -> None:
    _seed_history(
        conn, hostname, port, issuer=_ACME, lifetime_days=90, cadence_days=60,
        lead_days=30, periods=3, last_seen=datetime.now(UTC),
    )


def _seed_manual(conn, hostname: str, port: int) -> None:
    _seed_history(
        conn, hostname, port, issuer=_PRIVATE, lifetime_days=365, cadence_days=365,
        lead_days=0, periods=3, last_seen=datetime.now(UTC),
    )


def test_real_scan_store_refreshes_classification_for_browse_filter_and_counts(tmp_path):
    """store_scanned stages history on the caller connection (conn= branch)."""
    from cert_watch.scan import ScannedEntry, store_scanned

    db = tmp_path / "scan-store.sqlite3"
    init_schema(db)
    hostname = "scanned.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        conn.commit()
    assert _cached(db, hostname, 443) is None

    store_scanned(
        ScannedEntry(
            host=hostname, port=443, leaf=_scan_cert(hostname, 443, _ACME, 90)
        ),
        db,
    )

    python = compute_endpoint_analytics(db, ((hostname, 443),))[0]
    assert python.automation_classification == "likely-automated"
    assert _cached(db, hostname, 443) == "likely-automated"

    now = datetime.now(UTC)
    rows, total = list_dashboard_page(db, per_page=0, now=now)
    assert total == 1
    assert rows[0]["renewal"] == "automation_configured"
    filtered, filtered_total = list_dashboard_page(
        db, renewal="automation_configured", per_page=0, now=now
    )
    assert filtered_total == 1
    assert [row["hostname"] for row in filtered] == [hostname]
    assert list_dashboard_page(db, renewal="unknown", per_page=0, now=now)[1] == 0
    stats = dashboard_axis_stats(db)["renewal"]
    assert stats["automation_configured"] == 1
    assert stats["unknown"] == 0


def test_refresh_classifies_each_port_from_its_own_history(tmp_path):
    from cert_watch.scan import ScannedEntry, store_scanned

    db = tmp_path / "ports.sqlite3"
    init_schema(db)
    hostname = "multiport.example.test"
    hosts = SqliteHostRepository(db)
    hosts.add(hostname, 443)
    hosts.add(hostname, 8443)
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        _seed_manual(conn, hostname, 8443)
        conn.commit()

    store_scanned(
        ScannedEntry(host=hostname, port=443, leaf=_scan_cert(hostname, 443, _ACME, 90)),
        db,
    )
    store_scanned(
        ScannedEntry(
            host=hostname, port=8443, leaf=_scan_cert(hostname, 8443, _PRIVATE, 365)
        ),
        db,
    )

    python = {
        item.port: item.automation_classification
        for item in compute_endpoint_analytics(db, ((hostname, 443), (hostname, 8443)))
    }
    assert python == {443: "likely-automated", 8443: "manual"}
    assert _cached(db, hostname, 443) == "likely-automated"
    assert _cached(db, hostname, 8443) == "manual"

    rows, _total = list_dashboard_page(db, per_page=0, now=datetime.now(UTC))
    assert {int(row["port"]): row["renewal"] for row in rows} == {
        443: "automation_configured",
        8443: "manual",
    }


def test_raw_history_delete_invalidates_only_that_endpoint(tmp_path):
    db = tmp_path / "trigger-delete.sqlite3"
    init_schema(db)
    hostname = "trigger-delete.example.test"
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        _seed_acme(conn, hostname, 8443)
        refresh_endpoint_analytics(conn, hostname, 443)
        refresh_endpoint_analytics(conn, hostname, 8443)
        conn.commit()
    assert _cached(db, hostname, 443) is not None

    with _connect(db) as conn:
        conn.execute(
            "DELETE FROM cert_history WHERE id = ?", (f"seed-{hostname}-443-0",)
        )
        conn.commit()

    assert _cached(db, hostname, 443) is None
    assert _cached(db, hostname, 8443) == "likely-automated"


def test_raw_history_update_invalidates_old_and_new_endpoints(tmp_path):
    db = tmp_path / "trigger-update.sqlite3"
    init_schema(db)
    old_host = "trigger-old.example.test"
    new_host = "trigger-new.example.test"
    bystander = "trigger-bystander.example.test"
    with _connect(db) as conn:
        for hostname in (old_host, new_host, bystander):
            _seed_acme(conn, hostname, 443)
            refresh_endpoint_analytics(conn, hostname, 443)
        conn.commit()

    # Moving a row changes both endpoints' histories.
    with _connect(db) as conn:
        conn.execute(
            "UPDATE cert_history SET hostname = ? WHERE id = ?",
            (new_host, f"seed-{old_host}-443-0"),
        )
        conn.commit()
    assert _cached(db, old_host, 443) is None
    assert _cached(db, new_host, 443) is None
    assert _cached(db, bystander, 443) == "likely-automated"

    # An in-place edit invalidates the endpoint it belongs to.
    with _connect(db) as conn:
        refresh_endpoint_analytics(conn, bystander, 443)
        conn.execute(
            "UPDATE cert_history SET issuer = ? WHERE id = ?",
            (_PRIVATE, f"seed-{bystander}-443-1"),
        )
        conn.commit()
    assert _cached(db, bystander, 443) is None


def test_certificate_delete_cascade_refreshes_from_remaining_history(tmp_path):
    from cert_watch.database import delete_certificate_cascade
    from cert_watch.scan import ScannedEntry, store_scanned

    db = tmp_path / "cascade.sqlite3"
    init_schema(db)
    hostname = "cascade.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        conn.commit()
    leaf_id = store_scanned(
        ScannedEntry(host=hostname, port=443, leaf=_scan_cert(hostname, 443, _ACME, 90)),
        db,
    )
    assert _cached(db, hostname, 443) == "likely-automated"

    assert delete_certificate_cascade(db, leaf_id)

    with _connect(db) as conn:
        remaining = conn.execute(
            "SELECT COUNT(*) FROM cert_history WHERE hostname = ? AND port = 443",
            (hostname,),
        ).fetchone()[0]
        cached = conn.execute(
            """SELECT classification, basis_history_count, basis_latest_fingerprint
               FROM endpoint_renewal_analytics WHERE hostname = ? AND port = 443""",
            (hostname,),
        ).fetchone()
    assert remaining == 3
    assert cached is not None
    python = compute_endpoint_analytics(db, ((hostname, 443),))[0]
    assert tuple(cached) == (python.automation_classification, 3, "fp-443-2")
    assert python.automation_classification == "likely-automated"


def test_purge_refreshes_exactly_the_endpoints_it_purged(tmp_path):
    """A purged endpoint gets a recomputed row; the cutoff selects old rows.

    For an endpoint whose history is fully purged the recomputed row reads
    unknown, the same as a missing row, so this pins the refresh contract at
    the cache-row level rather than through Browse.
    """
    db = tmp_path / "purge.sqlite3"
    init_schema(db)
    old_host = "purge-old.example.test"
    fresh_host = "purge-fresh.example.test"
    now = datetime.now(UTC)
    with _connect(db) as conn:
        _seed_history(
            conn, old_host, 443, issuer=_ACME, lifetime_days=90, cadence_days=60,
            lead_days=30, periods=3, last_seen=now - timedelta(days=200),
        )
        _seed_acme(conn, fresh_host, 443)
        refresh_endpoint_analytics(conn, old_host, 443)
        refresh_endpoint_analytics(conn, fresh_host, 443)
        conn.commit()

    assert purge_old_history(db, retention_days=190) == 3

    with _connect(db) as conn:
        purged = conn.execute(
            """SELECT classification, basis_history_count
               FROM endpoint_renewal_analytics WHERE hostname = ? AND port = 443""",
            (old_host,),
        ).fetchone()
    assert purged is not None
    assert tuple(purged) == ("unknown", 0)
    assert _cached(db, fresh_host, 443) == "likely-automated"
