"""Persisted Browse renewal evidence stays identical to the Python classifier."""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import random
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta

import pytest

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
    CLASSIFIER_SOURCE_HASH,
    CLASSIFIER_VERSION,
    compute_endpoint_analytics,
    refresh_endpoint_analytics,
    refresh_stale_classifier_rows,
)

NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)
_STATE = {
    "likely-automated": "automation_configured",
    "manual": "manual",
    "unknown": "unknown",
}


def test_renewal_classifier_version_matches_logic() -> None:
    """A classifier change must invalidate rows written by the prior logic."""
    import cert_watch.database.connection as connection
    import cert_watch.renewal_analytics as analytics

    parts = [
        repr(analytics.ACME_ISSUER_FRAGMENTS),
        inspect.getsource(connection._parse_iso),
    ]
    parts.extend(
        inspect.getsource(getattr(analytics, name))
        for name in (
            "_is_acme_issuer",
            "_compute_trend",
            "_known_timestamp",
            "_known_validity_days",
            "_classify_automation",
            "_compute_host_from_entries",
            "_endpoint_entries",
        )
    )
    actual = hashlib.sha256("\n".join(parts).encode()).hexdigest()
    assert actual == CLASSIFIER_SOURCE_HASH, (
        "renewal classifier source changed (formatting-only edits also trip this "
        "guard): bump CLASSIFIER_VERSION, recompute CLASSIFIER_SOURCE_HASH from "
        "this test's source list, and re-check the harmless-append trigger"
    )


def _assert_cache_matches_from_scratch(db, hostname: str, port: int) -> None:
    expected = compute_endpoint_analytics(db, ((hostname, port),))[0]
    with _connect(db) as conn:
        row = conn.execute(
            """SELECT classifier_version, classification, evidence_json,
                      observed_lifetimes_json, lifetime_trend,
                      renewal_lead_times_json, median_lead_time,
                      median_cadence_days, deployment_count, basis_history_count
               FROM endpoint_renewal_analytics
               WHERE hostname = ? AND port = ?""",
            (hostname, port),
        ).fetchone()
        history_count = conn.execute(
            "SELECT COUNT(*) FROM cert_history WHERE hostname = ? AND port = ?",
            (hostname, port),
        ).fetchone()[0]
    assert row is not None
    assert row["classifier_version"] == CLASSIFIER_VERSION
    assert row["classification"] == expected.automation_classification
    assert json.loads(row["evidence_json"]) == expected.classification_evidence
    assert json.loads(row["observed_lifetimes_json"]) == expected.observed_lifetimes
    assert row["lifetime_trend"] == expected.lifetime_trend
    assert json.loads(row["renewal_lead_times_json"]) == expected.renewal_lead_times
    assert row["median_lead_time"] == expected.median_lead_time
    assert row["median_cadence_days"] == expected.median_cadence_days
    assert row["deployment_count"] == expected.cert_count
    assert row["basis_history_count"] == history_count


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


def test_repeat_scan_skips_history_refresh_but_new_period_does_not(
    tmp_path, monkeypatch
):
    import cert_watch.renewal_analytics as analytics

    db = tmp_path / "repeat.sqlite3"
    init_schema(db)
    hostname = "repeat.example.test"
    first_seen = NOW - timedelta(days=10)

    def cert(fingerprint: str) -> Certificate:
        return Certificate(
            subject=f"CN={hostname}",
            issuer=_ACME,
            not_before=first_seen,
            not_after=first_seen + timedelta(days=90),
            fingerprint_sha256=fingerprint,
        )

    record_cert_history(db, hostname, 443, cert("same"), scanned_at=first_seen.isoformat())
    original = analytics.refresh_endpoint_analytics
    refreshed: list[str] = []

    def counted(conn, host: str, port: int):
        refreshed.append(host)
        return original(conn, host, port)

    monkeypatch.setattr(analytics, "refresh_endpoint_analytics", counted)
    record_cert_history(
        db,
        hostname,
        443,
        cert("same"),
        scanned_at=(first_seen + timedelta(days=1)).isoformat(),
    )
    assert refreshed == []
    _assert_cache_matches_from_scratch(db, hostname, 443)

    record_cert_history(
        db,
        hostname,
        443,
        cert("new"),
        scanned_at=(first_seen + timedelta(days=2)).isoformat(),
    )
    assert refreshed == [hostname]
    _assert_cache_matches_from_scratch(db, hostname, 443)


def test_same_fingerprint_validity_recovery_still_refreshes(tmp_path, monkeypatch):
    import cert_watch.renewal_analytics as analytics

    db = tmp_path / "validity-recovery.sqlite3"
    init_schema(db)
    hostname = "validity-recovery.example.test"
    first_seen = NOW - timedelta(days=10)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO cert_history
               (id, hostname, port, fingerprint_sha256, issuer,
                not_before, not_after, scanned_at)
               VALUES ('missing', ?, 443, 'same', ?, NULL, ?, ?)""",
            (
                hostname,
                _ACME,
                (first_seen + timedelta(days=90)).isoformat(),
                first_seen.isoformat(),
            ),
        )
        refresh_endpoint_analytics(conn, hostname, 443)
        conn.commit()

    original = analytics.refresh_endpoint_analytics
    refreshed = 0

    def counted(conn, host: str, port: int):
        nonlocal refreshed
        refreshed += 1
        return original(conn, host, port)

    monkeypatch.setattr(analytics, "refresh_endpoint_analytics", counted)
    record_cert_history(
        db,
        hostname,
        443,
        Certificate(
            subject=f"CN={hostname}",
            issuer=_ACME,
            not_before=first_seen,
            not_after=first_seen + timedelta(days=90),
            fingerprint_sha256="same",
        ),
        scanned_at=(first_seen + timedelta(days=1)).isoformat(),
    )
    assert refreshed == 1
    _assert_cache_matches_from_scratch(db, hostname, 443)


@pytest.mark.parametrize("invalid_kind", ["julian-day", "malformed"])
def test_non_iso_validity_never_takes_the_repeat_scan_fast_path(
    tmp_path, invalid_kind
):
    db = tmp_path / f"non-iso-{invalid_kind}.sqlite3"
    init_schema(db)
    hostname = f"non-iso-{invalid_kind}.example.test"
    first_seen = NOW - timedelta(days=200)

    def cert(fingerprint: str, issued_at: datetime) -> Certificate:
        return Certificate(
            subject=f"CN={hostname}",
            issuer=_ACME,
            not_before=issued_at,
            not_after=issued_at + timedelta(days=90),
            fingerprint_sha256=fingerprint,
        )

    for index, fingerprint in enumerate(("A", "B")):
        issued_at = first_seen + timedelta(days=index * 60)
        record_cert_history(
            db,
            hostname,
            443,
            cert(fingerprint, issued_at),
            scanned_at=issued_at.isoformat(),
        )

    issued_at = first_seen + timedelta(days=120)
    with _connect(db) as conn:
        invalid_not_before = "not-a-date"
        if invalid_kind == "julian-day":
            invalid_not_before = str(
                conn.execute(
                    "SELECT julianday(?)", (issued_at.isoformat(),)
                ).fetchone()[0]
            )
        conn.execute(
            """INSERT INTO cert_history
               (id, hostname, port, fingerprint_sha256, issuer,
                not_before, not_after, scanned_at)
               VALUES ('invalid-first', ?, 443, 'C', ?, ?, ?, ?)""",
            (
                hostname,
                _ACME,
                invalid_not_before,
                (issued_at + timedelta(days=90)).isoformat(),
                issued_at.isoformat(),
            ),
        )
        refresh_endpoint_analytics(conn, hostname, 443)
        conn.commit()
    assert _cached(db, hostname, 443) == "unknown"

    record_cert_history(
        db,
        hostname,
        443,
        cert("C", issued_at),
        scanned_at=(issued_at + timedelta(days=1)).isoformat(),
    )
    assert _cached(db, hostname, 443) == "likely-automated"
    _assert_cache_matches_from_scratch(db, hostname, 443)


def test_insert_or_replace_invalidates_reused_history_id(tmp_path):
    """The reviewer's REPLACE probe must fail closed, even with triggers off."""
    db = tmp_path / "replace.sqlite3"
    init_schema(db)
    hostname = "replace.example.test"
    first_seen = NOW - timedelta(days=200)
    history_ids: list[str] = []

    for fingerprint, day in (("A", 0), ("A", 40), ("B", 60), ("C", 120), ("C", 121)):
        issued_at = first_seen + timedelta(days={"A": 0, "B": 60, "C": 120}[fingerprint])
        history_ids.append(
            record_cert_history(
                db,
                hostname,
                443,
                Certificate(
                    subject=f"CN={hostname}",
                    issuer=_ACME,
                    not_before=issued_at,
                    not_after=issued_at + timedelta(days=90),
                    fingerprint_sha256=fingerprint,
                ),
                scanned_at=(first_seen + timedelta(days=day)).isoformat(),
            )
        )
    assert _cached(db, hostname, 443) == "likely-automated"

    issued_at = first_seen + timedelta(days=120)
    with _connect(db) as conn:
        assert conn.execute("PRAGMA recursive_triggers").fetchone()[0] == 0
        conn.execute(
            """INSERT OR REPLACE INTO cert_history
               (id, hostname, port, fingerprint_sha256, issuer,
                not_before, not_after, scanned_at)
               VALUES (?, ?, 443, 'C', ?, ?, ?, ?)""",
            (
                history_ids[0],
                hostname,
                _ACME,
                issued_at.isoformat(),
                (issued_at + timedelta(days=90)).isoformat(),
                (first_seen + timedelta(days=122)).isoformat(),
            ),
        )
        conn.commit()

    assert _cached(db, hostname, 443) is None
    expected = compute_endpoint_analytics(db, ((hostname, 443),))[0]
    assert expected.automation_classification == "manual"


def test_incremental_cache_matches_from_scratch_after_each_insert_and_prune(tmp_path):
    db = tmp_path / "incremental-property.sqlite3"
    init_schema(db)
    hostname = "property.example.test"
    randomizer = random.Random(128)
    base = datetime.now(UTC) - timedelta(days=220)
    fingerprints = ["fp-0"]

    for index in range(80):
        if randomizer.random() < 0.3:
            fingerprints.append(f"fp-{len(fingerprints)}")
        fingerprint = randomizer.choice(fingerprints[-2:])
        scanned_at = base + timedelta(
            days=index * 3 + randomizer.choice([-4, -1, 0, 0, 1])
        )
        lifetime = randomizer.choice([60, 90, 365])
        record_cert_history(
            db,
            hostname,
            443,
            Certificate(
                subject=f"CN={hostname}",
                issuer=_ACME if lifetime <= 90 else _PRIVATE,
                not_before=scanned_at - timedelta(days=1),
                not_after=scanned_at - timedelta(days=1) + timedelta(days=lifetime),
                fingerprint_sha256=fingerprint,
            ),
            scanned_at=scanned_at.isoformat(),
        )
        _assert_cache_matches_from_scratch(db, hostname, 443)

    assert purge_old_history(db, retention_days=120) > 0
    _assert_cache_matches_from_scratch(db, hostname, 443)


def test_stale_classifier_version_is_hidden_then_refreshed(tmp_path):
    db = tmp_path / "version.sqlite3"
    init_schema(db)
    hostname = "version.example.test"
    SqliteHostRepository(db).add(hostname, 443)
    replace_scanned(db, hostname, 443, _live_cert(hostname, "live"), [], True)
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        refresh_endpoint_analytics(conn, hostname, 443)
        conn.execute(
            """UPDATE endpoint_renewal_analytics
               SET classifier_version = 0, classification = 'manual'
               WHERE hostname = ? AND port = 443""",
            (hostname,),
        )
        conn.commit()

    rows, total = list_dashboard_page(db, per_page=0, now=NOW)
    assert total == 1
    assert rows[0]["renewal"] == "unknown"
    assert refresh_stale_classifier_rows(db) == 1
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW)
    assert rows[0]["renewal"] == "automation_configured"
    _assert_cache_matches_from_scratch(db, hostname, 443)


def test_init_schema_refreshes_stale_versions_once(tmp_path, monkeypatch):
    import cert_watch.database.schema as schema
    import cert_watch.renewal_analytics as analytics

    db = tmp_path / "startup-version.sqlite3"
    init_schema(db)
    hostname = "startup-version.example.test"
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        refresh_endpoint_analytics(conn, hostname, 443)
        conn.execute(
            "UPDATE endpoint_renewal_analytics SET classifier_version = 0"
        )
        conn.commit()

    original = analytics.refresh_stale_classifier_rows
    calls = 0

    def counted(db_path):
        nonlocal calls
        calls += 1
        return original(db_path)

    monkeypatch.setattr(analytics, "refresh_stale_classifier_rows", counted)
    schema._initialized.clear()
    init_schema(db)
    init_schema(db)

    assert calls == 1
    _assert_cache_matches_from_scratch(db, hostname, 443)


def test_repeat_write_refreshes_a_stale_classifier_version(tmp_path):
    db = tmp_path / "write-version.sqlite3"
    init_schema(db)
    hostname = "write-version.example.test"
    with _connect(db) as conn:
        _seed_acme(conn, hostname, 443)
        refresh_endpoint_analytics(conn, hostname, 443)
        latest = conn.execute(
            """SELECT fingerprint_sha256, not_before, not_after, scanned_at
               FROM cert_history WHERE hostname = ? AND port = 443
               ORDER BY scanned_at DESC, id DESC LIMIT 1""",
            (hostname,),
        ).fetchone()
        conn.execute(
            """UPDATE endpoint_renewal_analytics
               SET classifier_version = 0, classification = 'manual'
               WHERE hostname = ? AND port = 443""",
            (hostname,),
        )
        conn.commit()

    record_cert_history(
        db,
        hostname,
        443,
        Certificate(
            subject=f"CN={hostname}",
            issuer=_ACME,
            not_before=datetime.fromisoformat(latest["not_before"]),
            not_after=datetime.fromisoformat(latest["not_after"]),
            fingerprint_sha256=str(latest["fingerprint_sha256"]),
        ),
        scanned_at=(datetime.fromisoformat(latest["scanned_at"]) + timedelta(days=1)).isoformat(),
    )
    _assert_cache_matches_from_scratch(db, hostname, 443)
    assert _cached(db, hostname, 443) == "likely-automated"


def test_startup_refresh_logs_one_failure_and_continues(
    tmp_path, monkeypatch, caplog
):
    import cert_watch.database.schema as schema
    import cert_watch.renewal_analytics as analytics

    db = tmp_path / "startup-failure.sqlite3"
    init_schema(db)
    hostnames = ["good-one.example.test", "broken.example.test", "good-two.example.test"]
    with _connect(db) as conn:
        for hostname in hostnames:
            _seed_acme(conn, hostname, 443)
            refresh_endpoint_analytics(conn, hostname, 443)
        conn.execute(
            "UPDATE endpoint_renewal_analytics SET classifier_version = 0"
        )
        conn.commit()

    original = analytics.refresh_endpoint_analytics
    attempted: list[str] = []

    def sometimes_fails(conn, hostname: str, port: int):
        attempted.append(hostname)
        if hostname == "broken.example.test":
            raise ValueError("injected classifier failure")
        return original(conn, hostname, port)

    monkeypatch.setattr(analytics, "refresh_endpoint_analytics", sometimes_fails)
    schema._initialized.clear()
    with caplog.at_level(logging.WARNING, logger="cert_watch.renewal_analytics"):
        init_schema(db)
    init_schema(db)

    assert attempted == sorted(hostnames)
    with _connect(db) as conn:
        versions = dict(
            conn.execute(
                "SELECT hostname, classifier_version FROM endpoint_renewal_analytics"
            )
        )
    assert versions == {
        "broken.example.test": 0,
        "good-one.example.test": CLASSIFIER_VERSION,
        "good-two.example.test": CLASSIFIER_VERSION,
    }
    assert any(
        "broken.example.test:443 (ValueError)" in record.getMessage()
        for record in caplog.records
    )


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


def test_startup_refresh_commits_once_per_batch(tmp_path, monkeypatch):
    import contextlib

    import cert_watch.renewal_analytics as analytics

    db = tmp_path / "batches.sqlite3"
    init_schema(db)
    hostnames = [f"batch-{i}.example.test" for i in range(5)]
    with _connect(db) as conn:
        for hostname in hostnames:
            _seed_acme(conn, hostname, 443)
            refresh_endpoint_analytics(conn, hostname, 443)
        conn.execute("UPDATE endpoint_renewal_analytics SET classifier_version = 0")
        conn.commit()

    statements: list[str] = []
    original_connect = analytics._connect

    @contextlib.contextmanager
    def traced(path):
        with original_connect(path) as conn:
            conn.set_trace_callback(statements.append)
            yield conn

    monkeypatch.setattr(analytics, "_connect", traced)
    monkeypatch.setattr(analytics, "_STALE_REFRESH_BATCH_SIZE", 2)
    assert refresh_stale_classifier_rows(db) == 5

    # Three batches (2 + 2 + 1): each opens one transaction, so the per-endpoint
    # savepoints nest inside it instead of each committing on its own.
    assert sum(s.strip().upper() == "BEGIN" for s in statements) == 3
    assert sum(s.strip().upper() == "COMMIT" for s in statements) == 3
