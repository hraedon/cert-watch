"""Tests for the migration runner and backup CLI (Plan 009).

AC-1: Starting a new binary against an older-schema DB applies pending
     migrations idempotently and records them in schema_version.
AC-2: Re-running migrations is a no-op (idempotent).
AC-3: A pre-migration backup file is produced automatically.
AC-4: cert-watch backup produces a restorable copy while the app is running
     (WAL-safe); a round-trip restore test passes.
AC-5: Documented, tested restore procedure.
"""

from __future__ import annotations

import contextlib
import json
import logging
import multiprocessing
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from cert_watch.database.schema import ensure_base, init_schema


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    return db


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def _run_concurrent_migration(
    db_path: str,
    start: Any,
    results: Any,
) -> None:
    """Spawn-safe worker that widens the pre-migration backup race window."""
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.database.connection import close_connections
    from cert_watch.migrations import runner

    original_backup = runner._backup

    def delayed_backup(*args: Any, **kwargs: Any) -> Path:
        time.sleep(0.5)
        return original_backup(*args, **kwargs)

    runner._backup = delayed_backup
    start.wait(timeout=10)
    try:
        results.put(runner.run_pending_migrations(db_path, backup=True))
    finally:
        close_connections()


# v0.6.x baseline DDL — the tables and columns that existed before numbered
# migrations were introduced. Newer tables/columns are added only by the
# migration runner during the upgrade under test.
_V06X_BASELINE_DDL = """
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    source TEXT NOT NULL DEFAULT 'unknown',
    hostname TEXT,
    port INTEGER,
    is_leaf INTEGER NOT NULL DEFAULT 1,
    parent_cert_id TEXT,
    chain_valid INTEGER,
    replaces_cert_id TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    threshold_days INTEGER,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    threshold_days INTEGER,
    tags TEXT NOT NULL DEFAULT '',
    scan_interval_hours INTEGER,
    owner_name TEXT NOT NULL DEFAULT '',
    owner_email TEXT NOT NULL DEFAULT '',
    owner_slack TEXT NOT NULL DEFAULT '',
    renewal_status TEXT NOT NULL DEFAULT 'pending',
    renewal_method TEXT NOT NULL DEFAULT '',
    runbook_url TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL,
    UNIQUE(hostname, port)
);

CREATE TABLE IF NOT EXISTS trust_anchors (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_posture (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    hostname TEXT,
    port INTEGER,
    grade TEXT NOT NULL,
    protocol_version TEXT,
    ocsp_stapling INTEGER,
    hsts INTEGER,
    must_staple INTEGER DEFAULT 0,
    findings TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);
"""


def _create_v06x_baseline_db(db_path: Path) -> None:
    """Create a SQLite DB with only the v0.6.x-era baseline schema."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
        conn.executescript(_V06X_BASELINE_DDL)
        conn.commit()


def _insert_v06x_sample_data(db_path: Path) -> None:
    """Insert a small sanitized dataset into a v0.6.x baseline DB."""
    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, threshold_days, tags, owner_email, added_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "h1",
                "example.com",
                443,
                14,
                "prod",
                "admin@example.com",
                "2025-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, threshold_days, tags, owner_email, added_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "h2",
                "test.example.com",
                8443,
                7,
                "dev",
                "dev@example.com",
                "2025-01-02T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, san_dns_names,"
            " fingerprint_sha256, raw_der, source, hostname, port, is_leaf, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "c1",
                "CN=example.com",
                "CN=Test CA",
                "2025-01-01T00:00:00+00:00",
                "2026-01-01T00:00:00+00:00",
                '["example.com"]',
                "aa" * 32,
                b"leaf-der",
                "scan",
                "example.com",
                443,
                1,
                "2025-01-01T00:00:00+00:00",
                "2025-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, san_dns_names,"
            " fingerprint_sha256, raw_der, source, is_leaf, created_at, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "c2",
                "CN=Test CA",
                "CN=Test Root",
                "2020-01-01T00:00:00+00:00",
                "2030-01-01T00:00:00+00:00",
                '["Test CA"]',
                "bb" * 32,
                b"intermediate-der",
                "upload",
                0,
                "2025-01-01T00:00:00+00:00",
                "2025-01-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO alerts (id, cert_id, alert_type, status, message,"
            " threshold_days, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "a1",
                "c1",
                "expiry",
                "pending",
                "Certificate expires soon",
                14,
                "2025-06-01T00:00:00+00:00",
            ),
        )
        conn.execute(
            "INSERT INTO scan_history (id, hostname, port, status, scanned_at)"
            " VALUES (?, ?, ?, ?, ?)",
            ("sh1", "example.com", 443, "ok", "2025-06-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO scan_posture (id, cert_id, hostname, port, grade, findings, scanned_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("sp1", "c1", "example.com", 443, "A", "[]", "2025-06-01T00:00:00+00:00"),
        )
        conn.execute(
            "INSERT INTO trust_anchors (id, subject, issuer, not_before, not_after, san_dns_names,"
            " fingerprint_sha256, raw_der, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ta1",
                "CN=Test Root",
                "CN=Test Root",
                "2020-01-01T00:00:00+00:00",
                "2030-01-01T00:00:00+00:00",
                '["Test Root"]',
                "cc" * 32,
                b"root-der",
                "2025-01-01T00:00:00+00:00",
            ),
        )
        conn.commit()


# ---------- AC-1: Migrations apply and record in schema_version ----------

def test_init_schema_creates_all_tables(db_path: Path) -> None:
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        ).fetchall()}
    # Core tables
    assert "certificates" in tables
    assert "alerts" in tables
    assert "scan_history" in tables
    assert "hosts" in tables
    assert "trust_anchors" in tables
    assert "scan_posture" in tables
    assert "audit_log" in tables
    # Migration tracking
    assert "schema_version" in tables


def test_schema_version_records_baseline(db_path: Path) -> None:
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, description FROM schema_version ORDER BY id"
        ).fetchall()
    ids = [r[0] for r in rows]
    assert "0001" in ids


def test_schema_version_records_audit_migration(db_path: Path) -> None:
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id FROM schema_version ORDER BY id"
        ).fetchall()
    ids = [r[0] for r in rows]
    assert "0002" in ids


# ---------- AC-2: Re-running migrations is a no-op ----------

def test_init_schema_idempotent(db_path: Path) -> None:
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        count1 = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
    # Run again
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        count2 = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
    assert count1 == count2


def test_run_pending_nothing_pending(db_path: Path) -> None:
    init_schema(db_path)
    import cert_watch.migrations.registry  # noqa: F401 — side-effect: registers migrations
    from cert_watch.migrations.registry import runner

    applied = runner.run_pending_migrations(db_path, backup=False)
    assert applied == []


def test_concurrent_processes_serialize_migration_startup(tmp_path: Path) -> None:
    """Two app processes wait their turn and only one applies each migration."""
    db = tmp_path / "concurrent.sqlite3"
    init_schema(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute("DELETE FROM schema_version WHERE id = '0035'")
        conn.commit()
    for old_backup in tmp_path.glob("concurrent-pre-migration-*.sqlite3"):
        old_backup.unlink()

    ctx = multiprocessing.get_context("spawn")
    start = ctx.Barrier(2)
    results = ctx.Queue()
    processes = [
        ctx.Process(
            target=_run_concurrent_migration,
            args=(str(db), start, results),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=20)
    try:
        assert [process.exitcode for process in processes] == [0, 0]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)

    assert sorted([results.get(timeout=2), results.get(timeout=2)]) == [[], ["0035"]]
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_version WHERE id = '0035'"
        ).fetchone() == (1,)

    backups = list(tmp_path.glob("concurrent-pre-migration-*.sqlite3"))
    assert len(backups) == 1
    with sqlite3.connect(str(backups[0])) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert conn.execute(
            "SELECT COUNT(*) FROM schema_version WHERE id = '0035'"
        ).fetchone() == (0,)


# ---------- AC-3: Pre-migration backup ----------

def test_ct_issuer_first_seen_dropped(db_path: Path) -> None:
    """Migration 0028 drops the unused ct_issuer_first_seen table (WI-082)."""
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        assert conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ct_issuer_first_seen'"
        ).fetchone() is None


def test_drop_ct_issuer_first_seen_idempotent(db_path: Path) -> None:
    """Migration 0028 is idempotent."""
    from cert_watch.migrations.m0028_drop_ct_issuer_first_seen import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        upgrade(conn)
        upgrade(conn)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert "ct_issuer_first_seen" not in tables


def test_digest_delivery_ledger_migration_is_idempotent(db_path: Path) -> None:
    from cert_watch.migrations.m0029_digest_delivery_ledger import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        upgrade(conn)
        upgrade(conn)
        columns = {r[1] for r in conn.execute(
            "PRAGMA table_info(digest_deliveries)"
        ).fetchall()}
    assert {"digest_key", "channel", "target", "lease_expires_at", "sent_at"} <= columns


def test_backup_created_before_migration(tmp_path: Path) -> None:
    db = tmp_path / "test.sqlite3"
    init_schema(db)

    # Add some data
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, added_at)"
            " VALUES ('h1', 'test.example.com', 443, '2026-01-01T00:00:00+00:00')"
        )
        conn.commit()

    # Simulate a new migration (we'll just re-run pending, which should be no-op)
    from cert_watch.migrations.runner import create_backup
    backup_path = tmp_path / "manual_backup.sqlite3"
    result = create_backup(db, backup_path)
    assert result == backup_path
    assert backup_path.exists()
    assert backup_path.stat().st_size > 0

    # Verify backup is a valid SQLite database
    with sqlite3.connect(str(backup_path)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        assert count == 1


def test_automatic_backup_names_are_unique(tmp_path: Path) -> None:
    from cert_watch.migrations.runner import _backup

    db = tmp_path / "unique.sqlite3"
    with sqlite3.connect(str(db)) as conn:
        conn.execute("CREATE TABLE probe (value TEXT NOT NULL)")
        conn.execute("INSERT INTO probe VALUES ('preserved')")
        conn.commit()

    backups = [_backup(db), _backup(db)]
    assert backups[0] != backups[1]
    for backup in backups:
        with sqlite3.connect(str(backup)) as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert conn.execute("SELECT value FROM probe").fetchone() == ("preserved",)


# ---------- AC-4: cert-watch backup round-trip ----------

def test_backup_restore_round_trip(tmp_path: Path) -> None:
    """AC-4: backup produces a restorable copy."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    # Insert data. Use contextlib.closing: a sqlite3 ``with`` block only commits,
    # it does NOT close the connection, so the handle (and the -wal it holds)
    # would survive into the restore step below and block the unlink on Windows.
    with contextlib.closing(sqlite3.connect(str(db))) as conn:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, added_at)"
            " VALUES ('h1', 'roundtrip.example.com', 443, '2026-01-01T00:00:00+00:00')"
        )
        conn.execute(
            "INSERT INTO audit_log (id, ts, actor, action, target_type, target_id)"
            " VALUES ('a1', '2026-01-01T00:00:00', 'test', 'host.add', 'host', 'h1')"
        )
        conn.commit()

    # Backup
    from cert_watch.migrations.runner import create_backup
    backup = create_backup(db, tmp_path / "backup.sqlite3")

    # Restore: stop the service, replace the file, start (verify). Closing the
    # cached connections is the in-process stand-in for stopping the service —
    # without it the cache still holds the -wal/-shm handles, which POSIX lets
    # you unlink anyway but Windows does not (WinError 32). (BC-049)
    from cert_watch.database.connection import close_connections
    close_connections()
    for artifact in (db.with_suffix(".sqlite3-wal"), db.with_suffix(".sqlite3-shm")):
        artifact.unlink(missing_ok=True)
    db.unlink()
    backup.rename(db)

    # Verify restored data (closing() again so the tmp dir teardown can delete
    # the DB + -wal on Windows).
    init_schema(db)  # Should be idempotent on restored DB
    with contextlib.closing(sqlite3.connect(str(db))) as conn:
        hosts = conn.execute("SELECT hostname FROM hosts").fetchone()
        assert hosts[0] == "roundtrip.example.com"
        audits = conn.execute("SELECT action FROM audit_log").fetchone()
        assert audits[0] == "host.add"


# ---------- AC-5: Migration baseline stamps for existing DB ----------

def test_baseline_stamps_on_existing_db(tmp_path: Path) -> None:
    """An existing database (pre-migration) gets 0001 stamped automatically."""
    db = tmp_path / "test.sqlite3"

    # Create a "pre-migration" database with just the core tables
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        # No schema_version table should exist yet (ensure_base doesn't create it)
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "schema_version" not in tables

    # Now run init_schema which should stamp the baseline
    init_schema(db)
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT id FROM schema_version ORDER BY id"
        ).fetchall()
    ids = [r[0] for r in rows]
    assert "0001" in ids
    assert "0002" in ids


def test_fresh_db_gets_all_migrations(db_path: Path) -> None:
    """A fresh database gets all migrations applied."""
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id FROM schema_version ORDER BY id"
        ).fetchall()
    ids = [r[0] for r in rows]
    # Should have baseline + audit_log migration
    assert "0001" in ids
    assert "0002" in ids


def test_hosts_has_renewal_method_column(db_path: Path) -> None:
    """Verify the migration system doesn't break column additions."""
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cols = _table_columns(conn, "hosts")
    assert "renewal_method" in cols
    assert "runbook_url" in cols


def test_audit_log_table_exists(db_path: Path) -> None:
    """Verify audit_log table was created (from migration 0002)."""
    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert "audit_log" in tables


def test_migration_from_v06x_baseline_with_data(db_path: Path) -> None:
    """A v0.6.x-era database with real rows migrates to the current schema.

    Simulates a long-lived production database created before numbered migrations,
    runs the full migration runner, and asserts both schema completeness and
    data survival.
    """
    _create_v06x_baseline_db(db_path)
    _insert_v06x_sample_data(db_path)

    # Run the upgrade path used by the app on startup.
    init_schema(db_path)

    # All registered migrations should be recorded.
    import cert_watch.migrations.registry  # noqa: F401 — side-effect: registers
    from cert_watch.migrations.runner import get_migrations

    expected_ids = [m[0] for m in get_migrations()]
    with sqlite3.connect(str(db_path)) as conn:
        applied_ids = [r[0] for r in conn.execute(
            "SELECT id FROM schema_version ORDER BY id"
        ).fetchall()]
    assert applied_ids == expected_ids

    # Tables added after the baseline must exist.
    with sqlite3.connect(str(db_path)) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    for table in (
        "audit_log",
        "rate_limits",
        "kv_store",
        "alert_groups",
        "alert_group_certs",
        "cert_history",
        "session_versions",
        "api_keys",
        "users",
        "roles",
        "event_log",
    ):
        assert table in tables

    # Columns added after the baseline must exist.
    with sqlite3.connect(str(db_path)) as conn:
        alerts_cols = _table_columns(conn, "alerts")
        certs_cols = _table_columns(conn, "certificates")
        hosts_cols = _table_columns(conn, "hosts")
        posture_cols = _table_columns(conn, "scan_posture")
        cert_history_cols = _table_columns(conn, "cert_history")

    assert "extra_recipients" in alerts_cols
    assert "read" in alerts_cols
    assert "hostname" in alerts_cols
    assert "subject" in alerts_cols
    assert "tags" in certs_cols
    # 0031: certificates.notes is merged into hosts.notes and dropped.
    assert "notes" not in certs_cols
    assert "notes" in hosts_cols
    assert "expected_issuers" in hosts_cols
    assert "chain_incomplete" in posture_cols
    assert "chain_status" in posture_cols
    assert "caa_present" in posture_cols
    assert "caa_records" in posture_cols
    assert "verify_requested" in posture_cols
    assert "not_before" in cert_history_cols

    # Original rows must survive unchanged where columns existed in v0.6.x.
    with sqlite3.connect(str(db_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM scan_posture").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM trust_anchors").fetchone()[0] == 1

        host = conn.execute(
            "SELECT hostname, port, owner_email FROM hosts WHERE id = ?", ("h1",)
        ).fetchone()
        assert host == ("example.com", 443, "admin@example.com")

        cert = conn.execute(
            "SELECT subject, fingerprint_sha256, source FROM certificates WHERE id = ?",
            ("c1",),
        ).fetchone()
        assert cert == ("CN=example.com", "aa" * 32, "scan")

        alert = conn.execute(
            "SELECT cert_id, alert_type, status, message FROM alerts WHERE id = ?",
            ("a1",),
        ).fetchone()
        assert alert == ("c1", "expiry", "pending", "Certificate expires soon")

    # Smoke-read the real dashboard query helpers against the migrated DB.
    # Schema/row-count assertions above prove structure and data survival;
    # this proves the app's actual read paths execute against a database that
    # reached the current schema by *migration* (not fresh init) — the class of
    # bug a long-lived production DB hits that fresh-schema tests cannot (P3.1).
    from cert_watch.database.dashboard import (
        list_dashboard_grouped_page,
        list_dashboard_page,
    )
    from cert_watch.database.fleet import list_fleet_pivot

    rows, total = list_dashboard_page(db_path)
    assert total >= 1
    leaf = next(r for r in rows if r["name"] == "example.com")
    # The san_dns_names JSON column must round-trip through json.loads — the
    # read path the raw-SQL assertions above never exercise.
    assert leaf["san_dns_names"] == ["example.com"]

    grouped_rows, grouped_total = list_dashboard_grouped_page(db_path)
    assert grouped_total >= 1
    assert grouped_rows  # at least one grouped entry materialises

    for pivot in ("issuer", "owner", "renewal_method"):
        groups = list_fleet_pivot(db_path, pivot)
        # Aggregation must execute and total the surviving leaf certs.
        assert isinstance(groups, list)
        assert sum(g["count"] for g in groups) >= 1


# ---------- CLI backup subcommand ----------

def test_backup_cli_subcommand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that cert-watch backup creates a restorable file."""
    db = tmp_path / "cert-watch.sqlite3"
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    init_schema(db)

    # Insert data
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, added_at)"
            " VALUES ('h1', 'cli-test.example.com', 443, '2026-01-01T00:00:00+00:00')"
        )
        conn.commit()

    from cert_watch.__main__ import main
    backup_path = tmp_path / "cli_backup.sqlite3"
    main(["backup", str(backup_path)])

    assert backup_path.exists()
    # Verify it's a valid database
    with sqlite3.connect(str(backup_path)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        assert count == 1


# ── chain_status column (BC-100) ────────────────────────────────────────────


def test_migration_0016_adds_chain_status_column(tmp_path):
    from cert_watch.database.schema import ensure_base
    from cert_watch.migrations.m0016_chain_status import upgrade

    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    assert "chain_status" in cols


# ── CAA columns (BC-121) ────────────────────────────────────────────────────


def test_migration_0017_adds_caa_columns(tmp_path):
    from cert_watch.database.schema import ensure_base
    from cert_watch.migrations.m0017_caa_per_scan import upgrade

    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    assert "caa_present" in cols
    assert "caa_records" in cols


# ── 0031: merge per-certificate notes into host notes (UI-INVENTORY V1) ──────


def _mk_pre0031_db(db: Path, *, include_orphan: bool = True) -> None:
    """Create a current DB with the pre-0031 notes column restored."""
    init_schema(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute("DROP TABLE schema_version")
        conn.execute(
            "ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''"
        )
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, notes, added_at)"
            " VALUES ('h1', 'a.example.com', 443, 'existing host note', '2026-01-01')"
        )
        certs = [
            ("c1", "CN=a.example.com", "a.example.com", 443, "cert note one"),
            ("c2", "CN=a.example.com", "a.example.com", 443, "cert note two"),
        ]
        if include_orphan:
            certs.append(
                ("c3", "CN=orphan.example.com", None, None, "orphan uploaded note")
            )
        for cid, subject, hostname, port, notes in certs:
            conn.execute(
                "INSERT INTO certificates (id, subject, issuer, not_before, not_after,"
                " san_dns_names, fingerprint_sha256, raw_der, source, hostname, port,"
                " is_leaf, notes, created_at, updated_at)"
                " VALUES (?, ?, 'CN=Test CA', '2025-01-01', '2026-01-01', '[]',"
                " ?, X'00', 'scan', ?, ?, 1, ?, '2025-01-01', '2025-01-01')",
                (cid, subject, "ab" * 32, hostname, port, notes),
            )
        conn.commit()


def test_migration_0031_merges_notes_and_drops_column(tmp_path: Path) -> None:
    from cert_watch.migrations.m0031_merge_cert_notes import upgrade

    db = tmp_path / "test.db"
    _mk_pre0031_db(db, include_orphan=False)
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)

    with sqlite3.connect(str(db)) as conn:
        certs_cols = _table_columns(conn, "certificates")
        merged = conn.execute(
            "SELECT notes FROM hosts WHERE hostname = 'a.example.com'"
        ).fetchone()[0]
    assert "notes" not in certs_cols
    assert "existing host note" in merged
    assert "cert note one" in merged
    assert "cert note two" in merged


def test_migration_0031_does_not_treat_substring_as_duplicate(tmp_path: Path) -> None:
    from cert_watch.migrations.m0031_merge_cert_notes import upgrade

    db = tmp_path / "substring.db"
    _mk_pre0031_db(db, include_orphan=False)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "UPDATE hosts SET notes = 'context around cert note one' WHERE id = 'h1'"
        )
        conn.execute("UPDATE certificates SET notes = '' WHERE id = 'c2'")
        upgrade(conn)

    with sqlite3.connect(str(db)) as conn:
        merged = conn.execute("SELECT notes FROM hosts WHERE id = 'h1'").fetchone()[0]
    assert merged == "context around cert note one\n\ncert note one"


def test_migration_0031_skips_normalized_exact_duplicate(tmp_path: Path) -> None:
    from cert_watch.migrations.m0031_merge_cert_notes import upgrade

    db = tmp_path / "exact-duplicate.db"
    _mk_pre0031_db(db, include_orphan=False)
    with sqlite3.connect(str(db)) as conn:
        conn.execute("UPDATE hosts SET notes = '  cert note one  ' WHERE id = 'h1'")
        conn.execute("UPDATE certificates SET notes = '' WHERE id = 'c2'")
        upgrade(conn)

    with sqlite3.connect(str(db)) as conn:
        merged = conn.execute("SELECT notes FROM hosts WHERE id = 'h1'").fetchone()[0]
    assert merged == "  cert note one  "


def test_migration_0031_warns_on_orphan_notes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Startup preserves orphan notes while moving matched notes to hosts."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.certificate_model import Certificate
    from cert_watch.database.repo import SqliteCertificateRepository
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "test.db"
    _mk_pre0031_db(db)
    _stamp_feature_branch_migrations(
        db, tuple(f"{number:04d}" for number in range(1, 31))
    )
    with caplog.at_level(logging.WARNING, logger="cert_watch.migrations.0031"):
        run_pending_migrations(db, backup=False)

    with sqlite3.connect(str(db)) as conn:
        certs_cols = _table_columns(conn, "certificates")
        legacy_notes = dict(
            conn.execute("SELECT id, notes FROM certificates ORDER BY id").fetchall()
        )
        host_notes = conn.execute(
            "SELECT notes FROM hosts WHERE id = 'h1'"
        ).fetchone()[0]
    assert "notes" in certs_cols
    assert legacy_notes == {"c1": "", "c2": "", "c3": "orphan uploaded note"}
    assert "cert note one" in host_notes
    assert "cert note two" in host_notes
    assert any(
        "preserving" in record.message and "c3" in record.message
        for record in caplog.records
    )

    # Current repository inserts omit the deprecated column and rely on its
    # non-null empty-string default while an orphan keeps the column alive.
    new_id = SqliteCertificateRepository(db, source="upload").add(
        Certificate(
            subject="CN=new.example.com",
            issuer="CN=Test CA",
            not_before=datetime(2026, 1, 1, tzinfo=UTC),
            not_after=datetime(2027, 1, 1, tzinfo=UTC),
            fingerprint_sha256="cd" * 32,
            raw_der=b"new",
        )
    )
    with sqlite3.connect(str(db)) as conn:
        assert conn.execute(
            "SELECT notes FROM certificates WHERE id = ?", (new_id,)
        ).fetchone()[0] == ""


def test_migration_0031_noop_without_column(tmp_path: Path) -> None:
    """Idempotent on fresh DBs where the column never existed."""
    from cert_watch.migrations.m0031_merge_cert_notes import upgrade

    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)  # must not raise
        cols = _table_columns(conn, "certificates")
    assert "notes" not in cols


def _stamp_feature_branch_migrations(
    db: Path, ids: tuple[str, ...]
) -> None:
    """Record old feature-branch ids without assuming their descriptions."""
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "CREATE TABLE schema_version ("
            "id TEXT PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        conn.executemany(
            "INSERT INTO schema_version (id, description, applied_at) "
            "VALUES (?, 'feature branch migration', '2026-08-30')",
            ((mid,) for mid in ids),
        )
        conn.commit()


# ── 0033: alerts.deferred_since (bounded evidence deferral, #38) ─────────────


def test_migration_0033_adds_deferred_since_and_is_idempotent(db_path: Path) -> None:
    from cert_watch.migrations.m0033_alert_deferred_since import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        assert "deferred_since" in _table_columns(conn, "alerts")
        upgrade(conn)
        upgrade(conn)  # must not raise: the column already exists
        assert "deferred_since" in _table_columns(conn, "alerts")


def _mk_pre0033_db(db: Path) -> None:
    """A database whose ledger says 0001–0032 and 0034 but whose alerts lack
    the 0033 column (0034 is stamped so only 0033 stays pending)."""
    ensure_base(db)
    _stamp_feature_branch_migrations(
        db,
        (*tuple(f"{number:04d}" for number in range(1, 33)), "0034", "0035", "0036"),
    )


def test_migration_0033_manual_sql_is_equivalent_to_the_runner(tmp_path: Path) -> None:
    """UPGRADING.md tells an operator how to apply 0033 by hand. Prove that the
    documented statements leave the database exactly where startup would."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.m0033_alert_deferred_since import MANUAL_SQL
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "manual.sqlite3"
    _mk_pre0033_db(db)
    with sqlite3.connect(str(db)) as conn:
        for statement in MANUAL_SQL:
            conn.execute(statement)
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0037", "0038"]
    with sqlite3.connect(str(db)) as conn:
        assert "deferred_since" in _table_columns(conn, "alerts")
        ledger = conn.execute("SELECT id FROM schema_version WHERE id = '0033'").fetchall()
    assert ledger == [("0033",)]



def test_migration_0033_tolerates_a_column_added_by_hand_without_the_ledger(
    tmp_path: Path,
) -> None:
    """An operator who ran only the ALTER gets the ledger row from startup."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.m0033_alert_deferred_since import COLUMN_SQL
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "half-manual.sqlite3"
    _mk_pre0033_db(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(COLUMN_SQL)
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0033", "0037", "0038"]


# ── 0034: alerts.trigger_cert_id (stable resolve keying, #62) ───────────────


def test_migration_0034_adds_trigger_cert_id_and_is_idempotent(db_path: Path) -> None:
    from cert_watch.migrations.m0034_alert_trigger_cert_id import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        assert "trigger_cert_id" in _table_columns(conn, "alerts")
        upgrade(conn)
        upgrade(conn)  # must not raise: the column already exists (and re-backfill is a no-op)
        assert "trigger_cert_id" in _table_columns(conn, "alerts")


def test_migration_0034_backfills_existing_alerts_with_their_trigger_row(
    tmp_path: Path,
) -> None:
    """Every released version deletes an alert together with its certificate
    row, so a pre-existing alert's cert_id IS the row it fired against — the
    id its open PagerDuty incident was keyed with. The carry behaviour of #57
    ships in the same release as this migration, so without the backfill the
    first post-upgrade rescan would move the alert to a row id the incident
    never saw and the renewal resolve would silently miss (#62).
    """
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "backfill.sqlite3"
    _mk_pre0034_db(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO alerts (id, cert_id, alert_type, status, message,"
            " threshold_days, created_at) VALUES ('a1', 'row-that-fired',"
            " 'expiry_warning', 'pending', 'expiring', 7, '2026-09-01T00:00:00Z')"
        )
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0034", "0037", "0038"]
    with sqlite3.connect(str(db)) as conn:
        row = conn.execute(
            "SELECT trigger_cert_id FROM alerts WHERE id = 'a1'"
        ).fetchone()
    assert row == ("row-that-fired",)


def _mk_pre0034_db(db: Path) -> None:
    """A database whose ledger says 0001–0033 but whose alerts lack the column."""
    ensure_base(db)
    _stamp_feature_branch_migrations(
        db, (*tuple(f"{number:04d}" for number in range(1, 34)), "0035", "0036")
    )


def test_migration_0034_manual_sql_is_equivalent_to_the_runner(tmp_path: Path) -> None:
    """UPGRADING.md tells an operator how to apply 0034 by hand. Prove that the
    documented statements leave the database exactly where startup would."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.m0034_alert_trigger_cert_id import MANUAL_SQL
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "manual.sqlite3"
    _mk_pre0034_db(db)
    with sqlite3.connect(str(db)) as conn:
        for statement in MANUAL_SQL:
            conn.execute(statement)
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0037", "0038"]
    with sqlite3.connect(str(db)) as conn:
        assert "trigger_cert_id" in _table_columns(conn, "alerts")
        ledger = conn.execute("SELECT id FROM schema_version WHERE id = '0034'").fetchall()
    assert ledger == [("0034",)]



def test_migration_0034_tolerates_a_column_added_by_hand_without_the_ledger(
    tmp_path: Path,
) -> None:
    """An operator who ran only the ALTER gets the ledger row from startup."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.m0034_alert_trigger_cert_id import COLUMN_SQL
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "half-manual.sqlite3"
    _mk_pre0034_db(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute(COLUMN_SQL)
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0034", "0037", "0038"]


def test_migration_0035_preserves_legacy_tls_verified_values(db_path: Path) -> None:
    from cert_watch.migrations.m0035_schema_reconciliation import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("ALTER TABLE scan_posture ADD COLUMN tls_verified INTEGER")
        conn.executemany(
            "INSERT INTO scan_posture "
            "(id, cert_id, grade, findings, scanned_at, verify_requested, tls_verified) "
            "VALUES (?, 'cert', 'A', '[]', '2026-09-22', ?, ?)",
            (("legacy", None, 1), ("current", 0, 1)),
        )
        upgrade(conn)
        assert "tls_verified" not in _table_columns(conn, "scan_posture")
        assert conn.execute(
            "SELECT id, verify_requested FROM scan_posture ORDER BY id"
        ).fetchall() == [("current", 0), ("legacy", 1)]


def test_reconciled_migrations_repair_old_ui_feature_database(tmp_path: Path) -> None:
    """Old UI ids 0029/0030 must not suppress the canonical digest table.

    The UI branch used 0029 for role tiers and 0030 for note merging.  Once
    those ids mean digest and role tiers, id-only migration tracking would
    otherwise skip both canonical functions on a database that ran that branch.
    """
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.m0030_role_tag_tiers import upgrade as add_role_tiers
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "old-ui-feature.sqlite3"
    init_schema(db)
    with sqlite3.connect(str(db)) as conn:
        # Reproduce the UI branch's resulting schema: role tiers exist and the
        # notes column is already gone, but the digest ledger did not exist.
        add_role_tiers(conn)
        conn.execute("DROP TABLE digest_deliveries")
        conn.execute("DROP TABLE schema_version")
        conn.commit()
    _stamp_feature_branch_migrations(
        db, tuple(f"{number:04d}" for number in range(1, 31))
    )

    assert run_pending_migrations(db, backup=False) == [
        "0031", "0032", "0033", "0034", "0035", "0036", "0037", "0038"
    ]

    with sqlite3.connect(str(db)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        applied = {
            row[0] for row in conn.execute("SELECT id FROM schema_version")
        }
    assert {"digest_deliveries", "role_tag_tiers"} <= tables
    assert "0031" in applied


def test_reconciled_migrations_upgrade_old_review_feature_database(
    tmp_path: Path,
) -> None:
    """A review-branch DB with canonical 0029 receives role tiers and 0031."""
    import cert_watch.migrations.registry  # noqa: F401 — registers migrations
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "old-review-feature.sqlite3"
    init_schema(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute("DROP TABLE schema_version")
        conn.commit()
    _stamp_feature_branch_migrations(
        db, tuple(f"{number:04d}" for number in range(1, 30))
    )

    assert run_pending_migrations(db, backup=False) == [
        "0030", "0031", "0032", "0033", "0034", "0035", "0036", "0037", "0038"
    ]

    with sqlite3.connect(str(db)) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
    assert {"digest_deliveries", "role_tag_tiers"} <= tables


# ---------------------------------------------------------------------------
# 0038: stored hostnames are canonical, aliases of one endpoint are merged
# ---------------------------------------------------------------------------


def _insert_alias_estate(conn: sqlite3.Connection) -> None:
    """Rows written before 0038, spelled three ways for one endpoint, plus a
    second endpoint on another port that must stay separate."""
    now = datetime.now(UTC).isoformat()
    def _ts(month: int, day: int) -> str:
        return f"2026-{month:02d}-{day:02d}T00:00:00+00:00"

    hosts = [
        # (id, hostname, port, tags, owner_name, notes, threshold, added_at)
        ("h-old", "victim.example.test", 443, "team-b", "", "old note", None, _ts(1, 1)),
        ("h-upper", "VICTIM.example.test", 443, "team-a,web", "Ada", "", 30, _ts(2, 1)),
        ("h-dot", "victim.example.test.", 443, "TEAM-B", "Bob", "old note", 14, _ts(3, 1)),
        ("h-8443", "Victim.example.test", 8443, "team-a", "", "", None, _ts(1, 15)),
        ("h-v6", "2001:0db8:0:0:0:0:0:1", 443, "team-c", "", "", None, _ts(1, 15)),
    ]
    for hid, hn, port, tags, owner, notes, threshold, added in hosts:
        conn.execute(
            "INSERT INTO hosts (id, hostname, port, tags, owner_name, notes, threshold_days,"
            " added_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (hid, hn, port, tags, owner, notes, threshold, added),
        )
    for cid, hn, port in (
        ("c-old", "victim.example.test", 443),
        ("c-upper", "VICTIM.example.test", 443),
        ("c-8443", "Victim.example.test", 8443),
    ):
        conn.execute(
            "INSERT INTO certificates (id, subject, issuer, not_before, not_after, san_dns_names,"
            " fingerprint_sha256, raw_der, source, hostname, port, is_leaf, created_at, updated_at)"
            " VALUES (?, 'CN=x', 'CN=ca', ?, ?, '[]', ?, X'00', 'scanned', ?, ?, 1, ?, ?)",
            (cid, now, now, "fp-" + cid, hn, port, now, now),
        )
        conn.execute(
            "INSERT INTO scan_history (id, hostname, port, status, scanned_at)"
            " VALUES (?, ?, ?, 'success', ?)", ("sh-" + cid, hn, port, now),
        )
        conn.execute(
            "INSERT INTO cert_history (id, hostname, port, fingerprint_sha256, issuer, not_after,"
            " scanned_at) VALUES (?, ?, ?, ?, 'CN=ca', ?, ?)",
            ("ch-" + cid, hn, port, "fp-" + cid, now, now),
        )
        conn.execute(
            "INSERT INTO scan_posture (id, cert_id, hostname, port, grade, findings, scanned_at)"
            " VALUES (?, ?, ?, ?, 'A', '[]', ?)", ("sp-" + cid, cid, hn, port, now),
        )
    # Two open alerts for the same condition under two spellings, and a
    # sent one that keeps its history.
    for aid, cid, hn, status, created in (
        ("a-old", "c-old", "victim.example.test", "pending", "2026-01-02T00:00:00+00:00"),
        ("a-upper", "c-upper", "VICTIM.example.test", "pending", "2026-02-02T00:00:00+00:00"),
        ("a-sent", "c-upper", "VICTIM.example.test", "sent", "2026-02-03T00:00:00+00:00"),
    ):
        conn.execute(
            "INSERT INTO alerts (id, cert_id, alert_type, status, message, created_at, hostname,"
            " dedupe_key) VALUES (?, ?, 'expiry_warning', ?, 'm', ?, ?, ?)",
            (aid, cid, status, created, hn, f"expiry:{hn}:443:fp:expiry_warning:30"),
        )
    for key, first, last, count in (
        ("overdue:victim.example.test:443:fp", _ts(1, 1), _ts(1, 5), 2),
        ("overdue:VICTIM.example.test:443:fp", "2025-12-01T00:00:00+00:00", _ts(1, 9), 3),
        ("overdue:2001:0db8:0:0:0:0:0:1:443:fp", _ts(1, 1), _ts(1, 1), 1),
    ):
        conn.execute(
            "INSERT INTO rule_firings (dedupe_key, first_fired_at, last_fired_at, fire_count)"
            " VALUES (?, ?, ?, ?)", (key, first, last, count),
        )
    for hn, port in (("VICTIM.example.test", 443), ("victim.example.test.", 443),
                     ("Victim.example.test", 8443), ("2001:0db8:0:0:0:0:0:1", 443)):
        conn.execute(
            "INSERT INTO event_log (event_type, timestamp, source, payload, delivery_status,"
            " created_at) VALUES ('scan_failed', ?, 'scan', ?, 'failed', ?)",
            (now, json.dumps({"hostname": hn, "port": port, "error_message": "x"}), now),
        )
    conn.execute(
        "INSERT INTO event_log (event_type, timestamp, source, payload, delivery_status,"
        " created_at) VALUES ('cert_added', ?, 'upload', ?, 'delivered', ?)",
        (now, json.dumps({"cert_id": "c-up"}), now),
    )


def test_migration_0038_merges_aliases_and_canonicalizes_every_hostname_keyed_row(
    db_path: Path,
) -> None:
    import json as _json

    from cert_watch.migrations.m0038_canonical_hostnames import upgrade

    init_schema(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        _insert_alias_estate(conn)
        conn.commit()
        upgrade(conn)
        conn.commit()
        conn.row_factory = sqlite3.Row

        hosts = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM hosts")}
        # Three spellings became the oldest row; the other port and the IPv6
        # endpoint stayed separate but were rewritten.
        assert set(hosts) == {"h-old", "h-8443", "h-v6"}
        kept = hosts["h-old"]
        assert kept["hostname"] == "victim.example.test"
        assert set(kept["tags"].split(",")) == {"team-b", "team-a", "web"}  # union, case-folded
        assert kept["owner_name"] == "Ada"  # oldest row had none; next one wins
        assert kept["threshold_days"] == 30
        assert kept["notes"] == "old note"  # identical notes are not repeated
        assert hosts["h-8443"]["hostname"] == "victim.example.test"
        assert hosts["h-v6"]["hostname"] == "2001:db8::1"
        assert conn.execute(
            "SELECT COUNT(*) FROM hosts WHERE hostname = 'victim.example.test' AND port = 443"
        ).fetchone()[0] == 1

        for table in ("certificates", "scan_history", "cert_history", "scan_posture", "alerts"):
            spellings = {r[0] for r in conn.execute(f"SELECT DISTINCT hostname FROM {table}")}
            assert spellings == {"victim.example.test"}, (table, spellings)
        # Nothing was dropped from the history tables.
        assert conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0] == 3
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 3

        payloads = [
            _json.loads(r[0]) for r in conn.execute("SELECT payload FROM event_log ORDER BY id")
        ]
        assert [p.get("hostname") for p in payloads] == [
            "victim.example.test", "victim.example.test", "victim.example.test",
            "2001:db8::1", None,
        ]
        assert [p.get("port") for p in payloads] == [443, 443, 8443, 443, None]

        alerts = {r["id"]: dict(r) for r in conn.execute("SELECT * FROM alerts")}
        assert {a["dedupe_key"] for a in alerts.values()} == {
            "expiry:victim.example.test:443:fp:expiry_warning:30"
        }
        # One open row per condition: the older stays pending.
        assert alerts["a-old"]["status"] == "pending"
        assert alerts["a-upper"]["status"] == "cancelled" and alerts["a-upper"]["closed_at"]
        assert alerts["a-sent"]["status"] == "sent"

        firings = {r["dedupe_key"]: dict(r) for r in conn.execute("SELECT * FROM rule_firings")}
        assert set(firings) == {
            "overdue:victim.example.test:443:fp", "overdue:2001:db8::1:443:fp",
        }
        merged = firings["overdue:victim.example.test:443:fp"]
        assert merged["first_fired_at"] == "2025-12-01T00:00:00+00:00"
        assert merged["last_fired_at"] == "2026-01-09T00:00:00+00:00"
        assert merged["fire_count"] == 5

        # The merge is reported, with the merged rows kept in full.
        audit = conn.execute(
            "SELECT target_id, detail FROM audit_log WHERE action = 'host.merge_alias'"
        ).fetchall()
        assert [a["target_id"] for a in audit] == ["h-old"]
        detail = _json.loads(audit[0]["detail"])
        assert {m["id"] for m in detail["merged"]} == {"h-upper", "h-dot"}
        assert {m["hostname"] for m in detail["merged"]} == {
            "VICTIM.example.test", "victim.example.test.",
        }

        # Idempotent: a second run changes nothing.
        before = [tuple(r) for t in ("hosts", "alerts", "rule_firings", "event_log")
                  for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]
        upgrade(conn)
        conn.commit()
        after = [tuple(r) for t in ("hosts", "alerts", "rule_firings", "event_log")
                 for r in conn.execute(f"SELECT * FROM {t} ORDER BY rowid")]
        assert before == after
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'host.merge_alias'"
        ).fetchone()[0] == 1


def test_repository_add_stores_the_canonical_spelling_and_finds_aliases(db_path: Path) -> None:
    from cert_watch.database import SqliteHostRepository

    init_schema(db_path)
    repo = SqliteHostRepository(db_path)
    host_id = repo.add("VICTIM.example.test.", 443, tags="team-b")
    host = repo.get(host_id)
    assert host is not None and host.hostname == "victim.example.test"
    for alias in ("victim.example.test", "Victim.Example.Test", "victim.example.test."):
        found = repo.get_by_endpoint(alias, 443)
        assert found is not None and found.id == host_id
    assert repo.get_by_endpoint("victim.example.test", 8443) is None
    assert repo.get_by_endpoint("not a host", 443) is None
    # Re-adding under another spelling is the same idempotent add.
    assert repo.add("victim.example.test", 443) == host_id
    assert repo.count_all() == 1
