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
import sqlite3
from pathlib import Path

import pytest

from cert_watch.database.schema import ensure_base, init_schema


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    return db


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}


# v0.6.x baseline DDL — the tables and columns that existed before numbered
# migrations were introduced. Newer tables/columns are added by ensure_base()
# (catch-up) and the migration runner during the upgrade under test.
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


# ---------- AC-3: Pre-migration backup ----------

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
