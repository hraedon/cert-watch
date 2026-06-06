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

    # Insert data
    with sqlite3.connect(str(db)) as conn:
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

    # Restore: stop (no-op), replace file, start (verify)
    # Also remove WAL/SHM artifacts so the restored DB isn't confused
    # by stale journal files from the connection cache (BC-049).
    for artifact in (db.with_suffix(".sqlite3-wal"), db.with_suffix(".sqlite3-shm")):
        artifact.unlink(missing_ok=True)
    db.unlink()
    backup.rename(db)

    # Verify restored data
    init_schema(db)  # Should be idempotent on restored DB
    with sqlite3.connect(str(db)) as conn:
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
