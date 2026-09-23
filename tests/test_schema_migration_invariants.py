"""Schema parity and transaction invariants for numbered migrations."""

from __future__ import annotations

import ast
import contextlib
import re
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from cert_watch.database.schema import init_schema

# Recovered from the parent of commit 1e00b7f, which introduced migration
# 0001.  Keep this test fixture independent of the live baseline definition:
# its purpose is to prove that a genuine pre-runner database converges with a
# newly-created database.
_HISTORICAL_0001_DDL = """
CREATE TABLE certificates (
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
CREATE TABLE alerts (
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
CREATE TABLE scan_history (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    error_message TEXT
);
CREATE TABLE hosts (
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
    added_at TEXT NOT NULL,
    UNIQUE(hostname, port)
);
CREATE TABLE trust_anchors (
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
CREATE TABLE scan_posture (
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
CREATE INDEX idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX idx_cert_replaces ON certificates(replaces_cert_id);
CREATE INDEX idx_alert_cert ON alerts(cert_id);
CREATE INDEX idx_alert_status ON alerts(status);
CREATE UNIQUE INDEX ux_hosts_hostname_port ON hosts(hostname, port);
"""


def _normalize_sql(sql: str | None) -> str | None:
    if sql is None:
        return None
    return re.sub(r"\s+", " ", sql.strip()).casefold()


def _schema_snapshot(db_path: Path) -> dict[str, Any]:
    """Return a semantic sqlite_master snapshot, insensitive to DDL formatting."""
    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        table_names = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        tables: dict[str, Any] = {}
        indexes: dict[str, Any] = {}
        for table in table_names:
            quoted = table.replace("'", "''")
            columns = {
                row[1]: (row[2].upper(), row[3], row[4], row[5], row[6])
                for row in conn.execute(f"PRAGMA table_xinfo('{quoted}')")
            }
            foreign_keys = sorted(
                tuple(row[2:8])
                for row in conn.execute(f"PRAGMA foreign_key_list('{quoted}')")
            )
            tables[table] = {"columns": columns, "foreign_keys": foreign_keys}

            for row in conn.execute(f"PRAGMA index_list('{quoted}')"):
                index_name = row[1]
                index_quoted = index_name.replace("'", "''")
                index_sql_row = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?",
                    (index_name,),
                ).fetchone()
                indexes[index_name] = {
                    "table": table,
                    "unique": row[2],
                    "origin": row[3],
                    "partial": row[4],
                    "columns": tuple(
                        (item[2], item[3], item[4], item[5])
                        for item in conn.execute(f"PRAGMA index_xinfo('{index_quoted}')")
                    ),
                    # This retains partial-index WHERE clauses while ignoring
                    # irrelevant whitespace/case differences.
                    "sql": _normalize_sql(index_sql_row[0] if index_sql_row else None),
                }

        triggers = {
            row[0]: _normalize_sql(row[1])
            for row in conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' ORDER BY name"
            )
        }
    return {"tables": tables, "indexes": indexes, "triggers": triggers}


def _upgrade_historical_0001(db_path: Path) -> None:
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import run_pending_migrations

    with contextlib.closing(sqlite3.connect(db_path)) as conn:
        conn.executescript(_HISTORICAL_0001_DDL)
        conn.commit()
    run_pending_migrations(db_path, backup=False)


def test_fresh_schema_matches_genuine_0001_upgrade(tmp_path: Path) -> None:
    fresh = tmp_path / "fresh.sqlite3"
    upgraded = tmp_path / "upgraded.sqlite3"

    init_schema(fresh)
    _upgrade_historical_0001(upgraded)

    assert _schema_snapshot(fresh) == _schema_snapshot(upgraded)


def test_v090_schema_upgrades_to_fresh_schema(tmp_path: Path) -> None:
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import run_pending_migrations

    fresh = tmp_path / "fresh.sqlite3"
    upgraded = tmp_path / "v090.sqlite3"
    dump = Path(__file__).parent / "fixtures" / "cw_v090_dump.sql"

    init_schema(fresh)
    with contextlib.closing(sqlite3.connect(upgraded)) as conn:
        conn.executescript(dump.read_text(encoding="utf-8"))
    run_pending_migrations(upgraded, backup=False)

    assert _schema_snapshot(fresh) == _schema_snapshot(upgraded)


def test_migration_modules_do_not_commit_or_use_executescript() -> None:
    migrations_dir = (
        Path(__file__).resolve().parents[1] / "src" / "cert_watch" / "migrations"
    )
    violations: list[str] = []
    for module in sorted(migrations_dir.glob("m[0-9][0-9][0-9][0-9]_*.py")):
        tree = ast.parse(module.read_text(encoding="utf-8"), filename=str(module))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"commit", "executescript"}
            ):
                violations.append(f"{module.name}:{node.lineno} {node.func.attr}()")

    assert violations == []


def test_backup_is_taken_before_any_migration_work(tmp_path: Path) -> None:
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "legacy.sqlite3"
    with contextlib.closing(sqlite3.connect(db)) as conn:
        conn.executescript(_HISTORICAL_0001_DDL)
        conn.execute(
            "INSERT INTO hosts (id, hostname, added_at) "
            "VALUES ('h1', 'before.example', '2026-01-01')"
        )
        conn.commit()

    run_pending_migrations(db, backup=True)
    backups = list(tmp_path.glob("legacy-pre-migration-*.sqlite3"))
    assert len(backups) == 1
    with contextlib.closing(sqlite3.connect(backups[0])) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert "schema_version" not in tables
        assert conn.execute("SELECT hostname FROM hosts").fetchone() == (
            "before.example",
        )


def test_failed_migration_rolls_back_work_and_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations import runner

    db = tmp_path / "crash.sqlite3"
    init_schema(db)
    original = runner.get_migrations()
    previous_id = original[-1][0]

    def crash_after_partial_work(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE crash_probe (value TEXT NOT NULL)")
        conn.execute("INSERT INTO crash_probe VALUES ('partial')")
        raise RuntimeError("injected migration crash")

    monkeypatch.setattr(
        runner,
        "_MIGRATIONS",
        [*original, ("9999", "injected crash", crash_after_partial_work)],
    )
    with pytest.raises(RuntimeError, match="injected migration crash"):
        runner.run_pending_migrations(db, backup=False)

    with contextlib.closing(sqlite3.connect(db)) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        last_applied = conn.execute(
            "SELECT id FROM schema_version ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
    assert "crash_probe" not in tables
    assert last_applied == previous_id

    def succeed(conn: sqlite3.Connection) -> None:
        conn.execute("CREATE TABLE crash_probe (value TEXT NOT NULL)")
        conn.execute("INSERT INTO crash_probe VALUES ('complete')")

    monkeypatch.setattr(
        runner,
        "_MIGRATIONS",
        [*original, ("9999", "retry succeeds", succeed)],
    )
    assert runner.run_pending_migrations(db, backup=False) == ["9999"]
    with contextlib.closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT value FROM crash_probe").fetchone() == ("complete",)
        assert conn.execute(
            "SELECT id FROM schema_version WHERE id = '9999'"
        ).fetchone() == ("9999",)
