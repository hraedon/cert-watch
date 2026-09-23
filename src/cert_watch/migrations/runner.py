"""Migration registry and runner.

Migrations are ordered callables that take a SQLite connection and modify
the schema or data. Each migration has an id (e.g. "0001") and a description.
The runner records applied migrations in the `schema_version` table.

Usage::

    from cert_watch.migrations.runner import run_pending_migrations
    run_pending_migrations(db_path)
"""

from __future__ import annotations

import contextlib
import logging
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.database.connection import _connect

logger = logging.getLogger("cert_watch.migrations")

# ---------- Migration definitions ----------
# Each entry: (id: str, description: str, fn: callable(conn) -> None)
# Ids must be monotonically increasing strings.
# The first migration (0001) creates the frozen pre-runner baseline.
_MIGRATIONS: list[tuple[str, str, Callable[[sqlite3.Connection], None]]] = []


def register(id: str, description: str, fn: Callable[[sqlite3.Connection], None]) -> None:
    """Register a migration. Ids must be unique and monotonically ordered."""
    ids = [m[0] for m in _MIGRATIONS]
    if id in ids:
        raise ValueError(f"Duplicate migration id: {id}")
    _MIGRATIONS.append((id, description, fn))


def get_migrations() -> list[tuple[str, str, Callable[[sqlite3.Connection], None]]]:
    """Return all registered migrations in order."""
    return list(_MIGRATIONS)


# ---------- Helpers ----------


def _ensure_schema_version_table(conn: sqlite3.Connection) -> None:
    """Create the schema_version tracking table if it doesn't exist."""
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version"
        " (id TEXT PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )


def _applied_ids(conn: sqlite3.Connection) -> set[str]:
    """Return the set of migration ids already applied."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if exists is None:
        return set()
    rows = conn.execute("SELECT id FROM schema_version ORDER BY id").fetchall()
    return {r[0] for r in rows}


def _backup(db_path: str | Path, backup_path: str | Path | None = None) -> Path:
    """WAL-safe backup using VACUUM INTO. Works while the app is running.

    ``VACUUM INTO`` cannot run inside a transaction, so the runner calls this
    before opening any migration transaction. It is backup plumbing, not part
    of a migration's atomic DDL/DML unit.

    Returns the backup file path.
    """
    db_path = Path(db_path)
    if backup_path is None:
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        backup_path = db_path.parent / f"{db_path.stem}-pre-migration-{ts}{db_path.suffix}"
    backup_path = Path(backup_path)
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    # closing(): a sqlite3 ``with`` block commits but does not close, leaving the
    # source DB (and its -wal) handle open until GC — which blocks a subsequent
    # file replace/restore on Windows. Close it deterministically.
    with contextlib.closing(sqlite3.connect(str(db_path))) as conn:
        conn.execute("VACUUM INTO ?", (str(backup_path),))
    # Remove any stale WAL/SHM artifacts so the backup is a clean standalone file.
    for suffix in ("-wal", "-shm"):
        artifact = backup_path.parent / (backup_path.name + suffix)
        artifact.unlink(missing_ok=True)
    logger.info("backed up %s -> %s", db_path, backup_path)
    return backup_path


# ---------- Runner ----------


def run_pending_migrations(
    db_path: str | Path,
    *,
    backup: bool = True,
) -> list[str]:
    """Run all pending migrations for the database at *db_path*.

    Returns the list of migration ids that were applied (empty if none).
    If *backup* is True (default), creates a timestamped backup before
    applying any migration.
    """
    db_path = Path(db_path)
    with _connect(db_path) as conn:
        applied = _applied_ids(conn)

    pending = [
        (mid, desc, fn) for mid, desc, fn in get_migrations() if mid not in applied
    ]
    if not pending:
        return []

    # Pre-migration backup
    if backup:
        _backup(db_path)

    applied_ids: list[str] = []
    with _connect(db_path) as conn:
        for mid, desc, fn in pending:
            logger.info("applying migration %s: %s", mid, desc)
            try:
                # sqlite3's legacy transaction control does not automatically
                # begin a transaction for DDL. An explicit BEGIN makes the
                # migration's DDL/DML and ledger row one atomic unit.
                conn.execute("BEGIN IMMEDIATE")
                _ensure_schema_version_table(conn)
                fn(conn)
                ts = datetime.now(UTC).isoformat()
                conn.execute(
                    "INSERT INTO schema_version (id, description, applied_at) "
                    "VALUES (?, ?, ?)",
                    (mid, desc, ts),
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            applied_ids.append(mid)
            logger.info("migration %s applied", mid)

    return applied_ids


def create_backup(db_path: str | Path, backup_path: str | Path) -> Path:
    """Public API for the `cert-watch backup` CLI subcommand.

    Creates a WAL-safe backup using VACUUM INTO. The app can be running.
    """
    return _backup(db_path, backup_path)
