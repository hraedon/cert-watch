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
import errno
import importlib
import logging
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
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


@contextlib.contextmanager
def _migration_lock(db_path: str | Path) -> Iterator[None]:
    """Serialize the complete migration step across threads and processes.

    The lock file is deliberately persistent: removing it after unlock creates
    a race where a waiter can hold the old inode while a newcomer locks a new
    one. OS advisory locks are released automatically if a process exits.
    """
    db_path = Path(db_path)
    lock_path = db_path.parent / f".{db_path.name}.migration.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()

        if os.name == "nt":
            msvcrt = importlib.import_module("msvcrt")
            while True:
                lock_file.seek(0)
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as exc:
                    if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                        raise
                    time.sleep(0.05)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl = importlib.import_module("fcntl")
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _backup(db_path: str | Path, backup_path: str | Path | None = None) -> Path:
    """WAL-safe backup using VACUUM INTO. Works while the app is running.

    ``VACUUM INTO`` cannot run inside a transaction, so the runner calls this
    before opening any migration transaction. It is backup plumbing, not part
    of a migration's atomic DDL/DML unit.

    Returns the backup file path.
    """
    db_path = Path(db_path)
    if backup_path is None:
        ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
        unique = f"{os.getpid()}-{secrets.token_hex(4)}"
        backup_path = db_path.parent / (
            f"{db_path.stem}-pre-migration-{ts}-{unique}{db_path.suffix}"
        )
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
    with _migration_lock(db_path):
        # Read the ledger only after taking the cross-process lock. A process
        # that waited for another startup must observe the migrations that
        # startup committed rather than act on a stale pending list.
        with _connect(db_path) as conn:
            applied = _applied_ids(conn)

        pending = [
            (mid, desc, fn) for mid, desc, fn in get_migrations() if mid not in applied
        ]
        if not pending:
            return []

        # VACUUM INTO cannot run inside a migration transaction, but the OS
        # lock remains held across both the backup and every migration.
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
