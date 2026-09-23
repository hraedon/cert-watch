"""Database schema initialization through the numbered migration chain."""
from __future__ import annotations

import contextlib
import sqlite3
import threading
from pathlib import Path

from cert_watch.migrations.m0001_baseline import BASELINE_INDEXES, BASELINE_TABLES
from cert_watch.migrations.m0001_baseline import upgrade as create_baseline

# Backward-compatible private re-exports; the sole definitions live in 0001.
_BASE_TABLES = BASELINE_TABLES
_BASE_INDEXES = BASELINE_INDEXES

# Maps resolved path → (st_ino, st_size, st_mtime) from the last successful
# init. Keyed on the file's identity tuple (not just the path string) so a
# restored backup with an older schema is detected and migrations re-run
# (WI-091). Mirrors the connection-layer cache in connection._connect.
_initialized: dict[str, tuple[int, int, float] | None] = {}
_init_lock = threading.Lock()


def _stat_tuple(db_path: str | Path) -> tuple[int, int, float] | None:
    """Return (st_ino, st_size, st_mtime) or None if the file doesn't exist yet."""
    with contextlib.suppress(OSError):
        st = Path(db_path).stat()
        return (st.st_ino, st.st_size, st.st_mtime)
    return None


def ensure_base(db_path: str | Path) -> None:
    """Create or repair only the frozen migration-0001 baseline.

    This compatibility helper intentionally does not create current-schema
    objects. Normal startup uses :func:`init_schema`, which applies 0001 and
    every later migration through the runner.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(str(path))) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")
        create_baseline(conn)
        conn.commit()


def init_schema(db_path: str | Path) -> None:
    """Apply the complete numbered migration chain to *db_path*.

    Idempotent: repeat calls for the same path return immediately after the
    first successful initialization, as long as the database file has not been
    replaced (for example by a restore).
    """
    path = Path(db_path)
    path_str = str(path.resolve())
    with _init_lock:
        cached = _initialized.get(path_str)
        if cached is not None:
            current = _stat_tuple(path)
            if current is not None and current == cached:
                return

        path.parent.mkdir(parents=True, exist_ok=True)
        import cert_watch.migrations.registry  # noqa: F401
        from cert_watch.migrations.runner import run_pending_migrations

        run_pending_migrations(path, backup=True)
        _initialized[path_str] = _stat_tuple(path)
