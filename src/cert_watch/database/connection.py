"""Database connection helpers."""
from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.certificate_model import Certificate

_conn_local = threading.local()


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Return a cached connection for the current thread.

    Reuses one connection per (thread, db_path) pair. WAL mode and
    busy_timeout are set once on first connect; they persist in the
    database file and connection respectively.

    Detects external database file replacement (e.g. restore from backup)
    by comparing inode, size, and mtime. Stale connections are discarded
    automatically.
    """
    path_str = str(db_path)
    cache = getattr(_conn_local, "connections", None)
    if cache is None:
        cache = {}
        _conn_local.connections = cache
    meta = getattr(_conn_local, "connection_meta", None)
    if meta is None:
        meta = {}
        _conn_local.connection_meta = meta

    conn = cache.get(path_str)
    current_stat = None
    with contextlib.suppress(OSError, FileNotFoundError):
        current_stat = Path(db_path).stat()

    if conn is not None:
        try:
            conn.execute("SELECT 1")
            cached_stat = meta.get(path_str)
            if current_stat is None:
                # File disappeared; discard cached connection.
                pass
            elif cached_stat is not None:
                if (
                    current_stat.st_ino,
                    current_stat.st_size,
                    current_stat.st_mtime,
                ) == cached_stat:
                    return conn
            else:
                # No cached stat yet; record it and reuse.
                meta[path_str] = (
                    current_stat.st_ino,
                    current_stat.st_size,
                    current_stat.st_mtime,
                )
                return conn
        except (OSError, sqlite3.Error):
            pass
        # The cached connection is stale (file replaced/removed, or the handle
        # errored). Close it before discarding: an unclosed connection keeps the
        # DB's -wal/-shm handles open, which POSIX tolerates but Windows does not
        # (a later file replace fails with WinError 32). On 3.14 the orphan also
        # sits in a GC cycle rather than being refcount-closed, so it lingers.
        with contextlib.suppress(sqlite3.Error):
            conn.close()
        cache.pop(path_str, None)
        meta.pop(path_str, None)

    conn = sqlite3.connect(path_str, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    cache[path_str] = conn
    if current_stat:
        meta[path_str] = (current_stat.st_ino, current_stat.st_size, current_stat.st_mtime)
    return conn


def close_connections() -> None:
    """Close and forget all cached connections for the current thread.

    SQLite holds the database (and its ``-wal`` / ``-shm`` sidecars) open for the
    life of a cached connection. On POSIX an open file can still be unlinked or
    replaced; on Windows it cannot (``WinError 32``). Callers that delete, rename,
    or replace the database file from *within the same process* — e.g. a restore
    that swaps in a backup — must release the handles first. This is the in-process
    equivalent of stopping the service in the documented restore runbook.
    """
    cache = getattr(_conn_local, "connections", None)
    if cache:
        for conn in cache.values():
            with contextlib.suppress(sqlite3.Error):
                conn.close()
        cache.clear()
    meta = getattr(_conn_local, "connection_meta", None)
    if meta:
        meta.clear()


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _row_to_cert(row: sqlite3.Row | dict[str, Any]) -> Certificate:
    cert = Certificate(
        subject=row["subject"],
        issuer=row["issuer"],
        not_before=_parse_iso(row["not_before"]),
        not_after=_parse_iso(row["not_after"]),
        san_dns_names=json.loads(row["san_dns_names"]),
        fingerprint_sha256=row["fingerprint_sha256"],
        raw_der=bytes(row["raw_der"]),
        is_leaf=bool(row["is_leaf"]),
        notes=dict(row).get("notes", ""),
        source=dict(row).get("source", "unknown"),
    )
    return cert
