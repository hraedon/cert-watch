"""Database connection helpers."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate

_conn_local = threading.local()


def _connect(db_path: str | Path) -> sqlite3.Connection:
    """Return a cached connection for the current thread.

    Reuses one connection per (thread, db_path) pair. WAL mode and
    busy_timeout are set once on first connect; they persist in the
    database file and connection respectively.
    """
    path_str = str(db_path)
    cache = getattr(_conn_local, "connections", None)
    if cache is None:
        cache = {}
        _conn_local.connections = cache
    conn = cache.get(path_str)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
            return conn
        except Exception:
            cache.pop(path_str, None)
    conn = sqlite3.connect(path_str, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    cache[path_str] = conn
    return conn


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.isoformat()


def _parse_iso(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _row_to_cert(row: sqlite3.Row) -> Certificate:
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
    )
    return cert
