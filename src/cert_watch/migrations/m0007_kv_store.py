"""Migration 0007 — add kv_store table for setup wizard and boot config."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv_store ("
        "key TEXT PRIMARY KEY,"
        "value TEXT NOT NULL,"
        "updated_at TEXT NOT NULL"
        ")"
    )
    conn.commit()