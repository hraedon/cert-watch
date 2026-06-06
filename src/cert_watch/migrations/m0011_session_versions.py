"""Migration 0011 — add session_versions table for server-side session revocation (BC-081).

Each row tracks the current session version for a username. When a user logs out
or their credentials change, the version is bumped; any HMAC session token
issued before that version is invalid.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS session_versions ("
        "username TEXT PRIMARY KEY,"
        "version INTEGER NOT NULL DEFAULT 1,"
        "updated_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_session_versions_username"
        " ON session_versions(username)"
    )
    conn.commit()
