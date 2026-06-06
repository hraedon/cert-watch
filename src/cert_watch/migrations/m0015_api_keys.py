"""Migration 0015 — add api_keys table for machine-to-machine auth (Plan 039).

BC-104: the REST API is only reachable with a browser session cookie, so cron
jobs, cert-manager hooks, and monitoring tools cannot authenticate. This table
backs scoped bearer-token API keys. Only the SHA-256 hash of the raw token is
stored; the raw token is shown once at creation and never persisted.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            scope TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    conn.commit()
