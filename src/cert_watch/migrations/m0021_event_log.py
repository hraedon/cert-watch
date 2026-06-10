"""Migration 0021 — add event_log table for event streaming (Plan 044)."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            payload TEXT NOT NULL,
            delivery_status TEXT DEFAULT 'pending',
            error_message TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_event_log_event_type ON event_log (event_type)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_event_log_timestamp ON event_log (timestamp)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_event_log_delivery_status ON event_log (delivery_status)"
    )
    conn.commit()