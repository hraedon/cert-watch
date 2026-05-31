"""Migration 0003 — add rate_limits table for cross-worker rate limiting.

Introduced to resolve BC-049: in-memory rate limiting is not shared
across multiple workers. This table stores sliding-window timestamps
as JSON so all workers share the same rate-limit state.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS rate_limits ("
        " key TEXT PRIMARY KEY,"
        " timestamps TEXT NOT NULL,"
        " updated_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_rate_limits_updated "
        "ON rate_limits(updated_at DESC)"
    )
    conn.commit()
