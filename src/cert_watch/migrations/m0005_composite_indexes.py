"""Migration 0005 — add composite indexes for common query patterns.

Resolves the known performance issue: queries filtering by
(hostname, port, is_leaf) and (hostname, port, scanned_at) were
doing full table scans because no composite index covered the
predicates.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cert_host_port_leaf"
        " ON certificates(hostname, port, is_leaf)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_host_port_ts"
        " ON scan_history(hostname, port, scanned_at DESC)"
    )
    conn.commit()
