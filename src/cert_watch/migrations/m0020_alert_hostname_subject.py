"""Migration 0020 — add hostname and subject columns to alerts table.

Persist alert enrichment data so Alertmanager labels survive DB round-trips.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "hostname" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN hostname TEXT NOT NULL DEFAULT ''")
    if "subject" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN subject TEXT NOT NULL DEFAULT ''")
    conn.commit()
