"""Migration 0010 — add extra_recipients column to alerts table (BC-051)."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "extra_recipients" not in cols:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN extra_recipients TEXT NOT NULL DEFAULT '[]'"
        )
    conn.commit()
