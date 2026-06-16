"""Migration 0025 — add threshold_days and digest_cadence_days to alert_groups."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(alert_groups)")}
    if "threshold_days" not in cols:
        conn.execute("ALTER TABLE alert_groups ADD COLUMN threshold_days INTEGER")
    if "digest_cadence_days" not in cols:
        conn.execute(
            "ALTER TABLE alert_groups ADD COLUMN digest_cadence_days INTEGER NOT NULL DEFAULT 7"
        )
    conn.commit()
