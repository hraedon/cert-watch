"""Migration 0014 — add read flag to alerts for unread tracking.

BC-127: Alerts page needs segmented filter (All/Unread/Critical) and
per-alert unread tags. The read flag tracks whether an alert has been
seen by the user.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    if "read" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN read INTEGER NOT NULL DEFAULT 0")
    conn.commit()
