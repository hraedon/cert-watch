"""Migration 0026 — add alert_group_id to roles for joint alert routing (WI-061).

Subscribing a role to tags grants BOTH visibility and alert routing.  The
role→alert_group link lets a team's scoped role route alerts through a
specific alert_group's recipients/webhook without merging the two systems.

The column is nullable and additive — no data loss.  The existing
auto-backup (``cert-watch-pre-migration-*.sqlite3``) covers it.

Note: ``alert_groups.id`` is ``TEXT`` (UUID), so the FK column is ``TEXT``,
not ``INTEGER`` as the original spec draft suggested.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(roles)")}
    if "alert_group_id" not in cols:
        conn.execute(
            "ALTER TABLE roles ADD COLUMN alert_group_id TEXT"
            " REFERENCES alert_groups(id) ON DELETE SET NULL"
        )
    conn.commit()
