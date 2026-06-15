"""Migration 0024 — add explicit permission tier and scope tag to roles.

Decouples the team/role name from the effective permission set (WI-050) and
stores the team's scope tag used for auto-tagging and tag-scoped access
control (WI-051 / WI-052).
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(roles)")}
    if "permission_tier" not in cols:
        conn.execute(
            "ALTER TABLE roles ADD COLUMN permission_tier TEXT NOT NULL DEFAULT 'viewer'"
        )
    if "scope_tag" not in cols:
        conn.execute(
            "ALTER TABLE roles ADD COLUMN scope_tag TEXT NOT NULL DEFAULT ''"
        )
    conn.commit()
