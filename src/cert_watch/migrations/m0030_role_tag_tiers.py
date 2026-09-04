"""Migration 0030 — per-tag permission tiers for roles (Plan 053 / WI-064).

``role_tag_tiers`` scopes a role's permission tier to individual tags: a
role may be operator for ``prod`` and viewer for ``edge``. Absence of a row
for a (role, tag) pair means the tag inherits the role's default
``permission_tier`` — so an empty table reproduces pre-0029 behavior
exactly (the migration is a no-op by construction).
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS role_tag_tiers (
            role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            tag TEXT NOT NULL,
            permission_tier TEXT NOT NULL DEFAULT 'viewer',
            PRIMARY KEY (role_id, tag)
        )
        """
    )
    conn.commit()
