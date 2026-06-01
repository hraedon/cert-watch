"""Migration 0006 — add a free-form tags column to certificates.

Hosts already carry a ``tags`` string; certificates gain the same so tags can
be applied per-cert (and inherited from the host). See plan 013.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(certificates)")}
    if "tags" not in cols:
        conn.execute(
            "ALTER TABLE certificates ADD COLUMN tags TEXT NOT NULL DEFAULT ''"
        )
    conn.commit()
