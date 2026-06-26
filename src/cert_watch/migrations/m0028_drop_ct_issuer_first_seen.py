"""Migration 0028 — drop ct_issuer_first_seen table (WI-082).

The table was created by migration 0018 for CT mis-issuance first-seen tracking
but is no longer read or written by application code.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute("DROP TABLE IF EXISTS ct_issuer_first_seen")
    conn.commit()
