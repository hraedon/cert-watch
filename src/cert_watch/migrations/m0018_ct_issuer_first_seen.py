"""Migration 0018 — add ct_issuer_first_seen table (BC-151).

Store per-issuer first-seen dates from CT logs for the Discover page's
mis-issuance detection and first-seen capture.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ct_issuer_first_seen (
            issuer_name TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
