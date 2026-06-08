"""Migration 0016 — add chain_status column to scan_posture (BC-100).

Store the computed chain trust status ("public", "private", "self-signed",
"incomplete", "invalid", "unknown") so that the Discover page can count
private-CA hosts without hardcoded issuer name fragments.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    if "chain_status" not in cols:
        conn.execute("ALTER TABLE scan_posture ADD COLUMN chain_status TEXT")
    conn.commit()
