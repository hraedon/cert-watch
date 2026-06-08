"""Migration 0017 — add CAA columns to scan_posture (BC-121).

Store CAA lookup results per scan so the compliance report can show a real
percentage instead of "Not collected".
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    if "caa_present" not in cols:
        conn.execute("ALTER TABLE scan_posture ADD COLUMN caa_present INTEGER")
    if "caa_records" not in cols:
        conn.execute("ALTER TABLE scan_posture ADD COLUMN caa_records TEXT")
    conn.commit()
