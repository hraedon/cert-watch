"""Migration 0012 — add chain_incomplete column to scan_posture (BC-108).

Records whether a scan was degraded (Python < 3.13 without openssl, leaf-only
extraction) so the UI can surface the degradation reason separately from
structural chain incompleteness.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    if "chain_incomplete" not in cols:
        conn.execute(
            "ALTER TABLE scan_posture ADD COLUMN chain_incomplete INTEGER"
        )
    conn.commit()
