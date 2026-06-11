"""Migration 0023 — add not_before column to cert_history.

Plan 048 WI-2.1: Renewal analytics needs actual cert lifetime (not_after - not_before),
not the proxy of remaining-validity-at-first-scan.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(cert_history)").fetchall()}
    if "not_before" not in cols:
        conn.execute("ALTER TABLE cert_history ADD COLUMN not_before TEXT")
    conn.commit()
