"""Migration 0022 — add expected_issuers column to hosts table.

WI-007: CT mis-issuance detection uses strict string equality on issuer names,
which false-positives when CAs like Let's Encrypt rotate intermediates (R3/R4).
The expected_issuers column stores a CSV allowlist of acceptable issuer CNs
per host, so legitimate multi-issuer hosts don't trigger alerts.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    if "expected_issuers" not in cols:
        conn.execute("ALTER TABLE hosts ADD COLUMN expected_issuers TEXT NOT NULL DEFAULT ''")
    conn.commit()
