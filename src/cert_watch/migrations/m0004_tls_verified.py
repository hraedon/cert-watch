"""Migration 0004 — add tls_verified column to scan_posture.

Introduced to resolve BC-064: persist per-scan boolean indicating whether
the TLS handshake was performed with verification enabled (CERT_REQUIRED
+ hostname check). When tls_verified is NULL the scan was made without
verification (the default). When True, chain trust and hostname match
were confirmed by the TLS stack.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    if "tls_verified" not in cols:
        conn.execute(
            "ALTER TABLE scan_posture ADD COLUMN tls_verified INTEGER"
        )
    conn.commit()
