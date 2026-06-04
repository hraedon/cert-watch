"""Migration 0013 — rename tls_verified to verify_requested in scan_posture.

BC-125: The old name `tls_verified` was misleading because the field stores
whether the *operator requested* TLS verification during the scan (verify=)
not whether the TLS handshake itself succeeded. The openssl path even hardcodes
False regardless of outcome. Renaming to `verify_requested` makes the semantics
clear.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    if "tls_verified" in cols and "verify_requested" not in cols:
        conn.execute(
            "ALTER TABLE scan_posture RENAME COLUMN tls_verified TO verify_requested"
        )
    conn.commit()
