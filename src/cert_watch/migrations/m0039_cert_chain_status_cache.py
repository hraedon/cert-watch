"""Migration 0039 — cache each leaf's chain trust status on the certificate row.

Counting the estate by status in SQL (Home's cards, the Browse group views,
``/metrics``) needs each leaf's chain status, and that status takes signature
verification against the uploaded trust anchors and the system trust store,
which SQL cannot do. ``chain_status`` caches it; ``chain_status_basis`` records
the inputs it was computed from (the trust anchors, the system store, and the
fingerprints of the leaf and of each stored chain certificate); a status whose
basis no longer matches the row is never used, and reads as unverified, so the
cache fails closed whichever code path changed its inputs (#113). Rows start
empty and are filled on first read by ``cert_watch.database.chain_status_cache``.
"""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0039"
DESCRIPTION = "cache leaf chain status and the inputs it was computed from"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(certificates)")}
    if "chain_status" not in columns:
        conn.execute("ALTER TABLE certificates ADD COLUMN chain_status TEXT")
    if "chain_status_basis" not in columns:
        conn.execute("ALTER TABLE certificates ADD COLUMN chain_status_basis TEXT")
