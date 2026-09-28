"""Migration 0048 — renewal verification evidence and scan claims (#118 S4)."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0048"
DESCRIPTION = "add renewal verification evidence and cross-process scan claims"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(renewal_attempts)")
    }
    additions = {
        "checks_done": "INTEGER NOT NULL DEFAULT 0",
        "last_check_at": "TEXT",
        "first_qualifying_check_at": "TEXT",
        "verification_blocked_at": "TEXT",
        "raised_at": "TEXT",
        "verification_reason": "TEXT",
        "verified_fingerprint": "TEXT",
        "success_received_at": "TEXT",
    }
    for name, definition in additions.items():
        if name not in columns:
            conn.execute(
                f"ALTER TABLE renewal_attempts ADD COLUMN {name} {definition}"
            )
    conn.execute(
        """UPDATE renewal_attempts SET success_received_at=received_at
           WHERE success_received_at IS NULL
             AND state IN ('verifying','not_deployed','verified')"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_pending_check "
        "ON renewal_attempts(next_check_at) WHERE is_current=1 AND next_check_at IS NOT NULL"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS host_scan_claims (
               host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
               claimed_by TEXT NOT NULL,
               claimed_at TEXT NOT NULL,
               claim_expires_at TEXT NOT NULL
           )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_host_scan_claims_expiry "
        "ON host_scan_claims(claim_expires_at)"
    )
