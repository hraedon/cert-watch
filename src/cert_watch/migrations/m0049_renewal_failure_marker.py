"""Migration 0049 — durable renewal failure transition marker (#118 S5)."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0049"
DESCRIPTION = "record renewal failure transitions for alerts and digests"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(renewal_attempts)")
    }
    if "failure_reported_at" not in columns:
        conn.execute("ALTER TABLE renewal_attempts ADD COLUMN failure_reported_at TEXT")
    conn.execute(
        """UPDATE renewal_attempts
           SET failure_reported_at=(
               SELECT MIN(r.received_at) FROM renewal_reports r
               WHERE r.attempt_id=renewal_attempts.attempt_id
                 AND r.outcome='failed'
                 AND r.effect IN ('applied','no_change')
           )
           WHERE failure_reported_at IS NULL
             AND EXISTS (
                 SELECT 1 FROM renewal_reports r
                 WHERE r.attempt_id=renewal_attempts.attempt_id
                   AND r.outcome='failed'
                   AND r.effect IN ('applied','no_change')
             )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_failure_reported "
        "ON renewal_attempts(failure_reported_at) WHERE failure_reported_at IS NOT NULL"
    )
