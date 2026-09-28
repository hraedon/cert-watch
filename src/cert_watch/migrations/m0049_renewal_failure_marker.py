"""Migration 0049 — durable renewal failure conditions and rule wakes (#118 S5)."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0049"
DESCRIPTION = "record renewal failure conditions for alerts and digests"


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(renewal_attempts)")
    }
    additions = {
        "failure_attempt_id": "TEXT",
        "failure_reported_at": "TEXT",
        "failure_cleared_at": "TEXT",
        "rule_due_at": "TEXT",
    }
    for name, definition in additions.items():
        if name not in columns:
            conn.execute(
                f"ALTER TABLE renewal_attempts ADD COLUMN {name} {definition}"
            )
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
        """UPDATE renewal_attempts
           SET failure_attempt_id=attempt_id,
               rule_due_at=COALESCE(rule_due_at,failure_reported_at)
           WHERE failure_reported_at IS NOT NULL
             AND failure_attempt_id IS NULL"""
    )
    # 0048 could leave pre-existing not-deployed attempts without the transition
    # timestamp.  Their accepted success time (or, for historical rows, the
    # attempt receive time) is the durable fallback used by the digest.
    conn.execute(
        """UPDATE renewal_attempts
           SET raised_at=COALESCE(success_received_at,received_at)
           WHERE state='not_deployed' AND raised_at IS NULL"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_failure_condition "
        "ON renewal_attempts(failure_attempt_id,failure_cleared_at) "
        "WHERE failure_attempt_id IS NOT NULL"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_attempts_rule_due "
        "ON renewal_attempts(rule_due_at) WHERE rule_due_at IS NOT NULL"
    )
