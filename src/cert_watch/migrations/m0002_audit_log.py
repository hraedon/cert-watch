"""Migration 0002 — add audit_log table.

Introduced by Plan 008 (audit log). The audit_log table was previously
created inline in init_schema(); this migration moves it into the ordered
migration system so future upgrades apply it cleanly.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    # Idempotent: CREATE TABLE IF NOT EXISTS is safe on both fresh and
    # existing databases (the table may already exist from init_schema).
    conn.execute(
        "CREATE TABLE IF NOT EXISTS audit_log ("
        " id TEXT PRIMARY KEY,"
        " ts TEXT NOT NULL,"
        " actor TEXT,"
        " action TEXT NOT NULL,"
        " target_type TEXT,"
        " target_id TEXT,"
        " detail TEXT,"
        " source_ip TEXT"
        ")"
    )
    # Indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id)"
    )
    conn.commit()
