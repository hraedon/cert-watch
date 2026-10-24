"""Application credential metadata, without a place for credential values."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0050"
DESCRIPTION = "track application credential expiry metadata"


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS application_secrets (
            id TEXT PRIMARY KEY,
            application_name TEXT NOT NULL,
            application_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            credential_name TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT '',
            expires_at TEXT NOT NULL,
            owner_email TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            retired_at TEXT,
            last_alert_threshold INTEGER
                CHECK(last_alert_threshold IN (0,1,3,7,14,30))
        )"""
    )
    conn.execute(
        """CREATE UNIQUE INDEX IF NOT EXISTS ux_application_secret_active
           ON application_secrets(tenant_id,application_id,credential_id)
           WHERE retired_at IS NULL"""
    )
    conn.execute(
        """CREATE INDEX IF NOT EXISTS idx_application_secret_expiry
           ON application_secrets(expires_at) WHERE retired_at IS NULL"""
    )
