"""Migration 0029 — add the durable digest-delivery claim ledger."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS digest_deliveries (
            digest_key TEXT NOT NULL,
            channel TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('claimed', 'failed', 'sent')),
            lease_owner TEXT,
            lease_expires_at TEXT,
            idempotency_key TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            sent_at TEXT,
            PRIMARY KEY (digest_key, channel, target)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS ux_digest_deliveries_idempotency
            ON digest_deliveries(idempotency_key);
        CREATE INDEX IF NOT EXISTS idx_digest_deliveries_lease
            ON digest_deliveries(status, lease_expires_at);
        """
    )
    conn.commit()
