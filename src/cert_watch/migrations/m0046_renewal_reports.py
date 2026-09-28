"""Migration 0046 — durable renewal reports and current attempts (#118 S2)."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0046"
DESCRIPTION = "add renewal reports, attempts and idempotency"


def upgrade(conn: sqlite3.Connection) -> None:
    lineage_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(certificate_lineage)")
    }
    if "old_fingerprint" not in lineage_columns:
        conn.execute("ALTER TABLE certificate_lineage ADD COLUMN old_fingerprint TEXT")
    # Best-effort upgrade fill. Future scans write this directly; retained
    # history lets most recent lineage rows remain fingerprint-addressable
    # immediately after upgrading too.
    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    if "cert_history" in tables:
        conn.execute(
            """UPDATE certificate_lineage AS cl SET old_fingerprint = COALESCE(
                   (SELECT c.fingerprint_sha256 FROM certificates c
                    WHERE c.id=cl.old_cert_id),
                   (SELECT ch.fingerprint_sha256 FROM cert_history ch
                    WHERE ch.hostname=cl.hostname AND ch.port=cl.port
                      AND ch.scanned_at<cl.created_at
                    ORDER BY ch.scanned_at DESC LIMIT 1)
               ) WHERE old_fingerprint IS NULL"""
        )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_certificate_lineage_old_fingerprint "
        "ON certificate_lineage(old_fingerprint, created_at)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS renewal_reports (
               seq INTEGER PRIMARY KEY,
               host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
               hostname_snapshot TEXT NOT NULL,
               port_snapshot INTEGER NOT NULL,
               outcome TEXT NOT NULL CHECK (outcome IN ('started','succeeded','failed')),
               message TEXT,
               tool TEXT,
               correlation_id TEXT,
               new_fingerprint TEXT,
               occurred_at TEXT,
               received_at TEXT NOT NULL,
               source TEXT NOT NULL,
               effect TEXT NOT NULL CHECK (
                   effect IN ('applied','ignored_late','duplicate','no_change')
               ),
               attempt_id TEXT NOT NULL
           )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_reports_host_seq "
        "ON renewal_reports(host_id, seq DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_reports_source_seq "
        "ON renewal_reports(source, seq DESC)"
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS renewal_attempts (
               host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
               attempt_id TEXT NOT NULL UNIQUE,
               state TEXT NOT NULL CHECK (
                   state IN ('open','abandoned','failed','verifying',
                             'not_deployed','verified','cancelled')
               ),
               opened_seq INTEGER NOT NULL,
               baseline_fingerprint TEXT,
               baseline_not_after TEXT,
               new_fingerprint TEXT,
               lease_expires_at TEXT,
               suppresses_stalled INTEGER NOT NULL DEFAULT 0
                   CHECK (suppresses_stalled IN (0,1)),
               received_at TEXT NOT NULL,
               next_check_at TEXT,
               closed_reason TEXT
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS renewal_idempotency (
               source TEXT NOT NULL,
               key TEXT NOT NULL,
               host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
               body_sha256 TEXT NOT NULL,
               response_status INTEGER NOT NULL,
               response_body TEXT NOT NULL,
               created_at TEXT NOT NULL,
               UNIQUE(source, key)
           )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_renewal_idempotency_created "
        "ON renewal_idempotency(created_at)"
    )
