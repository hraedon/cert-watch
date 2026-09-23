"""Migration 0035 — reconcile structures formerly supplied by ensure_base.

Historical startup code created several post-0001 objects outside the numbered
chain. Genuine 0001 upgrades therefore missed four indexes and ``hosts.notes``,
while fresh databases retained both ``tls_verified`` and its renamed successor
``verify_requested``. Converge every supported path on the migration-defined
schema, preserving the current application-facing structures.
"""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    host_columns = {row[1] for row in conn.execute("PRAGMA table_info(hosts)")}
    if "notes" not in host_columns:
        conn.execute(
            "ALTER TABLE hosts ADD COLUMN notes TEXT NOT NULL DEFAULT ''"
        )

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at "
        "ON scan_history(scanned_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_created_at "
        "ON alerts(created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status_created "
        "ON alerts(status, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_posture_cert_scanned "
        "ON scan_posture(cert_id, scanned_at DESC)"
    )

    posture_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(scan_posture)")
    }
    if "tls_verified" in posture_columns and "verify_requested" in posture_columns:
        conn.execute("ALTER TABLE scan_posture DROP COLUMN tls_verified")
    elif "tls_verified" in posture_columns:
        conn.execute(
            "ALTER TABLE scan_posture RENAME COLUMN tls_verified TO verify_requested"
        )
    elif "verify_requested" not in posture_columns:
        conn.execute(
            "ALTER TABLE scan_posture ADD COLUMN verify_requested INTEGER"
        )
