"""Migration 0036 — persisted alert dispatch lifecycle."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0036"
DESCRIPTION = "add alert dispatch claims, leases, backoff, and give-up fields"

COLUMNS = {
    "attempt_count": "INTEGER NOT NULL DEFAULT 0",
    "next_attempt_at": "TEXT",
    "last_attempt_at": "TEXT",
    "lease_owner": "TEXT",
    "lease_expires_at": "TEXT",
    "failure_reason": "TEXT",
}


def upgrade(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
    for name, definition in COLUMNS.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")

    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_dispatch "
        "ON alerts(status, next_attempt_at)"
    )
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    }
    if "alert_delivery_events" in tables:
        conn.execute(
            """UPDATE alerts
               SET last_attempt_at = (
                   SELECT MAX(event.occurred_at)
                   FROM alert_delivery_events AS event
                   WHERE event.alert_id = alerts.id
               )
               WHERE last_attempt_at IS NULL
                 AND EXISTS (
                   SELECT 1 FROM alert_delivery_events AS event
                   WHERE event.alert_id = alerts.id
               )"""
        )
