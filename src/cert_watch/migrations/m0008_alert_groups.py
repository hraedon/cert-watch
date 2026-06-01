"""Migration 0008 — add alert_groups and alert_group_certs tables (Plan 015)."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_groups ("
        "id TEXT PRIMARY KEY,"
        "name TEXT NOT NULL UNIQUE,"
        "recipients TEXT NOT NULL DEFAULT '',"
        "webhook_url TEXT NOT NULL DEFAULT '',"
        "match_tags TEXT NOT NULL DEFAULT '',"
        "created_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_group_certs ("
        "group_id TEXT NOT NULL,"
        "cert_id TEXT NOT NULL,"
        "PRIMARY KEY (group_id, cert_id)"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_group_certs_cert"
        " ON alert_group_certs(cert_id)"
    )
    conn.commit()
