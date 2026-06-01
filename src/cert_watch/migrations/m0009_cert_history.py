"""Migration 0009 — add cert_history table (Plan 016)."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cert_history ("
        "id TEXT PRIMARY KEY,"
        "hostname TEXT,"
        "port INTEGER,"
        "fingerprint_sha256 TEXT NOT NULL,"
        "issuer TEXT NOT NULL,"
        "not_after TEXT NOT NULL,"
        "key_algo TEXT,"
        "sig_algo TEXT,"
        "posture_grade TEXT,"
        "protocol_version TEXT,"
        "san_count INTEGER,"
        "scanned_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cert_history_host_port_ts"
        " ON cert_history(hostname, port, scanned_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_cert_history_fp"
        " ON cert_history(fingerprint_sha256)"
    )
    conn.commit()
