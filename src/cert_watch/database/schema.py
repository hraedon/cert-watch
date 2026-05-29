"""Schema DDL and migration logic."""
from __future__ import annotations

import sqlite3
from pathlib import Path

_TABLES_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    source TEXT NOT NULL DEFAULT 'unknown',
    hostname TEXT,
    port INTEGER,
    is_leaf INTEGER NOT NULL DEFAULT 1,
    parent_cert_id TEXT,
    chain_valid INTEGER,
    replaces_cert_id TEXT,
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    threshold_days INTEGER,
    created_at TEXT NOT NULL,
    sent_at TEXT,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 443,
    threshold_days INTEGER,
    tags TEXT NOT NULL DEFAULT '',
    scan_interval_hours INTEGER,
    owner_name TEXT NOT NULL DEFAULT '',
    owner_email TEXT NOT NULL DEFAULT '',
    owner_slack TEXT NOT NULL DEFAULT '',
    renewal_status TEXT NOT NULL DEFAULT 'pending',
    added_at TEXT NOT NULL,
    UNIQUE(hostname, port)
);

CREATE TABLE IF NOT EXISTS trust_anchors (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    san_dns_names TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    raw_der BLOB NOT NULL,
    created_at TEXT NOT NULL
);
"""

_INDEXES_SCHEMA = """
CREATE INDEX IF NOT EXISTS idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX IF NOT EXISTS idx_cert_replaces ON certificates(replaces_cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_cert ON alerts(cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
"""

_initialized_paths: set[str] = set()


def init_schema(db_path: str | Path) -> None:
    """Create all tables if they do not exist. Idempotent. See AC-06.

    Tracks initialized paths so repeat calls for the same database
    return immediately after the first successful initialization.
    """
    path = Path(db_path)
    path_str = str(path)
    if path_str in _initialized_paths:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        # 1. Create tables first (no-op if they already exist)
        conn.executescript(_TABLES_SCHEMA)

        # 2. Migrate columns that may be missing on existing databases
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()}
        if "chain_valid" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN chain_valid INTEGER")
        if "replaces_cert_id" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN replaces_cert_id TEXT")
        if "notes" not in cols:
            conn.execute("ALTER TABLE certificates ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        host_cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
        if "threshold_days" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN threshold_days INTEGER")
        if "tags" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN tags TEXT NOT NULL DEFAULT ''")
        if "scan_interval_hours" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN scan_interval_hours INTEGER")
        if "owner_name" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN owner_name TEXT NOT NULL DEFAULT ''")
        if "owner_email" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN owner_email TEXT NOT NULL DEFAULT ''")
        if "owner_slack" not in host_cols:
            conn.execute("ALTER TABLE hosts ADD COLUMN owner_slack TEXT NOT NULL DEFAULT ''")
        if "renewal_status" not in host_cols:
            conn.execute(
                "ALTER TABLE hosts ADD COLUMN renewal_status"
                " TEXT NOT NULL DEFAULT 'pending'"
            )
        # trust_anchors migration
        ta_cols = {r[1] for r in conn.execute("PRAGMA table_info(trust_anchors)").fetchall()}
        if not ta_cols:
            conn.execute(
                """
                CREATE TABLE trust_anchors (
                    id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    san_dns_names TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    raw_der BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

        # 3. Create indexes only after columns are guaranteed to exist
        conn.executescript(_INDEXES_SCHEMA)

        # 4. Idempotent unique-index migration for hosts(hostname, port) — BC-019
        indexes = {r[1] for r in conn.execute("PRAGMA index_list('hosts')").fetchall()}
        if "ux_hosts_hostname_port" not in indexes:
            conn.execute(
                """
                DELETE FROM hosts
                WHERE rowid NOT IN (
                    SELECT MIN(rowid)
                    FROM hosts
                    GROUP BY hostname, port
                )
                """
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_hosts_hostname_port ON hosts(hostname, port)"
            )
        conn.commit()
    _initialized_paths.add(path_str)
