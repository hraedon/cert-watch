"""Migration 0001 — the pre-runner cert-watch schema baseline.

The DDL was recovered from the parent of commit 1e00b7f, which introduced the
numbered migration runner. It is intentionally frozen: every structure added
after that commit belongs to a later migration.

The column guards preserve upgrades from still older, unstamped databases.
They are part of the baseline migration rather than a second, current-schema
definition in ``database.schema``.
"""

from __future__ import annotations

import sqlite3

BASELINE_TABLES = """
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
    renewal_method TEXT NOT NULL DEFAULT '',
    runbook_url TEXT NOT NULL DEFAULT '',
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

CREATE TABLE IF NOT EXISTS scan_posture (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    hostname TEXT,
    port INTEGER,
    grade TEXT NOT NULL,
    protocol_version TEXT,
    ocsp_stapling INTEGER,
    hsts INTEGER,
    must_staple INTEGER DEFAULT 0,
    findings TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);
"""

BASELINE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX IF NOT EXISTS idx_cert_replaces ON certificates(replaces_cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_cert ON alerts(cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
"""


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_missing_baseline_columns(conn: sqlite3.Connection) -> None:
    certificate_columns = _columns(conn, "certificates")
    additions = {
        "chain_valid": "chain_valid INTEGER",
        "replaces_cert_id": "replaces_cert_id TEXT",
        "notes": "notes TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in additions.items():
        if name not in certificate_columns:
            conn.execute(f"ALTER TABLE certificates ADD COLUMN {definition}")

    host_columns = _columns(conn, "hosts")
    host_additions = {
        "threshold_days": "threshold_days INTEGER",
        "tags": "tags TEXT NOT NULL DEFAULT ''",
        "scan_interval_hours": "scan_interval_hours INTEGER",
        "owner_name": "owner_name TEXT NOT NULL DEFAULT ''",
        "owner_email": "owner_email TEXT NOT NULL DEFAULT ''",
        "owner_slack": "owner_slack TEXT NOT NULL DEFAULT ''",
        "renewal_status": "renewal_status TEXT NOT NULL DEFAULT 'pending'",
        "renewal_method": "renewal_method TEXT NOT NULL DEFAULT ''",
        "runbook_url": "runbook_url TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in host_additions.items():
        if name not in host_columns:
            conn.execute(f"ALTER TABLE hosts ADD COLUMN {definition}")


def upgrade(conn: sqlite3.Connection) -> None:
    for statement in BASELINE_TABLES.split(";"):
        if statement.strip():
            conn.execute(statement)
    _add_missing_baseline_columns(conn)
    for statement in BASELINE_INDEXES.split(";"):
        if statement.strip():
            conn.execute(statement)

    indexes = {row[1] for row in conn.execute("PRAGMA index_list('hosts')")}
    if "ux_hosts_hostname_port" not in indexes:
        # Old pre-runner versions did not enforce uniqueness. Preserve their
        # historical repair behavior before adding the baseline index.
        conn.execute(
            "DELETE FROM hosts WHERE rowid NOT IN "
            "(SELECT MIN(rowid) FROM hosts GROUP BY hostname, port)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX ux_hosts_hostname_port ON hosts(hostname, port)"
        )
