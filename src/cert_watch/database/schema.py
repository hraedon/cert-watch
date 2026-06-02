"""Schema DDL and migration logic.

The entry point is ``init_schema(db_path)`` which:
1. Calls ``ensure_base(db_path)`` to create all core tables and indexes.
2. Calls ``run_pending_migrations(db_path)`` to apply numbered migrations.

For existing databases (upgraded from pre-migration versions), the runner
stamps the baseline (0001) automatically so subsequent migrations apply
cleanly.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

_BASE_TABLES = """
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
    tags TEXT NOT NULL DEFAULT '',
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
    extra_recipients TEXT NOT NULL DEFAULT '[]',
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
    tls_verified INTEGER,
    findings TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    source_ip TEXT
);

CREATE TABLE IF NOT EXISTS kv_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    recipients TEXT NOT NULL DEFAULT '',
    webhook_url TEXT NOT NULL DEFAULT '',
    match_tags TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_group_certs (
    group_id TEXT NOT NULL,
    cert_id TEXT NOT NULL,
    PRIMARY KEY (group_id, cert_id)
);

CREATE TABLE IF NOT EXISTS cert_history (
    id TEXT PRIMARY KEY,
    hostname TEXT,
    port INTEGER,
    fingerprint_sha256 TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_after TEXT NOT NULL,
    key_algo TEXT,
    sig_algo TEXT,
    posture_grade TEXT,
    protocol_version TEXT,
    san_count INTEGER,
    scanned_at TEXT NOT NULL
);
"""

_BASE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX IF NOT EXISTS idx_cert_replaces ON certificates(replaces_cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_cert ON alerts(cert_id);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_created ON alerts(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_posture_cert_scanned ON scan_posture(cert_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_host_port_leaf
    ON certificates(hostname, port, is_leaf);
CREATE INDEX IF NOT EXISTS idx_scan_history_host_port_ts
    ON scan_history(hostname, port, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_group_certs_cert
    ON alert_group_certs(cert_id);
CREATE INDEX IF NOT EXISTS idx_cert_history_host_port_ts
    ON cert_history(hostname, port, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_cert_history_fp
    ON cert_history(fingerprint_sha256);
"""

_initialized_paths: set[str] = set()


def ensure_base(db_path: str | Path) -> None:
    """Create all core tables and indexes if they don't exist.

    This is the "base schema" — the tables and columns that existed before
    the migration system was introduced. For fresh databases, this creates
    everything. For existing databases, this is a no-op (IF NOT EXISTS).

    Also handles column migrations for databases created before certain columns
    were added — these are idempotent ALTER TABLE ADD COLUMN statements that
    are no-ops if the column already exists.
    """
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        # 1. Create tables (no-op if they already exist)
        conn.executescript(_BASE_TABLES)

        # 2. Migrate columns that may be missing on existing databases.
        # These are the pre-migration PRAGMA guards carried forward for
        # backward compatibility with DBs created before the column was added.
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
        if "renewal_method" not in host_cols:
            conn.execute(
                "ALTER TABLE hosts ADD COLUMN renewal_method"
                " TEXT NOT NULL DEFAULT ''"
            )
        if "runbook_url" not in host_cols:
            conn.execute(
                "ALTER TABLE hosts ADD COLUMN runbook_url"
                " TEXT NOT NULL DEFAULT ''"
            )

        # 3. Create indexes
        conn.executescript(_BASE_INDEXES)

        # 4. Ensure unique index on hosts(hostname, port) — BC-019
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


def init_schema(db_path: str | Path) -> None:
    """Initialize the database schema and run pending migrations.

    Idempotent: repeat calls for the same path return immediately after the
    first successful initialization. Creates core tables via ``ensure_base``,
    then applies any pending numbered migrations via the migration runner.
    """
    path_str = str(Path(db_path).resolve())
    if path_str in _initialized_paths:
        return

    ensure_base(db_path)

    # Import the registry to register all migrations, then run pending.
    import cert_watch.migrations.registry  # noqa: F401 — side-effect: registers migrations
    from cert_watch.migrations.runner import run_pending_migrations

    run_pending_migrations(db_path, backup=True)
    _initialized_paths.add(path_str)