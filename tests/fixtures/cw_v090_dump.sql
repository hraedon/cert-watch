BEGIN TRANSACTION;
CREATE TABLE alert_group_certs (
    group_id TEXT NOT NULL,
    cert_id TEXT NOT NULL,
    PRIMARY KEY (group_id, cert_id)
);
CREATE TABLE alert_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    recipients TEXT NOT NULL DEFAULT '',
    webhook_url TEXT NOT NULL DEFAULT '',
    match_tags TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT NOT NULL,
    threshold_days INTEGER,
    extra_recipients TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    sent_at TEXT,
    error_message TEXT,
    hostname TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT ''
, read INTEGER NOT NULL DEFAULT 0);
INSERT INTO "alerts" VALUES('a1','c1','expiry','pending','prod.hraedon.com expires soon',14,'[]','2026-06-20T00:00:00+00:00',NULL,NULL,'','',0);
CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    ts TEXT NOT NULL,
    actor TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    source_ip TEXT
);
CREATE TABLE cert_history (
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
    scanned_at TEXT NOT NULL,
    not_before TEXT
);
CREATE TABLE certificates (
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
INSERT INTO "certificates" VALUES('c1','CN=prod.hraedon.com','CN=Hraedon Issuing CA','2026-04-01T00:00:00+00:00','2026-07-05T00:00:00+00:00','["prod.hraedon.com"]','abababababababababababababababababababababababababababababababab',X'6465722D6C656166','scan','prod.hraedon.com',443,1,NULL,NULL,NULL,'','','2026-05-01T00:00:00+00:00','2026-05-01T00:00:00+00:00');
CREATE TABLE ct_issuer_first_seen (
            issuer_name TEXT PRIMARY KEY,
            first_seen_at TEXT NOT NULL
        );
CREATE TABLE event_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            payload TEXT NOT NULL,
            delivery_status TEXT DEFAULT 'pending',
            error_message TEXT,
            created_at TEXT NOT NULL
        );
CREATE TABLE hosts (
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
    notes TEXT NOT NULL DEFAULT '',
    expected_issuers TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL,
    UNIQUE(hostname, port)
);
INSERT INTO "hosts" VALUES('h1','prod.hraedon.com',443,14,'prod',NULL,'','plm@hraedon.com','','pending','','','','','2026-05-01T00:00:00+00:00');
INSERT INTO "hosts" VALUES('h2','legacy.hraedon.com',8443,30,'legacy',NULL,'','plm@hraedon.com','','pending','','','','','2026-05-02T00:00:00+00:00');
CREATE TABLE kv_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE rate_limits ( key TEXT PRIMARY KEY, timestamps TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
INSERT INTO "roles" VALUES('r1','operators','','ops team','2026-05-01T00:00:00+00:00','2026-05-01T00:00:00+00:00');
CREATE TABLE scan_history (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    status TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    error_message TEXT
);
INSERT INTO "scan_history" VALUES('s1','prod.hraedon.com',443,'ok','2026-06-20T00:00:00+00:00',NULL);
CREATE TABLE scan_posture (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    hostname TEXT,
    port INTEGER,
    grade TEXT NOT NULL,
    protocol_version TEXT,
    ocsp_stapling INTEGER,
    hsts INTEGER,
    must_staple INTEGER DEFAULT 0,
    verify_requested INTEGER,
    findings TEXT NOT NULL,
    scanned_at TEXT NOT NULL, chain_incomplete INTEGER, chain_status TEXT, caa_present INTEGER, caa_records TEXT, tls_verified INTEGER,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);
CREATE TABLE schema_version (id TEXT PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL);
INSERT INTO "schema_version" VALUES('0001','baseline: snapshot of pre-migration schema','2026-06-27T04:45:00.540284+00:00');
INSERT INTO "schema_version" VALUES('0002','add audit_log table (Plan 008)','2026-06-27T04:45:00.553077+00:00');
INSERT INTO "schema_version" VALUES('0003','add rate_limits table (BC-049)','2026-06-27T04:45:00.556517+00:00');
INSERT INTO "schema_version" VALUES('0004','add tls_verified column to scan_posture (BC-064)','2026-06-27T04:45:00.558864+00:00');
INSERT INTO "schema_version" VALUES('0005','add composite indexes for hostname/port queries','2026-06-27T04:45:00.559867+00:00');
INSERT INTO "schema_version" VALUES('0006','add tags column to certificates (plan 013)','2026-06-27T04:45:00.562500+00:00');
INSERT INTO "schema_version" VALUES('0007','add kv_store table (Plan 014)','2026-06-27T04:45:00.563789+00:00');
INSERT INTO "schema_version" VALUES('0008','add alert_groups tables (Plan 015)','2026-06-27T04:45:00.565505+00:00');
INSERT INTO "schema_version" VALUES('0009','add cert_history table (Plan 016)','2026-06-27T04:45:00.566656+00:00');
INSERT INTO "schema_version" VALUES('0010','add extra_recipients column to alerts (BC-051)','2026-06-27T04:45:00.568058+00:00');
INSERT INTO "schema_version" VALUES('0011','add session_versions table for session revocation (BC-081)','2026-06-27T04:45:00.570194+00:00');
INSERT INTO "schema_version" VALUES('0012','add chain_incomplete column to scan_posture (BC-108)','2026-06-27T04:45:00.571630+00:00');
INSERT INTO "schema_version" VALUES('0013','rename tls_verified to verify_requested in scan_posture (BC-125)','2026-06-27T04:45:00.572709+00:00');
INSERT INTO "schema_version" VALUES('0014','add read flag to alerts for unread tracking (BC-127)','2026-06-27T04:45:00.575514+00:00');
INSERT INTO "schema_version" VALUES('0015','add api_keys table for M2M auth (Plan 039 / BC-104)','2026-06-27T04:45:00.576601+00:00');
INSERT INTO "schema_version" VALUES('0016','add chain_status column to scan_posture (BC-100)','2026-06-27T04:45:00.577944+00:00');
INSERT INTO "schema_version" VALUES('0017','add CAA columns to scan_posture (BC-121)','2026-06-27T04:45:00.578901+00:00');
INSERT INTO "schema_version" VALUES('0018','add ct_issuer_first_seen table (BC-151)','2026-06-27T04:45:00.580890+00:00');
INSERT INTO "schema_version" VALUES('0019','add users and roles tables for local auth (Plan 040)','2026-06-27T04:45:00.588816+00:00');
INSERT INTO "schema_version" VALUES('0020','add hostname and subject columns to alerts','2026-06-27T04:45:00.589814+00:00');
INSERT INTO "schema_version" VALUES('0021','add event_log table for event streaming (Plan 044)','2026-06-27T04:45:00.595632+00:00');
INSERT INTO "schema_version" VALUES('0022','add expected_issuers column to hosts (WI-007)','2026-06-27T04:45:00.596720+00:00');
INSERT INTO "schema_version" VALUES('0023','add not_before column to cert_history (Plan 048 WI-2.1)','2026-06-27T04:45:00.599015+00:00');
CREATE TABLE session_versions (
    username TEXT PRIMARY KEY,
    version INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
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
);
CREATE TABLE users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL DEFAULT '',
            role_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        );
CREATE INDEX idx_cert_fp ON certificates(fingerprint_sha256);
CREATE INDEX idx_cert_parent ON certificates(parent_cert_id);
CREATE INDEX idx_cert_replaces ON certificates(replaces_cert_id);
CREATE INDEX idx_alert_cert ON alerts(cert_id);
CREATE INDEX idx_alert_status ON alerts(status);
CREATE INDEX idx_scan_history_scanned_at ON scan_history(scanned_at DESC);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_status_created ON alerts(status, created_at DESC);
CREATE INDEX idx_scan_posture_cert_scanned ON scan_posture(cert_id, scanned_at DESC);
CREATE INDEX idx_cert_host_port_leaf
    ON certificates(hostname, port, is_leaf);
CREATE INDEX idx_scan_history_host_port_ts
    ON scan_history(hostname, port, scanned_at DESC);
CREATE INDEX idx_alert_group_certs_cert
    ON alert_group_certs(cert_id);
CREATE INDEX idx_cert_history_host_port_ts
    ON cert_history(hostname, port, scanned_at DESC);
CREATE INDEX idx_cert_history_fp
    ON cert_history(fingerprint_sha256);
CREATE INDEX idx_session_versions_username
    ON session_versions(username);
CREATE UNIQUE INDEX ux_hosts_hostname_port ON hosts(hostname, port);
CREATE INDEX idx_audit_ts ON audit_log(ts);
CREATE INDEX idx_audit_target ON audit_log(target_type, target_id);
CREATE INDEX idx_rate_limits_updated ON rate_limits(updated_at DESC);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role_id ON users(role_id);
CREATE INDEX ix_event_log_event_type ON event_log (event_type);
CREATE INDEX ix_event_log_timestamp ON event_log (timestamp);
CREATE INDEX ix_event_log_delivery_status ON event_log (delivery_status);
DELETE FROM "sqlite_sequence";
COMMIT;
