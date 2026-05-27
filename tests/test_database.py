from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
    list_unified_entries,
)


def test_init_schema_idempotent(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    init_schema(db)
    assert db.exists()


def test_init_schema_migrates_old_database_without_replaces_cert_id(tmp_path):
    """Regression for k8s CrashLoopBackOff: indexes referencing migrated columns
    must be created AFTER the column migration, not inside the table DDL."""
    db = tmp_path / "legacy.sqlite3"
    import sqlite3

    # Simulate a pre-migration database
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            """
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
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """CREATE TABLE hosts (
                id TEXT PRIMARY KEY, hostname TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 443, added_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE alerts (
                id TEXT PRIMARY KEY, cert_id TEXT NOT NULL,
                alert_type TEXT NOT NULL, status TEXT NOT NULL,
                message TEXT NOT NULL, created_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE scan_history (
                id TEXT PRIMARY KEY, hostname TEXT NOT NULL,
                port INTEGER NOT NULL, status TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )"""
        )
        conn.commit()

    # Must not raise "no such column: replaces_cert_id"
    init_schema(db)

    # Verify migrated columns exist
    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)").fetchall()}
        assert "replaces_cert_id" in cols
        assert "notes" in cols
        idx = {r[1] for r in conn.execute("PRAGMA index_list('certificates')").fetchall()}
        assert "idx_cert_replaces" in idx


def test_add_and_get_certificate(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    cert = parse_certificate(self_signed_leaf.der)
    cert_id = repo.add(cert)
    fetched = repo.get_by_id(cert_id)
    assert fetched is not None
    # Verifies non-trivial dep field survives round-trip per AC-02.
    assert fetched.fingerprint_sha256 == cert.fingerprint_sha256
    assert fetched.subject == cert.subject


def test_list_all_and_expiring_within(tmp_path, self_signed_leaf, expiring_soon_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    repo.add(parse_certificate(self_signed_leaf.der))
    repo.add(parse_certificate(expiring_soon_leaf.der))
    assert len(repo.list_all()) == 2
    soon = repo.list_expiring_within(30)
    assert len(soon) == 1


def test_update_expiry_and_delete(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    cid = repo.add(parse_certificate(self_signed_leaf.der))
    new = datetime.now(UTC) + timedelta(days=1)
    repo.update_expiry(cid, new)
    got = repo.get_by_id(cid)
    assert abs((got.not_after - new).total_seconds()) < 5
    repo.delete(cid)
    assert repo.get_by_id(cid) is None


def test_alert_repository_lifecycle(tmp_path):
    db = tmp_path / "cw.sqlite3"
    arepo = SqliteAlertRepository(db)
    a = Alert(
        cert_id="cert-1",
        alert_type="expiry_warning",
        status="pending",
        message="expires soon",
        threshold_days=7,
    )
    aid = arepo.create(a)
    pending = arepo.list_pending()
    assert len(pending) == 1 and pending[0].id == aid
    arepo.mark_sent(aid)
    assert arepo.list_pending() == []
    a2 = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    a2id = arepo.create(a2)
    arepo.mark_failed(a2id, "smtp dead")
    rows = [a for a in arepo.list_all() if a.id == a2id]
    assert rows[0].status == "failed" and rows[0].error_message == "smtp dead"


def test_update_notes(tmp_path, self_signed_leaf):
    """FEAT-013: update_notes should persist notes to the database."""
    from cert_watch.certificate_model import Certificate

    db = tmp_path / "test.sqlite3"
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    repo = SqliteCertificateRepository(db, source="test")
    cert_id = repo.add(cert)

    loaded = repo.get_by_id(cert_id)
    assert loaded is not None
    assert loaded.notes == ""

    repo.update_notes(cert_id, "staging cert for renewal")
    loaded = repo.get_by_id(cert_id)
    assert loaded is not None
    assert loaded.notes == "staging cert for renewal"


def test_list_unified_entries_scanned_pending_uploaded(tmp_path, self_signed_leaf):
    """BC-028: list_unified_entries merges hosts, certs, and latest scan_history."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.scan import ScannedEntry, store_scanned
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "unified.sqlite3"
    init_schema(db)

    host_repo = SqliteHostRepository(db)
    host_repo.add("scanned.example.com", 443)
    host_repo.add("pending.example.com", 8443)

    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)

    # Store a scanned cert
    entry = ScannedEntry(host="scanned.example.com", port=443, leaf=cert, chain=[])
    store_scanned(entry, db)

    # Record two scan history entries — only the latest should surface
    old_time = datetime.now(UTC) - timedelta(hours=2)
    record_scan_history(
        db,
        ScanHistory(
            hostname="scanned.example.com",
            port=443,
            status="failure",
            scanned_at=old_time,
            error_message="timeout",
        ),
    )
    new_time = datetime.now(UTC) - timedelta(minutes=5)
    record_scan_history(
        db,
        ScanHistory(
            hostname="scanned.example.com",
            port=443,
            status="success",
            scanned_at=new_time,
        ),
    )

    # Add an uploaded cert (no host row)
    cert_repo = SqliteCertificateRepository(db, source="uploaded")
    cert_repo.add(cert)

    entries = list_unified_entries(db)

    scanned = next(
        (e for e in entries if e["host"] == "scanned.example.com:443"), None
    )
    pending = next(
        (e for e in entries if e["host"] == "pending.example.com:8443"), None
    )
    uploaded = next((e for e in entries if e["kind"] == "uploaded"), None)

    assert scanned is not None
    assert scanned["kind"] == "scanned"
    assert scanned["scan_status"] == "success"
    assert scanned["scan_error"] is None
    assert scanned["subject"] == cert.subject

    assert pending is not None
    assert pending["kind"] == "pending"
    assert pending["urgency"] == "gray"
    assert pending["subject"] is None

    assert uploaded is not None
    assert uploaded["kind"] == "uploaded"
    assert uploaded["source"] == "uploaded"
    assert uploaded["name"] == cert.subject
