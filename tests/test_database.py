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
from cert_watch.database.queries import (
    check_encrypted_values,
    derive_encryption_key,
    kv_get,
    kv_set,
    kv_set_secret,
    re_encrypt_kv_store,
)


def test_init_schema_idempotent(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    init_schema(db)
    assert db.exists()


def test_init_schema_detects_replaced_backup(tmp_path):
    """WI-091: init_schema must detect a restored backup (different file) and
    re-run migrations, even though the path string is unchanged.

    The module-level cache keys on (st_ino, st_size, st_mtime), not just the
    path — mirroring the connection layer. A path-only cache would short-
    circuit and skip migrations on the restored file.
    """
    import sqlite3

    from cert_watch.database.connection import close_connections
    from cert_watch.database.schema import ensure_base

    db = tmp_path / "cw.sqlite3"

    # 1. Full init — establishes the cache entry for this path.
    init_schema(db)

    # 2. Simulate a restore from a pre-migration backup: replace the file
    #    with one that has only the base schema (no schema_version table,
    #    no roles table, no permission_tier column).
    close_connections()  # release file handles before replacing
    for suffix in ("", "-wal", "-shm"):
        (tmp_path / f"cw.sqlite3{suffix}").unlink(missing_ok=True)
    # Clear pre-migration backups from the first init so the second init's
    # VACUUM INTO doesn't collide on the same-second timestamp.
    for f in tmp_path.glob("*-pre-migration-*"):
        f.unlink(missing_ok=True)
    ensure_base(db)  # fresh file: base tables only, no migrations applied

    # Confirm the "backup" lacks migration-added artifacts.
    with sqlite3.connect(str(db)) as conn:
        tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        assert "roles" not in tables  # added by migration 0019

    # 3. Re-init — must detect the replaced file and re-run migrations.
    init_schema(db)

    # 4. Migration-added column must now exist.
    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(roles)").fetchall()}
        assert "permission_tier" in cols  # added by migration 0024


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


def test_init_schema_creates_scan_history_and_alerts_indexes(tmp_path):
    """BC-050: scan_history and alerts must have indexes on scanned_at / created_at."""
    db = tmp_path / "indexes.sqlite3"
    init_schema(db)
    import sqlite3

    with sqlite3.connect(str(db)) as conn:
        for table, idx_name in (
            ("scan_history", "idx_scan_history_scanned_at"),
            ("alerts", "idx_alerts_created_at"),
            ("alerts", "idx_alerts_status_created"),
        ):
            idx = {r[1] for r in conn.execute(f"PRAGMA index_list('{table}')").fetchall()}
            assert idx_name in idx, f"{idx_name} missing on {table}"


def test_add_and_get_certificate(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
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
    init_schema(db)
    repo = SqliteCertificateRepository(db, source="uploaded")
    repo.add(parse_certificate(self_signed_leaf.der))
    repo.add(parse_certificate(expiring_soon_leaf.der))
    assert len(repo.list_all()) == 2
    soon = repo.list_expiring_within(30)
    assert len(soon) == 1


def test_update_expiry_and_delete(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
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
    init_schema(db)
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
    init_schema(db)
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
    assert uploaded["name"] == "leaf.example.com"


def test_list_unified_entries_page_pagination(tmp_path, self_signed_leaf):
    """BC-047: list_unified_entries_page returns paginated slice + total count."""
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import list_unified_entries_page
    from cert_watch.database.schema import init_schema
    from cert_watch.scan import ScannedEntry, store_scanned

    db = tmp_path / "page.sqlite3"
    init_schema(db)

    host_repo = SqliteHostRepository(db)
    host_repo.add("a.example.com", 443)
    host_repo.add("b.example.com", 443)

    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)

    entry = ScannedEntry(host="a.example.com", port=443, leaf=cert, chain=[])
    store_scanned(entry, db)
    entry2 = ScannedEntry(host="b.example.com", port=443, leaf=cert, chain=[])
    store_scanned(entry2, db)

    cert_repo = SqliteCertificateRepository(db, source="uploaded")
    cert_repo.add(cert)

    # page 1, limit 2
    rows, total = list_unified_entries_page(db, offset=0, limit=2)
    assert len(rows) == 2
    assert total == 3  # 2 scanned + 1 uploaded

    # page 2, limit 2
    rows2, total2 = list_unified_entries_page(db, offset=2, limit=2)
    assert len(rows2) == 1
    assert total2 == 3

    # filtering by q
    rows_q, total_q = list_unified_entries_page(db, offset=0, limit=10, q="a.example")
    assert total_q == 1
    assert rows_q[0]["host"] == "a.example.com:443"

    # filtering by source
    rows_src, total_src = list_unified_entries_page(db, offset=0, limit=10, source="scanned")
    assert total_src == 2
    for r in rows_src:
        assert r["kind"] in ("scanned", "pending")

    # sorting by days (default)
    rows_days, _ = list_unified_entries_page(
        db, offset=0, limit=10, sort_by="days", sort_order="asc"
    )
    # All three entries have the same cert, so days_remaining are identical.
    assert len(rows_days) == 3

    # sorting by expiry desc
    rows_exp, _ = list_unified_entries_page(
        db, offset=0, limit=10, sort_by="expiry", sort_order="desc"
    )
    assert len(rows_exp) == 3


def test_check_encrypted_values_no_encrypted(tmp_path):
    """check_encrypted_values returns empty list when no enc:v1: values exist."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    key = derive_encryption_key("test-signing-key")
    assert check_encrypted_values(db, key) == []


def test_check_encrypted_values_all_valid(tmp_path):
    """check_encrypted_values returns empty list when all values decrypt fine."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    key = derive_encryption_key("test-signing-key")
    kv_set_secret(db, "smtp_password", "hunter2", key)
    kv_set_secret(db, "ldap_bind_password", "secret123", key)
    assert check_encrypted_values(db, key) == []


def test_check_encrypted_values_detects_bad_key(tmp_path):
    """check_encrypted_values reports keys that can't be decrypted with the given key."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    old_key = derive_encryption_key("old-signing-key")
    kv_set_secret(db, "smtp_password", "hunter2", old_key)
    kv_set_secret(db, "ldap_bind_password", "secret123", old_key)
    kv_set(db, "alert_recipients", "admin@example.com")
    wrong_key = derive_encryption_key("different-signing-key")
    bad = check_encrypted_values(db, wrong_key)
    assert "smtp_password" in bad
    assert "ldap_bind_password" in bad
    assert "alert_recipients" not in bad


def test_re_encrypt_kv_store(tmp_path):
    """re_encrypt_kv_store re-encrypts values from old key to new key."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    old_key = derive_encryption_key("old-signing-key")
    new_key = derive_encryption_key("new-signing-key")

    kv_set_secret(db, "smtp_password", "hunter2", old_key)
    kv_set_secret(db, "ldap_bind_password", "secret123", old_key)
    kv_set(db, "alert_recipients", "admin@example.com")

    count = re_encrypt_kv_store(db, old_key, new_key)
    assert count == 2

    decrypted_smtp = kv_get(db, "smtp_password", encryption_key=new_key)
    assert decrypted_smtp == "hunter2"
    decrypted_ldap = kv_get(db, "ldap_bind_password", encryption_key=new_key)
    assert decrypted_ldap == "secret123"
    plain = kv_get(db, "alert_recipients")
    assert plain == "admin@example.com"


def test_re_encrypt_skips_undecryptable(tmp_path):
    """re_encrypt_kv_store skips values that can't be decrypted with old key."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    wrong_key = derive_encryption_key("wrong-key")
    good_key = derive_encryption_key("good-key")
    new_key = derive_encryption_key("new-key")

    kv_set_secret(db, "smtp_password", "hunter2", good_key)
    kv_set_secret(db, "oauth_client_secret", "oauth-secret", good_key)

    count = re_encrypt_kv_store(db, wrong_key, new_key)
    assert count == 0

    assert kv_get(db, "smtp_password", encryption_key=good_key) == "hunter2"


# --- WI-024: connection lifetime ---------------------------------------------


def test_thread_exit_closes_cached_connection(tmp_path):
    """A dying thread must close its cached connection even when something
    else still references it (the WI-024 leak: stranded connections kept
    -wal/-shm handles open until GC noticed)."""
    import gc
    import sqlite3
    import threading

    import pytest

    from cert_watch.database.connection import _connect

    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    captured = {}

    def work():
        conn = _connect(db)
        conn.execute("SELECT 1")
        captured["conn"] = conn

    t = threading.Thread(target=work)
    t.start()
    t.join()
    del t
    gc.collect()  # 3.14: thread-local teardown can route through cyclic GC

    with pytest.raises(sqlite3.ProgrammingError):
        captured["conn"].execute("SELECT 1")


def test_connection_cache_evicts_oldest(tmp_path):
    """The per-thread cache is bounded: opening more than the cap closes the
    oldest connection instead of accumulating handles for the thread's life."""
    import sqlite3

    import pytest

    from cert_watch.database.connection import (
        _MAX_CACHED_CONNECTIONS,
        _connect,
        _thread_cache,
        close_connections,
    )

    close_connections()  # isolate from connections cached by earlier tests
    conns = []
    for i in range(_MAX_CACHED_CONNECTIONS + 1):
        db = tmp_path / f"cw-{i}.sqlite3"
        init_schema(db)
        conns.append(_connect(db))

    assert len(_thread_cache().connections) <= _MAX_CACHED_CONNECTIONS
    with pytest.raises(sqlite3.ProgrammingError):
        conns[0].execute("SELECT 1")  # evicted + closed
    conns[-1].execute("SELECT 1")  # newest still live
    close_connections()
