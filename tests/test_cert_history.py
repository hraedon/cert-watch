"""Tests for Plan 016 — cert_history, drift, trends."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.queries import (
    list_cert_history,
    list_grade_trends,
    list_tls_version_trends,
    purge_old_history,
    record_cert_history,
)


def _make_leaf(
    subject: str = "CN=test.example.com",
    issuer: str = "CN=Test CA",
    days_valid: int = 90,
    sans: list[str] | None = None,
    fingerprint: str = "abc123",
    raw_der: bytes = b"",
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=subject,
        issuer=issuer,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days_valid),
        san_dns_names=sans or ["test.example.com"],
        fingerprint_sha256=fingerprint,
        raw_der=raw_der,
    )


# ---------- record_cert_history ----------


def test_record_cert_history_writes_row(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    row_id = record_cert_history(
        db, "host1.example.com", 443, leaf,
        posture_grade="A", protocol_version="TLSv1.3",
    )
    assert isinstance(row_id, str)
    with _connect(db) as conn:
        row = conn.execute("SELECT * FROM cert_history WHERE id = ?", (row_id,)).fetchone()
    assert row is not None
    assert row["hostname"] == "host1.example.com"
    assert row["port"] == 443
    assert row["posture_grade"] == "A"
    assert row["protocol_version"] == "TLSv1.3"
    assert row["fingerprint_sha256"] == "abc123"
    assert row["san_count"] == 1


def test_record_cert_history_multiple_scans(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf1 = _make_leaf(fingerprint="fp1", days_valid=90)
    leaf2 = _make_leaf(fingerprint="fp2", days_valid=60)

    record_cert_history(db, "h1.example.com", 443, leaf1, posture_grade="A")
    record_cert_history(db, "h1.example.com", 443, leaf2, posture_grade="B")

    history = list_cert_history(db, "h1.example.com", 443)
    assert len(history) == 2
    # Newest first
    assert history[0]["posture_grade"] == "B"
    assert history[1]["posture_grade"] == "A"


def test_record_cert_history_empty_optional_fields(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf(raw_der=b"")
    row_id = record_cert_history(db, "h.example.com", 443, leaf)
    with _connect(db) as conn:
        row = conn.execute("SELECT * FROM cert_history WHERE id = ?", (row_id,)).fetchone()
    assert row["key_algo"] == ""
    assert row["sig_algo"] == ""
    assert row["posture_grade"] == ""
    assert row["protocol_version"] == ""


def test_record_cert_history_san_count(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf(sans=["a.example.com", "b.example.com", "c.example.com"])
    row_id = record_cert_history(db, "h.example.com", 443, leaf)
    with _connect(db) as conn:
        row = conn.execute("SELECT * FROM cert_history WHERE id = ?", (row_id,)).fetchone()
    assert row["san_count"] == 3


# ---------- purge_old_history ----------


def test_purge_old_history_deletes_old_rows(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    old_time = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    recent_time = datetime.now(UTC).isoformat()

    # Insert an old row directly
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old1", "h.example.com", 443, "fp", "CN=CA", "2027-01-01",
             "", "", "A", "TLSv1.3", 1, old_time),
        )
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("recent1", "h.example.com", 443, "fp", "CN=CA", "2027-01-01",
             "", "", "A", "TLSv1.3", 1, recent_time),
        )
        conn.commit()

    deleted = purge_old_history(db, retention_days=365)
    assert deleted == 1

    history = list_cert_history(db, "h.example.com", 443, limit=100)
    assert len(history) == 1
    assert history[0]["id"] == "recent1"


def test_purge_old_history_zero_disables(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    old_time = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO cert_history
            (id, hostname, port, fingerprint_sha256, issuer, not_after,
             key_algo, sig_algo, posture_grade, protocol_version, san_count, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("old1", "h.example.com", 443, "fp", "CN=CA", "2027-01-01",
             "", "", "A", "TLSv1.3", 1, old_time),
        )
        conn.commit()

    deleted = purge_old_history(db, retention_days=0)
    assert deleted == 0
    history = list_cert_history(db, "h.example.com", 443, limit=100)
    assert len(history) == 1


def test_purge_old_history_negative_disables(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    deleted = purge_old_history(db, retention_days=-1)
    assert deleted == 0


# ---------- list_cert_history ----------


def test_list_cert_history_empty(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    history = list_cert_history(db, "nonexistent.example.com", 443)
    assert history == []


def test_list_cert_history_limit(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    for i in range(5):
        record_cert_history(db, "h.example.com", 443, leaf, posture_grade=f"G{i}")

    history = list_cert_history(db, "h.example.com", 443, limit=3)
    assert len(history) == 3


def test_list_cert_history_isolates_host_port(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    record_cert_history(db, "h1.example.com", 443, leaf, posture_grade="A")
    record_cert_history(db, "h2.example.com", 443, leaf, posture_grade="B")
    record_cert_history(db, "h1.example.com", 8443, leaf, posture_grade="C")

    h1_443 = list_cert_history(db, "h1.example.com", 443)
    assert len(h1_443) == 1
    assert h1_443[0]["posture_grade"] == "A"

    h2_443 = list_cert_history(db, "h2.example.com", 443)
    assert len(h2_443) == 1
    assert h2_443[0]["posture_grade"] == "B"

    h1_8443 = list_cert_history(db, "h1.example.com", 8443)
    assert len(h1_8443) == 1
    assert h1_8443[0]["posture_grade"] == "C"


# ---------- list_tls_version_trends ----------


def test_list_tls_version_trends_returns_grouped_data(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    record_cert_history(db, "h1.example.com", 443, leaf, protocol_version="TLSv1.3")
    record_cert_history(db, "h2.example.com", 443, leaf, protocol_version="TLSv1.3")
    record_cert_history(db, "h3.example.com", 443, leaf, protocol_version="TLSv1.2")

    trends = list_tls_version_trends(db, days=1)
    assert len(trends) >= 1
    # Should have two entries for today: TLSv1.3 (count=2) and TLSv1.2 (count=1)
    today = datetime.now(UTC).date().isoformat()
    today_entries = [t for t in trends if t["date"] == today]
    assert len(today_entries) == 2
    tls13 = next(t for t in today_entries if t["protocol_version"] == "TLSv1.3")
    tls12 = next(t for t in today_entries if t["protocol_version"] == "TLSv1.2")
    assert tls13["count"] == 2
    assert tls12["count"] == 1


def test_list_tls_version_trends_empty(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    trends = list_tls_version_trends(db, days=30)
    assert trends == []


# ---------- list_grade_trends ----------


def test_list_grade_trends_returns_grouped_data(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    record_cert_history(db, "h1.example.com", 443, leaf, posture_grade="A")
    record_cert_history(db, "h2.example.com", 443, leaf, posture_grade="A")
    record_cert_history(db, "h3.example.com", 443, leaf, posture_grade="B")

    trends = list_grade_trends(db, days=1)
    today = datetime.now(UTC).date().isoformat()
    today_entries = [t for t in trends if t["date"] == today]
    assert len(today_entries) == 2
    grade_a = next(t for t in today_entries if t["posture_grade"] == "A")
    grade_b = next(t for t in today_entries if t["posture_grade"] == "B")
    assert grade_a["count"] == 2
    assert grade_b["count"] == 1


def test_list_grade_trends_empty(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    trends = list_grade_trends(db, days=30)
    assert trends == []


# ---------- migration 0009 ----------


def test_migration_0009_creates_table(tmp_path):
    """Verify the migration creates cert_history with correct schema."""
    from cert_watch.migrations.m0009_cert_history import upgrade

    db = tmp_path / "mig.sqlite3"
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)
        cols = {
            r[1]
            for r in conn.execute("PRAGMA table_info(cert_history)").fetchall()
        }
    assert "id" in cols
    assert "hostname" in cols
    assert "port" in cols
    assert "fingerprint_sha256" in cols
    assert "issuer" in cols
    assert "not_after" in cols
    assert "key_algo" in cols
    assert "sig_algo" in cols
    assert "posture_grade" in cols
    assert "protocol_version" in cols
    assert "san_count" in cols
    assert "scanned_at" in cols


def test_migration_0009_idempotent(tmp_path):
    """Running migration twice should not error."""
    from cert_watch.migrations.m0009_cert_history import upgrade

    db = tmp_path / "mig.sqlite3"
    with sqlite3.connect(str(db)) as conn:
        upgrade(conn)
        upgrade(conn)  # Should not raise


# ---------- API integration ----------


def test_api_cert_history_endpoint(tmp_path, reload_app, self_signed_leaf):
    """GET /api/certificates/{id}/history returns history for a cert."""
    from starlette.testclient import TestClient

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    # Insert a cert with hostname/port
    repo = SqliteCertificateRepository(
        db, hostname="api-test.example.com", port=443,
    )
    from cryptography.hazmat.primitives import hashes as crypto_hashes

    from cert_watch.certificate_model import Certificate as Cert

    fp = self_signed_leaf.cert.fingerprint(
        crypto_hashes.SHA256()
    ).hex()
    cert = Cert(
        subject=self_signed_leaf.cert.subject.rfc4514_string(),
        issuer=self_signed_leaf.cert.issuer.rfc4514_string(),
        not_before=self_signed_leaf.cert.not_valid_before_utc,
        not_after=self_signed_leaf.cert.not_valid_after_utc,
        san_dns_names=["api-test.example.com"],
        fingerprint_sha256=fp,
        raw_der=self_signed_leaf.der,
    )
    cert_id = repo.add(cert)

    # Add some history
    record_cert_history(
        db, "api-test.example.com", 443, cert,
        posture_grade="A", protocol_version="TLSv1.3",
    )
    record_cert_history(
        db, "api-test.example.com", 443, cert,
        posture_grade="A+", protocol_version="TLSv1.3",
    )

    with TestClient(app_mod.app) as client:
        resp = client.get(f"/api/certificates/{cert_id}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert data["cert_id"] == cert_id
    assert len(data["history"]) == 2
    assert data["history"][0]["posture_grade"] == "A+"


def test_api_cert_history_not_found(reload_app):
    """GET /api/certificates/{id}/history returns 404 for unknown cert."""
    from starlette.testclient import TestClient

    app_mod = reload_app()

    with TestClient(app_mod.app) as client:
        resp = client.get("/api/certificates/nonexistent/history")
    assert resp.status_code == 404


def test_api_tls_versions_trends_endpoint(tmp_path, reload_app):
    """GET /api/trends/tls-versions returns fleet TLS version distribution."""
    from starlette.testclient import TestClient

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    record_cert_history(
        db, "h1.example.com", 443, leaf, protocol_version="TLSv1.3",
    )
    record_cert_history(
        db, "h2.example.com", 443, leaf, protocol_version="TLSv1.2",
    )

    with TestClient(app_mod.app) as client:
        resp = client.get("/api/trends/tls-versions?days=1")
    assert resp.status_code == 200
    data = resp.json()
    assert "trends" in data
    assert data["days"] == 1


def test_api_grade_trends_endpoint(tmp_path, reload_app):
    """GET /api/trends/grades returns fleet posture grade distribution."""
    from starlette.testclient import TestClient

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    leaf = _make_leaf()
    record_cert_history(
        db, "h1.example.com", 443, leaf, posture_grade="A",
    )
    record_cert_history(
        db, "h2.example.com", 443, leaf, posture_grade="B",
    )

    with TestClient(app_mod.app) as client:
        resp = client.get("/api/trends/grades?days=1")
    assert resp.status_code == 200
    data = resp.json()
    assert "trends" in data
    assert data["days"] == 1
