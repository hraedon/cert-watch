"""Tests for BC-151 — CT mis-issuance detection + first-seen capture."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.ct_monitor import (
    ReconciliationResult,
    _get_scanned_issuer,
    _record_ct_issuer_first_seen,
)
from cert_watch.database import init_schema, replace_scanned
from cert_watch.database.schema import ensure_base


def test_migration_0018_adds_ct_issuer_first_seen_table(tmp_path):
    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        tables = {r[0] for r in rows}
    assert "ct_issuer_first_seen" in tables


def test_record_ct_issuer_first_seen(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    ts = _record_ct_issuer_first_seen(db, "Test Issuer")
    assert ts is not None
    # Second call should return the same timestamp
    ts2 = _record_ct_issuer_first_seen(db, "Test Issuer")
    assert ts2 == ts


def test_get_scanned_issuer(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["example.com"],
        fingerprint_sha256="a" * 64,
        raw_der=b"\x30" + b"\x00" * 63,
    )
    replace_scanned(db, "example.com", 443, cert, [], True)
    result = _get_scanned_issuer(db, "example.com")
    assert result is not None
    assert result == "Test CA"


def test_reconciliation_result_has_misissued_field():
    r = ReconciliationResult(domain="example.com")
    assert r.misissued == []
    assert r.first_seen_by_issuer == {}
