"""Tests for BC-100 — trust-anchor-based private-CA detection.

chain_status on scan_posture replaces the hardcoded issuer-name-fragment SQL
formerly used in the Discover view.
"""

from __future__ import annotations

import sqlite3

from cert_watch.database import (
    init_schema,
    store_scan_posture,
)
from cert_watch.database.posture import get_posture_for_cert
from cert_watch.database.schema import ensure_base


def test_migration_0016_adds_chain_status_column(tmp_path):
    db = tmp_path / "test.db"
    ensure_base(db)
    with sqlite3.connect(str(db)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_posture)").fetchall()}
    assert "chain_status" in cols


def test_store_scan_posture_persists_chain_status(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    cert_id = "cert-001"
    store_scan_posture(
        db_path=db,
        cert_id=cert_id,
        hostname="example.com",
        port=443,
        grade="A",
        findings=[],
        chain_status="private",
    )
    posture = get_posture_for_cert(db, cert_id)
    assert posture is not None
    assert posture["chain_status"] == "private"

