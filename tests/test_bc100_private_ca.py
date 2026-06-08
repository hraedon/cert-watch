"""Tests for BC-100 — trust-anchor-based private-CA detection.

Replaces the hardcoded issuer-name-fragment SQL in the Discover view with
a proper chain_status query derived from the trust-anchor table.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteHostRepository,
    SqliteTrustAnchorRepository,
    init_schema,
    replace_scanned,
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


def test_discover_counts_private_ca_via_chain_status(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    # Add a private-CA host with a trust anchor
    repo = SqliteTrustAnchorRepository(db)
    repo.add(
        Certificate(
            subject="Custom Root CA",
            issuer="Custom Root CA",
            not_before=datetime.now(UTC) - timedelta(days=365),
            not_after=datetime.now(UTC) + timedelta(days=3650),
            san_dns_names=[],
            fingerprint_sha256="b" * 64,
        )
    )

    SqliteHostRepository(db).add("private.example.com", 443)
    now = datetime.now(UTC)
    leaf = Certificate(
        subject="private.example.com",
        issuer="Custom Root CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["private.example.com"],
        fingerprint_sha256="a" * 64,
    )
    intermediate = Certificate(
        subject="Custom Root CA",
        issuer="Custom Root CA",
        not_before=now - timedelta(days=365),
        not_after=now + timedelta(days=3650),
        san_dns_names=[],
        fingerprint_sha256="b" * 64,
    )
    leaf_id, _ = replace_scanned(db, "private.example.com", 443, leaf, [intermediate], True)

    # Store posture with chain_status="private"
    store_scan_posture(
        db_path=db,
        cert_id=leaf_id,
        hostname="private.example.com",
        port=443,
        grade="A",
        findings=[],
        chain_status="private",
    )

    from fastapi.testclient import TestClient
    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200
    assert "private-CA hosts excluded" in r.text
    # The private_count should be 1 because the chain_status is "private"
    assert "1 private-CA hosts excluded" in r.text or "1 private-CA" in r.text


def test_discover_does_not_count_public_ca_as_private(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    SqliteHostRepository(db).add("public.example.com", 443)
    now = datetime.now(UTC)
    leaf = Certificate(
        subject="public.example.com",
        issuer="Let's Encrypt",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["public.example.com"],
        fingerprint_sha256="c" * 64,
    )
    leaf_id, _ = replace_scanned(db, "public.example.com", 443, leaf, [], True)

    store_scan_posture(
        db_path=db,
        cert_id=leaf_id,
        hostname="public.example.com",
        port=443,
        grade="A",
        findings=[],
        chain_status="public",
    )

    from fastapi.testclient import TestClient
    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200
    # The private_count should be 0 because the chain_status is "public"
    assert "0 private-CA hosts excluded" in r.text or "0 private-CA" in r.text
