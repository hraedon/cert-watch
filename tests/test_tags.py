"""Tests for tagging (plan 013, slice 1): helpers, repo, migration, API."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    distinct_tags,
    init_schema,
)
from cert_watch.tags import format_tags, merge_tags, parse_tags, tags_match

# ---------- helpers ----------

def test_parse_tags_trims_dedupes_drops_empty():
    assert parse_tags("  web , prod ,, web ,Prod") == ["web", "prod"]
    assert parse_tags("") == []
    assert parse_tags(None) == []


def test_format_tags_roundtrip_is_canonical():
    assert format_tags(["Web", "web", " prod "]) == "Web,prod"
    assert parse_tags(format_tags(["a", "b", "a"])) == ["a", "b"]


def test_merge_tags_unions_strings_and_lists():
    assert merge_tags("web,prod", ["pci"], None) == ["web", "prod", "pci"]
    # case-insensitive de-dupe, first casing wins
    assert merge_tags("Web", "web,prod") == ["Web", "prod"]


def test_tags_match_is_case_insensitive():
    assert tags_match(["Web", "prod"], ["web"]) is True
    assert tags_match(["prod"], ["web"]) is False
    assert tags_match([], ["web"]) is False


# ---------- repo ----------

@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


def _make_cert(repo: SqliteCertificateRepository) -> str:
    cert = Certificate(
        subject="CN=test",
        issuer="CN=issuer",
        not_before=datetime.now(UTC),
        not_after=datetime.now(UTC) + timedelta(days=365),
        san_dns_names=["test.example.com"],
        fingerprint_sha256="aa" * 32,
        raw_der=b"\x00" * 10,
        is_leaf=True,
    )
    return repo.add(cert)


def test_cert_set_get_tags_normalizes(db_path: Path):
    repo = SqliteCertificateRepository(db_path)
    cert_id = _make_cert(repo)
    repo.set_tags(cert_id, " pci , web , pci ")
    assert repo.get_tags(cert_id) == "pci,web"


def test_effective_tags_inherit_from_host(db_path: Path):
    SqliteHostRepository(db_path).add("ex.com", 443, tags="team-web, prod")
    cert_repo = SqliteCertificateRepository(
        db_path, hostname="ex.com", port=443
    )
    cert_id = _make_cert(cert_repo)
    cert_repo.set_tags(cert_id, "pci")
    eff = cert_repo.effective_tags(cert_id)
    assert set(eff) == {"team-web", "prod", "pci"}


def test_effective_tags_no_host(db_path: Path):
    repo = SqliteCertificateRepository(db_path)
    cert_id = _make_cert(repo)
    repo.set_tags(cert_id, "team-infra")
    assert repo.effective_tags(cert_id) == ["team-infra"]


def test_host_set_tags_returns_false_when_missing(db_path: Path):
    repo = SqliteHostRepository(db_path)
    assert repo.set_tags("no-such-host", "x") is False
    host_id = repo.add("h.example.com", 443)
    assert repo.set_tags(host_id, " a , a ,b ") is True
    assert repo.get(host_id).tags == "a,b"


def test_distinct_tags_unions_hosts_and_certs(db_path: Path):
    SqliteHostRepository(db_path).add("ex.com", 443, tags="prod, team-web")
    repo = SqliteCertificateRepository(db_path)
    repo.set_tags(_make_cert(repo), "pci, prod")
    assert distinct_tags(db_path) == ["pci", "prod", "team-web"]


# ---------- migration ----------

def test_migration_adds_cert_tags_column(db_path: Path):
    with sqlite3.connect(str(db_path)) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(certificates)")}
    assert "tags" in cols


# ---------- API ----------

def test_api_set_and_get_cert_tags(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)
    with sqlite3.connect(str(db)) as conn:
        cert_id = conn.execute("SELECT id FROM certificates LIMIT 1").fetchone()[0]

    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": ["web", "web", "prod"]})
        assert r.status_code == 200, r.text
        assert r.json()["tags"] == ["web", "prod"]

        g = client.get(f"/api/certificates/{cert_id}")
        assert g.status_code == 200
        assert g.json()["tags"] == ["web", "prod"]
        assert set(g.json()["effective_tags"]) >= {"web", "prod"}

        t = client.get("/api/tags")
        assert t.status_code == 200
        assert "web" in t.json()["tags"]


def test_api_set_cert_tags_accepts_csv_string(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import store_uploaded, upload_certificate

    store_uploaded(upload_certificate(leaf_pem_file), db)
    with sqlite3.connect(str(db)) as conn:
        cert_id = conn.execute("SELECT id FROM certificates LIMIT 1").fetchone()[0]

    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": "a, b ,a"})
        assert r.status_code == 200
        assert r.json()["tags"] == ["a", "b"]


def test_api_set_cert_tags_bad_body(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import store_uploaded, upload_certificate

    store_uploaded(upload_certificate(leaf_pem_file), db)
    with sqlite3.connect(str(db)) as conn:
        cert_id = conn.execute("SELECT id FROM certificates LIMIT 1").fetchone()[0]

    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/certificates/{cert_id}/tags", json={"tags": 123})
        assert r.status_code == 400


def test_api_set_cert_tags_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.put("/api/certificates/nope/tags", json={"tags": ["x"]})
        assert r.status_code == 404


def test_api_set_host_tags(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("h.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.put(f"/api/hosts/{host_id}/tags", json={"tags": ["team-net"]})
        assert r.status_code == 200, r.text
        assert r.json()["tags"] == ["team-net"]
        miss = client.put("/api/hosts/missing/tags", json={"tags": ["x"]})
        assert miss.status_code == 404
