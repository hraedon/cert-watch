"""Tests for host expected-issuers API endpoints (WI-007)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cert_watch.database import SqliteHostRepository, init_schema


def _db_name():
    return "cert-watch.sqlite3"


def test_api_get_host_issuers(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443, expected_issuers="R3,R4")

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/hosts/{host_id}/issuers")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == host_id
    assert data["expected_issuers"] == ["R3", "R4"]


def test_api_get_host_issuers_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts/00000000-0000-0000-0000-000000000000/issuers")
    assert r.status_code == 404


def test_api_set_host_issuers_list(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443, expected_issuers="R3,R4")

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            json={"issuers": ["R3", "R4", "E1"]},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["expected_issuers"] == ["R3", "R4", "E1"]

    # Verify persistence
    repo = SqliteHostRepository(db)
    assert repo.get_expected_issuers(host_id) == ["R3", "R4", "E1"]


def test_api_set_host_issuers_csv_string(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            json={"issuers": "R3, R4"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["expected_issuers"] == ["R3", "R4"]


def test_api_set_host_issuers_clear(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443, expected_issuers="R3")

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            json={"issuers": []},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["expected_issuers"] == []


def test_api_set_host_issuers_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.put(
            "/api/hosts/00000000-0000-0000-0000-000000000000/issuers",
            json={"issuers": ["R3"]},
        )
    assert r.status_code == 404


def test_api_set_host_issuers_invalid_body(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            json={"issuers": 123},
        )
    assert r.status_code == 400


def test_api_set_host_issuers_invalid_list_items(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            json={"issuers": ["R3", 42]},
        )
    assert r.status_code == 400


def test_api_set_host_issuers_bad_json(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.put(
            f"/api/hosts/{host_id}/issuers",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
    assert r.status_code == 400


def test_api_host_list_includes_expected_issuers(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / _db_name()
    init_schema(db)
    host_id = SqliteHostRepository(db).add("le.example.com", 443, expected_issuers="R3,R4")

    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    hosts = r.json()["hosts"]
    matching = [h for h in hosts if h["id"] == host_id]
    assert len(matching) == 1
    assert matching[0]["expected_issuers"] == "R3,R4"


def test_migration_adds_expected_issuers_column(tmp_path):
    """Migration 0022 adds expected_issuers column to hosts."""
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    from cert_watch.database import _connect
    with _connect(db) as conn:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    assert "expected_issuers" in cols

    # Verify it's usable
    repo = SqliteHostRepository(db)
    host_id = repo.add("test.example.com", 443)
    assert repo.get(host_id).expected_issuers == ""

    # Set and read back
    assert repo.set_expected_issuers(host_id, "R3,R4") is True
    assert repo.get_expected_issuers(host_id) == ["R3", "R4"]


def test_set_expected_issuers_missing_host(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    assert repo.set_expected_issuers("nonexistent-id", "R3") is False


def test_get_expected_issuers_missing_host(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    assert repo.get_expected_issuers("nonexistent-id") == []
