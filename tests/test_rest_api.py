import importlib

from fastapi.testclient import TestClient


def _reload_app(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


def test_api_certificates_empty(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates")
    assert r.status_code == 200
    data = r.json()
    assert data["certificates"] == []
    assert "pagination" in data


def test_api_certificates_with_data(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates")
    assert r.status_code == 200
    certs = r.json()["certificates"]
    assert len(certs) >= 1


def test_api_certificate_by_id(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    from cert_watch.upload import UploadedEntry

    assert isinstance(entry, UploadedEntry)
    leaf_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{leaf_id}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == leaf_id
    assert "days_until_expiry" in data


def test_api_certificate_not_found(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/certificates/nonexistent")
    assert r.status_code == 404


def test_api_hosts_empty(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    data = r.json()
    assert data["hosts"] == []
    assert "pagination" in data


def test_api_hosts_with_data(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository

    SqliteHostRepository(db).add("api.example.com", 443)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    hosts = r.json()["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["hostname"] == "api.example.com"


def test_api_alerts_empty(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/api/alerts")
    assert r.status_code == 200
    data = r.json()
    assert data["alerts"] == []
    assert "pagination" in data
