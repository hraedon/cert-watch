import importlib

from fastapi.testclient import TestClient


def _reload_app(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


def test_metrics_empty(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_watch_cert_expiry_days" in text
    assert "cert_watch_hosts_tracked 0" in text
    assert "cert_watch_certificates_tracked 0" in text
    assert "cert_watch_certificates_expired 0" in text


def test_metrics_with_data(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload_app(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    from cert_watch.database import SqliteHostRepository

    SqliteHostRepository(db).add("metric.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_watch_cert_expiry_days{" in text
    assert "cert_watch_hosts_tracked 1" in text
    assert "cert_watch_certificates_tracked 1" in text
    assert "leaf.example.com" in text
