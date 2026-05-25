from fastapi.testclient import TestClient

from cert_watch.app import app
from cert_watch.upload import store_uploaded, upload_certificate


def test_dashboard_empty_state():
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "No certificates tracked yet" in r.text


def test_dashboard_shows_uploaded_cert(leaf_pem_file, monkeypatch, tmp_path):
    # Ensure app sees this tmp data dir.
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import importlib

    from cert_watch import config as _config

    importlib.reload(_config)
    # Re-import app module so it picks up the new settings.
    from cert_watch import app as app_mod

    importlib.reload(app_mod)

    with TestClient(app_mod.app) as client:
        # Use upload via HTTP to exercise the route.
        with open(leaf_pem_file, "rb") as f:
            r = client.post("/upload", files={"file": ("leaf.pem", f, "application/x-pem-file")})
        assert r.status_code in (200, 303)
        r = client.get("/")
    assert r.status_code == 200
    assert "leaf.example.com" in r.text


def test_dashboard_sorted_by_urgency(tmp_path, monkeypatch, leaf_pem_file, chain_pem_file):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import importlib

    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)

    db = tmp_path / "cert-watch.sqlite3"
    # Upload both.
    entry_a = upload_certificate(leaf_pem_file)
    entry_b = upload_certificate(chain_pem_file)
    store_uploaded(entry_a, db)
    store_uploaded(entry_b, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    # chain leaf is 90d, self_signed leaf is 365d — chain leaf should appear first.
    body = r.text
    idx_chain = body.find("chain-leaf.example.com")
    idx_leaf = body.find("leaf.example.com")
    # If both appear, chain-leaf row should come earlier in the document.
    assert idx_chain != -1
    assert idx_leaf != -1
    assert idx_chain < idx_leaf


def test_healthz():
    with TestClient(app) as client:
        r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
