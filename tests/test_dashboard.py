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


def _reload(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import importlib

    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


def test_dashboard_filter_by_search(tmp_path, monkeypatch, leaf_pem_file, chain_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)
    store_uploaded(upload_certificate(chain_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?q=chain-leaf")
    assert r.status_code == 200
    assert "chain-leaf.example.com" in r.text
    # self-signed leaf should be filtered out (unless chain-leaf is also in its data)
    # The filter matches subject, issuer, hostname — so check both don't appear
    # unless they share text. They don't, so leaf.example.com should not appear.
    assert r.text.count("leaf.example.com") <= 1  # may appear in chain-leaf context


def test_dashboard_filter_by_urgency(tmp_path, monkeypatch, leaf_pem_file, expiring_soon_leaf):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry

    entry_a = upload_certificate(leaf_pem_file)
    assert isinstance(entry_a, UploadedEntry)
    store_uploaded(entry_a, db)

    entry_b = upload_certificate_from_bytes(expiring_soon_leaf.der, "expiring.der")
    store_uploaded(entry_b, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?urgency=red")
    assert r.status_code == 200
    # expiring_soon (5d) is red; self_signed (365d) is green
    assert "expiring.example.com" in r.text


def test_dashboard_filter_by_source(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?source=uploaded")
    assert r.status_code == 200
    assert "leaf.example.com" in r.text

    with TestClient(app_mod.app) as client:
        r = client.get("/?source=scanned")
    assert r.status_code == 200
    assert "leaf.example.com" not in r.text


def test_dashboard_filter_clear_link(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?q=leaf")
    assert r.status_code == 200
    assert "Clear" in r.text
    assert '/"' in r.text  # clear link points to /


def test_dashboard_chain_tree_view(tmp_path, monkeypatch, chain_pem_file):
    """FEAT-001: chain certs should render with tree indent."""
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(chain_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "tree-indent" in r.text
    assert "chain-leaf.example.com" in r.text
    # Chain rows should show the tree connector character (HTML entity)
    assert "&#x2514;" in r.text


def test_dashboard_dark_mode_toggle():
    """FEAT-012: dashboard should have a dark mode toggle button."""
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "theme-toggle" in r.text
    assert "data-theme" in r.text
    assert "localStorage" in r.text
    assert "cw-theme" in r.text


def test_dark_mode_css_has_custom_properties():
    """FEAT-012: style.css should define CSS custom properties for theming."""
    from pathlib import Path

    css_path = (
        Path(__file__).resolve().parent.parent
        / "src" / "cert_watch" / "static" / "style.css"
    )
    css = css_path.read_text()
    assert ":root" in css
    assert "[data-theme=\"dark\"]" in css
    assert "--bg:" in css
    assert "--text:" in css


def test_dashboard_pagination_empty():
    """FEAT-009: empty dashboard should not show pagination."""
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "pagination" not in r.text or "Page" not in r.text


def test_dashboard_notes_ui(tmp_path, monkeypatch, leaf_pem_file):
    """FEAT-013: dashboard should show notes UI for certificates."""
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "notes-textarea" in r.text
    assert "notes-save" in r.text
    assert "Add notes" in r.text


def test_dashboard_notes_form_posts(tmp_path, monkeypatch, leaf_pem_file):
    """FEAT-013: notes form should POST and persist."""
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry
    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/notes",
            data={"notes": "test note from UI"},
            follow_redirects=False,
        )
    assert r.status_code == 303

    # Verify the note persisted via the API
    with TestClient(app_mod.app) as client:
        r = client.get(f"/api/certificates/{cert_id}")
    assert r.status_code == 200
    assert r.json()["notes"] == "test note from UI"


def test_dashboard_pagination_with_data(tmp_path, monkeypatch):
    """FEAT-009: dashboard should paginate when > 25 certs."""
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"

    from datetime import UTC, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = __import__("datetime").datetime.now(UTC)
    for i in range(30):
        cert = Certificate(
            subject=f"cert{i}.example.com",
            issuer="Test CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=365 - i),
        )
        repo = SqliteCertificateRepository(
            db, source="uploaded",
        )
        repo.add(cert)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "Page 1 of" in r.text
    assert "Next" in r.text
    # Sorted ascending by days_remaining; cert29 (336d) appears before cert0 (365d)
    assert "cert29.example.com" in r.text

    with TestClient(app_mod.app) as client:
        r = client.get("/?page=2")
    assert r.status_code == 200
    assert "Page 2 of" in r.text
    assert "Prev" in r.text


def upload_certificate_from_bytes(der_bytes, filename):
    """Helper to upload cert bytes directly."""
    import tempfile
    from pathlib import Path

    from cert_watch.upload import upload_certificate

    with tempfile.NamedTemporaryFile(delete=False, suffix=".der") as tmp:
        tmp.write(der_bytes)
        tmp_path = Path(tmp.name)
    try:
        return upload_certificate(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
