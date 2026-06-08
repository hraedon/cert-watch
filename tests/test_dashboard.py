from fastapi.testclient import TestClient

from cert_watch.app import app
from cert_watch.upload import store_uploaded, upload_certificate


def test_dashboard_empty_state():
    with TestClient(app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "No matching certificates" in r.text


def test_dashboard_shows_uploaded_cert(reload_app, leaf_pem_file):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        # Use upload via HTTP to exercise the route.
        with open(leaf_pem_file, "rb") as f:
            r = client.post("/upload", files={"file": ("leaf.pem", f, "application/x-pem-file")})
        assert r.status_code in (200, 303)
        r = client.get("/")
    assert r.status_code == 200
    assert "leaf.example.com" in r.text


def test_dashboard_sorted_by_urgency(reload_app, tmp_path, leaf_pem_file, chain_pem_file):
    app_mod = reload_app()
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


def test_readyz(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/readyz")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] in ("ok", "degraded")
    assert "checks" in data
    assert "database" in data["checks"]
    assert "scheduler" in data["checks"]


def _reload(reload_app):
    return reload_app()


def test_dashboard_filter_by_search(reload_app, tmp_path, leaf_pem_file, chain_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)
    store_uploaded(upload_certificate(chain_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?q=chain-leaf")
    assert r.status_code == 200
    assert "chain-leaf.example.com" in r.text
    # The self-signed leaf should be filtered out; only chain-leaf should render.
    import re
    # Count data-row occurrences (each cert row has a cw-row-link class)
    groups = re.findall(r'cw-row-link', r.text)
    assert len(groups) == 1


def test_dashboard_filter_by_urgency(reload_app, tmp_path, leaf_pem_file, expiring_soon_leaf):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.upload import UploadedEntry

    entry_a = upload_certificate(leaf_pem_file)
    assert isinstance(entry_a, UploadedEntry)
    store_uploaded(entry_a, db)

    entry_b = upload_certificate_from_bytes(expiring_soon_leaf.der, "expiring.der")
    store_uploaded(entry_b, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?urgency=critical")
    assert r.status_code == 200
    # expiring_soon (5d) is critical (< 7); self_signed (365d) is healthy
    assert "expiring.example.com" in r.text


def test_dashboard_filter_by_source(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
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


def test_dashboard_filter_clear_link(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    store_uploaded(upload_certificate(leaf_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get("/?q=leaf")
    assert r.status_code == 200
    # The search filter is applied; the q value should be in the input
    assert 'value="leaf"' in r.text


def test_dashboard_chain_tree_view(reload_app, tmp_path, chain_pem_file):
    """FEAT-001: chain certs should be visible on the detail page."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(chain_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "chain-leaf.example.com" in r.text
    # Chain is shown on the detail page
    assert "Certificate chain" in r.text


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
    """FEAT-012: tokens.css should define CSS custom properties for theming."""
    from pathlib import Path

    css_path = (
        Path(__file__).resolve().parent.parent
        / "src" / "cert_watch" / "static" / "css" / "tokens.css"
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


def test_dashboard_notes_ui(reload_app, tmp_path, leaf_pem_file):
    """FEAT-013: detail page should show notes UI for certificates."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)

    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "notes-textarea" in r.text
    assert "Notes" in r.text


def test_dashboard_notes_form_posts(reload_app, tmp_path, leaf_pem_file):
    """FEAT-013: notes form should POST and persist."""
    app_mod = reload_app()
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


def test_dashboard_pagination_with_data(reload_app, tmp_path):
    """FEAT-009: dashboard should paginate when > 25 certs."""
    app_mod = reload_app()
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


def test_group_entries_by_fingerprint():
    """BC-033: scanned entries sharing a fingerprint are grouped."""
    from cert_watch.database.queries import group_entries_by_fingerprint

    entries = [
        {
            "id": "a",
            "kind": "scanned",
            "fingerprint_sha256": "fp_shared",
            "host": "host1:443",
            "name": "host1:443",
            "subject": "*.example.com",
            "issuer": "Test CA",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "days_remaining": 200,
            "urgency": "healthy",
            "leaf_urgency": "healthy",
            "chain": [],
            "chain_valid": True,
            "chain_status": "public",
            "replaces_cert_id": None,
            "notes": "",
            "san_dns_names": ["*.example.com"],
            "host_id": "h1",
            "last_scanned_at": None,
            "scan_status": None,
            "scan_error": None,
            "added_at": None,
            "owner_name": "",
            "owner_email": "",
            "owner_slack": "",
            "renewal_status": "pending",
        },
        {
            "id": "b",
            "kind": "scanned",
            "fingerprint_sha256": "fp_shared",
            "host": "host2:443",
            "name": "host2:443",
            "subject": "*.example.com",
            "issuer": "Test CA",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "days_remaining": 200,
            "urgency": "healthy",
            "leaf_urgency": "healthy",
            "chain": [],
            "chain_valid": True,
            "chain_status": "public",
            "replaces_cert_id": None,
            "notes": "",
            "san_dns_names": ["*.example.com"],
            "host_id": "h2",
            "last_scanned_at": None,
            "scan_status": None,
            "scan_error": None,
            "added_at": None,
            "owner_name": "",
            "owner_email": "",
            "owner_slack": "",
            "renewal_status": "pending",
        },
        {
            "id": "c",
            "kind": "scanned",
            "fingerprint_sha256": "fp_unique",
            "host": "host3:443",
            "name": "host3:443",
            "subject": "unique.example.com",
            "issuer": "Test CA",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "days_remaining": 300,
            "urgency": "healthy",
            "leaf_urgency": "healthy",
            "chain": [],
            "chain_valid": True,
            "chain_status": "public",
            "replaces_cert_id": None,
            "notes": "",
            "san_dns_names": [],
            "host_id": "h3",
            "last_scanned_at": None,
            "scan_status": None,
            "scan_error": None,
            "added_at": None,
            "owner_name": "",
            "owner_email": "",
            "owner_slack": "",
            "renewal_status": "pending",
        },
        {
            "id": "d",
            "kind": "uploaded",
            "fingerprint_sha256": "fp_upload",
            "host": "(uploaded:file.pem)",
            "name": "upload.example.com",
            "subject": "upload.example.com",
            "issuer": "Other CA",
            "not_before": "2026-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "days_remaining": 365,
            "urgency": "healthy",
            "leaf_urgency": "healthy",
            "chain": [],
            "chain_valid": None,
            "chain_status": None,
            "replaces_cert_id": None,
            "notes": "",
            "san_dns_names": [],
            "source": "uploaded",
        },
    ]
    result = group_entries_by_fingerprint(entries)
    assert len(result) == 3
    grouped_entry = [e for e in result if e["kind"] == "grouped"][0]
    assert grouped_entry["host_count"] == 2
    assert grouped_entry["healthy_count"] == 2
    assert len(grouped_entry["hosts"]) == 2
    assert grouped_entry["subject"] == "*.example.com"
    ungrouped_scanned = [e for e in result if e["kind"] == "scanned"]
    assert len(ungrouped_scanned) == 1
    assert ungrouped_scanned[0]["host"] == "host3:443"
    uploaded = [e for e in result if e["kind"] == "uploaded"]
    assert len(uploaded) == 1


def test_group_entries_mixed_urgency():
    """BC-033: group urgency reflects worst host."""
    from cert_watch.database.queries import group_entries_by_fingerprint

    base = {
        "kind": "scanned",
        "fingerprint_sha256": "fp_mixed",
        "subject": "*.example.com",
        "issuer": "Test CA",
        "not_before": "2026-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "chain": [],
        "chain_valid": True,
        "chain_status": "public",
        "replaces_cert_id": None,
        "notes": "",
        "san_dns_names": [],
        "host_id": "h1",
        "last_scanned_at": None,
        "scan_status": None,
        "scan_error": None,
        "added_at": None,
        "owner_name": "",
        "owner_email": "",
        "owner_slack": "",
        "renewal_status": "pending",
    }
    entries = [
        {
            **base, "id": "a", "host": "h1:443", "name": "h1:443",
            "days_remaining": 200, "urgency": "healthy",
            "leaf_urgency": "healthy",
        },
        {
            **base, "id": "b", "host": "h2:443", "name": "h2:443",
            "days_remaining": 3, "urgency": "critical",
            "leaf_urgency": "critical",
        },
    ]
    result = group_entries_by_fingerprint(entries)
    assert len(result) == 1
    assert result[0]["kind"] == "grouped"
    assert result[0]["urgency"] == "critical"
    assert result[0]["healthy_count"] == 1
    assert result[0]["host_count"] == 2


def test_dashboard_grouped_by_fingerprint(reload_app, tmp_path):
    """BC-033: dashboard groups hosts with same cert fingerprint."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("host1.example.com", 443)
    hosts.add("host2.example.com", 443)
    hosts.add("host3.example.com", 443)

    now = datetime.now(UTC)
    shared_cert = Certificate(
        subject="*.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["*.example.com"],
        fingerprint_sha256="a" * 64,
    )
    unique_cert = Certificate(
        subject="unique.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=200),
        san_dns_names=["unique.example.com"],
        fingerprint_sha256="b" * 64,
    )

    replace_scanned(db, "host1.example.com", 443, shared_cert, [], True)
    replace_scanned(db, "host2.example.com", 443, shared_cert, [], True)
    replace_scanned(db, "host3.example.com", 443, unique_cert, [], True)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "2 hosts" in r.text
    assert "cw-group-header" in r.text
    assert "group-hosts-" in r.text
    assert "host3.example.com" in r.text


def test_dashboard_grouped_search_matches_host(reload_app, tmp_path):
    """BC-033: search matches hosts inside a group."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("alpha.example.com", 443)
    hosts.add("beta.example.com", 443)

    now = datetime.now(UTC)
    cert = Certificate(
        subject="*.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["*.example.com"],
        fingerprint_sha256="a" * 64,
    )

    replace_scanned(db, "alpha.example.com", 443, cert, [], True)
    replace_scanned(db, "beta.example.com", 443, cert, [], True)

    with TestClient(app_mod.app) as client:
        r = client.get("/?q=beta")
    assert r.status_code == 200
    assert "2 hosts" in r.text
    assert "*.example.com" in r.text


def test_dashboard_grouped_disabled(reload_app, tmp_path):
    """BC-033: grouped=0 shows individual rows."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("host1.example.com", 443)
    hosts.add("host2.example.com", 443)

    now = datetime.now(UTC)
    cert = Certificate(
        subject="*.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["*.example.com"],
        fingerprint_sha256="a" * 64,
    )

    replace_scanned(db, "host1.example.com", 443, cert, [], True)
    replace_scanned(db, "host2.example.com", 443, cert, [], True)

    with TestClient(app_mod.app) as client:
        r = client.get("/?grouped=0")
    assert r.status_code == 200
    assert "2 hosts" not in r.text
    assert "cw-group-header" not in r.text
    assert "host1.example.com" in r.text
    assert "host2.example.com" in r.text
