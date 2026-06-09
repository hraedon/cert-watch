"""Tests for BC-020: host-level notes."""

from __future__ import annotations

from fastapi.testclient import TestClient

from cert_watch.database import SqliteHostRepository, init_schema


def test_host_notes_roundtrip(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("notes.example.com", 443, notes="pending renewal")
    host = repo.get(hid)
    assert host is not None
    assert host.notes == "pending renewal"

    repo.update_notes(hid, "renewed via acme")
    updated = repo.get(hid)
    assert updated is not None
    assert updated.notes == "renewed via acme"


def test_host_notes_update_returns_false_for_missing_host(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    assert repo.update_notes("nonexistent", "notes") is False


def test_api_update_host_notes(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("api.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/notes",
            json={"notes": "api host notes"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == hid
    assert data["notes"] == "api host notes"

    host = repo.get(hid)
    assert host is not None
    assert host.notes == "api host notes"


def test_api_update_host_notes_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.patch(
            "/api/hosts/00000000-0000-0000-0000-000000000000/notes",
            json={"notes": "notes"},
        )
    assert r.status_code == 404
    assert r.json()["error"] == "not found"


def test_api_update_host_notes_invalid_json(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("invalid-json.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/notes",
            data="not json",
        )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid JSON"


def test_api_update_host_notes_too_long(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("long.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/notes",
            json={"notes": "x" * 10001},
        )
    assert r.status_code == 400
    assert r.json()["error"] == "notes too long (max 10000)"


def test_form_update_host_notes(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("form.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/hosts/{hid}/notes",
            data={"notes": "form notes"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/"

    host = repo.get(hid)
    assert host is not None
    assert host.notes == "form notes"


def test_form_update_host_notes_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/00000000-0000-0000-0000-000000000000/notes",
            data={"notes": "notes"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error=host+not+found" in r.headers["location"]


def test_form_update_host_notes_too_long(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("longform.example.com", 443)

    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/hosts/{hid}/notes",
            data={"notes": "x" * 10001},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "too" in r.headers["location"] and "long" in r.headers["location"]


def test_api_hosts_list_includes_notes(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("with-notes.example.com", 443, notes="host note")

    with TestClient(app_mod.app) as client:
        r = client.get("/api/hosts")
    assert r.status_code == 200
    hosts = r.json()["hosts"]
    assert len(hosts) == 1
    assert hosts[0]["notes"] == "host note"


def test_api_hosts_owner_patch_includes_notes(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("owner.example.com", 443, notes="existing note")

    with TestClient(app_mod.app) as client:
        r = client.patch(
            f"/api/hosts/{hid}/owner",
            json={"owner_name": "ops"},
        )
    assert r.status_code == 200
    assert r.json()["notes"] == "existing note"


def test_hosts_csv_export_includes_notes(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    repo.add("csv.example.com", 443, notes="csv note")

    with TestClient(app_mod.app) as client:
        r = client.get("/api/export/hosts.csv")
    assert r.status_code == 200
    lines = r.text.strip().split("\n")
    assert "notes" in lines[0]
    assert "csv note" in lines[1]


def test_certificate_detail_shows_host_notes(
    tmp_path, reload_app, leaf_pem_file, monkeypatch
):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    from cert_watch.database import SqliteHostRepository
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    cert_id = store_uploaded(entry, db)

    # Associate the uploaded cert with a host that has notes
    repo = SqliteHostRepository(db)
    repo.add("leaf.example.com", 443, notes="host-level note")

    # Update the cert to link to the host
    import sqlite3
    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "UPDATE certificates SET hostname = ?, port = ? WHERE id = ?",
            ("leaf.example.com", 443, cert_id),
        )
        conn.commit()

    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "Host notes" in r.text
    assert "host-level note" in r.text


def test_add_host_accepts_notes(tmp_path, reload_app, monkeypatch):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    from cert_watch.scan import ScanError

    async def fake_scan(hostname, port=443, **kw):
        return ScanError(hostname=hostname, port=port, error_message="fail")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan)

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts",
            data={"hostname": "add-notes.example.com", "port": 443, "notes": "added note"},
            follow_redirects=False,
        )
    assert r.status_code == 303

    repo = SqliteHostRepository(db)
    host = repo.list_all()[0]
    assert host.hostname == "add-notes.example.com"
    assert host.notes == "added note"


def test_import_hosts_accepts_notes_csv(tmp_path, reload_app, monkeypatch):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    from cert_watch.scan import ScanError

    async def fake_scan(hostname, port=443, **kw):
        return ScanError(hostname=hostname, port=port, error_message="fail")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan)

    csv_content = "hostname,port,notes\nimport.example.com,443,imported note"
    import io

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", io.BytesIO(csv_content.encode("utf-8")), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303

    repo = SqliteHostRepository(db)
    host = repo.list_all()[0]
    assert host.hostname == "import.example.com"
    assert host.notes == "imported note"


def test_dashboard_host_row_shows_notes_indicator(
    tmp_path, reload_app, leaf_pem_file, monkeypatch
):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    from cert_watch.database import SqliteHostRepository
    from cert_watch.scan import ScannedEntry, store_scanned
    from cert_watch.upload import UploadedEntry, store_uploaded, upload_certificate

    entry = upload_certificate(leaf_pem_file)
    assert isinstance(entry, UploadedEntry)
    store_uploaded(entry, db)

    repo = SqliteHostRepository(db)
    repo.add("dash.example.com", 443, notes="dashboard note")

    # Simulate a scanned entry so the host is linked in the dashboard
    se = ScannedEntry(host="dash.example.com", port=443, leaf=entry.leaf, chain=[])
    store_scanned(se, db)

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "dashboard note" in r.text
