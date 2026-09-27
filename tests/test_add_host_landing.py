"""#113 item 5: adding a host lands on the new host, with a confirmation.

It used to redirect Home with no message and no link to what was added.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.scan import ScanError, ScannedEntry


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    """Keep the lifespan's real scheduler from scanning the registered hosts
    while a test runs (#115 review: a startup scan raced such assertions)."""
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _no_dns(monkeypatch):
    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *_a, **_kw: (None, "192.0.2.10"),
    )


def _scan_ok(monkeypatch, leaf_der):
    async def fake(hostname, port=443, **_kw):
        return ScannedEntry(host=hostname, port=port, leaf=parse_certificate(leaf_der), chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake)


def _scan_fails(monkeypatch):
    async def fake(hostname, port=443, **_kw):
        return ScanError(hostname=hostname, port=port, error_message="Connection refused")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake)


def test_add_host_lands_on_the_new_certificate(
    tmp_path, reload_app, monkeypatch, self_signed_leaf
):
    _no_dns(monkeypatch)
    _scan_ok(monkeypatch, self_signed_leaf.der)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts", data={"hostname": "new-api.example.test"}, follow_redirects=False
        )
        assert r.status_code == 303
        host = SqliteHostRepository(db).list_all()[0]
        assert r.headers["location"] == f"/certificates/{host.id}?added=1"
        page = client.get(r.headers["location"])
    assert page.status_code == 200
    # Resolved from the host id to the certificate the first scan stored.
    assert "/certificates/" in str(page.url) and host.id not in str(page.url)
    assert 'data-testid="host-added-note"' in page.text
    assert "Host added and scanned." in page.text


def test_add_host_whose_first_scan_fails_says_so(tmp_path, reload_app, monkeypatch):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts", data={"hostname": "down.example.test"}, follow_redirects=True
        )
    host = SqliteHostRepository(db).list_all()[0]
    assert r.status_code == 200
    assert r.url.path == f"/certificates/{host.id}"
    assert "Host added. Its first scan failed" in r.text
    assert 'data-testid="scan-failure-panel"' in r.text


def test_add_host_on_common_ports_lands_on_browse_filtered_to_it(
    tmp_path, reload_app, monkeypatch
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts",
            data={"hostname": "multi.example.test", "common_ports": "true"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        target = urlsplit(r.headers["location"])
        assert target.path == "/browse"
        query = parse_qs(target.query)
        assert query["q"] == ["multi.example.test"]
        page = client.get(r.headers["location"]).text
    assert "Added 8 endpoints for multi.example.test" in page


def test_add_host_validation_error_still_bounces_home(tmp_path, reload_app):
    init_schema(tmp_path / "cert-watch.sqlite3")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/hosts", data={"hostname": "bad host!"}, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/?error=")


def test_add_host_stores_creation_owner_and_renewal_fields(
    tmp_path, reload_app, monkeypatch,
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        response = client.post(
            "/hosts",
            data={
                "hostname": "owned.example.test",
                "owner_name": "Platform Team",
                "owner_email": "platform@example.test",
                "renewal_method": "cert-manager",
            },
            follow_redirects=False,
        )
    assert response.status_code == 303
    host = SqliteHostRepository(db).list_all()[0]
    assert (host.owner_name, host.owner_email, host.renewal_method) == (
        "Platform Team",
        "platform@example.test",
        "cert-manager",
    )


def test_add_host_rejects_invalid_creation_ownership_before_insert(
    tmp_path, reload_app, monkeypatch,
):
    _no_dns(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    with TestClient(app_mod.app) as client:
        response = client.post(
            "/hosts",
            data={
                "hostname": "bad-owner.example.test",
                "owner_email": "not-an-address",
                "renewal_method": "hand-wavy",
            },
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert SqliteHostRepository(db).list_all() == []


def test_csv_import_accepts_creation_owner_and_renewal_columns(
    tmp_path, reload_app, monkeypatch,
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    content = (
        b"hostname,owner_name,owner_email,renewal_method\n"
        b"csv-owned.example.test,Network Team,network@example.test,manual\n"
    )
    with TestClient(app_mod.app) as client:
        response = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", content, "text/csv")},
            follow_redirects=False,
        )
    assert response.status_code == 303
    host = SqliteHostRepository(db).list_all()[0]
    assert (host.owner_name, host.owner_email, host.renewal_method) == (
        "Network Team",
        "network@example.test",
        "manual",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("owner_name", "x" * 201),
        ("owner_email", "x" * 255),
        ("owner_email", "not-an-address"),
        ("owner_slack", "x" * 101),
        ("renewal_method", "x" * 101),
        ("renewal_method", "ACME"),
        ("runbook_url", "https://example.test/" + "x" * 2030),
        ("runbook_url", "javascript:alert(1)"),
    ],
)
def test_ownership_limits_match_editor_html_json_and_csv(
    tmp_path,
    reload_app,
    monkeypatch,
    self_signed_leaf,
    field,
    value,
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    repo = SqliteHostRepository(db)
    existing_id = repo.add("existing.example.test")
    from tests._helpers import seed_scanned

    cert_id = seed_scanned(
        db,
        "existing.example.test",
        443,
        parse_certificate(self_signed_leaf.der),
    )
    complete_edit = {
        "owner_name": "",
        "owner_email": "",
        "owner_slack": "",
        "renewal_method": "",
        "runbook_url": "",
        "scan_interval_hours": "",
        "threshold_days": "",
        "renewal_status": "pending",
        "notes": "",
        "tags": "",
        field: value,
    }
    with TestClient(app_mod.app) as client:
        editor = client.post(
            f"/hosts/{existing_id}/owner",
            data={field: value},
            follow_redirects=False,
        )
        certificate_editor = client.post(
            f"/certificates/{cert_id}/owner",
            data={field: value},
            follow_redirects=False,
        )
        api_editor = client.patch(
            f"/api/hosts/{existing_id}/owner",
            json={field: value},
        )
        api_certificate_editor = client.patch(
            f"/api/hosts/{cert_id}/owner",
            json={field: value},
        )
        combined_html = client.post(
            f"/hosts/{existing_id}/edit",
            data=complete_edit,
            follow_redirects=False,
        )
        combined_json = client.put(
            f"/api/hosts/{existing_id}",
            json={
                **complete_edit,
                "scan_interval_hours": None,
                "threshold_days": None,
            },
        )
        html = client.post(
            "/hosts",
            data={"hostname": "html-limit.example.test", field: value},
            follow_redirects=False,
        )
        api = client.post(
            "/api/hosts",
            json={"hostname": "api-limit.example.test", field: value},
        )
        csv_body = f"hostname,{field}\ncsv-limit.example.test,{value}\n"
        csv_response = client.post(
            "/api/hosts/import",
            files={"file": ("hosts.csv", csv_body, "text/csv")},
        )
    assert "error=" in editor.headers["location"]
    assert "error=" in certificate_editor.headers["location"]
    assert api_editor.status_code == 400
    assert api_certificate_editor.status_code == 400
    assert combined_html.status_code == 422
    assert combined_json.status_code == 400
    assert "error=" in html.headers["location"]
    assert api.status_code == 400
    assert csv_response.status_code == 400
    assert {host.hostname for host in repo.list_all()} == {"existing.example.test"}


def test_ownership_whitespace_normalizes_on_every_write_path(
    tmp_path,
    reload_app,
    monkeypatch,
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    repo = SqliteHostRepository(db)
    existing_id = repo.add("edited.example.test")
    combined_id = repo.add("combined.example.test")
    padded = {
        "owner_name": "  Platform  ",
        "owner_email": "  ops@example.test  ",
        "owner_slack": "  #certs  ",
        "renewal_method": "  acme  ",
        "runbook_url": "  https://runbooks.example.test/certs  ",
    }
    with TestClient(app_mod.app) as client:
        assert (
            client.post(
                f"/hosts/{existing_id}/owner",
                data=padded,
                follow_redirects=False,
            ).status_code
            == 303
        )
        complete_edit = {
            **padded,
            "scan_interval_hours": "",
            "threshold_days": "",
            "renewal_status": "pending",
            "notes": "",
            "tags": "",
        }
        assert (
            client.post(
                f"/hosts/{combined_id}/edit",
                data=complete_edit,
                follow_redirects=False,
            ).status_code
            == 303
        )
        assert (
            client.put(
                f"/api/hosts/{combined_id}",
                json={
                    **complete_edit,
                    "scan_interval_hours": None,
                    "threshold_days": None,
                },
            ).status_code
            == 200
        )
        assert (
            client.post(
                "/hosts",
                data={"hostname": "html-normalized.example.test", **padded},
                follow_redirects=False,
            ).status_code
            == 303
        )
        assert (
            client.post(
                "/api/hosts",
                json={"hostname": "api-normalized.example.test", **padded},
            ).status_code
            == 201
        )
        csv_body = (
            "hostname,owner_name,owner_email,owner_slack,renewal_method,runbook_url\n"
            "csv-normalized.example.test,  Platform  ,  ops@example.test  ,"
            "  #certs  ,  acme  ,  https://runbooks.example.test/certs  \n"
        )
        assert (
            client.post(
                "/api/hosts/import",
                files={"file": ("hosts.csv", csv_body, "text/csv")},
            ).status_code
            == 201
        )
    for host in repo.list_all():
        assert (
            host.owner_name,
            host.owner_email,
            host.owner_slack,
            host.renewal_method,
            host.runbook_url,
        ) == (
            "Platform",
            "ops@example.test",
            "#certs",
            "acme",
            "https://runbooks.example.test/certs",
        )


def test_idempotent_add_reports_unapplied_owner_fields(
    tmp_path,
    reload_app,
    monkeypatch,
):
    _no_dns(monkeypatch)
    _scan_fails(monkeypatch)
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    repo = SqliteHostRepository(db)
    host_id = repo.add("existing-add.example.test", owner_name="Original owner")
    with TestClient(app_mod.app) as client:
        html = client.post(
            "/hosts",
            data={"hostname": "existing-add.example.test", "owner_name": "Replacement"},
            follow_redirects=False,
        )
        api = client.post(
            "/api/hosts",
            json={"hostname": "existing-add.example.test", "owner_name": "Replacement"},
        )
    assert html.status_code == 303
    assert "warning=" in html.headers["location"]
    assert "not%20applied" in html.headers["location"]
    assert api.status_code == 201
    assert "not applied" in api.json()["notice"]
    assert repo.get(host_id).owner_name == "Original owner"
