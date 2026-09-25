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
