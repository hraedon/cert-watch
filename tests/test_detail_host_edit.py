"""Detail A's single Edit host surface preserves every existing capability."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.database.connection import _connect
from cert_watch.services.host_edit import HostEditUpdate, edit_host
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

FORM = {
    "owner_name": "Platform Operations",
    "owner_email": "platform@example.test",
    "owner_slack": "#platform-certs",
    "renewal_method": "cert-manager",
    "runbook_url": "https://runbooks.example.test/tls",
    "scan_interval_hours": "6",
    "threshold_days": "21",
    "renewal_status": "in_progress",
    "notes": "Rotate through the shared ingress controller.",
    "tags": "team-a, edge",
}


@pytest.fixture(autouse=True)
def _no_startup_scan(monkeypatch):
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)


def _host(db, *, tags="old-host-tag"):
    return SqliteHostRepository(db).add(
        "detail.example.test",
        443,
        tags=tags,
        owner_name="Old owner",
        owner_email="old@example.test",
        owner_slack="#old",
        renewal_method="manual",
        runbook_url="https://old.example.test/runbook",
        scan_interval_hours=24,
        threshold_days=14,
        notes="Old notes",
    )


def _assert_host_fields(host):
    assert host.owner_name == "Platform Operations"
    assert host.owner_email == "platform@example.test"
    assert host.owner_slack == "#platform-certs"
    assert host.renewal_method == "cert-manager"
    assert host.runbook_url == "https://runbooks.example.test/tls"
    assert host.scan_interval_hours == 6
    assert host.threshold_days == 21
    assert host.renewal_status == "in_progress"
    assert host.notes == "Rotate through the shared ingress controller."


@pytest.mark.parametrize("certificate_detail", [False, True])
def test_edit_host_form_round_trips_every_field(
    tmp_path, reload_app, self_signed_leaf, certificate_detail
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    resource_id = host_id
    if certificate_detail:
        resource_id = seed_scanned(
            db,
            "detail.example.test",
            443,
            parse_certificate(self_signed_leaf.der),
        )
        SqliteCertificateRepository(db).set_tags(resource_id, "old-cert-tag")

    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{resource_id}/edit", data=FORM, follow_redirects=False
        )
        assert response.status_code == 303
        assert response.headers["location"] == (
            f"/certificates/{resource_id}?host_saved=1"
        )
        page = client.get(response.headers["location"])

    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    _assert_host_fields(host)
    if certificate_detail:
        assert host.tags == "old-host-tag"
        assert SqliteCertificateRepository(db).get_tags(resource_id) == "team-a,edge"
    else:
        assert host.tags == "team-a,edge"
    assert 'data-testid="endpoint-settings-saved"' in page.text
    assert page.text.count('data-testid="edit-host"') == 1


def test_edit_host_json_peer_requires_and_returns_the_complete_shape(
    tmp_path, reload_app
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    body = {
        **FORM,
        "scan_interval_hours": 6,
        "threshold_days": 21,
    }
    with TestClient(reload_app().app) as client:
        incomplete = client.put(
            f"/api/hosts/{host_id}", json={"owner_name": "partial"}
        )
        response = client.put(f"/api/hosts/{host_id}", json=body)

    assert incomplete.status_code == 400
    assert "requires exactly" in incomplete.json()["error"]
    assert response.status_code == 200
    assert response.json() == {
        "id": host_id,
        "owner_name": "Platform Operations",
        "owner_email": "platform@example.test",
        "owner_slack": "#platform-certs",
        "renewal_method": "cert-manager",
        "runbook_url": "https://runbooks.example.test/tls",
        "scan_interval_hours": 6,
        "threshold_days": 21,
        "renewal_status": "in_progress",
        "notes": "Rotate through the shared ingress controller.",
        "tags": ["team-a", "edge"],
        "tags_apply_to": "host",
    }


def test_invalid_combined_edit_is_atomic(tmp_path, reload_app):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/edit",
            data={**FORM, "owner_email": "not-an-address"},
            follow_redirects=False,
        )
        page = client.get(response.headers["location"])
    assert response.status_code == 303
    assert parse_qs(urlsplit(response.headers["location"]).query)["edit"] == ["1"]
    assert SqliteHostRepository(db).get(host_id) == before
    assert 'data-testid="endpoint-settings-error"' in page.text


def test_edit_host_form_enforces_csrf(tmp_path, reload_app, csrf_strict):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/edit", data=FORM, follow_redirects=False
        )
    assert response.status_code == 303
    assert "csrf" in response.headers["location"].lower()
    assert SqliteHostRepository(db).get(host_id) == before


def test_combined_edit_refuses_a_superseded_certificate_id(
    tmp_path, reload_app, self_signed_leaf
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    old_id = seed_scanned(
        db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der)
    )
    new_id = seed_scanned(
        db,
        "detail.example.test",
        443,
        parse_certificate(_make_cert("detail.example.test", days_valid=90).der),
    )
    before = SqliteHostRepository(db).get(host_id)
    api_body = {**FORM, "scan_interval_hours": 6, "threshold_days": 21}
    with TestClient(reload_app().app) as client:
        form = client.post(
            f"/hosts/{old_id}/edit", data=FORM, follow_redirects=False
        )
        api = client.put(f"/api/hosts/{old_id}", json=api_body)
    assert urlsplit(form.headers["location"]).path == f"/certificates/{new_id}"
    assert "renewed" in parse_qs(urlsplit(form.headers["location"]).query)["error"][0]
    assert api.status_code == 409
    assert api.json()["current_cert_id"] == new_id
    assert SqliteHostRepository(db).get(host_id) == before


def test_combined_edit_rechecks_scope_inside_its_transaction(tmp_path, monkeypatch):
    import cert_watch.services.host_edit as service

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-a")
    before = SqliteHostRepository(db).get(host_id)
    auth = AuthContext.from_tier(
        "team-a-operator",
        tier="viewer",
        scope_tag="team-a,team-b",
        tag_tiers={"team-a": "operator", "team-b": "viewer"},
    )
    real_begin = service.begin_immediate

    def move_target_then_begin(conn):
        with _connect(db) as other:
            other.execute("UPDATE hosts SET tags = 'team-b' WHERE id = ?", (host_id,))
            other.commit()
        real_begin(conn)

    monkeypatch.setattr(service, "begin_immediate", move_target_then_begin)
    with pytest.raises(PermissionError, match="read-only"):
        edit_host(
            db,
            host_id,
            HostEditUpdate(**{**FORM, "tags": "team-a"}),
            auth=auth,
            actor="team-a-operator",
            source_ip=None,
        )
    after = SqliteHostRepository(db).get(host_id)
    assert after == replace(before, tags="team-b")
