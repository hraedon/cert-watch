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
        response = client.post(f"/hosts/{resource_id}/edit", data=FORM, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == (f"/certificates/{resource_id}?host_saved=1")
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


def test_edit_host_json_peer_requires_and_returns_the_complete_shape(tmp_path, reload_app):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    body = {
        **FORM,
        "scan_interval_hours": 6,
        "threshold_days": 21,
    }
    with TestClient(reload_app().app) as client:
        incomplete = client.put(f"/api/hosts/{host_id}", json={"owner_name": "partial"})
        extra = client.put(f"/api/hosts/{host_id}", json={**body, "expected_issuers": "CN=Other"})
        response = client.put(f"/api/hosts/{host_id}", json=body)

    assert incomplete.status_code == 400
    assert "requires exactly" in incomplete.json()["error"]
    assert extra.status_code == 400
    assert "requires exactly" in extra.json()["error"]
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


def test_invalid_combined_edit_is_atomic(tmp_path, reload_app, self_signed_leaf):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    seed_scanned(
        db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der)
    )
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/edit",
            data={
                **FORM,
                "owner_name": "Unsaved owner",
                "owner_email": "not-an-address",
                "notes": "Unsaved note",
            },
            follow_redirects=False,
        )
    assert response.status_code == 422
    assert SqliteHostRepository(db).get(host_id) == before
    assert 'data-testid="endpoint-settings-error"' in response.text
    assert response.text.count("invalid email") == 1
    assert 'aria-describedby="host-owner-email-error"' in response.text
    assert 'id="host-owner-email-error"' in response.text
    assert 'data-replace-url="/certificates/' in response.text
    assert 'value="Unsaved owner"' in response.text
    assert "Unsaved note" in response.text
    assert 'value="Old owner"' not in response.text


def test_combined_edit_rejects_an_unsafe_runbook_without_writing(tmp_path, reload_app):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/edit",
            data={**FORM, "runbook_url": "javascript:alert(1)"},
        )
    assert response.status_code == 422
    assert "http(s) URL" in response.text
    assert 'aria-describedby="host-runbook-url-error"' in response.text
    assert 'id="host-runbook-url-error"' in response.text
    assert SqliteHostRepository(db).get(host_id) == before


def test_edit_host_form_rate_limit_prevents_the_write(tmp_path, reload_app, monkeypatch):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    monkeypatch.setattr("cert_watch.routes.hosts.check_rate_limit", lambda *_a: False)
    with TestClient(reload_app().app) as client:
        response = client.post(f"/hosts/{host_id}/edit", data=FORM, follow_redirects=False)
    assert response.status_code == 303
    assert "rate%20limited" in response.headers["location"]
    assert SqliteHostRepository(db).get(host_id) == before


def test_edit_host_form_enforces_csrf(tmp_path, reload_app, csrf_strict):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(f"/hosts/{host_id}/edit", data=FORM, follow_redirects=False)
    assert response.status_code == 303
    assert "csrf" in response.headers["location"].lower()
    assert SqliteHostRepository(db).get(host_id) == before


def test_combined_edit_refuses_a_superseded_certificate_id(tmp_path, reload_app, self_signed_leaf):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    old_id = seed_scanned(db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der))
    new_id = seed_scanned(
        db,
        "detail.example.test",
        443,
        parse_certificate(_make_cert("detail.example.test", days_valid=90).der),
    )
    before = SqliteHostRepository(db).get(host_id)
    api_body = {**FORM, "scan_interval_hours": 6, "threshold_days": 21}
    with TestClient(reload_app().app) as client:
        form = client.post(f"/hosts/{old_id}/edit", data=FORM, follow_redirects=False)
        api = client.put(f"/api/hosts/{old_id}", json=api_body)
    assert urlsplit(form.headers["location"]).path == f"/certificates/{new_id}"
    assert "renewed" in parse_qs(urlsplit(form.headers["location"]).query)["error"][0]
    assert api.status_code == 409
    assert api.json()["current_cert_id"] == new_id
    assert SqliteHostRepository(db).get(host_id) == before


def test_superseded_precheck_runs_before_deferred_input(tmp_path, self_signed_leaf):
    from cert_watch.services.certificate_identity import CertificateSupersededError

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _host(db)
    old_id = seed_scanned(db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der))
    seed_scanned(
        db,
        "detail.example.test",
        443,
        parse_certificate(_make_cert("detail.example.test", days_valid=90).der),
    )
    parsed = False

    def deferred():
        nonlocal parsed
        parsed = True
        return HostEditUpdate(**FORM)

    with pytest.raises(CertificateSupersededError):
        edit_host(
            db,
            old_id,
            deferred,
            auth=AuthContext.system(),
            actor="system",
            source_ip=None,
        )
    assert parsed is False


def test_explicit_superseded_precheck_precedes_deferred_input(
    tmp_path, self_signed_leaf, monkeypatch
):
    import cert_watch.services.host_edit as service

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _host(db)
    cert_id = seed_scanned(
        db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der)
    )
    parsed = False

    def deferred():
        nonlocal parsed
        parsed = True
        return HostEditUpdate(**FORM)

    def refuse(*_args, **_kwargs):
        raise RuntimeError("explicit superseded precheck")

    monkeypatch.setattr(service, "refuse_if_superseded", refuse)
    with pytest.raises(RuntimeError, match="explicit superseded precheck"):
        edit_host(
            db,
            cert_id,
            deferred,
            auth=AuthContext.system(),
            actor="system",
            source_ip=None,
        )
    assert parsed is False


def test_combined_edit_refuses_supersession_created_before_transaction(
    tmp_path, self_signed_leaf, monkeypatch
):
    import cert_watch.services.host_edit as service
    from cert_watch.services.certificate_identity import CertificateSupersededError

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    old_id = seed_scanned(db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der))
    before = SqliteHostRepository(db).get(host_id)
    real_begin = service.begin_immediate

    def renew_then_begin(conn):
        seed_scanned(
            db,
            "detail.example.test",
            443,
            parse_certificate(_make_cert("detail.example.test", days_valid=91).der),
        )
        real_begin(conn)

    monkeypatch.setattr(service, "begin_immediate", renew_then_begin)
    with pytest.raises(CertificateSupersededError):
        edit_host(
            db,
            old_id,
            HostEditUpdate(**FORM),
            auth=AuthContext.system(),
            actor="system",
            source_ip=None,
        )
    assert SqliteHostRepository(db).get(host_id) == before


def test_failed_certificate_tag_write_rolls_back_host_fields(
    tmp_path, self_signed_leaf, monkeypatch
):
    import cert_watch.services.host_edit as service

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    cert_id = seed_scanned(db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der))
    before = SqliteHostRepository(db).get(host_id)
    monkeypatch.setattr(service, "persist_certificate_tags", lambda *_a: False)
    with pytest.raises(LookupError, match="certificate not found"):
        edit_host(
            db,
            cert_id,
            HostEditUpdate(**FORM),
            auth=AuthContext.system(),
            actor="system",
            source_ip=None,
        )
    assert SqliteHostRepository(db).get(host_id) == before
    assert SqliteCertificateRepository(db).get_tags(cert_id) == ""


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


def test_certificate_addressed_edit_requires_host_and_certificate_write_scope(
    tmp_path, self_signed_leaf
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-b")
    cert_id = seed_scanned(db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der))
    SqliteCertificateRepository(db).set_tags(cert_id, "team-a")
    before = SqliteHostRepository(db).get(host_id)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        page = client.get(f"/certificates/{cert_id}")
        form = client.post(f"/hosts/{cert_id}/edit", data=FORM, follow_redirects=False)
        api = client.put(
            f"/api/hosts/{cert_id}",
            json={**FORM, "scan_interval_hours": 6, "threshold_days": 21},
        )
    assert page.status_code == 200
    assert 'data-testid="edit-host"' not in page.text
    assert form.status_code == 303
    assert "outside%20your%20team%20scope" in form.headers["location"]
    assert (api.status_code, api.json()) == (
        403,
        {"error": "operation not permitted outside your team scope"},
    )
    assert SqliteHostRepository(db).get(host_id) == before


@pytest.mark.parametrize("tags", ["team-a,team-b", "team-b", ""])
def test_mixed_tier_combined_edit_cannot_add_read_only_tags_or_leave_write_scope(tmp_path, tags):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-a")
    auth = AuthContext.from_tier(
        "mixed",
        tier="viewer",
        scope_tag="team-a,team-b",
        tag_tiers={"team-a": "operator", "team-b": "viewer"},
    )
    before = SqliteHostRepository(db).get(host_id)
    with pytest.raises(PermissionError):
        edit_host(
            db,
            host_id,
            HostEditUpdate(**{**FORM, "tags": tags}),
            auth=auth,
            actor="mixed",
            source_ip=None,
        )
    assert SqliteHostRepository(db).get(host_id) == before
