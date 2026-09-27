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


def _edit_values(adapter, **changes):
    values = {
        **FORM,
        "scan_interval_hours": 6 if adapter == "json" else "6",
        "threshold_days": 21 if adapter == "json" else "21",
        **changes,
    }
    return values


def _submit_edit(client, resource_id, adapter, values):
    if adapter == "html":
        return client.post(
            f"/hosts/{resource_id}/edit", data=values, follow_redirects=False
        )
    return client.put(f"/api/hosts/{resource_id}", json=values)


def _email_of_length(length):
    suffix = "@example.test"
    return "a" * (length - len(suffix)) + suffix


def _runbook_of_length(length):
    prefix = "https://example.test/"
    return prefix + "x" * (length - len(prefix))


@pytest.mark.parametrize("adapter", ["html", "json"])
@pytest.mark.parametrize(
    ("field", "limit", "value_factory"),
    [
        ("owner_email", 254, _email_of_length),
        ("runbook_url", 2048, _runbook_of_length),
    ],
)
def test_edit_host_accepts_exact_and_padded_ownership_limits_after_stripping(
    tmp_path, reload_app, adapter, field, limit, value_factory
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    exact = value_factory(limit)
    with TestClient(reload_app().app) as client:
        exact_response = _submit_edit(
            client, host_id, adapter, _edit_values(adapter, **{field: exact})
        )
        padded_response = _submit_edit(
            client, host_id, adapter, _edit_values(adapter, **{field: f" {exact} "})
        )
    expected = 303 if adapter == "html" else 200
    assert exact_response.status_code == expected, exact_response.text
    assert padded_response.status_code == expected, padded_response.text
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and getattr(host, field) == exact


@pytest.mark.parametrize("adapter", ["html", "json"])
@pytest.mark.parametrize(
    ("field", "limit", "value_factory"),
    [
        ("owner_email", 254, _email_of_length),
        ("runbook_url", 2048, _runbook_of_length),
    ],
)
def test_edit_host_rejects_ownership_values_one_past_the_limit(
    tmp_path, reload_app, adapter, field, limit, value_factory
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = _submit_edit(
            client,
            host_id,
            adapter,
            _edit_values(adapter, **{field: value_factory(limit + 1)}),
        )
    assert response.status_code == (422 if adapter == "html" else 400)
    assert f"at most {limit} characters" in response.text
    assert SqliteHostRepository(db).get(host_id) == before


@pytest.mark.parametrize(
    "field",
    [
        "owner_name",
        "owner_email",
        "owner_slack",
        "renewal_method",
        "runbook_url",
        "renewal_status",
        "notes",
        "tags",
    ],
)
def test_edit_host_json_rejects_null_string_fields(tmp_path, reload_app, field):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = _submit_edit(
            client, host_id, "json", _edit_values("json", **{field: None})
        )
    assert response.status_code == 400
    assert f"{field} must be a string" in response.json()["error"]
    assert SqliteHostRepository(db).get(host_id) == before


@pytest.mark.parametrize("adapter", ["html", "json"])
@pytest.mark.parametrize("renewal_status", ["renewed", "<x>"])
def test_edit_host_rejects_invalid_renewal_status(
    tmp_path, reload_app, adapter, renewal_status
):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db)
    before = SqliteHostRepository(db).get(host_id)
    with TestClient(reload_app().app) as client:
        response = _submit_edit(
            client,
            host_id,
            adapter,
            _edit_values(adapter, renewal_status=renewal_status),
        )
    assert response.status_code == (422 if adapter == "html" else 400)
    assert "renewal_status must be" in response.text
    assert "pending" in response.text and "in_progress" in response.text
    assert SqliteHostRepository(db).get(host_id) == before


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


@pytest.mark.parametrize("adapter", ["html", "json"])
def test_legacy_overlong_owner_loads_but_must_be_cleared_before_save(
    tmp_path, reload_app, adapter
):
    """Historical rows stay readable, while both complete-edit adapters
    refuse to write the legacy value back and still permit clearing it."""
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    legacy_name = "L" * 201
    host_id = SqliteHostRepository(db).add(
        "detail.example.test",
        443,
        tags="old-host-tag",
        owner_name=legacy_name,
        owner_email="old@example.test",
        owner_slack="#old",
        renewal_method="manual",
        runbook_url="https://old.example.test/runbook",
        scan_interval_hours=24,
        threshold_days=14,
        notes="Old notes",
    )
    values = {
        "owner_name": legacy_name,
        "owner_email": "old@example.test",
        "owner_slack": "#old",
        "renewal_method": "manual",
        "runbook_url": "https://old.example.test/runbook",
        "scan_interval_hours": 24 if adapter == "json" else "24",
        "threshold_days": 14 if adapter == "json" else "14",
        "renewal_status": "pending",
        "notes": "Old notes",
        "tags": "old-host-tag",
    }
    with TestClient(reload_app().app) as client:
        page = client.get(f"/certificates/{host_id}")
        if adapter == "html":
            refused = client.post(
                f"/hosts/{host_id}/edit", data=values, follow_redirects=False
            )
        else:
            refused = client.put(f"/api/hosts/{host_id}", json=values)

        assert page.status_code == 200
        assert legacy_name in page.text
        assert refused.status_code == (422 if adapter == "html" else 400)
        error = refused.text if adapter == "html" else refused.json()["error"]
        assert "owner_name must be at most 200 characters" in error
        assert SqliteHostRepository(db).get(host_id).owner_name == legacy_name

        cleared = {**values, "owner_name": ""}
        if adapter == "html":
            saved = client.post(
                f"/hosts/{host_id}/edit", data=cleared, follow_redirects=False
            )
            assert saved.status_code == 303
        else:
            saved = client.put(f"/api/hosts/{host_id}", json=cleared)
            assert saved.status_code == 200
    assert SqliteHostRepository(db).get(host_id).owner_name == ""


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


@pytest.mark.parametrize("adapter", ["html", "json"])
def test_certificate_edit_preserves_existing_foreign_tag_for_scoped_writer(
    tmp_path, reload_app, self_signed_leaf, adapter
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-b")
    cert_id = seed_scanned(
        db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der)
    )
    SqliteCertificateRepository(db).set_tags(cert_id, "team-a,team-b")
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        response = _submit_edit(
            client,
            cert_id,
            adapter,
            _edit_values(adapter, owner_name="Saved by team B", tags="team-a,team-b"),
        )
    assert response.status_code == (303 if adapter == "html" else 200), response.text
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None and host.owner_name == "Saved by team B"
    assert SqliteCertificateRepository(db).get_tags(cert_id) == "team-a,team-b"


@pytest.mark.parametrize("adapter", ["html", "json"])
@pytest.mark.parametrize("operation", ["add", "remove"])
def test_certificate_edit_refuses_foreign_tag_changes_for_scoped_writer(
    tmp_path, reload_app, self_signed_leaf, adapter, operation
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-b")
    cert_id = seed_scanned(
        db, "detail.example.test", 443, parse_certificate(self_signed_leaf.der)
    )
    initial = "team-b" if operation == "add" else "team-a,team-b"
    submitted = "team-a,team-b" if operation == "add" else "team-b"
    SqliteCertificateRepository(db).set_tags(cert_id, initial)
    before = SqliteHostRepository(db).get(host_id)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        response = _submit_edit(
            client,
            cert_id,
            adapter,
            _edit_values(adapter, owner_name="Must not save", tags=submitted),
        )
    assert response.status_code == (303 if adapter == "html" else 403)
    error = response.headers.get("location", "") if adapter == "html" else response.text
    assert "scope" in error
    assert SqliteHostRepository(db).get(host_id) == before
    assert SqliteCertificateRepository(db).get_tags(cert_id) == initial


@pytest.mark.parametrize("adapter", ["html", "json"])
def test_host_addressed_edit_preserves_foreign_tag_spelling_for_scoped_writer(
    tmp_path, reload_app, adapter
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="Team-A,team-b")
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        response = _submit_edit(
            client,
            host_id,
            adapter,
            _edit_values(adapter, owner_name="Saved by team B", tags="TEAM-A,team-b"),
        )
    assert response.status_code == (303 if adapter == "html" else 200), response.text
    host = SqliteHostRepository(db).get(host_id)
    assert host is not None
    assert (host.owner_name, host.tags) == ("Saved by team B", "Team-A,team-b")


@pytest.mark.parametrize("adapter", ["html", "json"])
def test_host_addressed_edit_refuses_foreign_tag_removal_for_scoped_writer(
    tmp_path, reload_app, adapter
):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = _host(db, tags="team-a,team-b")
    before = SqliteHostRepository(db).get(host_id)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-b")
    with _scoped_client(app, groups) as client:
        response = _submit_edit(
            client,
            host_id,
            adapter,
            _edit_values(adapter, owner_name="Must not save", tags="team-b"),
        )
    assert response.status_code == (303 if adapter == "html" else 403)
    error = response.headers.get("location", "") if adapter == "html" else response.text
    assert "scope" in error
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
