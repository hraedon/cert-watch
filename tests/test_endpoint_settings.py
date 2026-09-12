"""Endpoint settings preserve scope, stored state, and alert meaning."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cert_watch.app import create_app
from cert_watch.auth import SESSION_COOKIE, create_session
from cert_watch.certificate_model import Certificate
from cert_watch.config import Settings
from cert_watch.database import (
    Role,
    SqliteHostRepository,
    SqliteRoleRepository,
    init_schema,
)
from cert_watch.database.connection import _connect
from tests._helpers import seed_scanned


@pytest.fixture
def endpoint(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(
        "endpoint.example.test", 443, threshold_days=14, scan_interval_hours=48,
        tags="team-a", owner_name="Operations", owner_email="ops@example.test",
        renewal_method="acme", runbook_url="https://wiki.example.test/renew",
        notes="Keep these notes", expected_issuers="Legacy CA",
    )
    return db, repo, host_id


def _form(**changes):
    return {"scan_interval_hours": "6", "threshold_days": "21",
            "renewal_status": "in_progress", **changes}


def _audit(db):
    with _connect(db) as conn:
        return [dict(row) for row in conn.execute(
            "SELECT action, target_id, detail FROM audit_log WHERE action = 'host.update_settings'"
        )]


def test_save_endpoint_settings_preserves_other_fields_and_wakes_scheduler(
    reload_app, endpoint, monkeypatch,
):
    db, repo, host_id = endpoint
    before = repo.get(host_id)
    app = reload_app().app
    wakeups = []
    monkeypatch.setattr("cert_watch.scheduler.wake_scheduler", lambda: wakeups.append(True))
    with TestClient(app) as client:
        wakeups.clear()
        response = client.post(f"/hosts/{host_id}/settings", data=_form(), follow_redirects=False)
        assert response.status_code == 303
        assert urlsplit(response.headers["location"]).path == f"/certificates/{host_id}"
        page = client.get(response.headers["location"])
    assert repo.get(host_id) == replace(
        before, scan_interval_hours=6, threshold_days=21, renewal_status="in_progress",
    )
    assert wakeups == [True]
    assert 'data-testid="endpoint-settings-saved"' in page.text
    assert len(_audit(db)) == 1
    assert _audit(db)[0]["target_id"] == host_id


def test_blank_numeric_fields_restore_daily_and_automatic_thresholds(reload_app, endpoint):
    _db, repo, host_id = endpoint
    with TestClient(reload_app().app) as client:
        response = client.post(f"/hosts/{host_id}/settings", data=_form(
            scan_interval_hours="", threshold_days="", renewal_status="pending",
        ), follow_redirects=False)
    assert response.status_code == 303
    host = repo.get(host_id)
    assert host.scan_interval_hours is None
    assert host.threshold_days is None
    assert host.renewal_status == "pending"


@pytest.mark.parametrize("changes", [
    {"scan_interval_hours": "0"}, {"scan_interval_hours": "-1"},
    {"scan_interval_hours": "8761"}, {"scan_interval_hours": "1.5"},
    {"scan_interval_hours": "many"}, {"scan_interval_hours": "9" * 30},
    {"threshold_days": "0"}, {"threshold_days": "-1"},
    {"threshold_days": "1.5"}, {"threshold_days": "9223372036854775808"},
    {"renewal_status": "verified"},
])
def test_invalid_settings_do_not_partially_save(reload_app, endpoint, changes):
    db, repo, host_id = endpoint
    before = repo.get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(
            f"/hosts/{host_id}/settings", data=_form(**changes), follow_redirects=False,
        )
        assert response.status_code == 303
        assert "endpoint_error" in parse_qs(urlsplit(response.headers["location"]).query)
        page = client.get(response.headers["location"])
    assert 'data-testid="endpoint-settings-error"' in page.text
    assert repo.get(host_id) == before
    assert _audit(db) == []


@pytest.mark.parametrize("legacy", [0, -1, 9999])
def test_legacy_scan_interval_survives_unchanged_edit(reload_app, endpoint, legacy):
    db, repo, host_id = endpoint
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET scan_interval_hours = ? WHERE id = ?", (legacy, host_id))
        conn.commit()
    with TestClient(reload_app().app) as client:
        page = client.get(f"/certificates/{host_id}")
        assert "Legacy cadence" in page.text
        response = client.post(f"/hosts/{host_id}/settings", data=_form(
            scan_interval_hours=str(legacy),
        ), follow_redirects=False)
    assert response.status_code == 303
    assert "endpoint_saved" in response.headers["location"]
    assert repo.get(host_id).scan_interval_hours == legacy
    assert repo.get(host_id).renewal_status == "in_progress"


@pytest.mark.parametrize("with_certificate", [False, True])
def test_endpoint_editor_shows_state_without_claiming_verified_renewal(
    reload_app, endpoint, with_certificate,
):
    db, _repo, host_id = endpoint
    detail_id = host_id
    if with_certificate:
        now = datetime.now(UTC)
        detail_id = seed_scanned(db, "endpoint.example.test", 443, Certificate(
            subject="CN=endpoint.example.test", issuer="CN=Test CA", is_leaf=True,
            not_before=now - timedelta(days=90), not_after=now + timedelta(days=20),
            fingerprint_sha256="a" * 64,
        ))
    with TestClient(reload_app().app) as client:
        page = client.get(f"/certificates/{detail_id}")
        assert page.status_code == 200
        assert f'action="/hosts/{host_id}/settings"' in page.text
        assert 'name="scan_interval_hours"' in page.text
        assert 'name="threshold_days"' in page.text
        assert 'name="renewal_status"' in page.text
        assert "not proof of renewal" in page.text
        assert "suppresses new expiry alerts until the next successful scan" in page.text
        assert "Legacy CA" in page.text
        assert "not monitored" in page.text
        assert 'name="expected_issuers"' not in page.text
        response = client.post(f"/hosts/{host_id}/settings", data=_form(), follow_redirects=False)
        assert urlsplit(response.headers["location"]).path == f"/certificates/{detail_id}"


def _role_client(db, tier, *, scope=""):
    roles = SqliteRoleRepository(db)
    roles.add(Role(name="endpoint-access", permission_tier=tier))
    role_map = {"endpoint-access": {"groups": ["access"]}}
    groups = ["access"]
    if scope:
        roles.add(Role(name="endpoint-scope", permission_tier="viewer", scope_tag=scope))
        role_map["endpoint-scope"] = {"groups": ["scoped"]}
        groups.append("scoped")

    class Provider:
        provider_name = "mock"

    settings = replace(Settings.from_env(), role_map=role_map)
    app = create_app(settings=settings, auth_provider=Provider())
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE, create_session("endpoint-user", groups=groups))
    return client


@pytest.mark.parametrize("tier,scope,allowed", [
    ("viewer", "", False), ("operator", "team-b", False),
    ("operator", "team-a", True),
])
def test_endpoint_settings_honor_write_tier_and_host_scope(endpoint, tier, scope, allowed):
    db, repo, host_id = endpoint
    before = repo.get(host_id)
    with _role_client(db, tier, scope=scope) as client:
        page = client.get(f"/certificates/{host_id}")
        assert 'name="expected_issuers"' not in page.text
        assert "Legacy CA" not in page.text  # Legacy setting remains admin-only.
        response = client.post(f"/hosts/{host_id}/settings", data=_form(), follow_redirects=False)
    assert response.status_code == 303
    if allowed:
        assert repo.get(host_id).scan_interval_hours == 6
    else:
        assert repo.get(host_id) == before
        assert _audit(db) == []


def test_endpoint_settings_require_real_csrf(endpoint, reload_app, csrf_strict):
    db, repo, host_id = endpoint
    before = repo.get(host_id)
    with TestClient(reload_app().app) as client:
        response = client.post(f"/hosts/{host_id}/settings", data=_form(), follow_redirects=False)
    assert response.status_code == 303
    assert "csrf" in response.headers["location"].lower()
    assert repo.get(host_id) == before
    assert _audit(db) == []


def test_missing_endpoint_is_not_created(reload_app, endpoint):
    _db, repo, _host_id = endpoint
    before = repo.list_all()
    with TestClient(reload_app().app) as client:
        response = client.post(
            "/hosts/00000000-0000-0000-0000-000000000000/settings",
            data=_form(), follow_redirects=False,
        )
    assert response.status_code == 303
    assert "not" in response.headers["location"]
    assert repo.list_all() == before
