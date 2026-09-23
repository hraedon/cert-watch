"""Pre-1.0 threat-model hardening regressions."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient


def _local_admin_app(reload_app, tmp_path: Path):
    from cert_watch.auth import _scrypt_hash
    from cert_watch.database import init_schema

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=_scrypt_hash("hardening-test-password"),
        CERT_WATCH_COOKIE_SECURE="0",
    )
    return app_mod, db


def test_metrics_requires_admin_session_when_no_bearer_token(
    reload_app, tmp_path
):
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.auth.rbac import BREAK_GLASS_CLAIM, LOCAL_USER_CLAIM
    from cert_watch.database import Role, SqliteRoleRepository, SqliteUserRepository, User

    app_mod, db = _local_admin_app(reload_app, tmp_path)
    role_id = SqliteRoleRepository(db).add(
        Role(name="team-a-viewer", permission_tier="viewer", scope_tag="team-a")
    )
    SqliteUserRepository(db).add(
        User(username="scoped-viewer", email="", password_hash="unused", role_id=role_id)
    )

    with TestClient(app_mod.app, base_url="http://localhost") as client:
        viewer = create_session(
            "scoped-viewer",
            client.app.state.security,
            version=0,
            roles=[LOCAL_USER_CLAIM],
        )
        client.cookies.set(SESSION_COOKIE, viewer)
        denied = client.get("/metrics")
        assert denied.status_code == 403

        admin = create_session(
            "admin",
            client.app.state.security,
            version=0,
            roles=[BREAK_GLASS_CLAIM],
        )
        client.cookies.set(SESSION_COOKIE, admin)
        allowed = client.get("/metrics")
        assert allowed.status_code == 200


def test_metrics_accepts_admin_session_as_alternative_to_configured_token(
    reload_app, tmp_path, monkeypatch
):
    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.auth.rbac import BREAK_GLASS_CLAIM

    monkeypatch.setenv("CERT_WATCH_METRICS_TOKEN", "scraper-secret")
    app_mod, _db = _local_admin_app(reload_app, tmp_path)

    with TestClient(app_mod.app, base_url="http://localhost") as client:
        token = create_session(
            "admin",
            client.app.state.security,
            version=0,
            roles=[BREAK_GLASS_CLAIM],
        )
        client.cookies.set(SESSION_COOKIE, token)
        assert client.get("/metrics").status_code == 200


def test_metrics_token_gate_rejects_unauthenticated_browser_when_auth_enabled(
    reload_app, tmp_path, monkeypatch
):
    monkeypatch.setenv("CERT_WATCH_METRICS_TOKEN", "scraper-secret")
    app_mod, _db = _local_admin_app(reload_app, tmp_path)
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.get("/metrics")
    assert response.status_code == 401


def test_metrics_rejects_admin_application_api_key(reload_app, tmp_path):
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    app_mod, db = _local_admin_app(reload_app, tmp_path)
    _, admin_token = SqliteApiKeyRepository(db).create_key("metrics-admin", "admin")
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.get(
            "/metrics", headers={"Authorization": f"Bearer {admin_token}"}
        )
    assert response.status_code == 403
    assert response.json()["detail"] == "admin browser session required"


def test_metrics_token_check_allows_missing_token_configuration(monkeypatch):
    from starlette.requests import Request

    import cert_watch.auth.request_context as request_context

    monkeypatch.setattr(request_context, "_METRICS_TOKEN", "")
    request = Request({"type": "http", "headers": []})
    assert request_context.check_metrics_token(request) is True


def test_open_mode_rejects_untrusted_host_header(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        assert client.get("/", headers={"Host": "attacker.example"}).status_code == 400
        assert client.get("/", headers={"Host": "localhost:8000"}).status_code == 200


def test_open_mode_allows_configured_base_url_host(reload_app):
    app_mod = reload_app(CERT_WATCH_BASE_URL="https://certs.example.test")
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.get("/", headers={"Host": "certs.example.test:8443"})
    assert response.status_code == 200


@pytest.mark.parametrize("method", ["GET", "HEAD"])
@pytest.mark.parametrize("path", ["/healthz", "/readyz"])
def test_open_mode_kubernetes_probes_accept_pod_ip_host(
    reload_app, method: str, path: str
):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.request(method, path, headers={"Host": "10.42.0.7:8000"})
    assert response.status_code != 400


def test_open_mode_probe_exemption_is_exact(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        assert client.get("/", headers={"Host": "10.42.0.7:8000"}).status_code == 400
        assert (
            client.post("/healthz", headers={"Host": "10.42.0.7:8000"}).status_code
            == 400
        )


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/hosts"),
        ("PATCH", "/api/hosts/00000000-0000-0000-0000-000000000000/owner"),
        ("PATCH", "/api/hosts/00000000-0000-0000-0000-000000000000/settings"),
        ("PATCH", "/api/hosts/00000000-0000-0000-0000-000000000000/notes"),
        ("PUT", "/api/hosts/00000000-0000-0000-0000-000000000000/tags"),
        ("PUT", "/api/hosts/00000000-0000-0000-0000-000000000000/issuers"),
        ("PUT", "/api/certificates/00000000-0000-0000-0000-000000000000/tags"),
        ("POST", "/api/alert-groups"),
        ("PATCH", "/api/alert-groups/00000000-0000-0000-0000-000000000000"),
        ("POST", "/api/api-keys"),
        ("PUT", "/api/policy"),
    ],
)
def test_json_write_rejects_text_plain_even_when_auth_is_disabled(
    reload_app, method, path
):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.request(
            method,
            path,
            content='{"name":"cross-site","scope":"admin"}',
            headers={"Content-Type": "text/plain"},
        )
    assert response.status_code == 415


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("POST", "/api/api-keys", []),
        ("PUT", "/api/policy", None),
        ("POST", "/api/alert-groups", "not-an-object"),
    ],
)
def test_json_writes_reject_non_object_bodies_without_500(
    reload_app, method: str, path: str, body: Any
):
    app_mod = reload_app()
    with TestClient(
        app_mod.app, base_url="http://localhost", raise_server_exceptions=False
    ) as client:
        if body is None:
            response = client.request(
                method,
                path,
                content="null",
                headers={"Content-Type": "application/json"},
            )
        else:
            response = client.request(method, path, json=body)
    assert response.status_code in {400, 422}


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/alert-groups", b'{"name":"\\ud800","recipients":[]}'),
        ("/api/policy", b'{"default_severity":"\\ud800"}'),
        ("/api/hosts", b'{"hostname":"\\ud800","port":443}'),
        ("/api/api-keys", b'{"name":"\\ud800","scope":"read"}'),
    ],
)
def test_json_writes_reject_lone_surrogates_without_500(reload_app, path, body):
    app_mod = reload_app()
    with TestClient(
        app_mod.app, base_url="http://localhost", raise_server_exceptions=False
    ) as client:
        response = client.request(
            "PUT" if path == "/api/policy" else "POST",
            path,
            content=body,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid JSON"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/alert-groups"),
        ("PUT", "/api/policy"),
        ("POST", "/api/hosts"),
        ("POST", "/api/api-keys"),
    ],
)
def test_json_writes_reject_extreme_nesting_without_500(
    reload_app, method: str, path: str
):
    app_mod = reload_app()
    body = b'{"value":' + (b"[" * 100_000) + b"0" + (b"]" * 100_000) + b"}"
    with TestClient(
        app_mod.app, base_url="http://localhost", raise_server_exceptions=False
    ) as client:
        response = client.request(
            method,
            path,
            content=body,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid JSON"


@pytest.mark.parametrize(
    "body",
    [
        b'{"name":"first","name":"second"}',
        b'{"name":"group","threshold_days":NaN}',
        b'{"name":"group","threshold_days":Infinity}',
        b'{"name":"group","threshold_days":-Infinity}',
    ],
)
def test_json_writes_reject_duplicate_keys_and_non_finite_numbers(
    reload_app, body: bytes
):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.post(
            "/api/alert-groups",
            content=body,
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid JSON"


def test_open_mode_browser_mutations_require_csrf(reload_app, csrf_strict):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        # A normal page visit establishes the open-mode browser's CSRF session.
        client.get("/")
        for path in ("/api/hosts/scan", "/api/alerts/mark-all-read"):
            response = client.post(
                path,
                content=b"",
                headers={
                    "Content-Type": "text/plain",
                    "Origin": "https://attacker.example",
                },
            )
            assert response.status_code == 403
            assert response.json()["detail"] == "missing CSRF token"

        form_response = client.post(
            "/hosts",
            data={"hostname": "csrf.example.test", "port": "443"},
            headers={"Origin": "https://attacker.example"},
            follow_redirects=False,
        )
        assert form_response.status_code == 303
        assert "missing%20CSRF%20token" in form_response.headers["location"]

        inventory = client.get("/api/hosts")
        assert "csrf.example.test" not in inventory.text


def test_admin_api_key_cannot_create_or_revoke_api_keys(
    reload_app, tmp_path
):
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    app_mod, db = _local_admin_app(reload_app, tmp_path)
    repo = SqliteApiKeyRepository(db)
    _, admin_token = repo.create_key("admin-automation", "admin")
    target, _ = repo.create_key("target", "read")
    headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app_mod.app, base_url="http://localhost") as client:
        created = client.post(
            "/api/api-keys",
            headers=headers,
            json={"name": "forbidden", "scope": "read"},
        )
        revoked = client.delete(f"/api/api-keys/{target.id}", headers=headers)

    assert created.status_code == 403
    assert revoked.status_code == 403
    assert next(entry for entry in repo.list_keys() if entry.id == target.id).revoked is False
    assert all(entry.name != "forbidden" for entry in repo.list_keys())


def test_admin_api_key_cannot_use_html_key_management(reload_app, tmp_path):
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    app_mod, db = _local_admin_app(reload_app, tmp_path)
    repo = SqliteApiKeyRepository(db)
    _, admin_token = repo.create_key("admin-automation", "admin")
    target, _ = repo.create_key("target", "read")
    headers = {"Authorization": f"Bearer {admin_token}"}

    with TestClient(app_mod.app, base_url="http://localhost") as client:
        page = client.get(
            "/settings/api-keys",
            headers=headers,
            follow_redirects=False,
        )
        created = client.post(
            "/settings/api-keys",
            headers=headers,
            data={"name": "forbidden-html", "scope": "read"},
            follow_redirects=False,
        )
        revoked = client.post(
            f"/settings/api-keys/{target.id}/revoke",
            headers=headers,
            follow_redirects=False,
        )

    assert page.status_code == 303
    assert created.status_code == 303
    assert revoked.status_code == 303
    assert next(entry for entry in repo.list_keys() if entry.id == target.id).revoked is False
    assert all(entry.name != "forbidden-html" for entry in repo.list_keys())


@pytest.mark.parametrize(
    ("address", "allow_private"),
    [
        ("fd00:ec2::253", True),
        ("fd00:ec2::254", True),
        ("fd00:ec2::1234", True),
        ("64:ff9b:1::a9fe:a9fe", True),
        ("100.64.0.1", False),
    ],
)
def test_scan_blocks_new_sensitive_ranges(monkeypatch, address, allow_private):
    import cert_watch.scan_resolver as resolver

    family = 10 if ":" in address else 2
    monkeypatch.setattr(
        resolver,
        "resolve_hostname",
        lambda *_args, **_kwargs: [(family, (address, 443, 0, 0))],
    )
    error, pinned = resolver.resolve_and_validate_host(
        "target.example", 443, allow_private=allow_private
    )
    assert error is not None
    assert pinned is None


@pytest.mark.parametrize("address", ["fd00:ec2::253", "fd00:ec2::254", "fd00:ec2::1234"])
def test_ipv6_imds_is_always_blocked_for_scans_and_webhooks(address):
    from cert_watch.http_client import validate_webhook_url
    from cert_watch.scan_resolver import _is_blocked_ip

    parsed = ipaddress.ip_address(address)
    assert _is_blocked_ip(parsed, allow_private=True)
    assert validate_webhook_url(f"http://[{address}]/latest", allow_private=True)


def test_local_use_nat64_unwraps_embedded_ipv4_for_scans_and_webhooks():
    from cert_watch.http_client import validate_webhook_url
    from cert_watch.scan_resolver import _is_blocked_ip

    metadata = ipaddress.ip_address("64:ff9b:1::a9fe:a9fe")
    cgnat = ipaddress.ip_address("64:ff9b:1::6440:1")
    assert _is_blocked_ip(metadata, allow_private=True)
    assert validate_webhook_url(
        "http://[64:ff9b:1::a9fe:a9fe]/latest", allow_private=True
    )
    assert _is_blocked_ip(cgnat, allow_private=False)
    assert not _is_blocked_ip(cgnat, allow_private=True)


def test_cgnat_follows_private_policy_for_webhooks():
    from cert_watch.http_client import validate_webhook_url

    url = "http://100.64.0.1/hook"
    assert validate_webhook_url(url, allow_private=False)
    assert validate_webhook_url(url, allow_private=True) is None


class _RejectingLoginProvider:
    provider_name = "test"
    provider_label = "Test"
    supports_form_login = True

    def authenticate(self, username: str, password: str):
        from cert_watch.auth import AuthResult

        return AuthResult(success=False, error="login failed")


def test_login_tight_limit_is_per_ip_and_normalized_username(monkeypatch):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    app = create_app(auth_provider=_RejectingLoginProvider(), settings=Settings.from_env())
    with TestClient(app, base_url="http://localhost") as client:
        for index in range(10):
            username = " Alice " if index % 2 else "ALICE"
            response = client.post(
                "/login",
                data={"username": username, "password": "wrong"},
                follow_redirects=False,
            )
            assert "rate+limited" not in response.headers["location"]

        blocked = client.post(
            "/login",
            data={"username": "alice", "password": "wrong"},
            follow_redirects=False,
        )
        other_user = client.post(
            "/login",
            data={"username": "bob", "password": "wrong"},
            follow_redirects=False,
        )

    assert "rate+limited" in blocked.headers["location"]
    assert "rate+limited" not in other_user.headers["location"]


def test_login_keeps_looser_per_ip_ceiling():
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    app = create_app(auth_provider=_RejectingLoginProvider(), settings=Settings.from_env())
    with TestClient(app, base_url="http://localhost") as client:
        for index in range(50):
            response = client.post(
                "/login",
                data={"username": f"user-{index}", "password": "wrong"},
                follow_redirects=False,
            )
            assert "rate+limited" not in response.headers["location"]
        blocked = client.post(
            "/login",
            data={"username": "last-user", "password": "wrong"},
            follow_redirects=False,
        )
    assert "rate+limited" in blocked.headers["location"]


def test_plain_ldap_login_is_refused_by_default(monkeypatch):
    import ldap3

    from cert_watch.auth import LDAPAuthProvider

    connection = pytest.fail
    monkeypatch.setattr(ldap3, "Connection", connection)
    provider = LDAPAuthProvider("ldap://dc.example.test", "DC=example,DC=test")
    result = provider.authenticate("alice", "password")
    assert result.success is False
    assert "insecure" in (result.error or "").lower()


def test_suite_does_not_globally_allow_plain_ldap():
    assert "CERT_WATCH_LDAP_ALLOW_INSECURE" not in os.environ


def test_plain_ldap_login_route_surfaces_clear_refusal(reload_app, monkeypatch):
    monkeypatch.delenv("CERT_WATCH_LDAP_ALLOW_INSECURE", raising=False)
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.test",
        LDAP_BASE_DN="DC=example,DC=test",
    )
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.post(
            "/login",
            data={"username": "alice", "password": "password"},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert "Insecure%20LDAP%20simple%20bind%20refused" in response.headers["location"]


def test_plain_ldap_can_be_explicitly_allowed():
    from cert_watch.auth import LDAPAuthProvider

    provider = LDAPAuthProvider(
        "ldap://dc.example.test",
        "DC=example,DC=test",
        allow_insecure=True,
    )
    assert provider.allow_insecure is True


def test_ldap_insecure_override_loads_from_env(monkeypatch):
    from cert_watch.config import Settings

    monkeypatch.delenv("CERT_WATCH_LDAP_ALLOW_INSECURE", raising=False)
    assert Settings.from_env().ldap_allow_insecure is False
    monkeypatch.setenv("CERT_WATCH_LDAP_ALLOW_INSECURE", "1")
    assert Settings.from_env().ldap_allow_insecure is True


def test_settings_ldap_probe_refuses_plain_bind(reload_app, monkeypatch):
    import cert_watch.routes.settings.auth as settings_auth

    async def must_not_probe(*_args, **_kwargs):
        raise AssertionError("plain LDAP reached the network probe")

    monkeypatch.setattr(settings_auth, "_run_ldap_probe", must_not_probe)
    monkeypatch.setattr(settings_auth, "_check_ldap_ssrf", lambda *_a, **_k: (None, {}))
    monkeypatch.delenv("CERT_WATCH_LDAP_ALLOW_INSECURE", raising=False)
    app_mod = reload_app()
    with TestClient(
        app_mod.app, base_url="http://localhost", raise_server_exceptions=False
    ) as client:
        response = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc.example.test",
                "ldap_base_dn": "DC=example,DC=test",
                "ldap_start_tls": "0",
            },
        )
    assert response.status_code == 200
    assert response.json()["ok"] is False
    assert "insecure" in response.json()["error"].lower()


def test_request_body_limit_rejects_declared_oversize_before_parsing(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.post(
            "/api/api-keys",
            content=b"{}",
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(12 * 1024 * 1024 + 1),
            },
        )
    assert response.status_code == 413


def test_request_body_limit_counts_actual_streamed_bytes(reload_app):
    app_mod = reload_app()

    def chunks():
        chunk = b"x" * (1024 * 1024)
        for _ in range(13):
            yield chunk

    with TestClient(app_mod.app, base_url="http://localhost") as client:
        response = client.post(
            "/api/api-keys",
            content=chunks(),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 413


def test_new_guard_variants_have_stable_repr_and_reject_invalid_shape():
    from cert_watch.auth.guards import (
        MutationGuard,
        admin_session_json_write_guard,
        require_admin_session,
    )

    assert "session_only=True" in repr(require_admin_session)
    assert "MutationGuard" in repr(admin_session_json_write_guard)
    with pytest.raises(ValueError, match="JSON guards"):
        MutationGuard("write", form=True, json_only=True)
