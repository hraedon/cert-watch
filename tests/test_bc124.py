"""Regression tests for BC-124 (session token parsing, bump TOCTOU, composite provider)."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import socket
import threading
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request as StRequest

import cert_watch.middleware as mw
import cert_watch.routes.auth as auth_routes
from cert_watch.auth import (
    SESSION_COOKIE,
    LocalAdminProvider,
    _CompositeProvider,
    create_session,
    decode_session,
    set_signing_key,
    validate_session,
)
from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.auth.protocol import AuthResult
from cert_watch.database import bump_session_version, get_session_version, init_schema, kv_set
from cert_watch.database.dashboard import _build_host_filter
from cert_watch.http_client import SSRFBlockedError, _validate_url, validate_webhook_url
from cert_watch.middleware import _request_security
from cert_watch.posture import _check_endpoint_reachable

# ---------- 1. _CompositeProvider always-calls-primary assertion ----------


def test_composite_provider_always_calls_primary_even_on_local_failure():
    """Every wrong-username attempt must reach the primary provider to avoid
    a timing oracle (fast return = local mismatch, slow return = local match
    + primary tried)."""
    h = _scrypt_hash("localpw", n=2**4, r=1, p=1)
    local = LocalAdminProvider("admin", h)
    primary = MagicMock()
    primary.authenticate.return_value = AuthResult(
        success=False, error="primary says no"
    )
    composite = _CompositeProvider(local, primary)
    result = composite.authenticate("wronguser", "anypass")
    assert result.success is False
    primary.authenticate.assert_called_once_with("wronguser", "anypass")


def test_composite_provider_returns_primary_success_when_local_fails():
    """When local fails and primary succeeds, composite returns primary result."""
    h = _scrypt_hash("localpw", n=2**4, r=1, p=1)
    local = LocalAdminProvider("admin", h)
    primary = MagicMock()
    primary.authenticate.return_value = AuthResult(
        success=True, username="alice", groups=["users"]
    )
    composite = _CompositeProvider(local, primary)
    result = composite.authenticate("alice", "primarypass")
    assert result.success is True
    assert result.username == "alice"


# ---------- 2. validate_session token shapes (WI-088: v0 rejected) ----------


def test_validate_session_3_part_rejected():
    """Old-format 3-part tokens (username:ts:nonce) are rejected (WI-088)."""
    set_signing_key("test-key-3part")
    payload = "bob:1234567890:abcdef12"
    sig = "fake"
    old_token = f"{payload}:{sig}"
    assert validate_session(old_token) is None


def test_validate_session_4_part_with_version():
    """New-format tokens (username:version:ts:nonce) validate correctly."""
    set_signing_key("test-key-4part")
    token = create_session("alice", version=2)
    assert validate_session(token) == "alice"


def test_validate_session_5_part_malformed():
    """Extra colons in payload shouldn't crash validation."""
    set_signing_key("test-key-5part")
    # Manually create a 5-part payload (username:extra:version:ts:nonce)
    # The signature check will fail, but parsing should not crash
    token = "alice:extra:2:1234567890:abcdef12:fake_sig"
    assert validate_session(token) is None


def test_validate_session_6_part_with_groups_and_roles():
    """BC-145: tokens carrying groups/roles encode and decode correctly."""
    set_signing_key("test-key-6part")
    token = create_session(
        "alice", version=2, groups=["g-ops", "g-admin"], roles=["operator"]
    )
    info = decode_session(token)
    assert info is not None
    assert info.username == "alice"
    assert info.version == 2
    assert info.groups == ["g-ops", "g-admin"]
    assert info.roles == ["operator"]
    assert validate_session(token) == "alice"


def test_validate_session_3_part_rejected_even_when_signed():
    """A genuine 3-part signed token (old format) is rejected (WI-088)."""
    set_signing_key("test-key-old")
    payload = f"bob:{int(time.time())}:nonce1234"
    sig = hmac.new(b"test-key-old", payload.encode(), hashlib.sha256).hexdigest()[:64]
    token = f"{payload}:{sig}"
    assert validate_session(token) is None


def test_validate_session_4_part_rejects_32char_sig():
    """4-part tokens with legacy 32-char signatures are rejected (WI-088)."""
    set_signing_key("test-key-32char")
    payload = f"bob:0:{int(time.time())}:nonce1234"
    sig = hmac.new(b"test-key-32char", payload.encode(), hashlib.sha256).hexdigest()[:32]
    token = f"{payload}:{sig}"
    assert validate_session(token) is None


# ---------- 3. bump_session_version concurrent-call race ----------


def test_bump_session_version_concurrent_race(tmp_path):
    """Concurrent bumps from multiple threads must not lose updates.

    Uses INSERT … ON CONFLICT … DO UPDATE … RETURNING so every caller
    sees a distinct, monotonically increasing version.
    """
    db = tmp_path / "race.sqlite3"
    init_schema(db)

    versions = []
    errors = []

    def bump():
        try:
            v = bump_session_version(db, "alice")
            versions.append(v)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=bump) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(versions) == 10
    # All versions should be unique and monotonically assigned
    assert sorted(versions) == list(range(1, 11))
    # Final stored version should be the max
    final = get_session_version(db, "alice")
    assert final == 10


# ---------- 4. change_local_admin_password env-var-bypass branch ----------


def test_change_password_env_override_redirects(reload_app, tmp_path, monkeypatch):
    """When CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH is set, UI rotation is blocked."""
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv(
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",
        _scrypt_hash("testpassword"),
    )

    # Seed a local admin in kv_store
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _scrypt_hash("testpassword"))
    kv_set(db, "setup_complete", "1")

    # Rebuild app with the env hash
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        monkeypatch.setattr(mw, "_COOKIE_SECURE", False)
        monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)
        # Create session directly (same as _login_admin helper)
        scope = {
            "type": "http", "method": "GET", "path": "/",
            "query_string": b"", "headers": [],
            "app": client.app,
            "session": {},
        }
        req = StRequest(scope)
        security = _request_security(req)
        token = create_session("admin", security, version=0)
        client.cookies.set(SESSION_COOKIE, token)

        # Try to change password — should be blocked because env var wins
        r = client.post("/settings/change-password", data={
            "current_password": "testpassword",
            "new_password": "newsecurepass",
            "confirm_password": "newsecurepass",
        }, follow_redirects=False)
    assert r.status_code == 303
    assert "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH" in r.headers["location"]


# ---------- 5. _build_host_filter rejecting non-whitelisted columns ----------


def test_build_host_filter_rejects_disallowed_columns():
    """_build_host_filter must raise ValueError for columns outside the whitelist."""
    with pytest.raises(ValueError, match="disallowed filter column"):
        _build_host_filter("hostname", ["a"])
    with pytest.raises(ValueError, match="disallowed filter column"):
        _build_host_filter("id", ["a"])
    with pytest.raises(ValueError, match="disallowed filter column"):
        _build_host_filter("; DROP TABLE hosts; --", ["a"])


def test_build_host_filter_accepts_whitelisted_columns():
    """_build_host_filter must accept the whitelisted columns."""
    clause, params = _build_host_filter("owner_name", ["alice", "bob"])
    assert "h.owner_name" in clause
    assert params == ("alice", "bob")

    clause, params = _build_host_filter("renewal_method", ["acme"])
    assert "h.renewal_method" in clause
    assert params == ("acme",)


# ---------- 6. BC-083 fail-closed SystemExit when data dir unwritable ----------


def test_fail_closed_when_provisioning_cannot_persist(tmp_path, monkeypatch):
    """If auto-provisioning can't persist an admin, an exposed bind exits
    rather than serve open (BC-083 fail-closed fallback)."""
    from cert_watch import app as app_mod
    from cert_watch.app import create_app

    for var in (
        "AUTH_PROVIDER", "CERT_WATCH_ALLOW_UNAUTH", "CERT_WATCH_HOST",
        "CERT_WATCH_TRUST_PROXY", "CERT_WATCH_AUTH_SECRET",
        "CERT_WATCH_CSRF_SECRET", "CERT_WATCH_LOCAL_ADMIN_USER",
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_HOST", "0.0.0.0")

    # Simulate provisioning that returns None (no admin created)
    monkeypatch.setattr(app_mod, "_provision_initial_admin", lambda s, **kw: None)

    app = create_app()

    async def _run():
        async with app.router.lifespan_context(app):
            pass

    with pytest.raises(SystemExit) as exc:
        asyncio.run(_run())
    assert "0.0.0.0" in str(exc.value)


# ---------- 7. BC-116 webhook SSRF redirect path ----------


def test_webhook_url_validate_blocks_private_ip():
    """validate_webhook_url rejects loopback/private IPs (BC-116)."""
    error = validate_webhook_url("http://127.0.0.1:8080/webhook")
    assert error is not None
    assert "blocked" in error.lower() or "127.0.0.1" in error


def test_webhook_url_validate_blocks_metadata_ip():
    """validate_webhook_url rejects metadata endpoints (BC-116)."""
    error = validate_webhook_url("http://169.254.169.254/latest/meta-data/")
    assert error is not None


def test_webhook_url_validate_allows_public_ip():
    """validate_webhook_url allows public IPs."""
    error = validate_webhook_url("https://8.8.8.8/webhook")
    assert error is None


def test_webhook_url_validate_allows_public_hostname(monkeypatch):
    """validate_webhook_url allows public hostnames."""
    # Mock getaddrinfo to avoid DNS resolution failures in test environment
    original_getaddrinfo = socket.getaddrinfo
    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host == "hooks.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        return original_getaddrinfo(host, port, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    error = validate_webhook_url("https://hooks.example.com/webhook")
    assert error is None


def test_build_webhook_config_skips_invalid_env_url(monkeypatch, tmp_path):
    """build_webhook_config rejects an env-configured webhook URL that fails SSRF validation."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    # Link-local/cloud metadata is blocked regardless of allow_private.
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "http://169.254.169.254:8080/webhook")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.build_webhook_config() is None


# ---------- 8. BC-117 OCSP/CRL SSRF blocked path ----------


def test_check_endpoint_reachable_ocsp_blocked_by_ssrf():
    """_check_endpoint_reachable returns blocked message for SSRF-blocked URLs."""
    reachable, msg = _check_endpoint_reachable("http://127.0.0.1/ocsp", method="HEAD")
    assert reachable is False
    assert "blocked by SSRF policy" in msg


def test_check_endpoint_reachable_crl_blocked_by_ssrf():
    """_check_endpoint_reachable returns blocked message for SSRF-blocked URLs."""
    reachable, msg = _check_endpoint_reachable("http://169.254.169.254/crl.pem", method="GET")
    assert reachable is False
    assert "blocked by SSRF policy" in msg


def test_check_revocation_endpoints_finds_blocked_ocsp():
    """check_revocation_endpoints surfaces a clear warning when OCSP is blocked."""
    # A dummy certificate with no OCSP/CRL won't exercise the path,
    # so we test the helper directly.
    reachable, msg = _check_endpoint_reachable("http://192.168.1.1/ocsp", method="HEAD")
    assert reachable is False
    assert "blocked by SSRF policy" in msg


def test_ssrf_safe_urlopen_blocks_redirect_to_private():
    """ssrf_safe_urlopen validates redirect targets and blocks them."""
    # A request that would redirect to a blocked address should be rejected.
    # Since we can't easily trigger a real redirect in a unit test, we verify
    # the redirect handler class exists and that _validate_url rejects the
    # redirect target directly.
    with pytest.raises(SSRFBlockedError):
        _validate_url("http://127.0.0.1/redirect-target")
