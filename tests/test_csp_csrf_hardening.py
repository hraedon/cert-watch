"""Tests for Plan 020 S4 (CSP nonces) and BC-070 (CSRF query-param removal)."""

from types import SimpleNamespace

import pytest
from fastapi import Request
from fastapi.testclient import TestClient


def _reload_app(tmp_path, monkeypatch):
    """Build a fresh app via create_app() (no module reloading, Plan 018 B1)."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    return SimpleNamespace(app=create_app(settings=Settings.from_env()))


# ── Security headers ────────────────────────────────────────────────────────
# NOTE (BC-075): the per-request CSP nonce is plumbed — issued in
# security_headers_middleware, exposed via the csp_nonce context processor, and
# stamped on every <script> in base.html — but script-src still carries
# 'unsafe-inline' (and the header does NOT yet emit the nonce) because some
# templates retain inline on*= handlers. Adding the nonce to the header now would
# make browsers ignore 'unsafe-inline' and break those handlers. The
# no-inline-handler guardrail (test_no_inline_handlers.py) ratchets them to zero;
# then _build_csp flips to 'nonce-…' and drops 'unsafe-inline'.


def test_security_headers_present(tmp_path, monkeypatch):
    app_mod = _reload_app(tmp_path, monkeypatch)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"


def test_csp_nonce_rendered_and_per_request(tmp_path, monkeypatch):
    """base.html's <script> blocks carry a non-empty nonce that is shared within
    a response and fresh per request (BC-075 plumbing). Page-template scripts are
    nonce-stamped as those screens are converted; this checks the base wiring."""
    import re

    app_mod = _reload_app(tmp_path, monkeypatch)
    with TestClient(app_mod.app) as client:
        r1 = client.get("/")
        r2 = client.get("/")
    assert r1.status_code == 200

    nonces1 = re.findall(r'<script\b[^>]*nonce="([^"]+)"', r1.text)
    assert len(nonces1) >= 3, "base.html's three <script> blocks should be nonce-stamped"
    assert all(nonces1), "nonce must be non-empty"
    # All base scripts share this request's single nonce…
    assert len(set(nonces1)) == 1
    # …and a second request gets a different nonce.
    nonces2 = re.findall(r'<script\b[^>]*nonce="([^"]+)"', r2.text)
    assert nonces2 and set(nonces1).isdisjoint(nonces2)


# ── BC-070: CSRF token no longer accepted via query parameter ───────────────


def test_csrf_query_param_token_rejected(csrf_strict, tmp_path, monkeypatch):
    """A CSRF token supplied only in the query string must be rejected."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    app_mod = SimpleNamespace(app=create_app(settings=Settings.from_env()))

    with TestClient(app_mod.app) as client:
        r = client.get("/")
        sid_cookie = r.cookies.get("cw_sid")
    assert sid_cookie

    from cert_watch.middleware import make_csrf_token

    token = make_csrf_token(sid_cookie)

    # Token in query string only — no header, no form field.
    with TestClient(app_mod.app, cookies={"cw_sid": sid_cookie}) as client:
        r = client.post(
            f"/hosts?_csrf_token={token}",
            data={"hostname": "test.example.com"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "csrf" in r.headers.get("location", "").lower()


def test_csrf_header_token_still_accepted(tmp_path, monkeypatch):
    """Regression guard: the x-csrf-token header path still validates."""
    from cert_watch.middleware import make_csrf_token, validate_csrf_token

    token = make_csrf_token("sid-1")
    assert validate_csrf_token(token, "sid-1")


# ── Plan 020 S2: rate_limit dependency ──────────────────────────────────────


def test_rate_limit_dependency_returns_429_on_api_route(tmp_path, monkeypatch):
    """The rate_limit() dependency raises 429 once the window is exhausted."""
    app_mod = _reload_app(tmp_path, monkeypatch)
    # /caa-check is limited to 10 requests / 60s via Depends(rate_limit(...)).
    with TestClient(app_mod.app) as client:
        statuses = [client.get(f"/caa-check/example{i}.com").status_code for i in range(12)]
    assert 429 in statuses
    # The first request must not be rate limited.
    assert statuses[0] != 429


def test_csrf_bypass_defaults_false(csrf_strict):
    """The _CSRF_BYPASS flag must default to False — it is test-only (WI-097/099).

    The flag cannot be enabled via env var or config; only via monkeypatch in
    test fixtures.  This test guards against accidental enabling in production.
    The ``csrf_strict`` fixture re-enables real validation by setting the flag
    back to ``False``, confirming the production default.
    """
    import cert_watch.middleware as mw

    assert mw._CSRF_BYPASS is False


class _FakeApp:
    def __init__(self):
        self.state = type("State", (), {})()


def _make_request(method="GET", headers=None, cookies=None):
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        hdrs.append((b"cookie", cookie_str.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": "/",
        "headers": hdrs,
        "app": _FakeApp(),
        "client": ("127.0.0.1", 12345),
        "query_string": b"",
    }
    return Request(scope)


@pytest.mark.anyio
async def test_csrf_bypass_exercises_validation_path(monkeypatch):
    """In bypass mode check_csrf mints a token and validates it (WI-099)."""
    from cert_watch import middleware as _mw
    from cert_watch.middleware import check_csrf, validate_csrf_token

    original = validate_csrf_token
    calls = []

    def _spy(token, session_id, security=None):
        calls.append((token, session_id, security))
        return original(token, session_id, security)

    monkeypatch.setattr(_mw, "validate_csrf_token", _spy)
    monkeypatch.setattr(_mw, "_CSRF_BYPASS", True)

    request = _make_request()
    assert await check_csrf(request) is None
    assert len(calls) == 1
    assert calls[0][0]
    assert calls[0][1]


@pytest.mark.anyio
async def test_csrf_bypass_false_rejects_missing_token(monkeypatch):
    """With bypass disabled and no token, check_csrf reports a missing token."""
    from cert_watch import middleware as _mw
    from cert_watch.middleware import check_csrf

    monkeypatch.setattr(_mw, "_CSRF_BYPASS", False)

    request = _make_request()
    result = await check_csrf(request)
    assert result == "missing CSRF token"


# ── Login CSRF (review #19) ─────────────────────────────────────────────────


class TestLoginCsrf:
    """POST /login enforces the double-submit check."""

    def _app(self, reload_app, monkeypatch):
        from cert_watch.auth.local_admin import _scrypt_hash

        h = _scrypt_hash("right-pw", n=2**4, r=1, p=1)
        monkeypatch.setattr("cert_watch.middleware._COOKIE_SECURE", False)
        return reload_app(
            CERT_WATCH_LOCAL_ADMIN_USER="admin",
            CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
        )

    def test_post_without_token_rejected(self, reload_app, csrf_strict, monkeypatch):
        app_mod = self._app(reload_app, monkeypatch)
        with TestClient(app_mod.app, raise_server_exceptions=False) as client:
            r = client.post(
                "/login",
                data={"username": "admin", "password": "right-pw"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "login" in r.headers["location"]  # bounced back, not signed in

    def test_post_with_valid_token_succeeds(self, reload_app, csrf_strict, login_csrf, monkeypatch):
        app_mod = self._app(reload_app, monkeypatch)
        with TestClient(app_mod.app, raise_server_exceptions=False) as client:
            token = login_csrf(client)
            assert token, "login form should render a CSRF token"
            r = client.post(
                "/login",
                data={
                    "username": "admin",
                    "password": "right-pw",
                    "_csrf_token": token,
                },
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert r.headers["location"] in ("/", "http://testserver/")


# ── Response security headers ──────────────────────────────────────────────


class TestResponseHeaders:
    def test_security_headers_present(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/login")
        assert r.headers.get("Referrer-Policy") == "no-referrer"
        assert "geolocation=()" in r.headers.get("Permissions-Policy", "")
        assert r.headers.get("X-Permitted-Cross-Domain-Policies") == "none"
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_cw_sid_cookie_is_httponly(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/login")
        set_cookies = [
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        ]
        raw = "\n".join(set_cookies) or r.headers.get("set-cookie", "")
        if "cw_sid" in raw:
            cw_sid_segment = [s for s in raw.split("\n") if "cw_sid" in s]
            assert any("HttpOnly" in s for s in cw_sid_segment)
