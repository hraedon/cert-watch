"""Tests for the security-review hardening fixes (Minimax-M3 review).

Covers the fixes that were implemented directly:
- OAuth JWT algorithm allowlist (#2/#9)
- runbook_url scheme validation / stored-XSS guard (#5)
- compliance report fails closed when the signing key is unavailable (#10)
- response security headers (#other)
- cw_sid is HttpOnly (#4)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestOAuthAlgAllowlist:
    def test_filters_none_and_symmetric(self):
        from cert_watch.auth.oauth_provider import _safe_algs

        assert _safe_algs(["none", "HS256", "RS256"]) == ["RS256"]
        assert _safe_algs(["ES256", "RS512"]) == ["ES256", "RS512"]

    def test_hostile_list_falls_back_to_rs256(self):
        from cert_watch.auth.oauth_provider import _safe_algs

        # A malicious IdP advertising only "none" must not reduce us to
        # accepting unsigned tokens.
        assert _safe_algs(["none"]) == ["RS256"]
        assert _safe_algs([]) == ["RS256"]
        assert _safe_algs(["HS256", "HS384"]) == ["RS256"]


class TestRunbookUrlGuard:
    def test_javascript_scheme_rejected(self):
        from cert_watch.routes.api._shared import _runbook_url_error

        assert _runbook_url_error("javascript:alert(1)") is not None
        assert _runbook_url_error("data:text/html,<script>") is not None
        assert _runbook_url_error("vbscript:msgbox") is not None

    def test_http_and_empty_allowed(self):
        from cert_watch.routes.api._shared import _runbook_url_error

        assert _runbook_url_error("https://wiki.example.com/runbook") is None
        assert _runbook_url_error("http://10.0.0.5/wiki") is None
        assert _runbook_url_error("") is None
        assert _runbook_url_error("   ") is None


class TestComplianceFailsClosed:
    def test_missing_security_returns_503_not_empty_signature(self):
        from fastapi import HTTPException

        from cert_watch.routes.api._shared import compliance_signing_key

        class _State:
            security = None

        class _App:
            state = _State()

        class _Req:
            app = _App()

        with pytest.raises(HTTPException) as exc:
            compliance_signing_key(_Req())
        assert exc.value.status_code == 503

    def test_empty_signing_key_returns_503(self):
        from fastapi import HTTPException

        from cert_watch.routes.api._shared import compliance_signing_key

        class _Security:
            signing_key = ""

        class _State:
            security = _Security()

        class _App:
            state = _State()

        class _Req:
            app = _App()

        with pytest.raises(HTTPException) as exc:
            compliance_signing_key(_Req())
        assert exc.value.status_code == 503


class TestLoginCsrf:
    """Login CSRF (review #19): POST /login enforces the double-submit check."""

    def _app(self, reload_app, monkeypatch):
        from cert_watch.auth.local_admin import _scrypt_hash

        h = _scrypt_hash("right-pw", n=2**4, r=1, p=1)
        # The cw_sid cookie defaults to Secure; TestClient speaks http, so flip
        # it off here or the double-submit cookie never round-trips in the test.
        monkeypatch.setattr("cert_watch.middleware._COOKIE_SECURE", False)
        # CSRF is globally disabled in the test env (autouse fixture); re-enable
        # it here so we actually exercise the new enforcement.
        return reload_app(
            CERT_WATCH_CSRF_DISABLED="0",
            CERT_WATCH_LOCAL_ADMIN_USER="admin",
            CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
        )

    def test_post_without_token_rejected(self, reload_app, monkeypatch):
        app_mod = self._app(reload_app, monkeypatch)
        with TestClient(app_mod.app, raise_server_exceptions=False) as client:
            r = client.post(
                "/login",
                data={"username": "admin", "password": "right-pw"},
                follow_redirects=False,
            )
            assert r.status_code == 303
            assert "login" in r.headers["location"]  # bounced back, not signed in

    def test_post_with_valid_token_succeeds(self, reload_app, login_csrf, monkeypatch):
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


class TestScryptDummyTiming:
    """review F#1: the username-mismatch dummy hash must use the stored hash's
    cost parameters, not a hardcoded n, or it reintroduces a timing oracle."""

    def test_dummy_verify_uses_stored_params(self, monkeypatch):
        import cert_watch.auth.local_admin as la
        from cert_watch.auth.local_admin import LocalAdminProvider, _scrypt_hash

        stored = _scrypt_hash("pw", n=2**4, r=1, p=1)
        parts = stored.split("$")
        parts[1] = "1024"  # advertise a distinctive, non-default cost
        provider = LocalAdminProvider("admin", "$".join(parts))

        seen: list[int | None] = []

        def fake_scrypt(*a, **k):
            seen.append(k.get("n"))
            return b"\x00" * 32

        monkeypatch.setattr(la.hashlib, "scrypt", fake_scrypt)
        # Mismatching username drives the dummy path.
        provider.authenticate("not-admin", "pw")
        assert seen and seen[-1] == 1024  # used stored n, not the hardcoded floor


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
        # Across however the test client surfaces Set-Cookie, the cw_sid cookie
        # must carry HttpOnly.
        raw = "\n".join(set_cookies) or r.headers.get("set-cookie", "")
        if "cw_sid" in raw:
            cw_sid_segment = [s for s in raw.split("\n") if "cw_sid" in s]
            assert any("HttpOnly" in s for s in cw_sid_segment)
