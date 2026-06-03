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
        from cert_watch.routes.api import _runbook_url_error

        assert _runbook_url_error("javascript:alert(1)") is not None
        assert _runbook_url_error("data:text/html,<script>") is not None
        assert _runbook_url_error("vbscript:msgbox") is not None

    def test_http_and_empty_allowed(self):
        from cert_watch.routes.api import _runbook_url_error

        assert _runbook_url_error("https://wiki.example.com/runbook") is None
        assert _runbook_url_error("http://10.0.0.5/wiki") is None
        assert _runbook_url_error("") is None
        assert _runbook_url_error("   ") is None


class TestComplianceFailsClosed:
    def test_missing_security_returns_503_not_empty_signature(self):
        from fastapi import HTTPException

        from cert_watch.routes.api import compliance_signing_key

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

        from cert_watch.routes.api import compliance_signing_key

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
