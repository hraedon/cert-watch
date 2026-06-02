"""Tests for Plan 020 S4 (CSP nonces) and BC-070 (CSRF query-param removal)."""

from types import SimpleNamespace

from fastapi.testclient import TestClient


def _reload_app(tmp_path, monkeypatch):
    """Build a fresh app via create_app() (no module reloading, Plan 018 B1)."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    return SimpleNamespace(app=create_app(settings=Settings.from_env()))


# ── Security headers ────────────────────────────────────────────────────────
# NOTE: Plan 020 S4 (CSP nonce) was reverted — see BC-075. CSP keeps
# 'unsafe-inline' for script-src because the templates use inline event-handler
# attributes (onclick=) that nonces cannot whitelist. Proper hardening is
# deferred to the design-session template rewrite.


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


# ── BC-070: CSRF token no longer accepted via query parameter ───────────────


def test_csrf_query_param_token_rejected(tmp_path, monkeypatch):
    """A CSRF token supplied only in the query string must be rejected."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("CERT_WATCH_CSRF_DISABLED", raising=False)
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
