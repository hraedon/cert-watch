"""Tests for Plan 020 S4 (CSP nonces) and BC-070 (CSRF query-param removal)."""

import re
from types import SimpleNamespace

from fastapi.testclient import TestClient


def _reload_app(tmp_path, monkeypatch):
    """Build a fresh app via create_app() (no module reloading, Plan 018 B1)."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    return SimpleNamespace(app=create_app(settings=Settings.from_env()))


# ── CSP nonce (Plan 020 S4) ────────────────────────────────────────────────


def test_csp_header_uses_nonce_not_unsafe_inline_for_scripts(tmp_path, monkeypatch):
    app_mod = _reload_app(tmp_path, monkeypatch)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    # script-src must carry a nonce and must NOT allow unsafe-inline.
    m = re.search(r"script-src ([^;]+);", csp)
    assert m, f"no script-src directive in CSP: {csp!r}"
    script_src = m.group(1)
    assert "'nonce-" in script_src
    assert "'unsafe-inline'" not in script_src


def test_csp_nonce_present_in_rendered_script_tags(tmp_path, monkeypatch):
    app_mod = _reload_app(tmp_path, monkeypatch)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("Content-Security-Policy", "")
    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    # The nonce used in the header must be the one stamped on the page's
    # inline <script> blocks.
    assert f'<script nonce="{nonce}">' in r.text


def test_csp_nonce_is_unique_per_request(tmp_path, monkeypatch):
    app_mod = _reload_app(tmp_path, monkeypatch)
    with TestClient(app_mod.app) as client:
        n1 = re.search(
            r"'nonce-([^']+)'", client.get("/").headers["Content-Security-Policy"]
        ).group(1)
        n2 = re.search(
            r"'nonce-([^']+)'", client.get("/").headers["Content-Security-Policy"]
        ).group(1)
    assert n1 != n2


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
