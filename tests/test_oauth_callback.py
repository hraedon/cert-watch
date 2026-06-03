"""OAuth callback handler tests (BC-113).

`/auth/callback` is the most security-sensitive request path in the app: it
validates the signed `state` against the `cw_oauth_state` cookie, completes the
code exchange at the provider boundary, runs the group/role authorization gate,
and mints the session cookie. These tests drive every branch of the handler
with adversarial inputs, asserting that a session is issued *only* on the happy
path and never when validation or authorization fails.

The OAuth provider is mocked at the `AuthProvider` boundary (no real IdP); the
signed-state cookie is forged with the app's live signing key from inside the
TestClient context, exactly as the real `/auth/login` step would mint it.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from cert_watch.auth import SESSION_COOKIE
from cert_watch.auth.protocol import AuthProvider, AuthResult, NoAuthProvider

STATE_COOKIE = "cw_oauth_state"


class FakeOAuthProvider(AuthProvider):
    """OAuth provider whose `complete_oauth_flow` returns a canned AuthResult."""

    def __init__(self, complete_result: AuthResult):
        self._complete_result = complete_result

    def authenticate(self, username: str, password: str) -> AuthResult:
        return AuthResult(success=False, error="form login not supported")

    def start_oauth_flow(self, redirect_uri: str) -> AuthResult:
        return AuthResult(
            success=True, redirect_url="https://idp.example/authorize", oauth_state="signed"
        )

    def complete_oauth_flow(self, code: str, redirect_uri: str, state: str = "") -> AuthResult:
        return self._complete_result

    @property
    def provider_name(self) -> str:
        return "oauth"

    @property
    def supports_form_login(self) -> bool:
        return False


def _make_app(monkeypatch, tmp_path, provider, **env):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    # OAuth requires an explicit base URL (review #3 — no Host-header fallback).
    env.setdefault("CERT_WATCH_BASE_URL", "https://cert-watch.example")
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    return SimpleNamespace(app=create_app(auth_provider=provider, settings=Settings.from_env()))


def _sign(raw_state: str) -> str:
    """Sign an OAuth state with the app's live module-level signing key."""
    from cert_watch.auth import _sign_state

    return _sign_state(raw_state, nonce="nonce0")


# ── No provider ─────────────────────────────────────────────────────────────


def test_callback_with_no_provider_redirects_home(monkeypatch, tmp_path):
    app_mod = _make_app(monkeypatch, tmp_path, NoAuthProvider(), CERT_WATCH_ALLOW_UNAUTH="1")
    with TestClient(app_mod.app) as client:
        r = client.get("/auth/callback?code=abc&state=x", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert r.cookies.get(SESSION_COOKIE) is None


# ── Provider-reported error / missing code ──────────────────────────────────


def test_callback_provider_error_redirects_to_login(monkeypatch, tmp_path):
    provider = FakeOAuthProvider(AuthResult(success=True, username="x"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        r = client.get("/auth/callback?error=access_denied", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=access_denied"
    assert r.cookies.get(SESSION_COOKIE) is None


def test_callback_missing_code(monkeypatch, tmp_path):
    provider = FakeOAuthProvider(AuthResult(success=True, username="x"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        r = client.get("/auth/callback?state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=no+authorization+code"
    assert r.cookies.get(SESSION_COOKIE) is None


# ── State validation (the core CSRF/fixation defenses) ──────────────────────


def test_callback_missing_state_cookie(monkeypatch, tmp_path):
    provider = FakeOAuthProvider(AuthResult(success=True, username="x"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        # No cw_oauth_state cookie set.
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=OAuth+state+cookie+missing"
    assert r.cookies.get(SESSION_COOKIE) is None


def test_callback_forged_state_cookie_bad_signature(monkeypatch, tmp_path):
    """A state cookie with an invalid signature must not authenticate."""
    provider = FakeOAuthProvider(AuthResult(success=True, username="attacker"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, "rawstate:nonce0:deadbeefdeadbeefdeadbeefdeadbeef")
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=OAuth+state+mismatch"
    assert r.cookies.get(SESSION_COOKIE) is None


def test_callback_state_param_does_not_match_cookie(monkeypatch, tmp_path):
    """A correctly signed cookie whose state differs from the query `state`
    (a swapped/replayed state) is rejected."""
    provider = FakeOAuthProvider(AuthResult(success=True, username="attacker"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("realstate"))
        r = client.get("/auth/callback?code=abc&state=DIFFERENT", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=OAuth+state+mismatch"
    assert r.cookies.get(SESSION_COOKIE) is None


# ── Code-exchange failure ───────────────────────────────────────────────────


def test_callback_token_exchange_failure(monkeypatch, tmp_path):
    """If the provider's code exchange fails, redirect to login with no session
    — not a 500, and not a partial session."""
    provider = FakeOAuthProvider(AuthResult(success=False, error="token_exchange_failed"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("rawstate"))
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/login?error=token_exchange_failed"
    assert r.cookies.get(SESSION_COOKIE) is None


# ── Authorization gate ──────────────────────────────────────────────────────


def test_callback_authz_denied_when_not_in_allowed_group(monkeypatch, tmp_path):
    """A successfully *authenticated* user outside CERT_WATCH_ALLOWED_GROUPS is
    denied: redirect to login, no session minted."""
    provider = FakeOAuthProvider(
        AuthResult(success=True, username="bob@example.com", groups=["other"], roles=[])
    )
    app_mod = _make_app(monkeypatch, tmp_path, provider, CERT_WATCH_ALLOWED_GROUPS="admins")
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("rawstate"))
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?error=access")
    assert r.cookies.get(SESSION_COOKIE) is None


def test_callback_authz_allowed_when_in_allowed_group(monkeypatch, tmp_path):
    """The same gate admits a user who holds an allowed group."""
    provider = FakeOAuthProvider(
        AuthResult(success=True, username="carol@example.com", groups=["admins"], roles=[])
    )
    app_mod = _make_app(monkeypatch, tmp_path, provider, CERT_WATCH_ALLOWED_GROUPS="admins")
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("rawstate"))
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    assert r.cookies.get(SESSION_COOKIE)


# ── Happy path ──────────────────────────────────────────────────────────────


def test_callback_refuses_without_base_url(monkeypatch, tmp_path):
    # review #3: with no CERT_WATCH_BASE_URL, OAuth must not derive redirect_uri
    # from the Host header — it refuses rather than risk redirect injection.
    provider = FakeOAuthProvider(AuthResult(success=True, username="alice@example.com"))
    app_mod = _make_app(monkeypatch, tmp_path, provider, CERT_WATCH_BASE_URL="")
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("rawstate"))
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert "CERT_WATCH_BASE_URL" in r.headers["location"]
    assert r.cookies.get(SESSION_COOKIE) is None


def test_callback_happy_path_mints_session(monkeypatch, tmp_path):
    provider = FakeOAuthProvider(AuthResult(success=True, username="alice@example.com"))
    app_mod = _make_app(monkeypatch, tmp_path, provider)
    with TestClient(app_mod.app) as client:
        client.cookies.set(STATE_COOKIE, _sign("rawstate"))
        r = client.get("/auth/callback?code=abc&state=rawstate", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"
    # Session issued…
    assert r.cookies.get(SESSION_COOKIE)
    # …and the one-time state cookie is cleared.
    set_cookie = " ".join(r.headers.get_list("set-cookie"))
    assert STATE_COOKIE in set_cookie
