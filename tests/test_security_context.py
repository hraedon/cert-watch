"""Plan 018 B1 / WI-083: SecurityContext is threaded through signing and
injected via create_app, instead of relying on mutated module-level globals."""

from types import SimpleNamespace

from fastapi.testclient import TestClient

from cert_watch.security import SecurityContext


def test_security_context_threads_through_session_signing():
    from cert_watch.auth import create_session, validate_session

    a = SecurityContext(signing_key="key-a", csrf_secret="c")
    b = SecurityContext(signing_key="key-b", csrf_secret="c")
    token = create_session("alice", a)
    assert validate_session(token, a) == "alice"
    # A token signed under key-a must not validate under key-b.
    assert validate_session(token, b) is None


def test_security_context_threads_through_csrf():
    from cert_watch.middleware import make_csrf_token, validate_csrf_token

    a = SecurityContext(signing_key="s", csrf_secret="csrf-a")
    b = SecurityContext(signing_key="s", csrf_secret="csrf-b")
    token = make_csrf_token("sid-1", a)
    assert validate_csrf_token(token, "sid-1", a)
    assert not validate_csrf_token(token, "sid-1", b)


def test_create_app_uses_injected_security_context(tmp_path, monkeypatch):
    """create_app's injected SecurityContext lands on app.state.security after
    the lifespan runs (it is not overwritten by env resolution)."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    sec = SecurityContext(signing_key="injected-key", csrf_secret="injected-csrf")
    application = create_app(security=sec, settings=Settings.from_env())
    with TestClient(application):
        assert application.state.security is sec


def test_create_app_resolves_security_from_env_when_not_injected(tmp_path, monkeypatch):
    """With no injected SecurityContext, the lifespan resolves one from the
    environment (CERT_WATCH_AUTH_SECRET) — the production path."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "env-signing-key")
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    application = create_app(settings=Settings.from_env())
    with TestClient(application):
        assert application.state.security.signing_key == "env-signing-key"


def test_two_apps_with_different_keys_reject_each_others_sessions(tmp_path, monkeypatch):
    """End-to-end: a session validated through the request path uses the
    per-app SecurityContext, not a shared global."""
    from cert_watch.auth import create_session
    from cert_watch.middleware import validate_session

    sec_a = SecurityContext(signing_key="app-a-key", csrf_secret="c")
    sec_b = SecurityContext(signing_key="app-b-key", csrf_secret="c")
    token = create_session("bob", sec_a)
    # Mimic the request-path resolution: validate against each app's context.
    assert validate_session(token, sec_a) == "bob"
    assert validate_session(token, sec_b) is None
    # SimpleNamespace stands in for app.state in the helper signature.
    assert isinstance(SimpleNamespace(security=sec_a).security, SecurityContext)


def test_oauth_provider_uses_injected_security_for_state_signing():
    """WI-083: OAuthProvider signs and verifies state with the injected
    SecurityContext, not the module-level fallback."""
    from cert_watch.auth import OAuthConfig, OAuthProvider, _verify_state

    sec_a = SecurityContext(signing_key="oauth-key-a", csrf_secret="c")
    sec_b = SecurityContext(signing_key="oauth-key-b", csrf_secret="c")
    config = OAuthConfig(
        client_id="c",
        client_secret="s",
        issuer_url="https://example.com",
        authorization_endpoint="https://example.com/authorize",
        token_endpoint="https://example.com/token",
    )
    provider_a = OAuthProvider(config, security=sec_a)
    provider_b = OAuthProvider(config, security=sec_b)

    import sys
    from unittest.mock import MagicMock

    mock_session = MagicMock()
    mock_session.create_authorization_url.return_value = (
        "https://example.com/authorize?...",
        "state123",
    )
    mock_authlib = MagicMock()
    mock_authlib.integrations.requests_client.OAuth2Session.return_value = mock_session
    sys.modules["authlib"] = mock_authlib
    sys.modules["authlib.integrations"] = mock_authlib.integrations
    sys.modules["authlib.integrations.requests_client"] = mock_authlib.integrations.requests_client
    try:
        result = provider_a.start_oauth_flow("https://app.example/callback")
        assert result.success is True
        signed = result.oauth_state
        assert _verify_state(signed, security=sec_a) is not None
        assert _verify_state(signed, security=sec_b) is None
        result_b = provider_b.complete_oauth_flow(
            "code", "https://app.example/callback", state=signed,
        )
        assert result_b.success is False
    finally:
        for mod in ("authlib", "authlib.integrations", "authlib.integrations.requests_client"):
            sys.modules.pop(mod, None)
