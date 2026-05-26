import importlib
import sys
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import (
    LDAPAuthProvider,
    NoAuthProvider,
    OAuthProvider,
    build_auth_provider,
    create_session,
    validate_session,
)


def _reload_app(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


@pytest.fixture
def _mock_ldap3():
    """Inject a mock ldap3 module so LDAPAuthProvider.__init__ doesn't raise."""
    mock_ldap3 = MagicMock()
    mock_ldap3.core = MagicMock()
    mock_ldap3.core.exceptions = MagicMock()
    mock_ldap3.core.exceptions.LDAPBindError = type("LDAPBindError", (Exception,), {})
    mock_ldap3.utils = MagicMock()
    mock_ldap3.utils.conv = MagicMock()
    mock_ldap3.utils.conv.escape_filter_chars = lambda x: x
    sys.modules["ldap3"] = mock_ldap3
    sys.modules["ldap3.core"] = mock_ldap3.core
    sys.modules["ldap3.core.exceptions"] = mock_ldap3.core.exceptions
    sys.modules["ldap3.utils"] = mock_ldap3.utils
    sys.modules["ldap3.utils.conv"] = mock_ldap3.utils.conv
    yield mock_ldap3
    for mod in ("ldap3", "ldap3.core", "ldap3.core.exceptions", "ldap3.utils", "ldap3.utils.conv"):
        sys.modules.pop(mod, None)


# ---------- Session token tests ----------


def test_create_and_validate_session():
    token = create_session("alice")
    assert validate_session(token) == "alice"


def test_validate_session_invalid_token():
    assert validate_session("garbage") is None
    assert validate_session("") is None


def test_validate_session_tampered():
    token = create_session("bob")
    tampered = "mallory" + token[token.index(":"):]
    assert validate_session(tampered) is None


def test_validate_session_expired(monkeypatch):
    import cert_watch.auth as auth_mod

    token = create_session("olduser")
    monkeypatch.setattr(auth_mod, "SESSION_TTL", 0)
    assert validate_session(token) is None


# ---------- NoAuth provider tests ----------


def test_noauth_authenticate():
    provider = NoAuthProvider()
    result = provider.authenticate("anyone", "anything")
    assert result.success is True
    assert result.username == "anyone"


def test_noauth_authenticate_empty():
    provider = NoAuthProvider()
    result = provider.authenticate("", "")
    assert result.success is True
    assert result.username == "anonymous"


def test_noauth_oauth():
    provider = NoAuthProvider()
    assert provider.start_oauth_flow("http://x").success is False
    assert provider.complete_oauth_flow("code", "http://x").success is False
    assert provider.provider_name == "none"
    assert provider.supports_form_login is False


# ---------- LDAP provider tests ----------


def test_ldap_authenticate_success(_mock_ldap3):
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()

    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
    )
    result = provider.authenticate("alice", "correct_password")
    assert result.success is True
    assert result.username == "alice"


def test_ldap_authenticate_user_not_found(_mock_ldap3):
    mock_conn = MagicMock()
    mock_conn.entries = []
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection = MagicMock(return_value=mock_conn)
    _mock_ldap3.Server.return_value = MagicMock()

    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
    )
    result = provider.authenticate("nobody", "pass")
    assert result.success is False
    assert "not found" in result.error


def test_ldap_authenticate_bad_password(_mock_ldap3):
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False):
        if user == "CN=alice,DC=example,DC=com":
            raise _mock_ldap3.core.exceptions.LDAPBindError("invalid creds")
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
    )
    result = provider.authenticate("alice", "wrong_password")
    assert result.success is False
    assert "invalid credentials" in result.error


def test_ldap_authenticate_empty_creds(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
    )
    result = provider.authenticate("", "")
    assert result.success is False
    assert "required" in result.error


def test_ldap_no_oauth(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
    )
    assert provider.start_oauth_flow("http://x").success is False
    assert provider.complete_oauth_flow("code", "http://x").success is False


def test_ldap_provider_properties(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
    )
    assert provider.provider_name == "ldap"
    assert provider.supports_form_login is True


# ---------- OAuth provider tests ----------


def test_oauth_no_form_login():
    config = MagicMock()
    config.client_id = "cid"
    config.client_secret = "sec"
    config.issuer_url = "https://login.microsoftonline.com/tid/v2.0"
    config.scope = "openid"
    config.authorization_endpoint = "https://login.microsoftonline.com/authorize"
    config.token_endpoint = "https://login.microsoftonline.com/token"
    config.userinfo_endpoint = ""

    provider = OAuthProvider.__new__(OAuthProvider)
    provider.config = config
    provider._discovered = {}

    assert provider.provider_name == "oauth"
    assert provider.supports_form_login is False
    assert provider.authenticate("u", "p").success is False


def test_oauth_start_flow():
    config = MagicMock()
    config.client_id = "cid"
    config.client_secret = "sec"
    config.issuer_url = "https://login.microsoftonline.com/tid/v2.0"
    config.scope = "openid"
    config.authorization_endpoint = "https://login.microsoftonline.com/authorize"
    config.token_endpoint = "https://login.microsoftonline.com/token"
    config.userinfo_endpoint = ""

    provider = OAuthProvider.__new__(OAuthProvider)
    provider.config = config
    provider._discovered = {
        "authorization_endpoint": "https://login.microsoftonline.com/authorize",
        "token_endpoint": "https://login.microsoftonline.com/token",
        "userinfo_endpoint": "",
    }

    mock_session = MagicMock()
    mock_session.create_authorization_url.return_value = (
        "https://login.microsoftonline.com/authorize?...",
        "state123",
    )

    # Mock authlib at the import location used inside start_oauth_flow
    mock_authlib = MagicMock()
    mock_authlib.integrations.requests_client.OAuth2Session.return_value = mock_session
    sys.modules["authlib"] = mock_authlib
    sys.modules["authlib.integrations"] = mock_authlib.integrations
    sys.modules["authlib.integrations.requests_client"] = mock_authlib.integrations.requests_client
    try:
        result = provider.start_oauth_flow("http://localhost/auth/callback")
        assert result.success is True
        assert result.redirect_url.startswith("https://")
    finally:
        for mod in ("authlib", "authlib.integrations", "authlib.integrations.requests_client"):
            sys.modules.pop(mod, None)


# ---------- build_auth_provider factory tests ----------


def test_build_noauth():
    provider = build_auth_provider("")
    assert isinstance(provider, NoAuthProvider)


def test_build_noauth_explicit():
    provider = build_auth_provider("none")
    assert isinstance(provider, NoAuthProvider)


def test_build_unknown():
    provider = build_auth_provider("foobar")
    assert isinstance(provider, NoAuthProvider)


def test_build_ldap_missing_config(_mock_ldap3):
    # Missing server/base_dn falls back to NoAuth
    provider = build_auth_provider("ldap")
    assert isinstance(provider, NoAuthProvider)


def test_build_oauth_missing_config():
    provider = build_auth_provider("oauth")
    assert isinstance(provider, NoAuthProvider)


def test_build_entra_alias():
    provider = build_auth_provider("entra")
    assert isinstance(provider, NoAuthProvider)


def test_build_ldap_with_config(_mock_ldap3):
    provider = build_auth_provider(
        "ldap",
        ldap_server="ldap://dc.example.com",
        ldap_base_dn="DC=example,DC=com",
    )
    assert isinstance(provider, LDAPAuthProvider)


# ---------- HTTP auth middleware tests ----------


def test_no_auth_all_routes_open(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
        assert r.status_code == 200
        r = client.get("/alerts")
        assert r.status_code == 200
        r = client.get("/scan-history")
        assert r.status_code == 200
        r = client.get("/healthz")
        assert r.status_code == 200
        r = client.get("/metrics")
        assert r.status_code == 200
        r = client.get("/api/certificates")
        assert r.status_code == 200


def test_auth_enabled_redirects_to_login(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers["location"]

        r = client.get("/alerts", follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers["location"]

        # Public routes stay open
        r = client.get("/healthz")
        assert r.status_code == 200

        r = client.get("/metrics")
        assert r.status_code == 200

        r = client.get("/api/certificates")
        assert r.status_code == 200


def test_auth_enabled_ui_redirect(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303


def test_login_page_rendered(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text


def test_login_page_redirects_when_no_auth(tmp_path, monkeypatch):
    app_mod = _reload_app(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client:
        r = client.get("/login", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] in ("/", "http://testserver/")


def test_logout_clears_cookie(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/auth/logout", follow_redirects=False)
        assert r.status_code == 303
        assert "cw_auth" in r.headers.get("set-cookie", "")


def test_auth_user_displayed_in_header(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    token = create_session("testuser")
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        client.cookies.set("cw_auth", token)
        r = client.get("/")
        assert r.status_code == 200
        assert "testuser" in r.text
        assert "Logout" in r.text


def test_authenticated_user_can_access_all_routes(tmp_path, monkeypatch, _mock_ldap3):
    app_mod = _reload_app(
        monkeypatch, tmp_path,
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    token = create_session("admin")
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        client.cookies.set("cw_auth", token)
        r = client.get("/")
        assert r.status_code == 200
        r = client.get("/alerts")
        assert r.status_code == 200
        r = client.get("/scan-history")
        assert r.status_code == 200
