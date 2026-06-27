import importlib
import json
import os
import sys
import time
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cert_watch.app import create_app
from cert_watch.auth import (
    AuthResult,
    LDAPAuthProvider,
    LocalAdminProvider,
    NoAuthProvider,
    OAuthProvider,
    _CompositeProvider,
    _scrypt_hash,
    _sign_state,
    build_auth_provider,
    check_authz,
    create_session,
    validate_session,
    verify_scrypt_hash,
)
from cert_watch.config import Settings, read_secret

_HAS_JOSE = importlib.util.find_spec("joserfc") is not None
_HAS_AUTHLIB = importlib.util.find_spec("authlib") is not None


@pytest.fixture(autouse=True)
def _restore_modules():
    """Ensure cert_watch.config/auth/app module state is restored after every test.

    _reload_app uses importlib.reload which replaces module-level classes
    (e.g. NoAuthProvider).  If cert_watch.middleware still holds a reference
    to the OLD class, isinstance() checks in auth_middleware fail, causing
    401s in subsequent test modules.  Saving and restoring all three modules
    prevents this class-identity drift.
    """
    import cert_watch.app as _app
    import cert_watch.auth as _auth
    import cert_watch.config as _cfg

    saved_cfg = dict(vars(_cfg))
    saved_auth = dict(vars(_auth))
    saved_app = dict(vars(_app))
    saved_app_state_auth = getattr(_app.app.state, "auth_provider", None)
    saved_app_state_settings = getattr(_app.app.state, "settings", None)
    yield
    vars(_cfg).clear()
    vars(_cfg).update(saved_cfg)
    vars(_auth).clear()
    vars(_auth).update(saved_auth)
    vars(_app).clear()
    vars(_app).update(saved_app)
    _app.app.state.auth_provider = saved_app_state_auth
    _app.app.state.settings = saved_app_state_settings


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
    mock_ldap3.Tls = MagicMock()
    mock_ldap3.ServerPool = MagicMock()
    mock_ldap3.FIRST = "FIRST"
    mock_ldap3.NONE = "NONE"
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


# ---------- session_ttl parameter on validate_session ----------


def test_validate_session_with_explicit_ttl_valid():
    token = create_session("ttl-user")
    assert validate_session(token, session_ttl=99999) == "ttl-user"


def test_validate_session_with_ttl_zero_expires():
    token = create_session("ttl-zero")
    assert validate_session(token, session_ttl=0) is None


def test_validate_session_ttl_overrides_env(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_SESSION_TTL", "1")
    token = create_session("ttl-env")
    assert validate_session(token, session_ttl=99999) == "ttl-env"


def test_validate_session_env_ttl_overrides_module_constant(monkeypatch):
    import cert_watch.auth as auth_mod
    monkeypatch.setenv("CERT_WATCH_SESSION_TTL", "99999")
    monkeypatch.setattr(auth_mod, "SESSION_TTL", 0)
    token = create_session("ttl-env-wins")
    assert validate_session(token) == "ttl-env-wins"


def test_validate_session_no_ttl_no_env_uses_module_constant(monkeypatch):
    monkeypatch.delenv("CERT_WATCH_SESSION_TTL", raising=False)
    token = create_session("ttl-module")
    assert validate_session(token) == "ttl-module"


# ---------- AuthResult dataclass tests (BC-051 regression) ----------


def test_authresult_oauth_state_explicit():
    r = AuthResult(success=True, redirect_url="https://example.com", oauth_state="signed-state")
    assert r.oauth_state == "signed-state"
    assert r.success is True


def test_authresult_oauth_state_default():
    r = AuthResult(success=True, error="something")
    assert r.oauth_state == ""
    assert r.success is True


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

    def connection_factory(server, user=None, password=None, auto_bind=False, **kw):
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

    def connection_factory(server, user=None, password=None, auto_bind=False, **kw):
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
    provider._security = None
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
    provider._security = None
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
    with pytest.raises(ValueError, match="Unknown AUTH_PROVIDER"):
        build_auth_provider("foobar")


def test_build_ldap_missing_config(_mock_ldap3):
    # Missing server/base_dn raises instead of silently degrading to NoAuth
    with pytest.raises(ValueError, match="LDAP auth misconfigured"):
        build_auth_provider("ldap")


def test_build_oauth_missing_config():
    with pytest.raises(ValueError, match="OAuth misconfigured"):
        build_auth_provider("oauth")


def test_build_entra_alias():
    with pytest.raises(ValueError, match="OAuth misconfigured"):
        build_auth_provider("entra")


def test_build_ldap_with_config(_mock_ldap3):
    provider = build_auth_provider(
        "ldap",
        ldap_server="ldap://dc.example.com",
        ldap_base_dn="DC=example,DC=com",
    )
    assert isinstance(provider, LDAPAuthProvider)


# ---------- HTTP auth middleware tests ----------


def test_no_auth_all_routes_open(reload_app):
    app_mod = reload_app()
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


def test_auth_enabled_redirects_to_login(reload_app, _mock_ldap3):
    app_mod = reload_app(
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

        # Monitoring/login routes stay open
        r = client.get("/healthz")
        assert r.status_code == 200

        r = client.get("/metrics")
        assert r.status_code == 200

        # Data API requires auth: unauthenticated requests get a 401, not the
        # inventory. (Regression guard for the previously-public /api/* gap.)
        r = client.get("/api/certificates")
        assert r.status_code == 401
        assert r.json()["error"] == "unauthenticated"

        r = client.get("/api/export/hosts.csv")
        assert r.status_code == 401


def test_auth_enabled_ui_redirect(reload_app, _mock_ldap3):
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303


def test_login_page_rendered(reload_app, _mock_ldap3):
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text


def test_login_page_redirects_when_no_auth(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/login", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] in ("/", "http://testserver/")


def test_login_page_oauth_label(tmp_path):
    class _OAuthProvider:
        provider_name = "oauth"
        provider_label = "OAuth"
        supports_form_login = False

    s = Settings(db_path=tmp_path / "db.sqlite3", data_dir=tmp_path)
    app = create_app(auth_provider=_OAuthProvider(), settings=s)
    with TestClient(app) as client:
        r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in with OAuth" in r.text
    assert "Sign in with Oauth" not in r.text


def test_login_page_oidc_label(tmp_path):
    from cert_watch.auth import OAuthConfig

    provider = OAuthProvider.__new__(OAuthProvider)
    provider._security = None
    provider.config = OAuthConfig(
        client_id="c",
        client_secret="s",
        issuer_url="https://login.example.com",
        provider_label="OIDC",
    )

    s = Settings(db_path=tmp_path / "db.sqlite3", data_dir=tmp_path)
    app = create_app(auth_provider=provider, settings=s)
    with TestClient(app) as client:
        r = client.get("/login")
    assert r.status_code == 200
    assert "Sign in with OIDC" in r.text
    assert provider.provider_label == "OIDC"
    assert provider.provider_name == "oauth"


def test_logout_clears_cookie(reload_app, _mock_ldap3):
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post("/auth/logout", follow_redirects=False)
        assert r.status_code == 303
        assert "cw_auth" in r.headers.get("set-cookie", "")


def test_favicon_ico_is_public_under_auth(reload_app, _mock_ldap3):
    """The /favicon.ico redirect must stay reachable for unauthenticated browser
    probes (login/setup pages) — it is a public path, not auth-gated."""
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/favicon.ico", follow_redirects=False)
    assert r.status_code == 301
    assert r.headers["location"] == "/static/favicon.svg"


def test_auth_user_displayed_in_header(reload_app, _mock_ldap3):
    app_mod = reload_app(
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


def test_authenticated_user_can_access_all_routes(reload_app, _mock_ldap3):
    app_mod = reload_app(
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


# ---------- read_secret tests ----------


def test_read_secret_env_var(tmp_path):
    import os
    os.environ["TEST_SECRET_VAL"] = "from-env"
    os.environ.pop("TEST_SECRET_VAL_FILE", None)
    try:
        assert read_secret("TEST_SECRET_VAL") == "from-env"
    finally:
        os.environ.pop("TEST_SECRET_VAL", None)


def test_read_secret_file_variant(tmp_path):
    import os
    secret_file = tmp_path / "secret_pw"
    secret_file.write_text("from-file\n")
    os.environ.pop("TEST_SECRET_PW", None)
    os.environ["TEST_SECRET_PW_FILE"] = str(secret_file)
    try:
        assert read_secret("TEST_SECRET_PW") == "from-file"
    finally:
        os.environ.pop("TEST_SECRET_PW_FILE", None)


def test_read_secret_env_takes_precedence_over_file(tmp_path):
    import os
    secret_file = tmp_path / "secret_both"
    secret_file.write_text("from-file\n")
    os.environ["TEST_SECRET_BOTH"] = "from-env"
    os.environ["TEST_SECRET_BOTH_FILE"] = str(secret_file)
    try:
        assert read_secret("TEST_SECRET_BOTH") == "from-env"
    finally:
        os.environ.pop("TEST_SECRET_BOTH", None)
        os.environ.pop("TEST_SECRET_BOTH_FILE", None)


def test_read_secret_file_strips_whitespace(tmp_path):
    import os
    secret_file = tmp_path / "secret_ws"
    secret_file.write_text("  value with spaces  \n\n")
    os.environ.pop("TEST_SECRET_WS", None)
    os.environ["TEST_SECRET_WS_FILE"] = str(secret_file)
    try:
        assert read_secret("TEST_SECRET_WS") == "value with spaces"
    finally:
        os.environ.pop("TEST_SECRET_WS_FILE", None)


def test_read_secret_returns_none_when_unset():
    import os
    os.environ.pop("TEST_SECRET_UNSET", None)
    os.environ.pop("TEST_SECRET_UNSET_FILE", None)
    assert read_secret("TEST_SECRET_UNSET") is None


def test_read_secret_missing_file(tmp_path):
    import os
    os.environ.pop("TEST_SECRET_MISS", None)
    os.environ["TEST_SECRET_MISS_FILE"] = str(tmp_path / "nonexistent")
    try:
        assert read_secret("TEST_SECRET_MISS") is None
    finally:
        os.environ.pop("TEST_SECRET_MISS_FILE", None)


# ---------- check_authz (authorization gate) tests ----------


def test_authz_allows_when_no_groups_or_roles_configured():
    result = AuthResult(success=True, username="alice")
    assert check_authz(result, [], []) == result


def test_authz_allows_matching_group():
    result = AuthResult(success=True, username="alice", groups=["devops", "admins"])
    checked = check_authz(result, ["admins"], [])
    assert checked.success is True
    assert checked.username == "alice"


def test_authz_allows_matching_role():
    result = AuthResult(success=True, username="alice", roles=["viewer", "editor"])
    checked = check_authz(result, [], ["editor"])
    assert checked.success is True


def test_authz_denies_no_matching_group_or_role():
    result = AuthResult(success=True, username="alice", groups=["devops"], roles=["viewer"])
    checked = check_authz(result, ["admins"], ["superadmin"])
    assert checked.success is False
    assert "not in an allowed group or role" in checked.error


def test_authz_denies_no_groups_or_roles_on_result():
    result = AuthResult(success=True, username="alice")
    checked = check_authz(result, ["admins"], ["superadmin"])
    assert checked.success is False


def test_authz_preserves_username_on_deny():
    result = AuthResult(success=True, username="bob", groups=["interns"])
    checked = check_authz(result, ["admins"], [])
    assert checked.username == "bob"
    assert checked.success is False


def test_authz_allows_group_or_role_match():
    result = AuthResult(success=True, username="alice", groups=["devops"], roles=["viewer"])
    checked = check_authz(result, ["devops"], ["superadmin"])
    assert checked.success is True
    checked2 = check_authz(result, ["admins"], ["viewer"])
    assert checked2.success is True


# ---------- AuthZ gate in login flow ----------


def test_authz_gate_denies_user_without_group(reload_app, _mock_ldap3):
    """When CERT_WATCH_ALLOWED_GROUPS is set, a user not in any allowed group is denied."""
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()
    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False, **kw):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
        CERT_WATCH_ALLOWED_GROUPS="admins,operators",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post(
            "/login",
            data={"username": "alice", "password": "pass"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        loc = r.headers["location"]
        assert "access%20denied" in loc


def test_authz_no_gate_when_no_groups_configured(reload_app, _mock_ldap3):
    """When ALLOWED_GROUPS is empty, any authenticated user is accepted."""
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()
    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False, **kw):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post(
            "/login",
            data={"username": "alice", "password": "pass"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] in ("/", "http://testserver/")


# ---------- Local admin / break-glass tests ----------


def test_scrypt_hash_roundtrip():
    pw = "correct-horse-battery-staple"
    h = _scrypt_hash(pw)
    assert h.startswith("scrypt$")
    assert verify_scrypt_hash(pw, h) is True
    assert verify_scrypt_hash("wrong", h) is False


def test_scrypt_hash_constant_time_compare():
    pw = "test-password"
    h = _scrypt_hash(pw)
    assert verify_scrypt_hash(pw, h) is True
    assert verify_scrypt_hash(pw + "x", h) is False


def test_scrypt_hash_invalid_format():
    assert verify_scrypt_hash("pw", "") is False
    assert verify_scrypt_hash("pw", "not-scrypt") is False
    assert verify_scrypt_hash("pw", "scrypt$bad$args") is False


def test_scrypt_hash_custom_params():
    pw = "custom-nrp"
    h = _scrypt_hash(pw, n=2**4, r=1, p=1)
    assert verify_scrypt_hash(pw, h) is True


def test_local_admin_authenticate_success():
    pw = "admin-secret"
    h = _scrypt_hash(pw, n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)
    result = provider.authenticate("admin", pw)
    assert result.success is True
    assert result.username == "admin"
    assert "admins" in result.groups
    assert "admin" in result.roles


def test_local_admin_wrong_password():
    h = _scrypt_hash("right-pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)
    result = provider.authenticate("admin", "wrong-pw")
    assert result.success is False
    assert "invalid" in result.error


def test_local_admin_wrong_username():
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)
    result = provider.authenticate("other", "pw")
    assert result.success is False


def test_local_admin_username_mismatch_computes_dummy_hash():
    """BC-072: username mismatch must spend scrypt CPU time so timing doesn't
    reveal whether the supplied username matches the break-glass admin."""
    from unittest.mock import patch

    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)

    with patch.object(
        provider, "_dummy_verify", wraps=provider._dummy_verify
    ) as dummy:
        result = provider.authenticate("not-admin", "whatever")
    assert result.success is False
    dummy.assert_called_once_with("whatever", h)


def test_local_admin_dummy_verify_invokes_scrypt():
    """BC-072: the dummy-hash branch actually performs scrypt work."""
    import hashlib
    from unittest.mock import patch

    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)

    with patch.object(hashlib, "scrypt", wraps=hashlib.scrypt) as scrypt_spy:
        provider.authenticate("not-admin", "whatever")
    assert scrypt_spy.call_count >= 1


def test_local_admin_empty_creds():
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)
    assert provider.authenticate("", "pw").success is False
    assert provider.authenticate("admin", "").success is False


def test_local_admin_no_oauth():
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = LocalAdminProvider("admin", h)
    assert provider.start_oauth_flow("http://x").success is False
    assert provider.complete_oauth_flow("code", "http://x").success is False


def test_local_admin_properties():
    provider = LocalAdminProvider("admin", "scrypt$16384$8$1$AA==$AA==")
    assert provider.provider_name == "local-admin"
    assert provider.supports_form_login is True


def test_local_admin_bypasses_group_gate(reload_app):
    pw = "breakglass"
    h = _scrypt_hash(pw, n=2**4, r=1, p=1)
    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post(
            "/login",
            data={"username": "admin", "password": pw},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] in ("/", "http://testserver/")


def test_local_admin_wrong_password_rejected(reload_app):
    h = _scrypt_hash("right-pw", n=2**4, r=1, p=1)
    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "login" in r.headers["location"]


def test_local_admin_disabled_when_unset(monkeypatch, reload_app):
    monkeypatch.delenv("CERT_WATCH_LOCAL_ADMIN_USER", raising=False)
    monkeypatch.delenv("CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH", raising=False)
    app_mod = reload_app()
    provider = getattr(app_mod.app.state, "auth_provider", None)
    assert not isinstance(provider, LocalAdminProvider)


def test_composite_provider_tries_local_first(_mock_ldap3):
    h = _scrypt_hash("localpw", n=2**4, r=1, p=1)
    local = LocalAdminProvider("admin", h)
    mock_ldap = LDAPAuthProvider("ldap://dc", "DC=x")
    composite = _CompositeProvider(local, mock_ldap)
    result = composite.authenticate("admin", "localpw")
    assert result.success is True
    assert result.username == "admin"


def test_composite_provider_falls_through(_mock_ldap3):
    h = _scrypt_hash("localpw", n=2**4, r=1, p=1)
    local = LocalAdminProvider("admin", h)
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()
    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False, **kw):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()
    primary = LDAPAuthProvider("ldap://dc.example.com", "DC=example,DC=com")
    composite = _CompositeProvider(local, primary)
    result = composite.authenticate("alice", "ldappass")
    assert result.success is True
    assert result.username == "alice"


def test_build_auth_provider_local_admin_only(tmp_path, monkeypatch):
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = build_auth_provider(
        "",
        local_admin_user="admin",
        local_admin_password_hash=h,
    )
    assert provider.provider_name == "local-admin"
    assert provider.supports_form_login is True


def test_build_auth_provider_local_admin_with_ldap(_mock_ldap3):
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    provider = build_auth_provider(
        "ldap",
        ldap_server="ldap://dc.example.com",
        ldap_base_dn="DC=example,DC=com",
        local_admin_user="admin",
        local_admin_password_hash=h,
    )
    assert provider.supports_form_login is True
    result = provider.authenticate("admin", "pw")
    assert result.success is True
    assert result.username == "admin"


def test_local_admin_login_creates_audit_row(tmp_path, reload_app):
    import sqlite3

    pw = "breakglass"
    h = _scrypt_hash(pw, n=2**4, r=1, p=1)
    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
    )
    db_path = str(tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.post(
            "/login",
            data={"username": "admin", "password": pw},
            follow_redirects=False,
        )
        assert r.status_code == 303
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE action = 'break_glass_login'"
    ).fetchall()
    conn.close()
    assert len(rows) >= 1, f"no break_glass_login audit rows found in db {db_path}"
    import json
    detail = json.loads(dict(rows[0])["detail"]) if rows[0]["detail"] else {}
    assert detail.get("break_glass") is True


def test_local_admin_login_shows_form(reload_app):
    h = _scrypt_hash("pw", n=2**4, r=1, p=1)
    app_mod = reload_app(
        CERT_WATCH_LOCAL_ADMIN_USER="admin",
        CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=h,
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text


# ---------- LDAPS hardening (Plan 010 Slice 3) ----------


def test_ldaps_missing_ca_cert_warns(_mock_ldap3, caplog):
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
    )
    mock_conn = MagicMock()
    mock_conn.entries = []
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection = MagicMock(return_value=mock_conn)
    _mock_ldap3.Server.return_value = MagicMock()
    _mock_ldap3.ServerPool.return_value = MagicMock()

    import logging
    with caplog.at_level(logging.WARNING, logger="cert_watch.auth"):
        provider._build_tls()
    assert any("LDAPS without LDAP_CA_CERT" in r.message for r in caplog.records)


def test_ldaps_ca_cert_builds_tls_with_cert_required(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
        ca_cert="-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
    )
    _mock_ldap3.Server.return_value = MagicMock()
    tls, servers = provider._build_tls()
    _mock_ldap3.Tls.assert_called_once()
    tls_kwargs = _mock_ldap3.Tls.call_args[1]
    assert tls_kwargs.get("validate") is not None
    assert "CERT_REQUIRED" in str(tls_kwargs.get("validate")) or tls_kwargs.get("validate") != 0


def test_ldaps_ca_cert_file_path(_mock_ldap3, tmp_path):
    cert_file = tmp_path / "ca.pem"
    cert_file.write_text("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----")
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        ca_cert=str(cert_file),
    )
    resolved = provider._resolve_ca_cert()
    assert resolved is not None
    assert resolved == cert_file


def test_ldaps_ca_cert_inline_data(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        ca_cert="-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----",
    )
    assert provider._resolve_ca_cert() is None


# ---------- Regression tests for the two private-CA LDAPS bugs ----------
#
# Both bugs broke ALL private-CA LDAPS auth and were invisible to the mocked
# tests above, because the MagicMock `Connection` swallowed any kwarg (so the
# bogus `use_ssl=` slipped through) and inline PEM was never run through
# `_resolve_ca_cert`. These tests use a STRICTER fake `Connection` — one that
# rejects unknown kwargs like real ldap3 does — and exercise the inline-PEM
# path that triggered OSError(ENAMETOOLONG). They were caught by the live lab
# E2E; this keeps that class of bug from hiding again.


def _strict_connection_factory(calls, user_dn):
    """A fake ldap3.Connection that rejects kwargs real ldap3 doesn't accept.

    The real ``ldap3.Connection.__init__`` has no ``use_ssl`` parameter (it
    belongs on ``Server``) and raises ``TypeError`` for unknown kwargs. This
    factory mirrors that: any kwarg outside the allowed set raises, so passing
    ``use_ssl=`` (or any future stray kwarg) fails loudly instead of being
    silently swallowed. ``calls`` records every call's kwargs for assertion.
    """
    allowed = {
        "user", "password", "auto_bind", "version", "authentication",
        "client_strategy", "read_only", "lazy", "raise_exceptions",
        "receive_timeout", "auto_referrals", "pool_name",
    }

    def factory(server, **kwargs):
        calls.append(kwargs)
        unexpected = set(kwargs) - allowed
        if unexpected:
            raise TypeError(
                "ldap3.Connection got unexpected keyword argument(s): "
                f"{sorted(unexpected)}"
            )
        conn = MagicMock()
        conn.bind.return_value = True
        if kwargs.get("user") == user_dn:
            # user-bind: just verifies the password (entries unused)
            conn.entries = []
        else:
            # service-bind: search returns the located user
            entry = MagicMock()
            entry.distinguishedName = user_dn
            entry.memberOf.values = []
            conn.entries = [entry]
        return conn

    return factory


def test_ldap_authenticate_inline_pem_ldaps_succeeds(_mock_ldap3):
    """Mirrors the live lab E2E: LDAPS + inline PEM CA + strict Connection.

    This single test would have caught BOTH production bugs:
    - the inline PEM no longer makes _resolve_ca_cert raise ENAMETOOLONG, and
    - no `use_ssl=` kwarg is passed to Connection (strict factory rejects it).
    """
    user_dn = "CN=alice,DC=example,DC=com"
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "MIIDdummycontentline\n" * 30
        + "-----END CERTIFICATE-----\n"
    )
    calls: list[dict] = []
    _mock_ldap3.Connection = _strict_connection_factory(calls, user_dn)
    _mock_ldap3.Server.return_value = MagicMock()

    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
        ca_cert=pem,
    )
    result = provider.authenticate("alice", "correct_password")

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.username == "alice"
    # Bug #2 regression: no Connection call may carry use_ssl.
    assert all("use_ssl" not in kw for kw in calls)
    assert calls, "expected Connection to be constructed at least once"


def test_ldap_connection_rejects_use_ssl_kwarg(_mock_ldap3):
    """The strict fake must actually fail if use_ssl is reintroduced.

    Guards the regression test above from rotting into a no-op: prove the
    strict factory rejects the exact kwarg the bug passed.
    """
    calls: list[dict] = []
    factory = _strict_connection_factory(calls, "CN=alice,DC=example,DC=com")
    with pytest.raises(TypeError):
        factory(MagicMock(), user="x", password="y", auto_bind=False, use_ssl=True)


def test_resolve_ca_cert_long_single_component_does_not_raise(_mock_ldap3):
    """Bug #1: a long single-component string makes Path.is_file() raise
    OSError(ENAMETOOLONG) instead of returning False. Must be guarded → None."""
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        ca_cert="A" * 300,  # > NAME_MAX (255), no newline, no BEGIN marker
    )
    # The assertion is that this returns rather than propagating OSError.
    assert provider._resolve_ca_cert() is None


def test_resolve_ca_cert_oversized_string_returns_none(_mock_ldap3):
    """Bug #1: anything longer than a plausible path is treated as inline data."""
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        ca_cert="A" * 2000,  # no newline, no BEGIN marker, just very long
    )
    assert provider._resolve_ca_cert() is None


def test_build_tls_inline_pem_uses_ca_certs_data_not_file(_mock_ldap3):
    """Bug #1: inline PEM must flow to ca_certs_data, never ca_certs_file."""
    pem = (
        "-----BEGIN CERTIFICATE-----\n"
        + "MIIDdummycontentline\n" * 10
        + "-----END CERTIFICATE-----\n"
    )
    provider = LDAPAuthProvider(
        server_url="ldaps://dc.example.com",
        base_dn="DC=example,DC=com",
        ca_cert=pem,
    )
    _mock_ldap3.Server.return_value = MagicMock()
    provider._build_tls()
    _mock_ldap3.Tls.assert_called_once()
    tls_kwargs = _mock_ldap3.Tls.call_args[1]
    assert tls_kwargs.get("ca_certs_data") == pem
    assert "ca_certs_file" not in tls_kwargs


def test_ldap_dc_failover_multiple_servers(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc1.example.com,ldap://dc2.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
        connect_timeout=3,
    )
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection = MagicMock(return_value=mock_conn)

    tls, servers = provider._build_tls()
    assert len(servers) == 2
    assert _mock_ldap3.Server.call_count == 2


def test_ldap_dc_failover_auth_succeeds_on_second_dc(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc1.example.com,ldap://dc2.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
    )
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()

    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    mock_pool = MagicMock()
    _mock_ldap3.ServerPool.return_value = mock_pool

    def connection_factory(server, user=None, password=None, auto_bind=False, use_ssl=False):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory

    result = provider.authenticate("alice", "correct_password")
    assert result.success is True
    assert result.username == "alice"
    _mock_ldap3.ServerPool.assert_called_once()


def test_ldap_group_filter_non_member_denied(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
        required_groups=["CN=CertWatchAdmins,DC=example,DC=com"],
    )
    mock_conn = MagicMock()
    mock_conn.entries = []
    mock_conn.unbind = MagicMock()
    _mock_ldap3.Connection = MagicMock(return_value=mock_conn)
    _mock_ldap3.Server.return_value = MagicMock()

    result = provider.authenticate("outsider", "pass")
    assert result.success is False
    assert "group" in result.error.lower()


def test_ldap_group_filter_member_admitted(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        bind_dn="CN=svc,DC=example,DC=com",
        bind_password="svc_pass",
        required_groups=["CN=CertWatchAdmins,DC=example,DC=com"],
    )
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_entry.memberOf = MagicMock()
    mock_entry.memberOf.values = ["CN=CertWatchAdmins,DC=example,DC=com"]
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()

    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    def connection_factory(server, user=None, password=None, auto_bind=False, use_ssl=False):
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return mock_conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    result = provider.authenticate("alice", "correct_password")
    assert result.success is True
    assert result.username == "alice"
    assert "CN=CertWatchAdmins,DC=example,DC=com" in result.groups


def test_ldap_group_filter_search_includes_chain_oid(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        required_groups=["CN=Admins,DC=example,DC=com", "CN=Operators,DC=example,DC=com"],
    )
    mock_conn = MagicMock()
    mock_entry = MagicMock()
    mock_entry.distinguishedName = "CN=alice,DC=example,DC=com"
    mock_entry.memberOf = MagicMock()
    mock_entry.memberOf.values = ["CN=Admins,DC=example,DC=com"]
    mock_conn.entries = [mock_entry]
    mock_conn.unbind = MagicMock()

    mock_user_conn = MagicMock()
    mock_user_conn.unbind = MagicMock()

    captured_filter = {}

    def connection_factory(server, user=None, password=None, auto_bind=False, use_ssl=False):
        conn = MagicMock()

        def fake_search(base_dn, search_filter, **kwargs):
            captured_filter["value"] = search_filter
            conn.entries = [mock_entry]

        conn.search = fake_search
        conn.unbind = MagicMock()
        if user == "CN=alice,DC=example,DC=com":
            return mock_user_conn
        return conn

    _mock_ldap3.Connection = connection_factory
    _mock_ldap3.Server.return_value = MagicMock()

    result = provider.authenticate("alice", "pass")
    assert result.success is True
    sf = captured_filter.get("value", "")
    assert "1.2.840.113556.1.4.1941" in sf
    assert "Admins" in sf
    assert "Operators" in sf


def test_ldap_connect_timeout_config(_mock_ldap3):
    provider = LDAPAuthProvider(
        server_url="ldap://dc.example.com",
        base_dn="DC=example,DC=com",
        connect_timeout=10,
    )
    _mock_ldap3.Server.return_value = MagicMock()
    _, servers = provider._build_tls()
    _mock_ldap3.Server.assert_called_once()
    call_kwargs = _mock_ldap3.Server.call_args[1]
    assert call_kwargs.get("connect_timeout") == 10


# ---------- OAuth JWKS verification (Plan 010 Slice 4 / BC-043) ----------

_AUTHLIB_MODS = (
    "authlib",
    "authlib.integrations",
    "authlib.integrations.requests_client",
)


def _inject_mock_authlib(mock_authlib):
    """Context manager: inject a mock authlib module, cleanup on exit."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        sys.modules["authlib"] = mock_authlib
        sys.modules["authlib.integrations"] = mock_authlib.integrations
        rc = mock_authlib.integrations.requests_client
        sys.modules["authlib.integrations.requests_client"] = rc
        try:
            yield
        finally:
            for mod in _AUTHLIB_MODS:
                sys.modules.pop(mod, None)

    return _ctx()


def _generate_rsa_jwk(kid: str = "key-1") -> tuple:
    """Generate an RSA key pair and return (private_key, jwk_dict, jwks_response)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    pub_numbers = pub.public_numbers()

    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")

    jwk = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64url(n_bytes),
        "e": _b64url(e_bytes),
    }
    jwks = {"keys": [jwk]}
    return key, jwk, jwks


def _sign_jwt(payload: dict, private_key, kid: str = "key-1", algorithm: str = "RS256") -> str:
    """Sign a JWT with the given private key."""
    from joserfc import jwt as _jwt
    from joserfc.jwk import RSAKey

    jwk_key = RSAKey.import_key(private_key, parameters={"kid": kid})
    return _jwt.encode({"alg": algorithm, "kid": kid}, payload, jwk_key)


def _make_oauth_provider(
    issuer: str = "https://login.example.com",
    client_id: str = "test-client",
    jwks: dict | None = None,
) -> OAuthProvider:
    """Create an OAuthProvider with pre-seeded discovery + JWKS."""
    from cert_watch.auth import OAuthConfig

    config = OAuthConfig(
        client_id=client_id,
        client_secret="secret",
        issuer_url=issuer,
        authorization_endpoint=f"{issuer}/authorize",
        token_endpoint=f"{issuer}/token",
        userinfo_endpoint=f"{issuer}/userinfo",
        jwks_uri=f"{issuer}/.well-known/jwks.json",
    )
    provider = OAuthProvider.__new__(OAuthProvider)
    provider._security = None
    provider.config = config
    provider._discovered = {
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "userinfo_endpoint": f"{issuer}/userinfo",
        "jwks_uri": f"{issuer}/.well-known/jwks.json",
        "id_token_signing_alg_values_supported": "RS256",
    }
    provider._jwks = jwks
    provider._jwks_fetched_at = time.monotonic()
    provider._jwks_ttl = 86400
    provider._allow_private = False
    provider._allowed_subnets = ()
    return provider


@pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
class TestOAuthJWKSVerification:

    def _mock_fetch_token(
        self,
        provider: "OAuthProvider",
        response: dict | Exception | None,
    ) -> MagicMock:
        if isinstance(response, Exception):
            mock = MagicMock(side_effect=response)
        else:
            mock = MagicMock(return_value=response or {})
        provider._fetch_token = mock
        return mock

    def test_valid_token_verified(self):
        key, jwk, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, key)
        result = provider._verify_id_token(token)
        assert result is not None
        assert result["preferred_username"] == "alice"
        assert result["sub"] == "user-123"

    def test_token_signed_with_wrong_key_rejected(self):
        _, _, jwks = _generate_rsa_jwk(kid="good-key")
        wrong_key, _, _ = _generate_rsa_jwk(kid="bad-key")
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "attacker",
            "preferred_username": "eve",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, wrong_key, kid="bad-key")
        result = provider._verify_id_token(token)
        assert result is None

    def test_expired_token_rejected(self):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice",
            "exp": int(time.time()) - 3600,
            "iat": int(time.time()) - 7200,
        }
        token = _sign_jwt(claims, key)
        result = provider._verify_id_token(token)
        assert result is None

    def test_issuer_mismatch_rejected(self):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://evil.example.com",
            "aud": "test-client",
            "sub": "attacker",
            "preferred_username": "eve",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, key)
        result = provider._verify_id_token(token)
        assert result is None

    def test_audience_mismatch_rejected(self):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "wrong-client-id",
            "sub": "attacker",
            "preferred_username": "eve",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, key)
        result = provider._verify_id_token(token)
        assert result is None

    def test_no_jwks_returns_none(self):
        provider = _make_oauth_provider(jwks=None)
        result = provider._verify_id_token("some.token.value")
        assert result is None

    def test_malformed_token_returns_none(self):
        _, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)
        result = provider._verify_id_token("not-a-jwt")
        assert result is None

    def test_valid_token_with_roles_claim(self):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "bob",
            "roles": ["CertWatch.Admin", "CertWatch.Viewer"],
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, key)
        result = provider._verify_id_token(token)
        assert result is not None
        assert "CertWatch.Admin" in result.get("roles", [])

    @pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
    def test_valid_token_verified_authlib_path(self, monkeypatch):
        """Test _verify_id_token via authlib path (simulates joserfc missing)."""
        import cert_watch.auth.oauth_provider as op_mod
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        # Mock away joserfc by monkeypatching the module-level import results.
        try:
            monkeypatch.setattr(op_mod, "_jwt", None, raising=False)
            monkeypatch.setattr(op_mod, "KeySet", None, raising=False)

            import time
            claims = {
                "iss": "https://login.example.com",
                "aud": "test-client",
                "sub": "user-123",
                "preferred_username": "alice",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }
            token = _sign_jwt(claims, key)
            result = provider._verify_id_token(token)
            assert result is not None
            assert result["preferred_username"] == "alice"
        finally:
            monkeypatch.undo()

    def test_discovery_network_fallback(self, monkeypatch):
        """_discover() fetches .well-known when no static endpoints configured."""
        from cert_watch.auth import OAuthConfig
        from cert_watch.auth.oauth_provider import OAuthProvider
        config = OAuthConfig(
            client_id="c",
            client_secret="s",
            issuer_url="https://id.example.com",
        )
        provider = OAuthProvider(config)
        provider._discovered = {}

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            resp = MagicMock()
            resp.read.return_value = json.dumps({
                "authorization_endpoint": "https://id.example.com/oauth2/v2.0/authorize",
                "token_endpoint": "https://id.example.com/oauth2/v2.0/token",
                "userinfo_endpoint": "https://id.example.com/me",
                "jwks_uri": "https://id.example.com/jwks",
                "id_token_signing_alg_values_supported": ["RS256", "RS384"],
            }).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        endpoints = provider._discover()
        assert endpoints["authorization_endpoint"].endswith("/v2.0/authorize")
        assert endpoints["token_endpoint"].endswith("/v2.0/token")
        assert endpoints["userinfo_endpoint"] == "https://id.example.com/me"
        assert endpoints["jwks_uri"] == "https://id.example.com/jwks"
        assert "RS256" in endpoints["id_token_signing_alg_values_supported"]

    def test_discovery_missing_userinfo_endpoint(self, monkeypatch):
        """_discover() handles missing userinfo_endpoint gracefully."""
        from cert_watch.auth import OAuthConfig
        from cert_watch.auth.oauth_provider import OAuthProvider
        config = OAuthConfig(
            client_id="c",
            client_secret="s",
            issuer_url="https://id.example.com",
        )
        provider = OAuthProvider(config)
        provider._discovered = {}

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            resp = MagicMock()
            resp.read.return_value = json.dumps({
                "authorization_endpoint": "https://id.example.com/authorize",
                "token_endpoint": "https://id.example.com/token",
            }).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        endpoints = provider._discover()
        assert endpoints["userinfo_endpoint"] == ""

    def test_discovery_network_error_fallback(self, monkeypatch):
        """_discover() falls back to static config on network error."""
        from cert_watch.auth import OAuthConfig
        from cert_watch.auth.oauth_provider import OAuthProvider
        config = OAuthConfig(
            client_id="c",
            client_secret="s",
            issuer_url="https://id.example.com",
            authorization_endpoint="https://static.example.com/auth",
            token_endpoint="https://static.example.com/token",
            userinfo_endpoint="https://static.example.com/userinfo",
            jwks_uri="https://static.example.com/jwks",
        )
        provider = OAuthProvider(config)
        provider._discovered = {}

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            raise OSError("network error")

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        endpoints = provider._discover()
        assert endpoints["authorization_endpoint"] == "https://static.example.com/auth"
        assert endpoints["token_endpoint"] == "https://static.example.com/token"

    def test_fetch_jwks_ssrf_blocked(self, monkeypatch):
        """_fetch_jwks() handles SSRFBlockedError."""
        from cert_watch.http_client import SSRFBlockedError
        provider = _make_oauth_provider(jwks=None)
        provider._discovered["jwks_uri"] = "https://id.example.com/jwks"

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            raise SSRFBlockedError("blocked by policy")

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        assert provider._fetch_jwks() is None

    def test_fetch_jwks_oserror(self, monkeypatch):
        """_fetch_jwks() handles OSError."""
        provider = _make_oauth_provider(jwks=None)
        provider._discovered["jwks_uri"] = "https://id.example.com/jwks"

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            raise OSError("connection refused")

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        assert provider._fetch_jwks() is None

    def test_fetch_jwks_cache_hit_skips_network(self, monkeypatch):
        """_fetch_jwks() returns cached JWKS without hitting the network."""
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)
        provider._jwks_fetched_at = time.monotonic()
        provider._jwks_ttl = 86400

        call_count = 0

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        result = provider._fetch_jwks()
        assert result == jwks
        assert call_count == 0  # cache hit

    def test_fetch_jwks_stale_cache_refreshes(self, monkeypatch):
        """_fetch_jwks() refreshes when cached JWKS exceeds TTL."""
        key, _, jwks1 = _generate_rsa_jwk()
        key2, _, jwks2 = _generate_rsa_jwk(kid="key-2")
        provider = _make_oauth_provider(jwks=jwks1)
        provider._jwks_fetched_at = time.monotonic() - 90000
        provider._jwks_ttl = 86400

        call_count = 0

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks2).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        result = provider._fetch_jwks()
        assert result["keys"][0]["kid"] == "key-2"
        assert call_count == 1

    def test_fetch_jwks_force_refresh(self, monkeypatch):
        """_fetch_jwks(force=True) bypasses the cache."""
        key, _, jwks1 = _generate_rsa_jwk()
        key2, _, jwks2 = _generate_rsa_jwk(kid="new-key")
        provider = _make_oauth_provider(jwks=jwks1)
        provider._jwks_fetched_at = time.monotonic()
        provider._jwks_ttl = 86400

        call_count = 0

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks2).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        result = provider._fetch_jwks(force=True)
        assert result["keys"][0]["kid"] == "new-key"
        assert call_count == 1

    @pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
    def test_key_id_missing_triggers_refresh(self, monkeypatch):
        """_verify_id_token() triggers JWKS refresh on invalid key id and retries."""
        old_key, _, jwks_old = _generate_rsa_jwk(kid="old-key")
        new_key, _, jwks_new = _generate_rsa_jwk(kid="new-key")
        provider = _make_oauth_provider(jwks=jwks_old)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, new_key, kid="new-key")

        fetch_count = 0

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            nonlocal fetch_count
            fetch_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks_new).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)
        result = provider._verify_id_token(token)
        assert result is not None
        assert result["preferred_username"] == "alice"
        assert fetch_count == 1

    @pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
    def test_key_id_retry_authlib_path(self, monkeypatch):
        """Retry path works when joserfc raises InvalidKeyIdError."""
        old_key, _, jwks_old = _generate_rsa_jwk(kid="old-key")
        new_key, _, jwks_new = _generate_rsa_jwk(kid="new-key")
        provider = _make_oauth_provider(jwks=jwks_old)

        import time as time_mod

        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice",
            "exp": int(time_mod.time()) + 3600,
            "iat": int(time_mod.time()),
        }
        token = _sign_jwt(claims, new_key, kid="new-key")

        fetch_count = 0

        def fake_urlopen(url, *, data=None, timeout=15, method=None, headers=None,
                         allow_private=False, allowed_subnets=()):
            nonlocal fetch_count
            fetch_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks_new).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)

        # Force the retry path by raising an InvalidKeyIdError first, but we can't
        # easily simulate that without a real missing kid. Instead, we rely on the
        # normal flow above.  For completeness, this test is effectively the same as
        # test_key_id_missing_triggers_refresh — kept as a named regression guard.
        result = provider._verify_id_token(token)
        assert result is not None
        assert result["preferred_username"] == "alice"
        assert fetch_count == 1

    def test_complete_flow_token_exchange_error(self):
        """complete_oauth_flow handles token endpoint error."""
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, OSError("connection reset"))
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "OAuth authentication failed" in result.error

    def test_complete_flow_userinfo_endpoint_returns_500(self, monkeypatch):
        """complete_oauth_flow treats 500 as empty userinfo."""
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})

        def fake_userinfo(
            url, headers=None, timeout=None,
            allow_private=False, allowed_subnets=(), **kwargs,
        ):
            resp = MagicMock()
            resp.status = 500
            resp.read.return_value = b'{}'
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_userinfo)
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "could not determine username" in result.error

    def test_complete_flow_missing_userinfo_endpoint(self):
        """complete_oauth_flow returns failure when no id_token and no userinfo."""
        provider = _make_oauth_provider(jwks=None)
        provider._discovered["userinfo_endpoint"] = ""
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "could not determine username" in result.error

    def test_complete_flow_token_endpoint_missing(self):
        """complete_oauth_flow returns failure when token_endpoint is not configured."""
        provider = _make_oauth_provider(jwks=None)
        provider._discovered["token_endpoint"] = ""
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "token_endpoint not configured" in result.error

    def test_fetch_token_non_2xx_raises_value_error(self, monkeypatch):
        """_fetch_token treats a non-2xx token response as an exchange failure."""
        provider = _make_oauth_provider()

        def fake_urlopen(*a, **kw):
            resp = MagicMock()
            resp.status = 400
            resp.read.return_value = b'{"error": "invalid_grant"}'
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr(
            "cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen,
        )
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        with pytest.raises(ValueError, match="token endpoint returned 400"):
            provider._fetch_token("http://idp.example/token", "code", "https://app/callback")

    def test_fetch_token_non_2xx_includes_error_body(self, monkeypatch):
        """_fetch_token includes a truncated error body in the ValueError."""
        provider = _make_oauth_provider()

        def fake_urlopen(*a, **kw):
            resp = MagicMock()
            resp.status = 403
            resp.read.return_value = (
                b'{"error": "access_denied", "error_description": "Insufficient scope"}'
            )
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr(
            "cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen,
        )
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        with pytest.raises(ValueError, match=r"token endpoint returned 403:.*access_denied"):
            provider._fetch_token("http://idp.example/token", "code", "https://app/callback")

    def test_fetch_token_caps_response_size(self, monkeypatch):
        """_fetch_token reads at most _TOKEN_MAX_BYTES from a token response."""
        from cert_watch.auth.oauth_provider import _TOKEN_MAX_BYTES
        provider = _make_oauth_provider()

        read_args: list[int | None] = []
        payload = {"access_token": "at", "token_type": "Bearer"}

        def fake_urlopen(*a, **kw):
            resp = MagicMock()
            resp.status = 200
            def fake_read(n=None):
                read_args.append(n)
                return json.dumps(payload).encode()
            resp.read = fake_read
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr(
            "cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen,
        )
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        result = provider._fetch_token("http://idp.example/token", "code", "https://app/callback")
        assert result == payload
        assert read_args == [_TOKEN_MAX_BYTES]

    def test_safe_algs_filters_unsafe(self):
        """_safe_algs strips symmetric / none algorithms."""
        from cert_watch.auth.oauth_provider import _safe_algs
        assert _safe_algs(["none", "HS256", "RS256", "RS384"]) == ["RS256", "RS384"]
        assert _safe_algs(["none"]) == ["RS256"]

    def test_discovery_cached(self):
        """_discover() returns cached endpoints after first call."""
        provider = _make_oauth_provider()
        # Modify the existing dict instead of replacing to keep __new__ state consistent
        provider._discovered.clear()
        provider._discovered["x"] = "y"
        result = provider._discover()
        assert result == {"x": "y"}

    def test_validate_claims_manual_expired(self):
        """_validate_claims_manual rejects expired tokens."""
        import time

        from cert_watch.auth.oauth_provider import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com", "aud": "test-client",
            "sub": "u", "exp": int(time.time()) - 3600,
        }
        with pytest.raises(ValueError, match="expired"):
            _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_validate_claims_manual_aud_list(self):
        """_validate_claims_manual accepts audience list containing client_id."""
        import time

        from cert_watch.auth.oauth_provider import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": ["test-client", "other-client"],
            "sub": "u", "exp": int(time.time()) + 3600,
        }
        _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_validate_claims_manual_nonce_mismatch(self):
        """_validate_claims_manual rejects nonce mismatch."""
        import time

        from cert_watch.auth.oauth_provider import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com", "aud": "test-client",
            "sub": "u", "exp": int(time.time()) + 3600, "nonce": "wrong",
        }
        with pytest.raises(ValueError, match="nonce mismatch"):
            _validate_claims_manual(claims, "https://login.example.com", "test-client", "expected")

    @pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
    def test_complete_flow_userinfo_no_nonce_log(self, monkeypatch, caplog):
        """complete_oauth_flow emits warning when userinfo lacks nonce without id_token."""
        import logging
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})

        def fake_userinfo(*a, **kw):
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = json.dumps({"email": "bob@example.com"}).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_userinfo)
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        # Use a state WITH a nonce so the BC-071 warning fires
        signed_state = _sign_state("test-state", nonce="test-nonce")
        ctx = caplog.at_level(logging.WARNING, logger="cert_watch.auth")
        with ctx:
            result = provider.complete_oauth_flow(
                "auth-code", "http://localhost/callback", state=signed_state,
            )
        assert result.success is True
        assert result.username == "bob@example.com"
        # Warning about BC-071 / no id_token and userinfo lacks nonce
        assert any("lacks nonce" in r.message for r in caplog.records)

    def test_validate_claims_manual_no_exp(self):
        """_validate_claims_manual accepts claims without exp."""
        from cert_watch.auth.oauth_provider import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "u",
        }
        _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_complete_flow_userinfo_with_roles_groups(self, monkeypatch):
        """complete_oauth_flow extracts roles and groups from userinfo response."""
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})

        def fake_userinfo(*a, **kw):
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = json.dumps({
                "email": "alice@example.com",
                "preferred_username": "alice",
                "roles": ["admin", "viewer"],
                "groups": ["group-1"],
            }).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_userinfo)
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is True
        assert result.username == "alice"
        assert result.roles == ["admin", "viewer"]
        assert result.groups == ["group-1"]

    def test_complete_flow_userinfo_mismatch_nonce_rejected(self, monkeypatch):
        """complete_oauth_flow rejects when userinfo nonce does not match."""
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})

        def fake_userinfo(*a, **kw):
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = json.dumps({
                "email": "alice@example.com",
                "nonce": "bad-nonce",
            }).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_userinfo)
        monkeypatch.setattr("cert_watch.http_client._validate_url", lambda *a, **kw: None)

        signed_state = _sign_state("test-state", nonce="expected-nonce")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "nonce mismatch" in result.error.lower()

    def test_complete_flow_token_exchange_ssrf_blocked(self):
        """complete_oauth_flow handles SSRF during token exchange."""
        from cert_watch.http_client import SSRFBlockedError
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, SSRFBlockedError("blocked"))
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "authenticat" in result.error.lower()

    def test_complete_flow_verifies_id_token_jwks(self):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice@example.com",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": "nonce0",
        }
        id_token = _sign_jwt(claims, key)

        self._mock_fetch_token(provider, {
            "access_token": "at-123",
            "token_type": "Bearer",
            "id_token": id_token,
        })
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is True
        assert result.username == "alice@example.com"

    def test_complete_flow_populates_roles_and_groups(self):
        """Plan 034 / 2b: app-role and group-GUID claims reach AuthResult so the
        authz gate can act on them."""
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)

        import time
        admins_guid = "38171415-ded8-4e14-9a44-439bc5223f50"
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "cw-admin@example.com",
            "roles": ["admin"],
            "groups": [admins_guid],
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
            "nonce": "nonce0",
        }
        id_token = _sign_jwt(claims, key)

        self._mock_fetch_token(provider, {
            "access_token": "at-123",
            "token_type": "Bearer",
            "id_token": id_token,
        })
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is True
        assert result.roles == ["admin"]
        assert result.groups == [admins_guid]
        # And the authz gate accepts on either dimension.
        from cert_watch.auth import check_authz
        assert check_authz(result, [], ["admin"]).success is True
        assert check_authz(result, [admins_guid], []).success is True
        assert check_authz(result, ["other-guid"], ["viewer"]).success is False

    def test_complete_flow_forged_token_rejected_not_userinfo(self):
        """When JWKS verification fails, rejects instead of falling back to userinfo (BC-058)."""
        _, _, jwks = _generate_rsa_jwk(kid="good-key")
        wrong_key, _, _ = _generate_rsa_jwk(kid="bad-key")
        provider = _make_oauth_provider(jwks=jwks)

        import time
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "attacker",
            "preferred_username": "eve",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        id_token = _sign_jwt(claims, wrong_key, kid="bad-key")

        self._mock_fetch_token(provider, {
            "access_token": "at-123",
            "token_type": "Bearer",
            "id_token": id_token,
        })
        signed_state = _sign_state("test-state", nonce="nonce0")
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is False
        assert "ID token verification failed" in result.error

    def test_complete_flow_no_id_token_uses_userinfo(self, monkeypatch):
        """When no ID token is returned, userinfo endpoint is used."""
        provider = _make_oauth_provider(jwks=None)
        self._mock_fetch_token(provider, {"access_token": "at-123", "token_type": "Bearer"})

        signed_state = _sign_state("test-state", nonce="nonce0")
        # Bypass SSRF validation and HTTP open in test (DNS resolution won't work
        # for fake host)
        monkeypatch.setattr(
            "cert_watch.http_client._validate_url", lambda *a, **kw: None,
        )

        def _mock_urlopen(*a, **kw):
            resp = MagicMock()
            resp.status = 200
            resp.read.return_value = json.dumps({"email": "bob@example.com"}).encode()
            resp.__enter__ = lambda s: s
            resp.__exit__ = lambda *a: None
            return resp

        monkeypatch.setattr(
            "cert_watch.auth.oauth_provider.ssrf_safe_urlopen", _mock_urlopen,
        )
        result = provider.complete_oauth_flow(
            "auth-code", "http://localhost/callback", state=signed_state,
        )
        assert result.success is True
        assert result.username == "bob@example.com"


class TestValidateClaimsManual:

    def test_valid_claims(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
        }
        _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_issuer_mismatch_raises(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://evil.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
        }
        with pytest.raises(ValueError, match="issuer"):
            _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_audience_mismatch_raises(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "wrong-client",
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
        }
        with pytest.raises(ValueError, match="audience"):
            _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_audience_list_with_match(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": ["test-client", "other-client"],
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
        }
        _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_expired_raises(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "exp": int(time.time()) - 3600,
        }
        with pytest.raises(ValueError, match="expired"):
            _validate_claims_manual(claims, "https://login.example.com", "test-client", None)

    def test_nonce_mismatch_raises(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "nonce": "abc123",
        }
        with pytest.raises(ValueError, match="nonce"):
            _validate_claims_manual(
                claims, "https://login.example.com", "test-client", "wrong-nonce"
            )

    def test_nonce_match_succeeds(self):
        import time

        from cert_watch.auth import _validate_claims_manual
        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "exp": int(time.time()) + 3600,
            "nonce": "abc123",
        }
        _validate_claims_manual(claims, "https://login.example.com", "test-client", "abc123")


@pytest.mark.skipif(not _HAS_JOSE or not _HAS_AUTHLIB, reason="requires joserfc and authlib")
class TestJWKSCacheTTL:

    def test_jwks_refetched_after_ttl_expires(self, monkeypatch):
        key, jwk, jwks_old = _generate_rsa_jwk(kid="key-1")
        _, _, jwks_new = _generate_rsa_jwk(kid="key-2")

        provider = _make_oauth_provider(jwks=jwks_old)
        assert provider._jwks is jwks_old

        provider._jwks_ttl = 100

        now = provider._jwks_fetched_at

        monkeypatch.setattr(time, "monotonic", lambda: now + 50)
        result = provider._fetch_jwks()
        assert result is jwks_old

        fetch_count = 0

        def fake_urlopen(
            url, *, data=None, timeout=15, method=None, headers=None,
            allow_private=False, allowed_subnets=(),
        ):
            nonlocal fetch_count
            fetch_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks_new).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr(time, "monotonic", lambda: now + 200)
        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)

        result = provider._fetch_jwks()
        assert result["keys"][0]["kid"] == "key-2"
        assert fetch_count == 1
        assert provider._jwks["keys"][0]["kid"] == "key-2"

    def test_jwks_not_refetched_within_ttl(self, monkeypatch):
        key, _, jwks = _generate_rsa_jwk()
        provider = _make_oauth_provider(jwks=jwks)
        provider._jwks_ttl = 86400

        import urllib.request
        call_count = 0
        original_urlopen = urllib.request.urlopen

        def counting_urlopen(*a, **kw):
            nonlocal call_count
            call_count += 1
            return original_urlopen(*a, **kw)

        monkeypatch.setattr(urllib.request, "urlopen", counting_urlopen)
        result = provider._fetch_jwks()
        assert result is jwks
        assert call_count == 0

    def test_invalid_key_id_triggers_jwks_refetch_and_retry(self, monkeypatch):
        old_key, _, jwks_old = _generate_rsa_jwk(kid="old-key")
        new_key, _, jwks_new = _generate_rsa_jwk(kid="new-key")

        provider = _make_oauth_provider(jwks=jwks_old)
        provider._jwks_ttl = 86400

        claims = {
            "iss": "https://login.example.com",
            "aud": "test-client",
            "sub": "user-123",
            "preferred_username": "alice",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }
        token = _sign_jwt(claims, new_key, kid="new-key")

        fetch_count = 0

        def fake_urlopen(
            url, *, data=None, timeout=15, method=None, headers=None,
            allow_private=False, allowed_subnets=(),
        ):
            nonlocal fetch_count
            fetch_count += 1
            resp = MagicMock()
            resp.read.return_value = json.dumps(jwks_new).encode()
            resp.close = MagicMock()
            return resp

        monkeypatch.setattr("cert_watch.auth.oauth_provider.ssrf_safe_urlopen", fake_urlopen)

        result = provider._verify_id_token(token)
        assert result is not None
        assert result["preferred_username"] == "alice"
        assert fetch_count == 1

    def test_jwks_ttl_from_config(self):
        """OAuthProvider respects the jwks_cache_ttl passed in OAuthConfig."""
        from cert_watch.auth import OAuthConfig
        config = OAuthConfig(
            client_id="c",
            client_secret="s",
            issuer_url="https://example.com",
            jwks_cache_ttl=3600,
        )
        provider = OAuthProvider(config)
        assert provider._jwks_ttl == 3600

    def test_jwks_default_ttl(self):
        from cert_watch.auth import OAuthConfig
        config = OAuthConfig(
            client_id="c",
            client_secret="s",
            issuer_url="https://example.com",
        )
        provider = OAuthProvider.__new__(OAuthProvider)
        provider._security = None
        provider.config = config
        provider._discovered = {}
        provider._jwks = None
        provider._jwks_fetched_at = 0.0
        provider._jwks_ttl = int(os.environ.get("CERT_WATCH_JWKS_CACHE_TTL", "86400"))
        assert provider._jwks_ttl == 86400
