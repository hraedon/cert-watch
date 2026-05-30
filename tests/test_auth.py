import importlib
import sys
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth import (
    AuthResult,
    LDAPAuthProvider,
    LocalAdminProvider,
    NoAuthProvider,
    OAuthProvider,
    _CompositeProvider,
    _scrypt_hash,
    build_auth_provider,
    check_authz,
    create_session,
    validate_session,
    verify_scrypt_hash,
)
from cert_watch.config import read_secret


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


def test_logout_clears_cookie(reload_app, _mock_ldap3):
    app_mod = reload_app(
        AUTH_PROVIDER="ldap",
        LDAP_SERVER="ldap://dc.example.com",
        LDAP_BASE_DN="DC=example,DC=com",
    )
    with TestClient(app_mod.app, raise_server_exceptions=False) as client:
        r = client.get("/auth/logout", follow_redirects=False)
        assert r.status_code == 303
        assert "cw_auth" in r.headers.get("set-cookie", "")


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
    from cert_watch import auth as auth_mod
    importlib.reload(auth_mod)
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
