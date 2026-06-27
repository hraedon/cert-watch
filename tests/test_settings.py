"""Tests for GUI settings page (Plan 019 Slice 1)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _mock_ssrf_resolver(monkeypatch):
    """Bypass DNS resolution in SSRF checks for test hostnames.

    The LDAP/SMTP test endpoints now resolve hostnames through
    resolve_and_validate_host before connecting. Tests use hostnames like
    smtp.example.com that don't resolve, so mock the resolver to return a
    public IP. Tests that pass literal IPs (e.g. 127.0.0.1) still hit the
    IP-check path before the resolver.
    """
    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_and_validate_host",
        lambda *a, **k: (None, "93.184.216.34"),
    )

# ---------- Settings page rendering ----------


def test_settings_page_loads(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings")
    assert r.status_code == 200
    assert "Authentication" in r.text
    assert "SMTP" in r.text
    assert "Alerts" in r.text


def test_settings_page_auth_tab(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "Authentication provider" in r.text
    assert "LDAP" in r.text


def test_settings_page_smtp_tab(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=smtp")
    assert r.status_code == 200
    assert "SMTP host" in r.text


def test_settings_page_alerts_tab(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=alerts")
    assert r.status_code == 200
    assert "Webhook URL" in r.text


# ---------- Auth config save ----------


def test_save_auth_config_sets_provider(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "",
                "ldap_server": "",
                "ldap_base_dn": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]


def test_save_auth_config_ldap_with_validation(reload_app):
    """Saving LDAP without required fields should fail gracefully."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "ldap",
                "ldap_server": "",
                "ldap_base_dn": "",
            },
            follow_redirects=False,
        )
    # Should redirect with error since LDAP requires server + base_dn
    assert r.status_code == 303
    assert "error" in r.headers["location"].lower()


# ---------- SMTP config save ----------


def test_save_smtp_config(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "test@example.com",
                "alert_recipients": "ops@example.com",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]


# ---------- Alert config save ----------


def test_save_alert_config(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/alerts",
            data={
                "webhook_url": "https://hooks.test/hook",
                "webhook_template": "",
                "alert_digest_only": "0",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]


# ---------- Test SMTP endpoint ----------


def test_test_smtp_missing_host(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "",
                "smtp_port": "587",
                "alert_from": "test@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "host" in data["error"].lower()


def test_test_smtp_missing_recipients(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "alert_from": "test@example.com",
                "alert_recipients": "",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "recipients" in data["error"].lower()


def test_test_smtp_send_success(reload_app, monkeypatch):
    """A successful SMTP test does STARTTLS, logs in, and sends the probe message."""
    import smtplib

    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            calls["target"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            calls["starttls"] = True

        def login(self, user, password):
            calls["login"] = (user, password)

        def send_message(self, msg):
            calls["sent_to"] = msg["To"]

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "smtp_user": "svc",
                "smtp_password": "pw",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert calls["target"] == ("smtp.example.com", 587)
    assert calls.get("starttls") is True
    assert calls.get("login") == ("svc", "pw")
    assert calls.get("sent_to") == "ops@example.com"


def test_test_smtp_port25_no_starttls_no_creds_succeeds(reload_app, monkeypatch):
    """Port-25 relay without STARTTLS and without auth should send in plaintext.

    Previously this failed unconditionally with "STARTTLS not supported by
    server" even though there were no credentials to protect.
    """
    import smtplib

    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            calls["target"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            raise smtplib.SMTPNotSupportedError("STARTTLS not supported")

        def send_message(self, msg):
            calls["sent_to"] = msg["To"]

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "relay.internal",
                "smtp_port": "25",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert calls.get("sent_to") == "ops@example.com"


def test_test_smtp_no_starttls_with_creds_refuses(reload_app, monkeypatch):
    """When credentials are set but STARTTLS is unavailable, refuse to leak them."""
    import smtplib

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            raise smtplib.SMTPNotSupportedError("STARTTLS not supported")

        def login(self, user, password):  # pragma: no cover - must not be reached
            raise AssertionError("login must not run without TLS")

        def send_message(self, msg):  # pragma: no cover - must not be reached
            raise AssertionError("send must not run without TLS")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "relay.internal",
                "smtp_port": "25",
                "smtp_user": "svc",
                "smtp_password": "pw",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "cleartext" in data["error"].lower()


def test_test_smtp_send_failure_reports_error(reload_app, monkeypatch):
    """A connection failure is surfaced as ok=False with the underlying message."""
    import smtplib

    class FakeSMTP:
        def __init__(self, *a, **k):
            raise OSError("connection refused")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "587",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "connection refused" in data["error"]


# ---------- Test LDAP endpoint ----------


def test_test_ldap_connect_success(reload_app, monkeypatch):
    """A successful LDAP test binds read-only and unbinds cleanly."""
    ldap3 = pytest.importorskip("ldap3")

    calls = {}

    class FakeConn:
        def __init__(self, *a, **k):
            calls["read_only"] = k.get("read_only")
            calls["bound"] = True

        def unbind(self):
            calls["unbound"] = True

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_bind_dn": "CN=svc,DC=example,DC=com",
                "ldap_bind_password": "pw",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert calls.get("bound") and calls.get("unbound")
    assert calls.get("read_only") is True  # the probe never mutates the directory


def test_test_ldap_connect_failure_reports_error(reload_app, monkeypatch):
    """A bind failure is surfaced as ok=False with the underlying message."""
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        def __init__(self, *a, **k):
            raise ldap3.core.exceptions.LDAPBindError("invalid credentials")

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "invalid credentials" in data["error"]


def test_test_ldap_missing_server(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "server" in data["error"].lower()


def test_test_ldap_missing_base_dn(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "base dn" in data["error"].lower()


def test_test_ldap_blank_timeout_returns_json_not_500(reload_app):
    """Regression: a blank connect-timeout must not 500.

    The timeout field has no fallback value, so the browser submits an empty
    string when it is cleared. The handler parsed it with an unguarded int()
    *before* its try/except, so int("") raised ValueError -> 500 "Internal
    Server Error" -> the frontend's r.json() failed with
    "Unexpected token 'I'". The parse is now guarded and blank means default.
    """
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_connect_timeout": "",
            },
        )
    # The point of the test: a clean JSON response, never a 500.
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["ok"] in (True, False)


def test_test_ldap_nonnumeric_timeout_returns_clean_error(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_connect_timeout": "abc",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "timeout" in data["error"].lower()


def test_test_smtp_blank_port_returns_json_not_500(reload_app):
    """Regression: the SMTP test handler had the same unguarded int(port)."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={"smtp_host": "smtp.example.com", "smtp_port": ""},
        )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["ok"] in (True, False)


def test_test_ldap_multi_server_reports_bad_source(reload_app, monkeypatch):
    """A bad URL anywhere in the list must fail the test, not be skipped.

    The old pooled FIRST-strategy probe short-circuited on the first reachable
    server, so a broken second source passed silently. Each URL is now probed.
    """
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        def __init__(self, server, *a, **k):
            # First DC binds fine; the second is unreachable.
            if "dc2" in str(server.host):
                raise ldap3.core.exceptions.LDAPSocketOpenError("connection refused")

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc1.example.com,ldap://dc2.example.com",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "dc2.example.com" in data["error"]


def test_save_auth_blank_bind_password_preserves_stored(reload_app, tmp_path):
    """A blank bind-password submit must not wipe the stored secret (BC fix).

    The field renders masked/blank, so a save without re-typing it previously
    overwrote the saved password with "" — which broke LDAP login after a
    successful test.
    """
    from cert_watch.database import init_schema, kv_get, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "ldap_bind_password", "existing-secret")

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "ldap",
                "ldap_server": "ldap://dc1.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_bind_dn": "CN=svc,DC=example,DC=com",
                "ldap_bind_password": "",  # left blank — must be preserved
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert kv_get(db, "ldap_bind_password") == "existing-secret"


# ---------- kv_store integration ----------


def test_settings_reads_kv_store_values(reload_app, tmp_path):
    """Values saved to kv_store should appear in the settings form."""
    from cert_watch.database import init_schema, kv_set
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "auth_provider", "ldap")
    kv_set(db, "ldap_server", "ldap://dc1.example.com")

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "ldap://dc1.example.com" in r.text


def test_settings_env_overrides_kv(reload_app, tmp_path, monkeypatch):
    """Env vars should take precedence over kv_store values."""
    from cert_watch.database import init_schema, kv_set
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "ldap_server", "ldap://kv-server.example.com")

    monkeypatch.setenv("LDAP_SERVER", "ldap://env-server.example.com")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "ldap://env-server.example.com" in r.text
    assert "ldap://kv-server.example.com" not in r.text


# ---------- Config merge ----------


def test_from_env_with_kv_merges(reload_app, tmp_path):
    """Settings.from_env_with_kv should merge kv_store with env vars."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "ldap_server", "ldap://dc1.example.com")
    kv_set(db, "ldap_base_dn", "DC=example,DC=com")

    s = Settings.from_env_with_kv(db)
    assert s.ldap_server == "ldap://dc1.example.com"
    assert s.ldap_base_dn == "DC=example,DC=com"


def test_from_env_with_kv_env_wins(reload_app, tmp_path, monkeypatch):
    """Env vars should override kv_store in from_env_with_kv."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "ldap_server", "ldap://kv-server.example.com")

    monkeypatch.setenv("LDAP_SERVER", "ldap://env-server.example.com")
    s = Settings.from_env_with_kv(db)
    assert s.ldap_server == "ldap://env-server.example.com"


# ---------- Regression: LDAP_REQUIRED_GROUPS must not split on DN commas ----------
#
# Group DNs contain commas, so a comma-delimited list shredded each DN into RDN
# fragments (CN=..., OU=..., DC=...), the group filter matched nothing, and every
# LDAP login failed "not in required group(s)". Caught by the live lab E2E. The
# delimiter is now semicolon/newline. These guard the whole class.


def test_split_group_dns_preserves_dn_commas():
    from cert_watch.config import split_group_dns

    raw = (
        "CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com;"
        "CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com"
    )
    groups = split_group_dns(raw)
    assert groups == (
        "CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com",
        "CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com",
    )


def test_split_group_dns_single_dn_kept_whole():
    from cert_watch.config import split_group_dns

    # A single DN (with its commas) must come back as ONE element, not five.
    dn = "CN=Admins,OU=Groups,DC=example,DC=com"
    assert split_group_dns(dn) == (dn,)


def test_split_group_dns_newline_delimiter_and_blanks():
    from cert_watch.config import split_group_dns

    raw = "CN=A,DC=x,DC=y\n  \nCN=B,DC=x,DC=y ; "
    assert split_group_dns(raw) == ("CN=A,DC=x,DC=y", "CN=B,DC=x,DC=y")
    assert split_group_dns("") == ()


def test_from_env_required_groups_keeps_full_dns(reload_app, monkeypatch):
    """End-to-end env parse: each semicolon-separated DN stays intact."""
    from cert_watch.config import Settings

    monkeypatch.setenv(
        "LDAP_REQUIRED_GROUPS",
        "CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com;"
        "CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com",
    )
    s = Settings.from_env()
    assert s.ldap_required_groups == (
        "CN=cert-watch-admins,OU=Groups,DC=ad,DC=hraedon,DC=com",
        "CN=cert-watch-users,OU=Groups,DC=ad,DC=hraedon,DC=com",
    )


def test_from_env_with_kv_required_groups_keeps_full_dns(reload_app, tmp_path):
    """Persisted (settings-UI) parse must also keep full DNs."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(
        db,
        "ldap_required_groups",
        "CN=Admins,OU=Groups,DC=example,DC=com;CN=Users,OU=Groups,DC=example,DC=com",
    )
    s = Settings.from_env_with_kv(db)
    assert s.ldap_required_groups == (
        "CN=Admins,OU=Groups,DC=example,DC=com",
        "CN=Users,OU=Groups,DC=example,DC=com",
    )


# ---------- BC-102: Change local admin password ----------


def _seed_local_admin(tmp_path, autogenerated="1"):
    """Seed kv_store with a local admin account."""
    from cert_watch.auth import _scrypt_hash
    from cert_watch.database import init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", _scrypt_hash("testpassword"))
    kv_set(db, "local_admin_autogenerated", autogenerated)
    kv_set(db, "setup_complete", "1")
    return db


def _login_admin(client, monkeypatch):
    """Log in as the local admin by creating a session directly."""
    import cert_watch.middleware as mw
    import cert_watch.routes.auth as auth_routes

    monkeypatch.setattr(mw, "_COOKIE_SECURE", False)
    monkeypatch.setattr(auth_routes, "_COOKIE_SECURE", False)

    # Build a fake request to get the security context
    from starlette.requests import Request as StRequest

    from cert_watch.auth import SESSION_COOKIE, create_session
    from cert_watch.middleware import _request_security
    scope = {
        "type": "http", "method": "GET", "path": "/",
        "query_string": b"", "headers": [],
        "app": client.app,
        "session": {},
    }
    req = StRequest(scope)
    security = _request_security(req)
    token = create_session("admin", security, version=0)
    client.cookies.set(SESSION_COOKIE, token)
    return client


def test_settings_page_shows_change_password_form(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "Local admin password" in r.text
    assert "Rotate password" in r.text
    assert "Current password" in r.text


def test_settings_page_shows_autogenerated_warning(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path, autogenerated="1")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "auto-generated" in r.text


def test_settings_page_no_change_password_without_local_admin(reload_app, tmp_path):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "Local admin password" not in r.text
    assert "Rotate password" not in r.text


def test_change_password_success(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "newsecurepass",
                "confirm_password": "newsecurepass",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "password_changed=1" in r.headers["location"]


def test_change_password_wrong_current(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "wrongpassword",
                "new_password": "newsecurepass",
                "confirm_password": "newsecurepass",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "incorrect" in r.headers["location"]


def test_change_password_mismatch(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "newsecurepass",
                "confirm_password": "differentpass",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "do+not+match" in r.headers["location"]


def test_change_password_too_short(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "short",
                "confirm_password": "short",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "8+characters" in r.headers["location"]


def test_change_password_clears_autogenerated_flag(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import kv_get

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path, autogenerated="1")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "newsecurepass",
                "confirm_password": "newsecurepass",
            },
        )
    db = tmp_path / "cert-watch.sqlite3"
    assert kv_get(db, "local_admin_autogenerated") == "0"


def test_change_password_invalidates_sessions(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import get_session_version

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "newsecurepass",
                "confirm_password": "newsecurepass",
            },
        )
    version = get_session_version(db, "admin")
    assert version >= 1


def test_change_password_env_override_blocks(reload_app, tmp_path, monkeypatch):
    from cert_watch.auth import _scrypt_hash

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv(
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",
        _scrypt_hash("testpassword"),
    )
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/change-password",
            data={
                "current_password": "testpassword",
                "new_password": "newsecurepass",
                "confirm_password": "newsecurepass",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH" in r.headers["location"]


def test_settings_env_hash_override_shows_warning(reload_app, tmp_path, monkeypatch):
    from cert_watch.auth import _scrypt_hash

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv(
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",
        _scrypt_hash("testpassword"),
    )
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/settings?tab=auth")
    assert r.status_code == 200
    assert "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH" in r.text
    assert "Rotate password" not in r.text


def test_autogenerated_banner_shown(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    _seed_local_admin(tmp_path, autogenerated="1")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/")
    assert r.status_code == 200
    assert "Local admin password is auto-generated" in r.text
    assert "Rotate it now" in r.text


def test_autogenerated_banner_not_shown_after_rotation(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    _seed_local_admin(tmp_path, autogenerated="0")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/")
    assert r.status_code == 200
    assert "Local admin password is auto-generated" not in r.text


def test_autogenerated_banner_not_shown_without_local_admin(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "Local admin password is auto-generated" not in r.text


def test_sensitive_setting_keys_single_source():
    """The encrypt-side and decrypt-side sensitive-key sets must not diverge.

    They previously did: `pagerduty_routing_key` was on the decrypt side
    (config) but missing from the settings-side set, so a future GUI-managed
    routing key would have been written to kv_store in cleartext. Both now
    reference one canonical set in config — this test fails if anyone re-inlines
    a separate literal that drifts.
    """
    from cert_watch.config import SENSITIVE_SETTING_KEYS
    from cert_watch.routes.settings import _SENSITIVE_KEYS

    assert _SENSITIVE_KEYS == SENSITIVE_SETTING_KEYS
    assert "pagerduty_routing_key" in SENSITIVE_SETTING_KEYS


# ---------- TOFU CA capture (Plan 037) ----------


def test_is_cert_verify_error_detects_ssl_phrases():
    from cert_watch.routes.settings import _is_cert_verify_error

    class FakeExc(Exception):
        pass

    assert _is_cert_verify_error(FakeExc("CERTIFICATE_VERIFY_FAILED")) is True
    assert _is_cert_verify_error(FakeExc("certificate verify failed")) is True
    assert _is_cert_verify_error(FakeExc("unable to get local issuer certificate")) is True
    assert _is_cert_verify_error(FakeExc("self signed certificate")) is True
    assert _is_cert_verify_error(FakeExc("connection refused")) is False
    assert _is_cert_verify_error(FakeExc("invalid credentials")) is False


def test_capture_ldaps_chain_skips_non_ldaps():
    from cert_watch.routes.settings import _capture_ldaps_chain

    assert _capture_ldaps_chain("ldap://dc.example.com") is None


def test_capture_ldaps_chain_blocks_ssrf():
    from cert_watch.routes.settings import _capture_ldaps_chain

    assert _capture_ldaps_chain("ldaps://127.0.0.1") is None


def test_capture_ldaps_chain_returns_ca_excluding_leaf(monkeypatch, chain_triplet):
    from cert_watch.routes.settings import _capture_ldaps_chain

    leaf = chain_triplet["leaf"]
    intermediate = chain_triplet["intermediate"]
    root = chain_triplet["root"]
    der_chain = [leaf.der, intermediate.der, root.der]

    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **k: (der_chain, "TLSv1.3"),
    )
    result = _capture_ldaps_chain("ldaps://dc.example.com")
    assert result is not None
    assert len(result) == 2  # intermediate + root
    assert result[0]["subject"] == "CN=Test Intermediate CA"
    assert result[1]["subject"] == "CN=Test Root CA"
    assert "BEGIN CERTIFICATE" in result[0]["pem"]
    assert "BEGIN CERTIFICATE" in result[1]["pem"]


def test_capture_ldaps_chain_single_cert_returns_none(monkeypatch, self_signed_leaf):
    """A self-signed-only chain has no CA after dropping the leaf."""
    from cert_watch.routes.settings import _capture_ldaps_chain

    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **k: ([self_signed_leaf.der], "TLSv1.3"),
    )
    assert _capture_ldaps_chain("ldaps://dc.example.com") is None


def test_test_ldap_tofu_on_cert_verify_failure(reload_app, monkeypatch, chain_triplet):
    """When the LDAPS connection fails with a cert error, the handler returns a tofu block."""
    from cryptography.hazmat.primitives import hashes

    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        def __init__(self, *a, **k):
            raise ldap3.core.exceptions.LDAPSocketOpenError(
                "SSL: CERTIFICATE_VERIFY_FAILED"
            )

    monkeypatch.setattr(ldap3, "Connection", FakeConn)

    root = chain_triplet["root"]

    def fake_capture(url, *a, **k):
        return [
            {
                "subject": "CN=Test Root CA",
                "issuer": "CN=Test Root CA",
                "not_after": root.cert.not_valid_after_utc.isoformat(),
                "sha256": root.cert.fingerprint(hashes.SHA256()).hex(),
                "pem": root.pem.decode(),
            }
        ]

    monkeypatch.setattr(
        "cert_watch.routes.settings._capture_ldaps_chain", fake_capture
    )

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldaps://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "tofu" in data
    assert data["tofu"]["pem"] == root.pem.decode()
    assert len(data["tofu"]["chain"]) == 1
    assert data["tofu"]["chain"][0]["subject"] == "CN=Test Root CA"


def test_pin_ldap_ca_success(reload_app, tmp_path, chain_triplet):
    """Pinning a CA writes the cert to kv_store and creates an audit row."""
    from cert_watch.audit import list_audit
    from cert_watch.database import derive_encryption_key, fernet_decrypt, kv_get

    app_mod = reload_app()
    root = chain_triplet["root"]
    pem = root.pem.decode()

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/pin-ldap-ca",
            data={"ldap_ca_cert": pem},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    stored = kv_get(tmp_path / "cert-watch.sqlite3", "ldap_ca_cert")
    enc_key = derive_encryption_key("test-auth-secret-for-tests")
    decrypted = fernet_decrypt(stored, enc_key)
    assert "BEGIN CERTIFICATE" in decrypted
    audit = list_audit(tmp_path / "cert-watch.sqlite3", target_type="ldap_ca")
    assert any(a["action"] == "ca_pinned" for a in audit)


def test_pin_ldap_ca_missing_pem(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/settings/pin-ldap-ca", data={"ldap_ca_cert": ""})
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "No CA certificate" in r.json()["error"]


# ---------- StartTLS TOFU capture (BC-156) ----------


def test_capture_starttls_chain_skips_non_ldap():
    from cert_watch.routes.settings import _capture_starttls_chain

    assert _capture_starttls_chain("ldaps://dc.example.com") is None


def test_capture_starttls_chain_blocks_ssrf():
    from cert_watch.routes.settings import _capture_starttls_chain

    assert _capture_starttls_chain("ldap://127.0.0.1") is None


def test_capture_starttls_chain_returns_ca_excluding_leaf(monkeypatch, chain_triplet):
    from cert_watch.routes.settings import _capture_starttls_chain

    ldap3 = pytest.importorskip("ldap3")
    leaf = chain_triplet["leaf"]
    intermediate = chain_triplet["intermediate"]
    root = chain_triplet["root"]
    der_chain = [leaf.der, intermediate.der, root.der]

    class FakeSSL:
        def get_unverified_chain(self):
            return der_chain

    class FakeConn:
        socket = FakeSSL()
        tls_started = True

        def open(self):
            pass

        def start_tls(self):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", lambda *a, **k: FakeConn())
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: None)

    result = _capture_starttls_chain("ldap://dc.example.com")
    assert result is not None
    assert len(result) == 2  # intermediate + root
    assert result[0]["subject"] == "CN=Test Intermediate CA"
    assert result[1]["subject"] == "CN=Test Root CA"


def test_capture_starttls_chain_fallback_to_probe(monkeypatch, chain_triplet):
    from cert_watch.routes.settings import _capture_starttls_chain

    ldap3 = pytest.importorskip("ldap3")
    # ldap3 StartTLS fails → falls back to raw TLS probe
    monkeypatch.setattr(
        ldap3, "Connection",
        lambda *a, **k: (_ for _ in ()).throw(Exception("boom")),
    )
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: None)
    monkeypatch.setattr(
        "cert_watch.routes.settings.ca_probe._probe_tls_chain",
        lambda *a, **k: [
            {
                "subject": "CN=Test Intermediate CA",
                "issuer": "CN=Test Root CA",
                "not_after": "",
                "sha256": "aa",
                "pem": "PEM1",
            },
            {
                "subject": "CN=Test Root CA",
                "issuer": "CN=Test Root CA",
                "not_after": "",
                "sha256": "bb",
                "pem": "PEM2",
            },
        ],
    )

    result = _capture_starttls_chain("ldap://dc.example.com")
    assert result is not None
    assert len(result) == 2


def test_test_ldap_starttls_tofu_on_cert_verify_failure(reload_app, monkeypatch, chain_triplet):
    """When StartTLS connection fails with a cert error, the handler returns a tofu block."""
    from cryptography.hazmat.primitives import hashes

    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        def __init__(self, *a, **k):
            raise ldap3.core.exceptions.LDAPSocketOpenError(
                "SSL: CERTIFICATE_VERIFY_FAILED"
            )

    monkeypatch.setattr(ldap3, "Connection", FakeConn)

    root = chain_triplet["root"]

    def fake_capture(url, *a, **k):
        return [
            {
                "subject": "CN=Test Root CA",
                "issuer": "CN=Test Root CA",
                "not_after": root.cert.not_valid_after_utc.isoformat(),
                "sha256": root.cert.fingerprint(hashes.SHA256()).hex(),
                "pem": root.pem.decode(),
            }
        ]

    monkeypatch.setattr(
        "cert_watch.routes.settings._capture_starttls_chain", fake_capture
    )
    monkeypatch.setattr(
        "cert_watch.routes.settings._capture_ldaps_chain", lambda *a, **k: None
    )

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_start_tls": "1",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "tofu" in data
    assert data["tofu"]["pem"] == root.pem.decode()
    assert len(data["tofu"]["chain"]) == 1
    assert data["tofu"]["chain"][0]["subject"] == "CN=Test Root CA"


# ---------- Role CRUD (Plan 040) ----------


def test_roles_page_loads(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/settings/roles")
    assert r.status_code == 200
    assert "Roles" in r.text


def test_create_role_success(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import SqliteRoleRepository

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/roles",
            data={"name": "ops-team", "email": "ops@example.com", "description": "Ops team"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]
    db = tmp_path / "cert-watch.sqlite3"
    roles = SqliteRoleRepository(db).list_all()
    assert any(ro.name == "ops-team" for ro in roles)


def test_create_role_missing_name(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/roles",
            data={"name": "", "email": "x@x.com", "description": ""},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_delete_role(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import Role, SqliteRoleRepository

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    role_id = SqliteRoleRepository(db).add(Role(name="to-delete"))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            f"/settings/roles/{role_id}/delete",
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert SqliteRoleRepository(db).get(role_id) is None


# ---------- User CRUD (Plan 040) ----------


def test_users_page_loads(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.get("/settings/users")
    assert r.status_code == 200
    assert "Users" in r.text


def test_create_user_success(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import SqliteUserRepository

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/users",
            data={
                "username": "analyst",
                "email": "analyst@example.com",
                "password": "securepass1",
                "role_id": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]
    db = tmp_path / "cert-watch.sqlite3"
    user = SqliteUserRepository(db).get_by_username("analyst")
    assert user is not None


def test_create_user_missing_username(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/users",
            data={"username": "", "password": "securepass1"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_create_user_short_password(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/users",
            data={"username": "analyst", "password": "short"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "8+characters" in r.headers["location"]


def test_delete_user(reload_app, tmp_path, monkeypatch):
    from cert_watch.auth import _scrypt_hash
    from cert_watch.database import SqliteUserRepository, User

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    user_id = SqliteUserRepository(db).add(
        User(username="to-delete", password_hash=_scrypt_hash("password1"))
    )

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            f"/settings/users/{user_id}/delete",
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert SqliteUserRepository(db).get(user_id) is None


# ---------- LDAP role mapping (Plan 040) ----------


def test_save_ldap_role_map(reload_app, tmp_path, monkeypatch):
    import json

    from cert_watch.database import Role, SqliteRoleRepository, kv_get

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    role_id = SqliteRoleRepository(db).add(Role(name="admins"))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/ldap-role-map",
            data={f"role_map_{role_id}": "cert-watch-admins; cert-watch-users"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "saved=1" in r.headers["location"]
    stored = json.loads(kv_get(db, "ldap_role_map"))
    assert "admins" in stored
    assert stored["admins"]["groups"] == ["cert-watch-admins", "cert-watch-users"]


def test_save_ldap_role_map_skips_blank_groups(reload_app, tmp_path, monkeypatch):
    import json

    from cert_watch.database import Role, SqliteRoleRepository, kv_get

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    role_id = SqliteRoleRepository(db).add(Role(name="ops"))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/ldap-role-map",
            data={f"role_map_{role_id}": "  "},
            follow_redirects=False,
        )
    assert r.status_code == 303
    stored = json.loads(kv_get(db, "ldap_role_map"))
    assert "ops" not in stored


# ---------- SMTP port 465 (SMTP_SSL) path ----------


def test_test_smtp_port_465_uses_smtp_ssl(reload_app, monkeypatch):
    import smtplib

    calls = {}

    class FakeSMTP_SSL:
        def __init__(self, host, port, timeout=10):
            calls["target"] = (host, port)
            calls["class"] = "SMTP_SSL"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def send_message(self, msg):
            calls["sent_to"] = msg["To"]

    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP_SSL)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "465",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True
    assert calls["target"] == ("smtp.example.com", 465)
    assert calls["class"] == "SMTP_SSL"


def test_test_smtp_nonnumeric_port_returns_error(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "smtp.example.com",
                "smtp_port": "abc",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "port" in data["error"].lower()


def test_test_smtp_ssrf_blocked_ip(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        # Link-local/cloud metadata is blocked regardless of allow_private.
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "169.254.169.254",
                "smtp_port": "25",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "blocked" in data["error"].lower()


def test_test_smtp_private_hostname_allowed_by_default(reload_app, monkeypatch):
    """Regression: a hostname resolving to a private IP (10.x) must not be
    blocked when CERT_WATCH_ALLOW_PRIVATE_IPS is unset (defaults to 1).

    Previously the test-smtp route hardcoded allow_private=False, blocking
    all internal SMTP relays even though the real alert-delivery path
    allowed them (BC-116 SMTP parity).
    """
    import smtplib
    import socket as _socket

    real_getaddrinfo = _socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "mail.internal.example":
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("10.5.101.151", 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(_socket, "getaddrinfo", fake_getaddrinfo)

    class FakeSMTP:
        def __init__(self, host, port, timeout=10):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            pass

        def send_message(self, msg):
            self.sent_to = msg["To"]

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "mail.internal.example",
                "smtp_port": "587",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_test_smtp_private_hostname_blocked_when_disallowed(reload_app, monkeypatch):
    """When CERT_WATCH_ALLOW_PRIVATE_IPS=0, a private SMTP host is blocked."""
    import socket as _socket

    real_getaddrinfo = _socket.getaddrinfo

    def fake_getaddrinfo(host, *args, **kwargs):
        if host == "mail.internal.example":
            return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", ("10.5.101.151", 0))]
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(_socket, "getaddrinfo", fake_getaddrinfo)

    app_mod = reload_app(CERT_WATCH_ALLOW_PRIVATE_IPS="0")
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-smtp",
            data={
                "smtp_host": "mail.internal.example",
                "smtp_port": "587",
                "smtp_user": "",
                "smtp_password": "",
                "alert_from": "a@example.com",
                "alert_recipients": "ops@example.com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "blocked" in data["error"].lower()


def test_check_ldap_ssrf_allows_private_when_allowed(monkeypatch):
    """Regression: _check_ldap_ssrf must allow private IPs when allow_private=True."""
    from cert_watch.routes.settings.auth import _check_ldap_ssrf

    def fake_resolve(host, port=443, *, allow_private=True, **kwargs):
        if not allow_private:
            return (
                "hostname resolves to blocked address 10.5.101.151. "
                "Set CERT_WATCH_ALLOW_PRIVATE_IPS=1 to allow scanning private IPs.",
                None,
            )
        return None, "10.5.101.151"

    monkeypatch.setattr(
        "cert_watch.scan_resolver.resolve_and_validate_host", fake_resolve
    )

    assert _check_ldap_ssrf("ldap.internal.example", allow_private=True) is None

    blocked = _check_ldap_ssrf("ldap.internal.example", allow_private=False)
    assert blocked is not None
    assert b"blocked" in blocked.body.lower()


# ---------- _probe_tls_chain native chain / openssl fallback ----------


def test_probe_tls_chain_returns_none_for_ssrf_ip():
    from cert_watch.routes.settings import _probe_tls_chain

    # Link-local/cloud metadata is blocked regardless of allow_private.
    assert _probe_tls_chain("169.254.169.254", 636) is None


def test_probe_tls_chain_openssl_fallback(monkeypatch, chain_triplet):
    from cert_watch.routes.settings import _probe_tls_chain

    leaf = chain_triplet["leaf"]
    intermediate = chain_triplet["intermediate"]
    root = chain_triplet["root"]
    der_chain = [leaf.der, intermediate.der, root.der]

    import socket as _socket

    class FakeSSLSock:
        def get_unverified_chain(self):
            raise RuntimeError("not available")

        def get_verified_chain(self):
            raise RuntimeError("not available")

        def getpeercert(self, binary_form=False):
            if binary_form:
                return leaf.der
            return {}

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_create_connection(addr, timeout=5):
        return FakeConn()

    def fake_wrap_socket(sock, server_hostname=None):
        return FakeSSLSock()

    monkeypatch.setattr(_socket, "create_connection", fake_create_connection)
    import ssl as _ssl

    monkeypatch.setattr(_ssl.SSLContext, "wrap_socket", fake_wrap_socket)

    monkeypatch.setattr(
        "cert_watch.scan._scan_via_openssl",
        lambda *a, **k: (der_chain, "TLSv1.3"),
    )

    result = _probe_tls_chain("dc.example.com", 636)
    assert result is not None
    assert len(result) == 2
    assert result[0]["subject"] == "CN=Test Intermediate CA"


# ---------- _der_chain_to_ca_dicts edge cases ----------


def test_der_chain_to_ca_dicts_empty():
    from cert_watch.routes.settings import _der_chain_to_ca_dicts

    assert _der_chain_to_ca_dicts([]) is None


def test_der_chain_to_ca_dicts_no_ca_certs(self_signed_leaf):
    from cert_watch.routes.settings import _der_chain_to_ca_dicts

    assert _der_chain_to_ca_dicts([self_signed_leaf.der]) is None


# ---------- Settings admin auth paths ----------


def test_require_admin_no_auth_provider(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings")
    assert r.status_code == 200


def test_require_admin_unauthenticated_redirects_with_auth(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


@pytest.mark.anyio
async def test_require_admin_non_admin_user_forbidden(reload_app, tmp_path, monkeypatch):
    from unittest.mock import MagicMock

    from cert_watch.auth import _CompositeProvider
    from cert_watch.auth.local_admin import LocalAdminProvider
    from cert_watch.config import Settings
    from cert_watch.middleware import require_admin_form

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    monkeypatch.setenv("CERT_WATCH_ADMINS", "superuser")
    app_mod = reload_app()

    settings = Settings.from_env()
    app_mod.app.state.settings = settings

    primary = MagicMock()
    primary.provider_name = "mock"
    local = LocalAdminProvider(
        "otheruser", "fakehash", db_path=str(tmp_path / "cert-watch.sqlite3")
    )
    composite = _CompositeProvider(local, primary)
    app_mod.app.state.auth_provider = composite

    from starlette.requests import Request

    scope = {
        "type": "http", "method": "GET", "path": "/settings",
        "query_string": b"", "headers": [],
        "app": app_mod.app,
        "auth_user": "admin",
        "session": {},
    }
    req = Request(scope)
    result = require_admin_form(req)
    assert result is not None
    assert result.status_code == 303


# ---------- API keys admin redirect ----------


def test_api_keys_page_unauthenticated_redirects(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/settings/api-keys", follow_redirects=False)
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


# ---------- _effective_config encrypted value decrypt ----------


def test_effective_config_decrypts_encrypted_values(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import derive_encryption_key, fernet_encrypt, init_schema, kv_set

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    enc_key = derive_encryption_key("test-auth-secret-for-tests")
    encrypted = fernet_encrypt("secret-value", enc_key)
    kv_set(db, "smtp_password", encrypted)

    from cert_watch.routes.settings import _SMTP_KEYS, _effective_config

    result = _effective_config(_SMTP_KEYS, db, enc_key)
    assert result["smtp_password"] == "secret-value"


def test_effective_config_file_secret_override(reload_app, tmp_path, monkeypatch):
    from cert_watch.database import init_schema

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)

    secret_file = tmp_path / "smtp_password_file"
    secret_file.write_text("file-secret-value")
    monkeypatch.setenv("SMTP_PASSWORD_FILE", str(secret_file))

    from cert_watch.routes.settings import _SMTP_KEYS, _effective_config

    result = _effective_config(_SMTP_KEYS, db)
    assert result["smtp_password"] == "file-secret-value"


# ---------- _capture_starttls_chain port parsing ----------


def test_capture_starttls_chain_custom_port(monkeypatch, chain_triplet):
    from cert_watch.routes.settings import _capture_starttls_chain

    ldap3 = pytest.importorskip("ldap3")
    leaf = chain_triplet["leaf"]
    intermediate = chain_triplet["intermediate"]
    root = chain_triplet["root"]
    der_chain = [leaf.der, intermediate.der, root.der]

    class FakeSSL:
        def get_unverified_chain(self):
            return der_chain

    class FakeConn:
        socket = FakeSSL()
        tls_started = True

        def open(self):
            pass

        def start_tls(self):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", lambda *a, **k: FakeConn())
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: None)

    result = _capture_starttls_chain("ldap://dc.example.com:390")
    assert result is not None
    assert len(result) == 2


def test_capture_starttls_chain_import_error(monkeypatch):
    from cert_watch.routes.settings import _capture_starttls_chain

    monkeypatch.setattr(
        "cert_watch.routes.settings.ca_probe._probe_tls_chain",
        lambda *a, **k: None,
    )
    import builtins

    real_import = builtins.__import__

    def blocking_import(name, *args, **kwargs):
        if name == "ldap3":
            raise ImportError("no ldap3")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocking_import)
    assert _capture_starttls_chain("ldap://dc.example.com") is None


# ---------- LDAP test SSRF block ----------


def test_test_ldap_ssrf_blocked_ip(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        # Link-local/cloud metadata is blocked regardless of allow_private.
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://169.254.169.254",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "blocked" in data["error"].lower()


# ---------- LDAP test TLS validated / StartTLS messages ----------


def test_test_ldap_tls_validated_with_ca_cert(reload_app, monkeypatch):
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        tls_started = True

        def __init__(self, *a, **k):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldaps://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_ca_cert": "-----BEGIN CERTIFICATE-----\nMIIDfake\n-----END CERTIFICATE-----",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "pinned CA certificate" in data["message"]


def test_test_ldap_tls_validated_without_ca_cert(reload_app, monkeypatch):
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        tls_started = True

        def __init__(self, *a, **k):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldaps://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is True
    assert "system trust store" in data["message"]


def test_test_ldap_tls_not_established(reload_app, monkeypatch):
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        tls_started = False

        def __init__(self, *a, **k):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_start_tls": "1",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "TLS was requested but not established" in data["error"]


def test_test_ldap_starttls_no_negotiation_message(reload_app, monkeypatch):
    ldap3 = pytest.importorskip("ldap3")

    class FakeConn:
        tls_started = False

        def __init__(self, *a, **k):
            pass

        def unbind(self):
            pass

    monkeypatch.setattr(ldap3, "Connection", FakeConn)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/test-ldap",
            data={
                "ldap_server": "ldap://dc.example.com",
                "ldap_base_dn": "DC=example,DC=com",
                "ldap_start_tls": "1",
            },
        )
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "TLS was requested but not established" in data["error"]


# ---------- pin_ldap_ca enc_key branch ----------


def test_pin_ldap_ca_without_encryption_key(reload_app, tmp_path, chain_triplet, monkeypatch):
    root = chain_triplet["root"]
    pem = root.pem.decode()

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        monkeypatch.setattr(
            "cert_watch.routes.settings._get_encryption_key",
            lambda r: None,
        )
        r = client.post(
            "/settings/pin-ldap-ca",
            data={"ldap_ca_cert": pem},
        )
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ---------- _save_config_section admin redirect ----------


def test_save_auth_config_admin_redirect(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/settings/auth",
            data={"auth_provider": "", "ldap_server": "", "ldap_base_dn": ""},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "/login" in r.headers["location"]


# ---------- save_auth_config rebuild failure ----------


def test_save_auth_config_rebuild_failure(reload_app, tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        r = client.post(
            "/settings/auth",
            data={
                "auth_provider": "ldap",
                "ldap_server": "",
                "ldap_base_dn": "",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303


# ---------- Form structure (WI-027) ----------


def _max_form_nesting_depth(html: str) -> int:
    """Walk <form>/</form> tokens and return the maximum nesting depth.

    Browsers drop a <form> start tag that appears inside an open form, so the
    inner form's </form> closes the OUTER form early — orphaning every later
    field and submit button. Depth must never exceed 1.
    """
    import re

    # HTML comments can legitimately mention form tags; only real markup counts.
    html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)
    depth = 0
    max_depth = 0
    for m in re.finditer(r"</?form\b", html):
        if m.group(0) == "<form":
            depth += 1
            max_depth = max(max_depth, depth)
        else:
            depth -= 1
    assert depth == 0, "unbalanced <form> tags"
    return max_depth


def test_save_role_mapping_persists_users_and_merges(reload_app, tmp_path):
    """#1: the save route stores per-role groups + users and merges (a submit for
    one role must not wipe another role's mapping)."""
    import json

    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema, kv_get
    from cert_watch.database.users_roles import Role, SqliteRoleRepository

    init_schema(db)
    repo = SqliteRoleRepository(db)
    ops_id = repo.add(Role(name="ops", email="ops@x.com"))
    sec_id = repo.add(Role(name="sec", email="sec@x.com"))

    with TestClient(app_mod.app) as client:
        # Map ops -> a group DN (contains commas) + direct users.
        client.post("/settings/ldap-role-map", data={
            f"role_map_{ops_id}": "CN=Ops,OU=Groups,DC=x",
            f"role_users_{ops_id}": "alice@x.com, bob@x.com",
        }, follow_redirects=False)
        # Separately map sec -> a user; ops must survive (merge, not rebuild).
        r = client.post("/settings/ldap-role-map", data={
            f"role_users_{sec_id}": "carol@x.com",
        }, follow_redirects=False)
        assert r.status_code == 303
        assert "tab=roles" in r.headers["location"]

    stored = json.loads(kv_get(db, "ldap_role_map"))
    # The full DN survives (semicolon-separated, not shattered on its commas).
    assert stored["ops"]["groups"] == ["CN=Ops,OU=Groups,DC=x"]
    assert stored["ops"]["users"] == ["alice@x.com", "bob@x.com"]
    assert stored["sec"]["users"] == ["carol@x.com"]


def test_save_role_mapping_clears_existing(reload_app, tmp_path, monkeypatch):
    """#1: submitting an empty groups+users for a role removes its mapping."""
    import json

    from cert_watch.database import Role, SqliteRoleRepository, kv_get

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    role_id = SqliteRoleRepository(db).add(Role(name="ops"))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        client.post("/settings/ldap-role-map",
                    data={f"role_users_{role_id}": "alice@x.com"}, follow_redirects=False)
        assert "ops" in json.loads(kv_get(db, "ldap_role_map"))
        # Now clear it.
        client.post("/settings/ldap-role-map",
                    data={f"role_map_{role_id}": "", f"role_users_{role_id}": ""},
                    follow_redirects=False)
    assert "ops" not in json.loads(kv_get(db, "ldap_role_map"))


def test_save_role_mapping_tolerates_bad_state(reload_app, tmp_path, monkeypatch):
    """auth.py defensive branches: corrupt/non-dict stored JSON and unknown role id."""
    import json

    from cert_watch.database import Role, SqliteRoleRepository, kv_get, kv_set

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    _seed_local_admin(tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    role_id = SqliteRoleRepository(db).add(Role(name="ops"))

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        _login_admin(client, monkeypatch)
        # Corrupt JSON in store -> treated as empty, then written cleanly.
        kv_set(db, "ldap_role_map", "{not json")
        client.post("/settings/ldap-role-map",
                    data={f"role_users_{role_id}": "a@x.com"}, follow_redirects=False)
        assert json.loads(kv_get(db, "ldap_role_map"))["ops"]["users"] == ["a@x.com"]
        # Non-dict JSON in store -> also reset.
        kv_set(db, "ldap_role_map", "[1, 2]")
        client.post("/settings/ldap-role-map",
                    data={f"role_users_{role_id}": "b@x.com"}, follow_redirects=False)
        assert json.loads(kv_get(db, "ldap_role_map"))["ops"]["users"] == ["b@x.com"]
        # Unknown role id referenced in the form -> skipped, no crash.
        r = client.post("/settings/ldap-role-map",
                        data={"role_map_nonexistent-role": "CN=X"}, follow_redirects=False)
        assert r.status_code == 303


def test_role_mapping_lives_on_roles_tab(reload_app, tmp_path):
    """#1: the IdP group/user -> role mapping moved from the Authentication tab
    to the Roles tab. It must be a self-contained form (WI-027: never nested in
    another form), carry both groups and users fields, and no longer appear on
    the auth tab.
    """
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.database.users_roles import Role, SqliteRoleRepository

    init_schema(db)
    role_id = SqliteRoleRepository(db).add(Role(name="Platform", email="p@example.com"))

    with TestClient(app_mod.app) as client:
        roles = client.get("/settings?tab=roles")
    assert roles.status_code == 200
    # No nested forms (the browser-killing hazard from WI-027).
    assert _max_form_nesting_depth(roles.text) == 1
    # The old auth-tab orphan form + form-attribute wiring are gone.
    assert "ldap-role-map-form" not in roles.text
    assert f'name="role_map_{role_id}" form=' not in roles.text
    # Mapping now rendered via the Roles-tab per-role UI, with groups + users.
    assert "IdP mapping</summary>" in roles.text
    assert 'action="/settings/ldap-role-map"' in roles.text
    assert f'name="role_map_{role_id}"' in roles.text
    assert f'name="role_users_{role_id}"' in roles.text


def test_no_nested_forms_on_any_settings_tab(reload_app, tmp_path):
    """Form-nesting sweep across all settings tabs (same parser hazard)."""
    app_mod = reload_app()
    from cert_watch.database import init_schema

    init_schema(tmp_path / "cert-watch.sqlite3")
    with TestClient(app_mod.app) as client:
        for tab in ("auth", "smtp", "alerts", "policy", "api-keys"):
            r = client.get(f"/settings?tab={tab}")
            assert r.status_code == 200
            assert _max_form_nesting_depth(r.text) == 1, f"nested form on tab={tab}"
        for page in ("/settings/roles", "/settings/users", "/settings/events"):
            r = client.get(page)
            assert r.status_code == 200
            assert _max_form_nesting_depth(r.text) == 1, f"nested form on {page}"
