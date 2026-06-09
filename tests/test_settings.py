"""Tests for GUI settings page (Plan 019 Slice 1)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    from cert_watch.database.queries import get_session_version

    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    monkeypatch.setenv("CERT_WATCH_CSRF_DISABLED", "1")
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
    intermediate = chain_triplet["intermediate"]
    root = chain_triplet["root"]
    der_chain = [intermediate.der, root.der]

    # ldap3 StartTLS fails → falls back to raw TLS probe
    monkeypatch.setattr(ldap3, "Connection", lambda *a, **k: (_ for _ in ()).throw(Exception("boom")))
    monkeypatch.setattr(ldap3, "Server", lambda *a, **k: None)
    monkeypatch.setattr(
        "cert_watch.routes.settings._probe_tls_chain",
        lambda *a, **k: [
            {"subject": "CN=Test Intermediate CA", "issuer": "CN=Test Root CA", "not_after": "", "sha256": "aa", "pem": "PEM1"},
            {"subject": "CN=Test Root CA", "issuer": "CN=Test Root CA", "not_after": "", "sha256": "bb", "pem": "PEM2"},
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
