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
