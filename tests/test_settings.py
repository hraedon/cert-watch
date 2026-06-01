"""Tests for GUI settings page (Plan 019 Slice 1)."""

from __future__ import annotations

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


# ---------- Test LDAP endpoint ----------


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
