"""Regression tests for BC-159: GUI-configured auth/smtp/alert settings must
survive application restart (kv_store merged into boot-time Settings).
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_lifespan_merges_kv_store_auth_settings(monkeypatch, tmp_path):
    """GUI-configured LDAP settings in kv_store are merged into the boot-time
    Settings object when the app starts without injected settings (production path).
    """
    from cert_watch.app import create_app
    from cert_watch.database import init_schema, kv_set

    data_dir = tmp_path / "bc159-data"
    data_dir.mkdir()
    db_path = data_dir / "cert-watch.sqlite3"
    init_schema(db_path)

    # Write LDAP config into kv_store (simulates GUI save)
    auth_secret = "test-auth-secret-for-bc159"
    kv_set(db_path, "auth_provider", "ldap")
    kv_set(db_path, "ldap_server", "ldap://dc.example.com")
    kv_set(db_path, "ldap_base_dn", "DC=example,DC=com")
    kv_set(db_path, "ldap_bind_dn", "CN=bind,DC=example,DC=com")
    kv_set(db_path, "ldap_bind_password", "plain-password")
    kv_set(db_path, "ldap_user_filter", "(sAMAccountName={username})")

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", auth_secret)
    # No AUTH_PROVIDER in env — must come from kv_store
    monkeypatch.delenv("AUTH_PROVIDER", raising=False)

    # Create app WITHOUT injected settings — the lifespan must resolve from env+kv
    app = create_app()
    with TestClient(app) as client:
        # Trigger lifespan by making a request
        r = client.get("/healthz")
        assert r.status_code == 200

    # The merged settings should carry the kv_store values
    s = app.state.settings
    assert s.auth_provider == "ldap", f"Expected auth_provider='ldap', got '{s.auth_provider}'"
    assert s.ldap_server == "ldap://dc.example.com"
    assert s.ldap_base_dn == "DC=example,DC=com"
    assert s.ldap_bind_dn == "CN=bind,DC=example,DC=com"
    assert s.ldap_bind_password == "plain-password"
    assert s.ldap_user_filter == "(sAMAccountName={username})"


def test_lifespan_merges_kv_store_smtp_settings(monkeypatch, tmp_path):
    """GUI-configured SMTP settings in kv_store are merged into boot-time Settings."""
    from cert_watch.app import create_app
    from cert_watch.database import init_schema, kv_set

    data_dir = tmp_path / "bc159-smtp"
    data_dir.mkdir()
    db_path = data_dir / "cert-watch.sqlite3"
    init_schema(db_path)

    auth_secret = "test-auth-secret-for-bc159-smtp"
    kv_set(db_path, "smtp_host", "smtp.example.com")
    kv_set(db_path, "smtp_port", "587")
    kv_set(db_path, "smtp_user", "alerts")
    kv_set(db_path, "smtp_password", "smtp-secret")
    kv_set(db_path, "alert_from", "alerts@example.com")

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", auth_secret)

    app = create_app()
    with TestClient(app) as client:
        client.get("/healthz")

    s = app.state.settings
    assert s.smtp_host == "smtp.example.com"
    assert s.smtp_port == 587
    assert s.smtp_user == "alerts"
    assert s.smtp_password == "smtp-secret"
    assert s.alert_from == "alerts@example.com"


def test_env_still_overrides_kv_store(monkeypatch, tmp_path):
    """Env vars take precedence over kv_store (the documented escape hatch)."""
    from cert_watch.app import create_app
    from cert_watch.database import init_schema, kv_set

    data_dir = tmp_path / "bc159-override"
    data_dir.mkdir()
    db_path = data_dir / "cert-watch.sqlite3"
    init_schema(db_path)

    auth_secret = "test-auth-secret-for-bc159-override"
    kv_set(db_path, "auth_provider", "ldap")
    kv_set(db_path, "ldap_server", "ldap://dc.example.com")

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", auth_secret)
    # Set env override — must win over kv_store
    monkeypatch.setenv("AUTH_PROVIDER", "oauth")
    monkeypatch.setenv("LDAP_SERVER", "ldap://env.example.com")
    monkeypatch.setenv("OAUTH_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("OAUTH_ISSUER_URL", "https://env.example.com")

    app = create_app()
    with TestClient(app) as client:
        client.get("/healthz")

    s = app.state.settings
    assert s.auth_provider == "oauth", "env should override kv_store"
    assert s.ldap_server == "ldap://env.example.com", "env should override kv_store"


def test_no_kv_store_falls_back_to_env_only(monkeypatch, tmp_path):
    """When kv_store is empty, boot uses env-only settings (no crash)."""
    from cert_watch.app import create_app
    from cert_watch.database import init_schema

    data_dir = tmp_path / "bc159-empty"
    data_dir.mkdir()
    db_path = data_dir / "cert-watch.sqlite3"
    init_schema(db_path)

    auth_secret = "test-auth-secret-for-bc159-empty"
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("CERT_WATCH_ALLOW_UNAUTH", "1")
    monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", auth_secret)
    monkeypatch.setenv("AUTH_PROVIDER", "ldap")
    monkeypatch.setenv("LDAP_SERVER", "ldap://env.example.com")
    monkeypatch.setenv("LDAP_BASE_DN", "DC=env,DC=com")

    app = create_app()
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200

    s = app.state.settings
    assert s.auth_provider == "ldap"
    assert s.ldap_server == "ldap://env.example.com"
