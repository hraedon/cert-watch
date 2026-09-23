"""Golden behaviour captured before Plan 057 W2's config-table refactor."""

from __future__ import annotations

import os
import socket

import pytest


def test_representative_env_and_kv_settings_golden(monkeypatch, tmp_path):
    """A representative mixed-source configuration keeps its exact shape."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set_multi

    data_dir = tmp_path / "configured-data"
    db_path = data_dir / "cert-watch.sqlite3"

    prefixes = ("CERT_WATCH_", "ALERT_", "SMTP_", "LDAP_", "OAUTH_")
    for name in tuple(os.environ):
        if name == "AUTH_PROVIDER" or name.startswith(prefixes):
            monkeypatch.delenv(name, raising=False)

    env = {
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_SCHED_HOUR": "8",
        "SMTP_HOST": "smtp.env.example",
        "SMTP_PASSWORD": "env-smtp-secret",
        "ALERT_RECIPIENTS": "ops@example.com, security@example.com",
        "ALERT_WEBHOOK_HEADERS": '{"Authorization": "Bearer env"}',
        "ALERT_WEBHOOK_KIND": "teams",
        "ALERT_DIGEST_ONLY": "1",
        "CERT_WATCH_ALLOW_PRIVATE_IPS": "0",
        "CERT_WATCH_ALLOWED_SUBNETS": "10.20.0.0/16,fd00::/8",
        "CERT_WATCH_DNS_SERVERS": "10.20.0.53,10.20.0.54",
        "CERT_WATCH_AUDIT_RETENTION_DAYS": "120",
        "CERT_WATCH_HISTORY_RETENTION_DAYS": "730",
        "CERT_WATCH_SCAN_TIMEOUT": "4.5",
        "CERT_WATCH_SCAN_RETRIES": "4",
        "CERT_WATCH_SCAN_RETRY_BACKOFF": "0.25",
        "CERT_WATCH_SCAN_MAX_OUTPUT_BYTES": "2097152",
        "CERT_WATCH_HSTS_TIMEOUT": "2.5",
        "AUTH_PROVIDER": "ldap",
        "LDAP_BIND_PASSWORD": "env-ldap-secret",
        "LDAP_START_TLS": "1",
        "CERT_WATCH_ALLOWED_GROUPS": "cert-readers,cert-admins",
        "CERT_WATCH_ADMINS": "alice,bob",
        "CERT_WATCH_SESSION_TTL": "14400",
        "CERT_WATCH_WRITE_USERS": "carol,dave",
        "CERT_WATCH_ROLE_MAP": '{"ops": {"permission_tier": "operator"}}',
        "CERT_WATCH_BASE_URL": "https://certs.example.test/",
        "CERT_WATCH_ALLOW_UNAUTH": "1",
        "CERT_WATCH_JWKS_CACHE_TTL": "43200",
        "CERT_WATCH_RENEWAL_WEBHOOK_URL": "https://renew.example.test/hook",
        "CERT_WATCH_RENEWAL_WEBHOOK_HEADERS": '{"X-Renewal": "token"}',
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    init_schema(db_path)
    kv_set_multi(
        db_path,
        {
            "sched_min": "15",
            "smtp_port": "2525",
            "smtp_user": "mailer",
            "alert_from": "cert-watch@example.com",
            "webhook_url": "https://alerts.example.test/hook",
            "webhook_headers": '{"X-Source": "kv"}',
            "pagerduty_routing_key": "pd-secret",
            "drift_alerts": "0",
            "check_revocation": "1",
            "renewal_window_days": "21",
            "alert_retention_days": "180",
            "ldap_server": "ldaps://dc.example.test",
            "ldap_base_dn": "DC=example,DC=test",
            "ldap_bind_dn": "CN=svc,DC=example,DC=test",
            "ldap_required_groups": (
                "CN=Readers,OU=Groups,DC=example,DC=test;"
                "CN=Admins,OU=Groups,DC=example,DC=test"
            ),
            "ldap_connect_timeout": "12",
            "ldap_group_filter": "(memberOf:1.2.3:={group})",
            "oauth_client_id": "client-from-kv",
            "oauth_client_secret": "oauth-secret-from-kv",
            "local_admin_user": "breakglass",
            "local_admin_password_hash": "scrypt-hash-from-kv",
        },
    )

    actual = Settings.from_env_with_kv(db_path)

    assert actual == Settings(
        db_path=db_path,
        data_dir=data_dir,
        sched_hour=8,
        sched_min=15,
        smtp_host="smtp.env.example",
        smtp_port=2525,
        smtp_user="mailer",
        smtp_password="env-smtp-secret",
        alert_from="cert-watch@example.com",
        alert_recipients=("ops@example.com", "security@example.com"),
        webhook_url="https://alerts.example.test/hook",
        webhook_headers={"Authorization": "Bearer env"},
        webhook_kind="teams",
        pagerduty_routing_key="pd-secret",
        alert_digest_only=True,
        allow_private=False,
        allowed_subnets=("10.20.0.0/16", "fd00::/8"),
        dns_servers=("10.20.0.53", "10.20.0.54"),
        audit_retention_days=120,
        history_retention_days=730,
        alert_retention_days=180,
        drift_alerts=False,
        renewal_window_days=21,
        check_revocation=True,
        scan_timeout=4.5,
        scan_retries=4,
        scan_retry_backoff=0.25,
        scan_max_output_bytes=2097152,
        hsts_timeout=2.5,
        auth_provider="ldap",
        ldap_server="ldaps://dc.example.test",
        ldap_base_dn="DC=example,DC=test",
        ldap_bind_dn="CN=svc,DC=example,DC=test",
        ldap_bind_password="env-ldap-secret",
        ldap_start_tls=True,
        ldap_required_groups=(
            "CN=Readers,OU=Groups,DC=example,DC=test",
            "CN=Admins,OU=Groups,DC=example,DC=test",
        ),
        ldap_connect_timeout=12,
        ldap_group_filter="(memberOf:1.2.3:={group})",
        oauth_client_id="client-from-kv",
        oauth_client_secret="oauth-secret-from-kv",
        allowed_groups=("cert-readers", "cert-admins"),
        admin_users=("alice", "bob"),
        session_ttl=14400,
        write_users=("carol", "dave"),
        role_map={"ops": {"permission_tier": "operator"}},
        local_admin_user="breakglass",
        local_admin_password_hash="scrypt-hash-from-kv",
        base_url="https://certs.example.test",
        allow_unauth=True,
        jwks_cache_ttl=43200,
        renewal_webhook_url="https://renew.example.test/hook",
        renewal_webhook_headers={"X-Renewal": "token"},
        instance_id=socket.gethostname(),
    )


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_env_is_unset_for_every_kv_backed_setting(monkeypatch, tmp_path, blank):
    """Blank deployment placeholders must not hide values saved in the GUI."""
    from cert_watch.config import FIELD_SPECS, Settings
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set_multi

    data_dir = tmp_path / "blank-env"
    db_path = data_dir / "cert-watch.sqlite3"
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    init_schema(db_path)

    raw_by_parser = {
        "str": "saved-value",
        "secret-file": "saved-secret",
        "int": "7",
        "bool": "1",
        "float": "2.5",
        "csv": "saved-a;saved-b",
        "json": '{"saved": "value"}',
    }
    covered = {
        field_name: spec
        for field_name, spec in FIELD_SPECS.items()
        if spec.kv_key is not None and spec.env_names
    }
    kv_set_multi(
        db_path,
        {spec.kv_key: raw_by_parser[spec.parser] for spec in covered.values()},
    )
    expected = Settings.from_env_with_kv(db_path)

    for spec in covered.values():
        for env_name in spec.env_names:
            monkeypatch.setenv(env_name, blank)

    actual = Settings.from_env_with_kv(db_path)

    for field_name in covered:
        assert getattr(actual, field_name) == getattr(expected, field_name), field_name


def test_blank_env_does_not_lock_settings_ui_field(monkeypatch, tmp_path):
    from cert_watch.routes.settings.config import _SMTP_KEYS, _env_overrides

    monkeypatch.setenv("SMTP_PASSWORD", "  ")

    assert "smtp_password" not in _env_overrides(_SMTP_KEYS, tmp_path / "unused.db")


def test_blank_direct_secret_env_allows_file_source(monkeypatch, tmp_path):
    from cert_watch.config import Settings

    secret_file = tmp_path / "ldap-password"
    secret_file.write_text("from-file\n")
    monkeypatch.setenv("LDAP_BIND_PASSWORD", " ")
    monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", str(secret_file))

    assert Settings.from_env().ldap_bind_password == "from-file"


@pytest.mark.parametrize("failure", ["missing", "directory", "empty", "unreadable"])
def test_explicit_secret_file_failures_are_configuration_errors(
    monkeypatch, tmp_path, failure
):
    from cert_watch.config import Settings

    secret_path = tmp_path / failure
    if failure == "directory":
        secret_path.mkdir()
    elif failure == "empty":
        secret_path.write_text(" \n")
    elif failure == "unreadable":
        secret_path.write_text("must-not-leak")
        secret_path.chmod(0)

    monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", str(secret_path))

    with pytest.raises(ValueError) as exc_info:
        Settings.from_env()

    message = str(exc_info.value)
    assert "LDAP_BIND_PASSWORD_FILE" in message
    assert str(secret_path) not in message
    assert "must-not-leak" not in message


def test_empty_secret_file_variable_is_unset_and_kv_falls_back(monkeypatch, tmp_path):
    from cert_watch.config import Settings
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set

    db_path = tmp_path / "cert-watch.sqlite3"
    init_schema(db_path)
    kv_set(db_path, "ldap_bind_password", "saved-password")
    monkeypatch.setenv("LDAP_BIND_PASSWORD_FILE", "")

    assert Settings.from_env_with_kv(db_path).ldap_bind_password == "saved-password"


def test_standalone_current_settings_resolves_once_until_invalidated(
    monkeypatch, tmp_path
):
    from cert_watch.config import Settings, current_settings, invalidate_settings
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set

    db_path = tmp_path / "cert-watch.sqlite3"
    init_schema(db_path)
    kv_set(db_path, "smtp_host", "first.example.test")
    original = Settings.from_env_with_kv.__func__
    calls = 0

    def counted(cls, *args, **kwargs):
        nonlocal calls
        calls += 1
        return original(cls, *args, **kwargs)

    monkeypatch.setattr(Settings, "from_env_with_kv", classmethod(counted))

    assert current_settings(db_path).smtp_host == "first.example.test"
    assert current_settings(db_path).smtp_host == "first.example.test"
    assert calls == 1

    kv_set(db_path, "smtp_host", "second.example.test")
    invalidate_settings(db_path)

    assert current_settings(db_path).smtp_host == "second.example.test"
    assert calls == 2


def test_upgrade_config_semantics_golden(monkeypatch, tmp_path):
    """Pin every operator-visible merge change called out in UPGRADING."""
    from cert_watch.config import Settings
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set_multi

    data_dir = tmp_path / "upgrade-semantics"
    db_path = data_dir / "cert-watch.sqlite3"
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "12")
    monkeypatch.setenv("ALERT_DIGEST_ONLY", "0")
    init_schema(db_path)
    kv_set_multi(
        db_path,
        {
            "smtp_port": "25",
            "ldap_connect_timeout": "3",
            "alert_digest_only": "1",
            "oauth_scope": "openid saved-scope",
            "ldap_user_filter": "(uid={username})",
            "webhook_kind": "teams",
            "renewal_window_days": "9999",
            "check_revocation": "True",
        },
    )

    settings = Settings.from_env_with_kv(db_path)

    assert settings.smtp_port == 2525
    assert settings.ldap_connect_timeout == 12
    assert settings.alert_digest_only is False
    assert settings.oauth_scope == "openid saved-scope"
    assert settings.ldap_user_filter == "(uid={username})"
    assert settings.webhook_kind == "teams"
    assert settings.renewal_window_days == 30
    assert settings.check_revocation is True


def test_nonblank_boolean_env_keeps_exact_one_semantics(monkeypatch):
    from cert_watch.config import Settings

    monkeypatch.setenv("ALERT_DIGEST_ONLY", " 1 ")

    assert Settings.from_env().alert_digest_only is False
