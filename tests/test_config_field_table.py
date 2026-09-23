"""Plan 057 W2 invariants for the declarative Settings field table."""

from __future__ import annotations

import socket
from dataclasses import MISSING, fields, replace

from cert_watch.config import FIELD_SPECS, Settings


def test_every_settings_field_has_exactly_one_spec():
    setting_names = {item.name for item in fields(Settings)}
    assert set(FIELD_SPECS) == setting_names


def test_dataclass_defaults_match_field_table(tmp_path):
    settings = Settings(db_path=tmp_path / "db", data_dir=tmp_path)
    for item in fields(Settings):
        if item.name in {"db_path", "data_dir"}:
            continue
        spec = FIELD_SPECS[item.name]
        expected = spec.default() if callable(spec.default) else spec.default
        actual = getattr(settings, item.name)
        assert actual == expected, item.name
        assert item.default is not MISSING or item.default_factory is not MISSING


def test_explicit_env_has_one_precedence_rule(monkeypatch, tmp_path):
    from cert_watch.database import init_schema
    from cert_watch.database.kv_store import kv_set_multi

    db = tmp_path / "cert-watch.sqlite3"
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("LDAP_CONNECT_TIMEOUT", "9")
    monkeypatch.setenv("ALERT_DIGEST_ONLY", "0")
    init_schema(db)
    kv_set_multi(
        db,
        {
            "smtp_port": "1025",
            "ldap_connect_timeout": "30",
            "alert_digest_only": "1",
        },
    )

    settings = Settings.from_env_with_kv(db)

    assert settings.smtp_port == 2525
    assert settings.ldap_connect_timeout == 9
    assert settings.alert_digest_only is False


def test_legacy_blank_default_exceptions_are_declarative(monkeypatch):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", "")
    monkeypatch.setenv("CERT_WATCH_INSTANCE_ID", "")

    settings = Settings.from_env()

    assert settings.data_dir == FIELD_SPECS["data_dir"].default()
    assert settings.instance_id == socket.gethostname()
    assert FIELD_SPECS["data_dir"].empty_uses_default
    assert FIELD_SPECS["instance_id"].empty_uses_default


def test_every_env_backed_sensitive_spec_supports_file(monkeypatch, tmp_path):
    sensitive_specs = {
        name: spec
        for name, spec in FIELD_SPECS.items()
        if spec.sensitive and spec.env_names
    }
    assert set(sensitive_specs) == {
        "smtp_password",
        "webhook_headers",
        "pagerduty_routing_key",
        "ldap_bind_password",
        "ldap_ca_cert",
        "oauth_client_secret",
        "local_admin_password_hash",
        "renewal_webhook_headers",
        "auth_secret",
        "csrf_secret",
        "metrics_token",
        "hec_token",
    }

    expected = {}
    for field_name, spec in sensitive_specs.items():
        for env_name in spec.env_names:
            monkeypatch.delenv(env_name, raising=False)
            monkeypatch.delenv(f"{env_name}_FILE", raising=False)
        env_name = spec.env_names[0]
        secret_file = tmp_path / field_name
        if spec.parser == "json":
            secret_file.write_text('{"token": "from-file"}\n')
            expected[field_name] = {"token": "from-file"}
        else:
            value = f"{field_name}-from-file"
            secret_file.write_text(f"  {value}  \n")
            expected[field_name] = value
        monkeypatch.setenv(f"{env_name}_FILE", str(secret_file))

    settings = Settings.from_env()

    for field_name, value in expected.items():
        assert getattr(settings, field_name) == value, field_name


def test_settings_repr_redacts_every_sensitive_field(tmp_path):
    sensitive_fields = {
        name for name, spec in FIELD_SPECS.items() if spec.sensitive
    }
    canaries = {
        name: f"sensitive-canary-{index}"
        for index, name in enumerate(sorted(sensitive_fields))
    }
    settings = replace(
        Settings(db_path=tmp_path / "db", data_dir=tmp_path),
        **canaries,
    )

    rendered = repr(settings)

    assert "Settings(" in rendered
    for field_name, canary in canaries.items():
        assert canary not in rendered, field_name
        assert f"{field_name}=" not in rendered, field_name
    assert str(settings) == rendered
