"""Plan 057 W2 invariants for the declarative Settings field table."""

from __future__ import annotations

import socket
from dataclasses import MISSING, fields

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
