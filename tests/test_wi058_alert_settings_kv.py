"""WI-058 — the six previously env-var-only alert settings must round-trip
through kv_store (GUI save), with env vars still taking precedence.

Before WI-058, ``_merge_kv_settings`` passed these straight from the env-derived
base, so a value saved by the Settings UI was silently ignored. These tests pin
the merge behaviour: kv_store is honoured when the env var is unset, and the env
var wins when set.
"""
from __future__ import annotations

import pytest

from cert_watch.config import Settings
from cert_watch.database import init_schema, kv_set

# (kv_key, env_name, kv_value, expected_attr, expected_from_kv, env_value,
#  expected_from_env)
_INT_CASES = [
    ("renewal_window_days", "CERT_WATCH_RENEWAL_WINDOW_DAYS", "0", 0, "45", 45),
    ("alert_retention_days", "CERT_WATCH_ALERT_RETENTION_DAYS", "0", 0, "120", 120),
    ("sched_hour", "CERT_WATCH_SCHED_HOUR", "0", 0, "9", 9),
    ("sched_min", "CERT_WATCH_SCHED_MIN", "30", 30, "15", 15),
]


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "cw.sqlite3"
    init_schema(path)
    return path


def _clear_alert_env(monkeypatch):
    for env in (
        "CERT_WATCH_DRIFT_ALERTS",
        "CERT_WATCH_CHECK_REVOCATION",
        "CERT_WATCH_RENEWAL_WINDOW_DAYS",
        "CERT_WATCH_ALERT_RETENTION_DAYS",
        "CERT_WATCH_SCHED_HOUR",
        "CERT_WATCH_SCHED_MIN",
        "ALERT_WEBHOOK_HEADERS",
    ):
        monkeypatch.delenv(env, raising=False)


@pytest.mark.parametrize("kv_key,env_name,kv_value,from_kv,env_value,from_env", _INT_CASES)
def test_int_alert_setting_honours_kv_then_env(
    db, monkeypatch, kv_key, env_name, kv_value, from_kv, env_value, from_env
):
    """kv_store value is honoured (note 0 is a *valid* value, not 'unset'); env wins.

    The Settings attribute name is the kv_key.
    """
    _clear_alert_env(monkeypatch)
    kv_set(db, kv_key, kv_value)
    s = Settings.from_env_with_kv(db)
    assert getattr(s, kv_key) == from_kv

    monkeypatch.setenv(env_name, env_value)
    s2 = Settings.from_env_with_kv(db)
    assert getattr(s2, kv_key) == from_env


def test_drift_alerts_kv_can_turn_off_default_on(db, monkeypatch):
    """drift_alerts defaults on; a kv '0' must turn it off, and env must win."""
    _clear_alert_env(monkeypatch)
    assert Settings.from_env_with_kv(db).drift_alerts is True  # default

    kv_set(db, "drift_alerts", "0")
    assert Settings.from_env_with_kv(db).drift_alerts is False

    monkeypatch.setenv("CERT_WATCH_DRIFT_ALERTS", "1")  # env wins even over kv off
    assert Settings.from_env_with_kv(db).drift_alerts is True


def test_check_revocation_kv_can_turn_on_default_off(db, monkeypatch):
    """check_revocation defaults off; kv '1' turns it on, env wins."""
    _clear_alert_env(monkeypatch)
    assert Settings.from_env_with_kv(db).check_revocation is False  # default

    kv_set(db, "check_revocation", "1")
    assert Settings.from_env_with_kv(db).check_revocation is True

    monkeypatch.setenv("CERT_WATCH_CHECK_REVOCATION", "0")  # env wins even over kv on
    assert Settings.from_env_with_kv(db).check_revocation is False


def test_webhook_headers_kv_json_parsed_and_env_wins(db, monkeypatch):
    """webhook_headers is a JSON object string in kv; env (ALERT_WEBHOOK_HEADERS) wins."""
    _clear_alert_env(monkeypatch)
    kv_set(db, "webhook_headers", '{"X-Scope": "certs"}')
    assert Settings.from_env_with_kv(db).webhook_headers == {"X-Scope": "certs"}

    monkeypatch.setenv("ALERT_WEBHOOK_HEADERS", '{"Authorization": "Bearer t"}')
    assert Settings.from_env_with_kv(db).webhook_headers == {"Authorization": "Bearer t"}


def test_webhook_headers_invalid_json_falls_back(db, monkeypatch):
    """Invalid JSON in kv must not crash; it falls back to the base default (None)."""
    _clear_alert_env(monkeypatch)
    kv_set(db, "webhook_headers", "{not valid json")
    assert Settings.from_env_with_kv(db).webhook_headers is None


def test_unset_keys_keep_dataclass_defaults(db, monkeypatch):
    """With no env and no kv, the merged Settings keeps the documented defaults."""
    _clear_alert_env(monkeypatch)
    s = Settings.from_env_with_kv(db)
    assert s.drift_alerts is True
    assert s.check_revocation is False
    assert s.renewal_window_days == 30
    assert s.alert_retention_days == 90
    assert s.sched_hour == 6
    assert s.sched_min == 0
    assert s.webhook_headers is None
