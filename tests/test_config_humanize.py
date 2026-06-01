"""Tests for AlertConfig env loading and humanize_expiry Jinja filter."""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta
from unittest.mock import patch


def _fresh_settings(monkeypatch, env: dict[str, str]):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    from cert_watch import config as _config
    importlib.reload(_config)
    return _config.Settings.from_env()


def test_alert_config_none_when_missing(monkeypatch, tmp_path):
    # Clear any SMTP envs.
    for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASSWORD", "ALERT_FROM", "ALERT_RECIPIENTS"):
        monkeypatch.delenv(k, raising=False)
    s = _fresh_settings(monkeypatch, {"CERT_WATCH_DATA_DIR": str(tmp_path)})
    assert s.build_alert_config() is None


def test_alert_config_built_from_env(monkeypatch, tmp_path):
    env = {
        "CERT_WATCH_DATA_DIR": str(tmp_path),
        "SMTP_HOST": "smtp.example.com",
        "SMTP_PORT": "2525",
        "SMTP_USER": "user",
        "SMTP_PASSWORD": "pw",
        "ALERT_FROM": "noreply@example.com",
        "ALERT_RECIPIENTS": "a@example.com, b@example.com",
    }
    s = _fresh_settings(monkeypatch, env)
    cfg = s.build_alert_config()
    assert cfg is not None
    assert cfg.smtp_host == "smtp.example.com"
    assert cfg.smtp_port == 2525
    assert cfg.smtp_user == "user"
    assert cfg.smtp_password == "pw"
    assert cfg.from_addr == "noreply@example.com"
    assert cfg.recipients == ["a@example.com", "b@example.com"]


def test_alert_config_none_when_recipients_missing(monkeypatch, tmp_path):
    env = {
        "CERT_WATCH_DATA_DIR": str(tmp_path),
        "SMTP_HOST": "smtp.example.com",
        "ALERT_FROM": "noreply@example.com",
    }
    for k in ("ALERT_RECIPIENTS",):
        monkeypatch.delenv(k, raising=False)
    s = _fresh_settings(monkeypatch, env)
    assert s.build_alert_config() is None


# ---------- humanize_expiry ----------


def _frozen_now(year=2026, month=6, day=1):
    return datetime(year, month, day, 12, 0, 0, tzinfo=UTC)


def test_humanize_in_days():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    target = fixed + timedelta(days=3)
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(target)
    assert "in 3 days" in out
    assert target.strftime("%Y-%m-%d") in out


def test_humanize_expired():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    target = fixed - timedelta(days=5)
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(target)
    assert "expired 5 days ago" in out


def test_humanize_months():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    target = fixed + timedelta(days=90)
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(target)
    assert "in 3 months" in out


def test_humanize_today():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(fixed)
    assert "today" in out


def test_humanize_accepts_iso_string():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    target = (fixed + timedelta(days=10)).isoformat()
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(target)
    assert "in 10 days" in out


def test_humanize_years():
    from cert_watch.filters import humanize_expiry
    fixed = _frozen_now()
    target = fixed + timedelta(days=800)
    with patch("cert_watch.filters.datetime") as mock_dt:
        mock_dt.now.return_value = fixed
        mock_dt.fromisoformat = datetime.fromisoformat
        out = humanize_expiry(target)
    assert "in 2 years" in out


# ---------- JSON logging ----------


def test_log_format_env_json(monkeypatch, tmp_path):
    monkeypatch.delenv("CERT_WATCH_LOG_FORMAT", raising=False)
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_LOG_FORMAT", "json")
    from cert_watch import config as _config
    importlib.reload(_config)
    s = _config.Settings.from_env()
    assert s.log_format == "json"


def test_log_format_env_text_default(monkeypatch, tmp_path):
    monkeypatch.delenv("CERT_WATCH_LOG_FORMAT", raising=False)
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch import config as _config
    importlib.reload(_config)
    s = _config.Settings.from_env()
    assert s.log_format == "text"


def test_json_formatter_output():
    import json
    import logging

    from cert_watch.app import _setup_logging

    # Remove existing handlers to get a clean slate for this test
    root = logging.getLogger("cert_watch")
    for h in list(root.handlers):
        root.removeHandler(h)

    _setup_logging(log_format="json")
    assert root.handlers, "expected at least one handler"
    formatter = root.handlers[-1].formatter

    record = logging.LogRecord(
        "cert_watch.test", logging.INFO, "", 0, "hello world", (), None
    )
    output = formatter.format(record)
    data = json.loads(output)
    assert data["level"] == "INFO"
    assert data["logger"] == "cert_watch.test"
    assert data["message"] == "hello world"
    assert "timestamp" in data

    # Clean up
    for h in list(root.handlers):
        root.removeHandler(h)


# ---------- default data dir (cross-platform) ----------


def test_default_data_dir_posix():
    from cert_watch import config as _config

    assert _config._default_data_dir_str("posix", None) == "/var/lib/cert-watch"
    assert _config._default_data_dir_str("posix", r"D:\ProgramData") == "/var/lib/cert-watch"


def test_default_data_dir_windows_uses_programdata():
    from cert_watch import config as _config

    assert (
        _config._default_data_dir_str("nt", r"D:\ProgramData")
        == r"D:\ProgramData\cert-watch"
    )


def test_default_data_dir_windows_fallback():
    from cert_watch import config as _config

    assert _config._default_data_dir_str("nt", None) == r"C:\ProgramData\cert-watch"


def test_data_dir_env_overrides_default(monkeypatch, tmp_path):
    s = _fresh_settings(monkeypatch, {"CERT_WATCH_DATA_DIR": str(tmp_path)})
    assert s.data_dir == tmp_path
    assert s.db_path == tmp_path / "cert-watch.sqlite3"


# ---------- audit retention ----------


def test_audit_retention_default(monkeypatch, tmp_path):
    monkeypatch.delenv("CERT_WATCH_AUDIT_RETENTION_DAYS", raising=False)
    s = _fresh_settings(monkeypatch, {"CERT_WATCH_DATA_DIR": str(tmp_path)})
    assert s.audit_retention_days == 90


def test_audit_retention_from_env(monkeypatch, tmp_path):
    s = _fresh_settings(
        monkeypatch,
        {"CERT_WATCH_DATA_DIR": str(tmp_path), "CERT_WATCH_AUDIT_RETENTION_DAYS": "30"},
    )
    assert s.audit_retention_days == 30


def test_audit_retention_invalid_falls_back(monkeypatch, tmp_path):
    s = _fresh_settings(
        monkeypatch,
        {"CERT_WATCH_DATA_DIR": str(tmp_path), "CERT_WATCH_AUDIT_RETENTION_DAYS": "soon"},
    )
    assert s.audit_retention_days == 90


def test_text_formatter_output():
    import logging


    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    record = logging.LogRecord(
        "cert_watch.test", logging.INFO, "", 0, "hello world", (), None
    )
    output = formatter.format(record)
    assert "hello world" in output
    assert "INFO" in output
