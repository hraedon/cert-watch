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
