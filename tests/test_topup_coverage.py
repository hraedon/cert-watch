"""Coverage tests for config.py, filters.py, and other modules.

Plan 024 Slice 5 — targeted top-ups to clear 90%.

Weak duplicates removed (2026-06-12 test-quality pass):
  Upload, cert_chain, database, tags, audit, and alert_adapter tests that
  were weaker copies of tests in test_upload.py, test_cert_chain.py,
  test_database.py, test_tags.py, test_audit.py, and test_alert_adapters.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

# ---------- config.py ----------


def test_config_from_env_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.db_path == tmp_path / "cert-watch.sqlite3"
    assert s.sched_hour == 6
    assert s.sched_min == 0
    assert s.allow_private is True


@pytest.mark.parametrize(
    "env_vars,attr,expected",
    [
        ({"CERT_WATCH_SCHED_HOUR": "3", "CERT_WATCH_SCHED_MIN": "15"}, "sched_hour", 3),
        ({"CERT_WATCH_SCHED_HOUR": "3", "CERT_WATCH_SCHED_MIN": "15"}, "sched_min", 15),
        ({"CERT_WATCH_ALLOW_PRIVATE_IPS": "0"}, "allow_private", False),
        ({"CERT_WATCH_CHECK_REVOCATION": "1"}, "check_revocation", True),
        ({"CERT_WATCH_DRIFT_ALERTS": "0"}, "drift_alerts", False),
        ({"CERT_WATCH_HISTORY_RETENTION_DAYS": "30"}, "history_retention_days", 30),
        ({"CERT_WATCH_ALERT_RETENTION_DAYS": "60"}, "alert_retention_days", 60),
        ({"CERT_WATCH_AUDIT_RETENTION_DAYS": "120"}, "audit_retention_days", 120),
    ],
)
def test_config_env_overrides(monkeypatch, tmp_path, env_vars, attr, expected):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    for k, v in env_vars.items():
        monkeypatch.setenv(k, v)
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert getattr(s, attr) == expected


def test_config_dns_servers(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_DNS_SERVERS", "8.8.8.8,8.8.4.4")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.dns_servers == ("8.8.8.8", "8.8.4.4")


def test_config_allowed_subnets(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_ALLOWED_SUBNETS", "10.0.0.0/8,192.168.0.0/16")
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.allowed_subnets == ("10.0.0.0/8", "192.168.0.0/16")


def test_config_build_webhook_config_none(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("ALERT_WEBHOOK_URL", raising=False)
    from cert_watch.config import Settings

    s = Settings.from_env()
    assert s.build_webhook_config() is None


def test_config_build_webhook_config(monkeypatch, tmp_path):
    import socket

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://hooks.example.com/test")
    original_getaddrinfo = socket.getaddrinfo

    def mock_getaddrinfo(host, port, *args, **kwargs):
        if host == "hooks.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        return original_getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", mock_getaddrinfo)
    from cert_watch.config import Settings

    s = Settings.from_env()
    cfg = s.build_webhook_config()
    assert cfg is not None
    assert cfg.url == "https://hooks.example.com/test"
    assert cfg.allow_private is True


def test_config_pagerduty_routing_key(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("ALERT_PAGERDUTY_ROUTING_KEY", "pd-key-123")
    monkeypatch.setenv("ALERT_WEBHOOK_URL", "https://events.pagerduty.com")
    from cert_watch.config import Settings

    s = Settings.from_env()
    cfg = s.build_webhook_config()
    assert cfg is not None
    assert cfg.routing_key == "pd-key-123"


# ---------- filters.py ----------


def test_compute_urgency():
    from cert_watch.filters import compute_urgency

    assert compute_urgency(-1) == "expired"
    assert compute_urgency(3) == "critical"
    assert compute_urgency(14) == "warning"
    assert compute_urgency(90) == "healthy"


def test_friendly_issuer():
    from cert_watch.filters import friendly_issuer

    result = friendly_issuer("CN=R3,O=Let's Encrypt,C=US")
    assert "Let's Encrypt" in result
    assert result != "CN=R3,O=Let's Encrypt,C=US"


def test_subject_cn():
    from cert_watch.filters import subject_cn

    assert subject_cn("CN=example.com,O=Test") == "example.com"
    assert subject_cn("O=Test") == "O=Test"


def test_issuer_cn():
    from cert_watch.filters import issuer_cn

    assert issuer_cn("CN=R3,O=Let's Encrypt") == "R3"


# ---------- database/connection.py ----------


def test_connect_creates_db(tmp_path):
    from cert_watch.database.connection import _connect

    db = tmp_path / "new.sqlite3"
    with _connect(db) as conn:
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.execute("INSERT INTO test VALUES (1)")
        row = conn.execute("SELECT * FROM test").fetchone()
    assert row[0] == 1


def test_parse_iso():
    from cert_watch.database.connection import _parse_iso

    dt = _parse_iso("2026-01-15T12:00:00+00:00")
    assert dt.year == 2026
    assert dt.month == 1
    assert dt.hour == 12


# ---------- database/repo.py ----------


def test_host_repo_crud(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("h.example.com", 443)
    assert hid
    host = repo.get(hid)
    assert host is not None
    assert host.hostname == "h.example.com"
    assert host.port == 443
    hosts = repo.list_all()
    assert len(hosts) == 1
    repo.delete(hid)
    assert repo.get(hid) is None


def test_host_repo_update_tags(tmp_path):
    from cert_watch.database import SqliteHostRepository, init_schema

    db = tmp_path / "test.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    hid = repo.add("h.example.com", 443)
    assert repo.set_tags(hid, "prod,web") is True
    host = repo.get(hid)
    assert host.tags == "prod,web"
    assert "prod" in host.tags
    assert "web" in host.tags


# ---------- certificate_model.py ----------


def test_certificate_expired():
    from cert_watch.certificate_model import Certificate

    now = datetime.now(UTC)
    cert = Certificate(
        subject="expired.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=60),
        not_after=now - timedelta(days=1),
    )
    assert cert.days_until_expiry() < 0
    assert cert.days_until_expiry() == -1 or cert.days_until_expiry() < 0
