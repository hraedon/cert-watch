from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteHostRepository,
    init_schema,
    replace_scanned,
)
from cert_watch.database.queries import list_fleet_pivot


def _insert_host_with_cert(
    db, hostname, port, issuer, owner_name, renewal_method, days_remaining
):
    hosts = SqliteHostRepository(db)
    host_id = hosts.add(hostname, port)
    now = datetime.now(UTC)
    cert = Certificate(
        subject=f"*.{hostname}",
        issuer=issuer,
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=days_remaining),
        san_dns_names=[f"*.{hostname}"],
        fingerprint_sha256=hostname,
    )
    replace_scanned(db, hostname, port, cert, [], True)
    if owner_name:
        hosts.update_owner(host_id, owner_name=owner_name)
    if renewal_method:
        hosts.update_renewal(host_id, renewal_method=renewal_method)
    return host_id


def test_fleet_pivot_by_issuer(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "O=Let's Encrypt,CN=R3", "alice", "acme", 90)
    _insert_host_with_cert(db, "b.example.com", 443, "O=Let's Encrypt,CN=R3", "bob", "acme", 30)
    _insert_host_with_cert(db, "c.example.com", 443, "O=DigiCert,CN=SHA2", "carol", "manual", 60)

    groups = list_fleet_pivot(db, "issuer")
    assert len(groups) == 2
    keys = [g["key"] for g in groups]
    assert "Let's Encrypt" in keys
    assert "DigiCert" in keys
    le = [g for g in groups if g["key"] == "Let's Encrypt"][0]
    assert le["count"] == 2
    dc = [g for g in groups if g["key"] == "DigiCert"][0]
    assert dc["count"] == 1


def test_fleet_pivot_by_owner(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "Test CA", "alice", "", 90)
    _insert_host_with_cert(db, "b.example.com", 443, "Test CA", "alice", "", 30)
    _insert_host_with_cert(db, "c.example.com", 443, "Test CA", "", "", 60)

    groups = list_fleet_pivot(db, "owner")
    keys = [g["key"] for g in groups]
    assert "alice" in keys
    assert "Unassigned" in keys
    alice = [g for g in groups if g["key"] == "alice"][0]
    assert alice["count"] == 2
    unassigned = [g for g in groups if g["key"] == "Unassigned"][0]
    assert unassigned["count"] == 1


def test_fleet_pivot_by_renewal_method(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "Test CA", "", "acme", 90)
    _insert_host_with_cert(db, "b.example.com", 443, "Test CA", "", "manual", 30)
    _insert_host_with_cert(db, "c.example.com", 443, "Test CA", "", "", 60)

    groups = list_fleet_pivot(db, "renewal_method")
    keys = [g["key"] for g in groups]
    assert "ACME" in keys
    assert "Manual" in keys
    assert "Unknown" in keys


def test_fleet_pivot_empty_db(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    groups = list_fleet_pivot(db, "issuer")
    assert groups == []


def test_fleet_pivot_worst_urgency(tmp_path):
    db = tmp_path / "test.db"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "Test CA", "", "", 90)
    _insert_host_with_cert(db, "b.example.com", 443, "Test CA", "", "", 3)

    groups = list_fleet_pivot(db, "issuer")
    assert len(groups) == 1
    assert groups[0]["worst_urgency"] == "critical"
    assert groups[0]["earliest_expiry"] <= 3


def test_fleet_dashboard_view_param(tmp_path, monkeypatch):
    import importlib

    from cert_watch import config as _config

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "O=TestCA,CN=CA1", "", "", 90)

    from fastapi.testclient import TestClient

    with TestClient(app_mod.app) as client:
        r = client.get("/?view=issuer")
    assert r.status_code == 200
    assert "cw-table-pivot" in r.text
    assert "By issuer" in r.text
    assert "TestCA" in r.text


def test_fleet_dashboard_view_all_shows_normal_table(tmp_path, monkeypatch):
    import importlib

    from cert_watch import config as _config

    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _insert_host_with_cert(db, "a.example.com", 443, "Test CA", "", "", 90)

    from fastapi.testclient import TestClient

    with TestClient(app_mod.app) as client:
        r = client.get("/?view=")
    assert r.status_code == 200
    assert "cw-table-pivot" not in r.text
