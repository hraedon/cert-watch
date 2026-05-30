"""Tests for new v0.2 endpoints: delete host, delete cert, scan-now, alerts, history."""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def test_delete_host_removes_host_and_certs(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository
    from cert_watch.scan import ScannedEntry, store_scanned
    from cert_watch.upload import upload_certificate

    entry = upload_certificate(leaf_pem_file)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("delete-me.example.com", 443)
    # Simulate a scan storing certs for that host.
    se = ScannedEntry(host="delete-me.example.com", port=443, leaf=entry.leaf, chain=[])
    store_scanned(se, db)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/delete", follow_redirects=False)
    assert r.status_code == 303

    assert host_repo.get(hid) is None
    # Cert with that hostname/port should be gone.
    import sqlite3
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT COUNT(*) FROM certificates WHERE hostname = ? AND port = ?",
            ("delete-me.example.com", 443),
        ).fetchone()
    assert rows[0] == 0


def test_delete_certificate_removes_leaf_and_chain(tmp_path, reload_app, chain_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.upload import store_uploaded, upload_certificate
    entry = upload_certificate(chain_pem_file)
    leaf_id = store_uploaded(entry, db)

    import sqlite3
    with sqlite3.connect(str(db)) as conn:
        before = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    assert before >= 2

    with TestClient(app_mod.app) as client:
        r = client.post(f"/certificates/{leaf_id}/delete", follow_redirects=False)
    assert r.status_code == 303

    with sqlite3.connect(str(db)) as conn:
        after = conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]
    assert after == 0


def test_scan_now_calls_scan_host(tmp_path, monkeypatch, reload_app, self_signed_leaf):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository
    from cert_watch.scan import ScannedEntry
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("scan-target.example.com", 443)

    called = {}

    def fake_scan_host(hostname, port=443, **kw):
        called["args"] = (hostname, port)
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host", fake_scan_host)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/scan", follow_redirects=False)
    assert r.status_code == 303
    assert called["args"] == ("scan-target.example.com", 443)


def test_scan_now_surfaces_failure_to_user(tmp_path, monkeypatch, reload_app):
    """Regression: scan-now used to silently swallow ScanError, leaving the user
    with no UI feedback. Failure must redirect with ?warning= AND write a failure
    row to scan_history so the user can see what happened."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository
    from cert_watch.scan import ScanError
    hid = SqliteHostRepository(db).add("refused.example.com", 443)

    def fake_scan_host(hostname, port=443, **kw):
        return ScanError(hostname=hostname, port=port, error_message="connection refused")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host", fake_scan_host)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/scan", follow_redirects=False)
    assert r.status_code == 303
    assert "warning=" in r.headers["location"]
    loc = r.headers["location"]
    assert "connection%20refused" in loc or "connection+refused" in loc

    import sqlite3
    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT status, error_message FROM scan_history WHERE hostname=? AND port=?",
            ("refused.example.com", 443),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "failure"
    assert rows[0][1] == "connection refused"


def test_scan_now_404_redirect_on_unknown_host(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/hosts/does-not-exist/scan", follow_redirects=False)
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_alerts_view_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert r.status_code == 200
    assert "No alerts recorded" in r.text


def test_alerts_view_lists_existing(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema
    init_schema(db)
    SqliteAlertRepository(db).create(
        Alert(
            cert_id="fp1",
            alert_type="expiry_warning",
            status="pending",
            message="m",
            threshold_days=7,
        )
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert r.status_code == 200
    assert "m" in r.text  # alert message is displayed


def test_scan_history_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/scan-history")
    assert r.status_code == 200
    assert "No scans recorded" in r.text


def test_scan_history_lists_records(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history
    init_schema(db)
    record_scan_history(db, ScanHistory(hostname="h.example.com", port=443, status="success"))
    record_scan_history(
        db,
        ScanHistory(
            hostname="bad.example.com", port=443, status="failure", error_message="timeout"
        ),
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/scan-history")
    assert r.status_code == 200
    assert "h.example.com" in r.text
    assert "bad.example.com" in r.text
    assert "timeout" in r.text


def test_dashboard_lists_tracked_hosts(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteHostRepository
    SqliteHostRepository(db).add("tracked.example.com", 8443)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "tracked.example.com" in r.text


def test_lifespan_starts_scheduler(tmp_path, monkeypatch):
    """Assert start_scheduler is invoked on app startup."""
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    from cert_watch import config as _config
    importlib.reload(_config)
    from cert_watch import app as app_mod
    importlib.reload(app_mod)

    calls = {"start": 0, "stop": 0}

    def fake_start(**kwargs):
        calls["start"] += 1
        calls["start_kwargs"] = kwargs

    def fake_stop():
        calls["stop"] += 1

    monkeypatch.setattr(app_mod, "start_scheduler", fake_start)
    monkeypatch.setattr(app_mod, "stop_scheduler", fake_stop)

    with TestClient(app_mod.app) as client:
        client.get("/healthz")
    assert calls["start"] == 1
    assert calls["stop"] == 1
    # default hour/minute from env (unset) should be 6/0
    assert calls["start_kwargs"]["hour"] == 6
    assert calls["start_kwargs"]["minute"] == 0


def test_lifespan_respects_sched_env(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CERT_WATCH_SCHED_HOUR", "3")
    monkeypatch.setenv("CERT_WATCH_SCHED_MIN", "15")
    from cert_watch import config as _config
    importlib.reload(_config)
    from cert_watch import app as app_mod
    importlib.reload(app_mod)

    captured = {}

    monkeypatch.setattr(app_mod, "start_scheduler", lambda **kw: captured.update(kw))
    monkeypatch.setattr(app_mod, "stop_scheduler", lambda: None)

    with TestClient(app_mod.app) as client:
        client.get("/healthz")
    assert captured["hour"] == 3
    assert captured["minute"] == 15


def test_common_ports_checkbox_scans_multiple(tmp_path, monkeypatch, reload_app, self_signed_leaf):
    """FEAT-008: common_ports flag should scan multiple TLS ports."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository
    from cert_watch.scan import ScannedEntry

    scanned_ports = []

    def fake_scan_host(hostname, port=443, **kw):
        scanned_ports.append(port)
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host", fake_scan_host)

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts",
            data={"hostname": "multi.example.com", "common_ports": "true"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    # Should have scanned common TLS ports
    assert 443 in scanned_ports
    assert 8443 in scanned_ports
    assert len(scanned_ports) >= 2

    # All ports should be registered as hosts
    host_repo = SqliteHostRepository(db)
    hosts = host_repo.list_all()
    hostnames = [(h.hostname, h.port) for h in hosts]
    assert ("multi.example.com", 443) in hostnames
    assert ("multi.example.com", 8443) in hostnames
