"""Tests for new v0.2 endpoints: delete host, delete cert, scan-now, alerts, history."""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient


def test_delete_host_removes_host_and_certs(tmp_path, reload_app, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry, store_scanned
    from cert_watch.upload import upload_certificate

    init_schema(db)
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

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry
    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("scan-target.example.com", 443)

    called = {}

    async def fake_scan_host(hostname, port=443, **kw):
        called["args"] = (hostname, port)
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)

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

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScanError
    init_schema(db)
    hid = SqliteHostRepository(db).add("refused.example.com", 443)

    async def fake_scan_host(hostname, port=443, **kw):
        return ScanError(hostname=hostname, port=port, error_message="connection refused")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/scan", follow_redirects=False)
    assert r.status_code == 303
    assert "warning=" in r.headers["location"]
    loc = r.headers["location"]
    assert "connection%20refused" in loc or "connection+refused" in loc

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
        r = client.post("/hosts/00000000-0000-0000-0000-000000000000/scan", follow_redirects=False)
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


def _seed_alert(db):
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema
    init_schema(db)
    SqliteAlertRepository(db).create(
        Alert(cert_id="fp1", alert_type="expiry_warning", status="pending",
              message="m", threshold_days=7)
    )


def test_alerts_channels_reflect_config(tmp_path, reload_app):
    """BC-130: delivery chips reflect configured channels, not hardcoded."""
    db = tmp_path / "cert-watch.sqlite3"
    # No channels configured → muted "No channels configured", no Email/Webhook.
    app_mod = reload_app()
    _seed_alert(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert "No channels configured" in r.text
    assert "Email" not in r.text and "Webhook" not in r.text


def test_alerts_channels_show_email_when_smtp_configured(tmp_path, reload_app):
    db = tmp_path / "cert-watch.sqlite3"
    app_mod = reload_app(
        SMTP_HOST="mail.example.com",
        ALERT_FROM="certs@example.com",
        ALERT_RECIPIENTS="ops@example.com",
    )
    _seed_alert(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert "Email" in r.text
    assert "No channels configured" not in r.text


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
    from cert_watch.database import SqliteHostRepository, init_schema
    init_schema(db)
    SqliteHostRepository(db).add("tracked.example.com", 8443)
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "tracked.example.com" in r.text


def test_lifespan_starts_scheduler(tmp_path, monkeypatch, reload_app):
    """Assert start_scheduler is invoked on app startup."""
    import cert_watch.app as app_module

    app_mod = reload_app()
    calls = {"start": 0, "stop": 0}

    def fake_start(**kwargs):
        calls["start"] += 1
        calls["start_kwargs"] = kwargs

    def fake_stop():
        calls["stop"] += 1

    monkeypatch.setattr(app_module, "start_scheduler", fake_start)
    monkeypatch.setattr(app_module, "stop_scheduler", fake_stop)

    with TestClient(app_mod.app) as client:
        client.get("/healthz")
    assert calls["start"] == 1
    assert calls["stop"] == 1
    # default hour/minute from env (unset) should be 6/0
    assert calls["start_kwargs"]["hour"] == 6
    assert calls["start_kwargs"]["minute"] == 0


def test_lifespan_respects_sched_env(tmp_path, monkeypatch, reload_app):
    monkeypatch.setenv("CERT_WATCH_SCHED_HOUR", "3")
    monkeypatch.setenv("CERT_WATCH_SCHED_MIN", "15")
    import cert_watch.app as app_module

    app_mod = reload_app()
    captured = {}

    monkeypatch.setattr(app_module, "start_scheduler", lambda **kw: captured.update(kw))
    monkeypatch.setattr(app_module, "stop_scheduler", lambda: None)

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

    async def fake_scan_host(hostname, port=443, **kw):
        scanned_ports.append(port)
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)

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


def test_hosts_store_path_survives_across_event_loops(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Regression (pre-existing _store_sem cross-loop bug): the /hosts store path
    must not rely on a module-level asyncio primitive that binds to the first
    event loop and raises RuntimeError on the next TestClient. WI-092's
    get_write_lock (inside store_scanned_async) serializes writes, so the
    module-level semaphore is gone.
    """
    from cert_watch.scan import ScannedEntry

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)

    app1 = reload_app()
    with TestClient(app1.app) as client:
        r1 = client.post(
            "/hosts",
            data={"hostname": "loop-a.example.com", "common_ports": "true"},
            follow_redirects=False,
        )
    assert r1.status_code == 303

    app2 = reload_app()
    with TestClient(app2.app) as client:
        r2 = client.post(
            "/hosts",
            data={"hostname": "loop-b.example.com", "common_ports": "true"},
            follow_redirects=False,
        )
    assert r2.status_code == 303


# ---------- Semaphore failure-isolation branches (BC-134) ----------


def test_add_host_store_scanned_async_failure_isolated(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """When store_scanned_async raises inside the semaphore, the exception is
    caught and the route still redirects (failure isolation per-task)."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry

    init_schema(db)
    host_repo = SqliteHostRepository(db)

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    async def failing_store(*args, **kwargs):
        raise sqlite3.DatabaseError("store boom")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", failing_store)

    with TestClient(app_mod.app) as client:
        r = client.post(
            "/hosts",
            data={"hostname": "store-fail.example.com", "port": "443"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    # Host was added even though store failed
    assert host_repo.count_all() == 1


def test_import_hosts_store_scanned_async_failure_isolated(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Import batch: one store failure must not abort the others and must be
    recorded in scan_history."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry

    init_schema(db)
    host_repo = SqliteHostRepository(db)

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    call_count = {"n": 0}

    async def flaky_store(*args, **kwargs):
        call_count["n"] += 1
        # Second call (fail.example.com) fails.
        if call_count["n"] == 2:
            raise sqlite3.DatabaseError("store boom")
        return "leaf-id"

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", flaky_store)

    with TestClient(app_mod.app) as client:
        csv_content = "hostname,port\nok.example.com,443\nfail.example.com,443\n"
        r = client.post(
            "/hosts/import",
            files={"file": ("hosts.csv", csv_content.encode(), "text/csv")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    # Both hosts were added despite one store failure
    assert host_repo.count_all() == 2

    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT hostname, status, error_message FROM scan_history ORDER BY hostname"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "fail.example.com"
    assert rows[0][1] == "failure"
    assert rows[0][2] == "store failed: store boom"
    assert rows[1][0] == "ok.example.com"
    assert rows[1][1] == "success"


def test_scan_now_store_scanned_async_failure_isolated(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Manual scan: store_scanned_async failure must redirect with warning and
    record scan_history."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry

    init_schema(db)
    hid = SqliteHostRepository(db).add("manual-store-fail.example.com", 443)

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    async def failing_store(*args, **kwargs):
        raise sqlite3.DatabaseError("store boom")

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", failing_store)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/scan", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert "warning=" in loc
    assert "store%20failed" in loc or "store+failed" in loc

    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT status, error_message FROM scan_history WHERE hostname=? AND port=?",
            ("manual-store-fail.example.com", 443),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "failure"
    assert rows[0][1] == "store failed: store boom"


def test_scan_all_hosts_store_scanned_async_failure_isolated(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """Scan-all: store_scanned_async failure on one host must not stop the loop
    and must be recorded in scan_history."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    host_repo.add("batch-a.example.com", 443)
    host_repo.add("batch-b.example.com", 443)

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    call_count = {"n": 0}

    async def flaky_store(*args, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 2:
            raise sqlite3.DatabaseError("store boom")
        return "leaf-id"

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", flaky_store)

    with TestClient(app_mod.app) as client:
        r = client.post("/hosts/all/scan", follow_redirects=False)
    assert r.status_code == 303

    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT hostname, status, error_message FROM scan_history ORDER BY hostname"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "batch-a.example.com"
    assert rows[0][1] == "success"
    assert rows[0][2] is None
    assert rows[1][0] == "batch-b.example.com"
    assert rows[1][1] == "failure"
    assert rows[1][2] == "store failed: store boom"


def test_scan_now_store_scanned_empty_return_treated_as_failure(
    tmp_path, monkeypatch, reload_app, self_signed_leaf
):
    """When store_scanned_async returns '' (transaction rolled back), the route
    must treat it as a store failure, not success (WI-094 regression)."""
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"

    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scan import ScannedEntry

    init_schema(db)
    hid = SqliteHostRepository(db).add("empty-return.example.com", 443)

    async def fake_scan_host(hostname, port=443, **kw):
        from cert_watch.certificate_model import parse_certificate
        cert = parse_certificate(self_signed_leaf.der)
        return ScannedEntry(host=hostname, port=port, leaf=cert, chain=[])

    async def empty_return_store(*args, **kwargs):
        return ""

    monkeypatch.setattr("cert_watch.routes.hosts.scan_host_async", fake_scan_host)
    monkeypatch.setattr("cert_watch.routes.hosts.store_scanned_async", empty_return_store)

    with TestClient(app_mod.app) as client:
        r = client.post(f"/hosts/{hid}/scan", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert "warning=" in loc

    with sqlite3.connect(str(db)) as conn:
        rows = conn.execute(
            "SELECT status, error_message FROM scan_history WHERE hostname=? AND port=?",
            ("empty-return.example.com", 443),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "failure"
    assert rows[0][1] == "store failed: transaction rolled back"


def test_flush_alert_queue(tmp_path, reload_app):
    """POST /alerts/flush triggers process_pending and redirects back."""
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema

    init_schema(db)
    SqliteAlertRepository(db).create(
        Alert(
            cert_id="fp1",
            alert_type="expiry_warning",
            status="pending",
            message="expiring soon",
            threshold_days=7,
        )
    )
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/alerts/flush", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/alerts?")


def test_flush_alert_queue_rate_limited(tmp_path, reload_app):
    """Flush is rate-limited: too many requests returns a rate-limit redirect."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        for _ in range(4):
            r = client.post("/alerts/flush", follow_redirects=False)
        assert r.status_code == 303
        assert "error" in r.headers["location"]


def test_mark_all_alerts_read(tmp_path, reload_app):
    """POST /alerts/mark-all-read marks all unread alerts as read."""
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, _connect, init_schema

    init_schema(db)
    SqliteAlertRepository(db).create(
        Alert(
            cert_id="fp1",
            alert_type="expiry_warning",
            status="pending",
            message="m1",
            threshold_days=7,
        )
    )
    SqliteAlertRepository(db).create(
        Alert(
            cert_id="fp2",
            alert_type="expired",
            status="sent",
            message="m2",
            threshold_days=0,
        )
    )
    # Verify both are unread before the action
    with _connect(db) as conn:
        unread_before = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE read = 0"
        ).fetchone()[0]
    assert unread_before == 2

    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/alerts/mark-all-read", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/alerts?")
    assert "saved" in r.headers["location"]

    # Verify all are now read
    with _connect(db) as conn:
        unread_after = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE read = 0"
        ).fetchone()[0]
    assert unread_after == 0


def test_mark_all_alerts_read_empty(tmp_path, reload_app):
    """Mark all read on an empty alerts table redirects gracefully."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/alerts/mark-all-read", follow_redirects=False)
    assert r.status_code == 303
    assert "0%20alert" in r.headers["location"]


def test_alerts_page_shows_action_buttons(reload_app):
    """Alerts page renders Mark all read and Flush queue buttons."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert r.status_code == 200
    assert "Mark all read" in r.text
    assert "Flush queue" in r.text


def test_alerts_page_saved_flash(reload_app):
    """Alerts page renders the saved flash message when present."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts?saved=3+alerts+sent")
    assert r.status_code == 200
    assert "3 alerts sent" in r.text


# ── Health endpoint DB check ────────────────────────────────────────────────


class TestHealthDBCheck:
    """/api/health must check DB connectivity."""

    def test_health_includes_db_check(self):
        import inspect

        from cert_watch.routes.views import api_health

        source = inspect.getsource(api_health)
        assert "SELECT 1" in source, (
            "Health endpoint should include a DB connectivity check (SELECT 1)"
        )
        assert "db_ok" in source, (
            "Health endpoint should track db_ok status"
        )


# ── kv_store persistence across restarts (BC-159) ──────────────────────────


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
    monkeypatch.delenv("AUTH_PROVIDER", raising=False)

    app = create_app()
    with TestClient(app) as client:
        r = client.get("/healthz")
        assert r.status_code == 200

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
