"""Coverage tests for routes/views.py, routes/certificates.py, routes/audit.py.

Plan 024 Slice 1 — read/render paths, filter branches, error paths.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cert_watch.upload import store_uploaded, upload_certificate


def _reload(monkeypatch, tmp_path):
    monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
    import importlib

    from cert_watch import config as _config

    importlib.reload(_config)
    from cert_watch import app as app_mod

    importlib.reload(app_mod)
    return app_mod


# ---------- readyz ----------


def test_readyz_with_scan_history(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    record_scan_history(db, ScanHistory(hostname="h.example.com", port=443, status="success"))
    with TestClient(app_mod.app) as client:
        r = client.get("/readyz")
    assert r.status_code == 200
    data = r.json()
    assert data["checks"]["last_scan"] != "none"
    assert data["checks"]["last_scan_status"] == "success"


def test_readyz_db_error(monkeypatch, reload_app):
    app_mod = reload_app()
    import cert_watch.routes.views as views_mod

    orig = views_mod._connect

    def bad_connect(db):
        raise RuntimeError("db down")

    monkeypatch.setattr(views_mod, "_connect", bad_connect)
    with TestClient(app_mod.app) as client:
        r = client.get("/readyz")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "degraded"
    monkeypatch.setattr(views_mod, "_connect", orig)


# ---------- api/health ----------


def test_api_health_no_scan(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["last_scan_at"] is None
    assert data["last_scan_status"] is None
    assert data["auth_provider"] == "none"
    assert data["break_glass_enabled"] is False


def test_api_health_with_scan_and_alerts(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    record_scan_history(db, ScanHistory(hostname="h.example.com", port=443, status="failure"))
    SqliteAlertRepository(db).create(
        Alert(
            cert_id="fp1",
            alert_type="expiry_warning",
            status="failed",
            message="m",
            threshold_days=7,
        )
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/api/health")
    assert r.status_code == 200
    data = r.json()
    assert data["last_scan_status"] == "failure"
    assert data["overall"] == "warning"


# ---------- dashboard pivot views ----------


def test_dashboard_pivot_issuer(tmp_path, monkeypatch, reload_app, self_signed_leaf):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="pivot.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    SqliteCertificateRepository(db, source="uploaded").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/?view=issuer")
    assert r.status_code == 200
    assert "Test CA" in r.text


def test_dashboard_pivot_owner(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="own.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    SqliteCertificateRepository(db, source="uploaded").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/?view=owner")
    assert r.status_code == 200


def test_dashboard_pivot_renewal_method(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="rm.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
    )
    SqliteCertificateRepository(db, source="uploaded").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/?view=renewal_method")
    assert r.status_code == 200


# ---------- dashboard fleet grade ----------


def test_dashboard_fleet_grade_with_data(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema, store_scan_posture

    init_schema(db)
    store_scan_posture(str(db), "cert-a", "h.example.com", 443, "A", [], protocol_version="TLSv1.3")
    store_scan_posture(
        str(db), "cert-b", "h2.example.com", 443, "B", [], protocol_version="TLSv1.2"
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "fleet-grade" in r.text or "Fleet" in r.text


# ---------- dashboard ungrouped view with data ----------


def test_dashboard_ungrouped_with_data(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    SqliteHostRepository(db).add("ung.example.com", 443)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="ung.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="c" * 64,
    )
    replace_scanned(db, "ung.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get("/?grouped=0")
    assert r.status_code == 200
    assert "ung.example.com" in r.text


# ---------- dashboard sort orders ----------


def test_dashboard_sort_by_subject(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema

    init_schema(db)
    now = datetime.now(UTC)
    for name in ["aaa.example.com", "zzz.example.com"]:
        cert = Certificate(
            subject=name,
            issuer="Test CA",
            not_before=now - timedelta(days=1),
            not_after=now + timedelta(days=90),
        )
        SqliteCertificateRepository(db, source="uploaded").add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get("/?sort_by=subject&sort_order=desc")
    assert r.status_code == 200


# ---------- alerts view with group routing ----------


def test_alerts_view_with_group_routing(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import (
        Alert,
        SqliteAlertGroupRepository,
        SqliteAlertRepository,
        SqliteCertificateRepository,
        init_schema,
    )

    init_schema(db)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="grp.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=5),
        fingerprint_sha256="d" * 64,
    )
    cert_id = SqliteCertificateRepository(db, source="scanned").add(cert)
    group_repo = SqliteAlertGroupRepository(db)
    gid = group_repo.create("ops-team", ["ops@example.com"], [], "")
    group_repo.assign_cert(gid, cert_id)
    SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status="pending",
            message="expiring!",
            threshold_days=7,
        )
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts")
    assert r.status_code == 200
    assert "expiring!" in r.text


def test_alerts_view_pagination(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import Alert, SqliteAlertRepository, init_schema

    init_schema(db)
    repo = SqliteAlertRepository(db)
    for i in range(60):
        repo.create(
            Alert(
                cert_id=f"fp{i}",
                alert_type="expiry_warning",
                status="pending",
                message=f"msg{i}",
                threshold_days=7,
            )
        )
    with TestClient(app_mod.app) as client:
        r = client.get("/alerts?page=2")
    assert r.status_code == 200
    assert "Page 2" in r.text


# ---------- scan-history pagination ----------


def test_scan_history_pagination(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    for i in range(60):
        record_scan_history(
            db, ScanHistory(hostname=f"h{i}.example.com", port=443, status="success")
        )
    with TestClient(app_mod.app) as client:
        r = client.get("/scan-history?page=2")
    assert r.status_code == 200
    assert "Page 2" in r.text


# ---------- insights ----------


def test_insights_view(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/insights")
    assert r.status_code == 200
    assert "insights" in r.text.lower() or "calendar" in r.text.lower()


def test_insights_view_tls_tab(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/insights?tab=tls")
    assert r.status_code == 200


# ---------- discover ----------


def test_discover_view_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200


def test_discover_view_with_hosts(tmp_path, monkeypatch, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    SqliteHostRepository(db).add("disc.example.com", 443)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="disc.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        san_dns_names=["disc.example.com"],
        fingerprint_sha256="a" * 64,
    )
    replace_scanned(db, "disc.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200


# ---------- ct-lookup ----------


def test_ct_lookup_error(monkeypatch, reload_app):
    app_mod = reload_app()
    import cert_watch.ct_lookup as ctl

    monkeypatch.setattr(ctl, "query_ct_log", lambda domain: "DNS error")
    with TestClient(app_mod.app) as client:
        r = client.get("/ct-lookup/example.com")
    assert r.status_code == 200
    assert r.json()["error"] == "DNS error"


def test_ct_lookup_success(monkeypatch, reload_app):
    from dataclasses import dataclass
    from datetime import UTC, datetime

    @dataclass
    class FakeEntry:
        common_name: str = "*.example.com"
        issuer_name: str = "Test CA"
        name_value: str = "*.example.com"
        not_before: datetime = datetime(2025, 1, 1, tzinfo=UTC)
        not_after: datetime = datetime(2027, 1, 1, tzinfo=UTC)
        serial_number: str = "abc123"

    app_mod = reload_app()
    import cert_watch.ct_lookup as ctl

    monkeypatch.setattr(ctl, "query_ct_log", lambda domain: [FakeEntry()])
    with TestClient(app_mod.app) as client:
        r = client.get("/ct-lookup/example.com")
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert data["entries"][0]["common_name"] == "*.example.com"


# ---------- caa-check ----------


def test_caa_check_invalid_domain(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/caa-check/invalid..domain")
    assert r.status_code == 200
    assert "error" in r.json()


def test_caa_check_empty_domain(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/caa-check/")
    assert r.status_code in (200, 404)


def test_caa_check_long_domain(reload_app):
    app_mod = reload_app()
    long_domain = "a" * 254 + ".com"
    with TestClient(app_mod.app) as client:
        r = client.get(f"/caa-check/{long_domain}")
    assert r.status_code == 200
    assert "error" in r.json()


def test_caa_check_success(monkeypatch, reload_app):
    from dataclasses import dataclass

    @dataclass
    class FakeCAA:
        records: list = None
        issue_allowed: bool = True
        issuewild_allowed: bool = False
        error: str = ""

        def __post_init__(self):
            if self.records is None:
                self.records = ['0 issue "letsencrypt.org"']

    app_mod = reload_app()
    import cert_watch.caa_check as cc

    monkeypatch.setattr(cc, "check_caa", lambda domain: FakeCAA())
    with TestClient(app_mod.app) as client:
        r = client.get("/caa-check/example.com")
    assert r.status_code == 200
    data = r.json()
    assert data["issue_allowed"] is True


def test_caa_check_with_error(monkeypatch, reload_app):
    from dataclasses import dataclass

    @dataclass
    class FakeCAA:
        records: list = None
        issue_allowed: bool = False
        issuewild_allowed: bool = False
        error: str = "DNS timeout"

        def __post_init__(self):
            if self.records is None:
                self.records = []

    app_mod = reload_app()
    import cert_watch.caa_check as cc

    monkeypatch.setattr(cc, "check_caa", lambda domain: FakeCAA())
    with TestClient(app_mod.app) as client:
        r = client.get("/caa-check/example.com")
    assert r.status_code == 200
    assert r.json()["error"] == "DNS timeout"


# ---------- metrics ----------


def test_metrics_unauthorized(reload_app, monkeypatch):
    app_mod = reload_app()
    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_METRICS_TOKEN", "secret-token")
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 401


def test_metrics_authorized(reload_app, monkeypatch):
    app_mod = reload_app()
    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_METRICS_TOKEN", "secret-token")
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200


def test_metrics_with_scan_errors(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    record_scan_history(
        db,
        ScanHistory(
            hostname="err.example.com",
            port=443,
            status="failure",
            error_message="connection refused",
        ),
    )
    record_scan_history(
        db,
        ScanHistory(
            hostname="to.example.com", port=443, status="failure", error_message="timed out"
        ),
    )
    record_scan_history(
        db,
        ScanHistory(
            hostname="dns.example.com",
            port=443,
            status="failure",
            error_message="dns resolve failed",
        ),
    )
    record_scan_history(
        db,
        ScanHistory(
            hostname="blk.example.com",
            port=443,
            status="failure",
            error_message="blocked by policy",
        ),
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    text = r.text
    assert "cert_scan_errors_total" in text
    assert "connection_refused" in text
    assert "timeout" in text
    assert "dns_failure" in text
    assert "blocked" in text


def test_metrics_unknown_error_reason(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    record_scan_history(
        db,
        ScanHistory(
            hostname="unk.example.com", port=443, status="failure", error_message="something weird"
        ),
    )
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200
    assert "unknown" in r.text


def test_metrics_no_error_message(reload_app, tmp_path):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    record_scan_history(db, ScanHistory(hostname="nm.example.com", port=443, status="failure"))
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics")
    assert r.status_code == 200


# ---------- certificate detail ----------


def test_certificate_detail_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/certificates/nonexistent", follow_redirects=False)
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_certificate_detail_with_chain(tmp_path, monkeypatch, chain_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(chain_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "chain-leaf.example.com" in r.text
    assert "Certificate chain" in r.text


def test_certificate_detail_with_trust_anchor(tmp_path, monkeypatch, chain_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteTrustAnchorRepository, init_schema
    from cert_watch.upload import upload_certificate

    init_schema(db)
    entry = upload_certificate(chain_pem_file)
    # Add root as trust anchor
    root_cert = entry.chain[-1] if entry.chain else entry.leaf
    SqliteTrustAnchorRepository(db).add(root_cert)
    cert_id = store_uploaded(entry, db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200


def test_certificate_detail_host_info_acme(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("acme.example.com", 443)
    host_repo.update_renewal(hid, renewal_method="acme")
    host_repo.update_owner(hid, owner_name="Ops Team", owner_email="ops@example.com")
    now = datetime.now(UTC)
    cert = Certificate(
        subject="acme.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="e" * 64,
    )
    replace_scanned(db, "acme.example.com", 443, cert, [], True)
    from cert_watch.scheduler import ScanHistory, record_scan_history

    record_scan_history(db, ScanHistory(hostname="acme.example.com", port=443, status="success"))
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert.fingerprint_sha256}")
    assert r.status_code == 200


def test_certificate_detail_host_info_cert_manager(tmp_path, monkeypatch):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("cm.example.com", 443)
    host_repo.update_renewal(hid, renewal_method="cert-manager")
    now = datetime.now(UTC)
    cert = Certificate(
        subject="cm.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="f" * 64,
    )
    replace_scanned(db, "cm.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert.fingerprint_sha256}")
    assert r.status_code == 200


def test_certificate_detail_host_info_manual(tmp_path, monkeypatch):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("man.example.com", 443)
    host_repo.update_renewal(hid, renewal_method="manual")
    now = datetime.now(UTC)
    cert = Certificate(
        subject="man.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="1" * 64,
    )
    replace_scanned(db, "man.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert.fingerprint_sha256}")
    assert r.status_code == 200


def test_certificate_detail_host_info_custom_method(tmp_path, monkeypatch):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("cust.example.com", 443)
    host_repo.update_renewal(hid, renewal_method="terraform")
    now = datetime.now(UTC)
    cert = Certificate(
        subject="cust.example.com",
        issuer="Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="2" * 64,
    )
    replace_scanned(db, "cust.example.com", 443, cert, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert.fingerprint_sha256}")
    assert r.status_code == 200


def test_certificate_detail_with_drift_events(tmp_path, monkeypatch):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    host_repo = SqliteHostRepository(db)
    host_repo.add("drift.example.com", 443)
    now = datetime.now(UTC)
    cert1 = Certificate(
        subject="drift.example.com",
        issuer="Old CA",
        not_before=now - timedelta(days=60),
        not_after=now + timedelta(days=30),
        fingerprint_sha256="a" * 64,
    )
    cert2 = Certificate(
        subject="drift.example.com",
        issuer="New CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="b" * 64,
    )
    replace_scanned(db, "drift.example.com", 443, cert1, [], True)
    replace_scanned(db, "drift.example.com", 443, cert2, [], True)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert2.fingerprint_sha256}")
    assert r.status_code == 200


# ---------- certificate delete ----------


def test_delete_certificate_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post("/certificates/nonexistent/delete", follow_redirects=False)
    assert r.status_code == 303


# ---------- certificate notes ----------


def test_update_notes_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/certificates/nonexistent/notes", data={"notes": "test"}, follow_redirects=False
        )
    assert r.status_code == 303
    assert "not+found" in r.headers["location"] or "not%20found" in r.headers["location"]


def test_update_notes_too_long(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/notes",
            data={"notes": "x" * 10001},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "too+long" in r.headers["location"] or "too%20long" in r.headers["location"]


# ---------- upload ----------


def test_upload_invalid_cert(reload_app, tmp_path):
    app_mod = reload_app()
    bad_file = tmp_path / "bad.pem"
    bad_file.write_text("not a cert")
    with TestClient(app_mod.app) as client, open(bad_file, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("bad.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_upload_pfx(tmp_path, monkeypatch, pfx_file_no_password):
    app_mod = _reload(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client, open(pfx_file_no_password, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("bundle.pfx", f, "application/x-pkcs12")},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_upload_p7b(tmp_path, monkeypatch, p7b_der_file):
    app_mod = _reload(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client, open(p7b_der_file, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("chain.p7b", f, "application/x-pkcs7-certificates")},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_upload_rate_limit(tmp_path, monkeypatch, leaf_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    import cert_watch.routes.certificates as cert_mod

    call_count = {"n": 0}

    def counting_rate_limit(*args, **kwargs):
        call_count["n"] += 1
        return not call_count["n"] > 10

    monkeypatch.setattr(cert_mod, "check_rate_limit", counting_rate_limit)
    with TestClient(app_mod.app) as client:
        for _ in range(11):
            with open(leaf_pem_file, "rb") as f:
                client.post("/upload", files={"file": ("leaf.pem", f, "application/x-pem-file")})
        with open(leaf_pem_file, "rb") as f:
            r = client.post(
                "/upload",
                files={"file": ("leaf.pem", f, "application/x-pem-file")},
                follow_redirects=False,
            )
    assert r.status_code == 303
    assert "rate+limited" in r.headers["location"] or "rate%20limited" in r.headers["location"]


# ---------- trust anchors ----------


def test_add_trust_anchor_valid(tmp_path, monkeypatch, chain_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client, open(chain_pem_file, "rb") as f:
        r = client.post(
            "/trust-anchors",
            files={"file": ("root.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_add_trust_anchor_invalid_cert(tmp_path, monkeypatch, leaf_pem_file):
    """Non-CA cert should be rejected as trust anchor."""
    app_mod = _reload(monkeypatch, tmp_path)
    with TestClient(app_mod.app) as client, open(leaf_pem_file, "rb") as f:
        r = client.post(
            "/trust-anchors",
            files={"file": ("leaf.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_delete_trust_anchor(tmp_path, monkeypatch, chain_pem_file):
    app_mod = _reload(monkeypatch, tmp_path)
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteTrustAnchorRepository, init_schema
    from cert_watch.upload import upload_certificate

    init_schema(db)
    entry = upload_certificate(chain_pem_file)
    root_cert = entry.chain[-1] if entry.chain else entry.leaf
    anchor_id = SqliteTrustAnchorRepository(db).add(root_cert)
    with TestClient(app_mod.app) as client:
        r = client.post(f"/trust-anchors/{anchor_id}/delete", follow_redirects=False)
    assert r.status_code == 303


# ---------- audit page ----------


def test_audit_page_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/audit")
    assert r.status_code == 200


def test_audit_page_with_entries(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.audit import record_audit
    from cert_watch.database import init_schema

    init_schema(db)
    for i in range(5):
        record_audit(db, actor="admin", action="host.add", target_type="host", target_id=f"h{i}")
    with TestClient(app_mod.app) as client:
        r = client.get("/audit")
    assert r.status_code == 200
    assert "admin" in r.text


def test_audit_page_filter_by_target_type(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.audit import record_audit
    from cert_watch.database import init_schema

    init_schema(db)
    record_audit(db, actor="admin", action="host.add", target_type="host", target_id="h1")
    record_audit(db, actor="admin", action="cert.upload", target_type="certificate", target_id="c1")
    with TestClient(app_mod.app) as client:
        r = client.get("/audit?target_type=host")
    assert r.status_code == 200
    assert "host.add" in r.text


def test_audit_page_filter_by_actor(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.audit import record_audit
    from cert_watch.database import init_schema

    init_schema(db)
    record_audit(db, actor="alice", action="host.add", target_type="host", target_id="h1")
    record_audit(db, actor="bob", action="cert.upload", target_type="certificate", target_id="c1")
    with TestClient(app_mod.app) as client:
        r = client.get("/audit?actor=alice")
    assert r.status_code == 200
    assert "alice" in r.text


def test_audit_page_pagination(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.audit import record_audit
    from cert_watch.database import init_schema

    init_schema(db)
    for i in range(60):
        record_audit(db, actor="admin", action="host.add", target_type="host", target_id=f"h{i}")
    with TestClient(app_mod.app) as client:
        r = client.get("/audit?page=2")
    assert r.status_code == 200
    assert "Page 2" in r.text


# ---------- API audit ----------


def test_api_audit_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/audit")
    assert r.status_code == 200
    data = r.json()
    assert data["audit"] == []
    assert "pagination" in data


def test_api_audit_with_filters(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.audit import record_audit
    from cert_watch.database import init_schema

    init_schema(db)
    record_audit(db, actor="admin", action="host.add", target_type="host", target_id="h1")
    record_audit(db, actor="admin", action="cert.upload", target_type="certificate", target_id="c1")
    with TestClient(app_mod.app) as client:
        r = client.get("/api/audit?target_type=host&actor=admin&limit=10")
    assert r.status_code == 200
    data = r.json()
    assert len(data["audit"]) == 1
    assert data["pagination"]["limit"] == 10


def test_api_audit_limit_clamped(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/audit?limit=500")
    assert r.status_code == 200
    data = r.json()
    assert data["pagination"]["limit"] == 200


def test_api_audit_page_minimum(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/api/audit?page=0")
    assert r.status_code == 200
    data = r.json()
    assert data["pagination"]["page"] == 1
