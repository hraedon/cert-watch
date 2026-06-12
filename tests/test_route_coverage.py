"""Coverage tests for routes/views.py, routes/certificates.py, routes/audit.py.

Plan 024 Slice 1 — read/render paths, filter branches, error paths.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cert_watch.upload import store_uploaded, upload_certificate


def _reload(reload_app):
    return reload_app()


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


def test_dashboard_pivot_issuer(reload_app, tmp_path, self_signed_leaf):
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


def test_dashboard_pivot_owner(reload_app, tmp_path):
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
    assert "own.example.com" in r.text  # cert appears in the owner pivot


def test_dashboard_pivot_renewal_method(reload_app, tmp_path):
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
    assert "rm.example.com" in r.text  # cert appears in the renewal-method pivot


# ---------- dashboard fleet grade ----------


def test_dashboard_fleet_grade_with_data(reload_app, tmp_path):
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
    assert "Fleet posture" in r.text


# ---------- dashboard ungrouped view with data ----------


def test_dashboard_ungrouped_with_data(reload_app, tmp_path):
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


def test_dashboard_sort_by_subject(reload_app, tmp_path):
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
    # The sorted view renders both certs (uploaded certs group by fingerprint, so
    # their relative order isn't asserted — only that the sort path includes them).
    assert "aaa.example.com" in r.text
    assert "zzz.example.com" in r.text


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
    from datetime import UTC, datetime, timedelta

    from cert_watch.database import init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    init_schema(db)
    base = datetime.now(UTC)
    for i in range(90):
        # Create records in 6-minute-separated batches so batch pagination
        # produces multiple pages.
        ts = base - timedelta(minutes=(i // 3) * 6)
        record_scan_history(
            db, ScanHistory(hostname=f"h{i}.example.com", port=443, status="success", scanned_at=ts)
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
    assert "Insights" in r.text


def test_insights_view_tls_tab(tmp_path, reload_app):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import init_schema

    init_schema(db)
    with TestClient(app_mod.app) as client:
        r = client.get("/insights?tab=trends")
    assert r.status_code == 200
    assert "TLS" in r.text


# ---------- discover ----------


def test_discover_view_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/discover")
    assert r.status_code == 200
    assert "Discover" in r.text


def test_discover_view_with_hosts(reload_app, tmp_path):
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
    assert "disc.example.com" in r.text


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
    assert r.status_code == 404


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
    assert "unauthorized" in r.text.lower()


def test_metrics_authorized(reload_app, monkeypatch):
    app_mod = reload_app()
    import cert_watch.middleware as mw

    monkeypatch.setattr(mw, "_METRICS_TOKEN", "secret-token")
    with TestClient(app_mod.app) as client:
        r = client.get("/metrics", headers={"Authorization": "Bearer secret-token"})
    assert r.status_code == 200
    assert "cert_" in r.text


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
    assert "cert_scan_errors_total" in r.text


# ---------- certificate detail ----------


def test_certificate_detail_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/certificates/00000000-0000-0000-0000-000000000000", follow_redirects=False)
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_certificate_detail_with_chain(reload_app, tmp_path, chain_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(chain_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "chain-leaf.example.com" in r.text
    assert "Certificate chain" in r.text


def test_certificate_detail_with_trust_anchor(reload_app, tmp_path, chain_pem_file):
    app_mod = reload_app()
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
    assert "cw-chip-public" in r.text or "Chain status" in r.text


def _stored_cert_id(db, hostname, port=443):
    """The UUID primary key of a stored cert. The detail route resolves certs by
    this id (``get_by_id`` matches ``certificates.id`` only, not the fingerprint),
    so navigating by ``cert.fingerprint_sha256`` 303-redirects to the dashboard —
    which TestClient silently follows to a 200, defeating the test. These tests
    must therefore use the real id."""
    from cert_watch.database import _connect

    with _connect(db) as conn:
        row = conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND port = ?",
            (hostname, port),
        ).fetchone()
    assert row is not None, f"no stored cert for {hostname}:{port}"
    return row["id"]


def test_certificate_detail_host_info_acme(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
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
        r = client.get(f"/certificates/{_stored_cert_id(db, 'acme.example.com')}",
                        follow_redirects=False)
    assert r.status_code == 200
    assert "acme.example.com" in r.text  # the detail page, not a redirect
    # ACME hosts render the "ACME" label and the "auto-renews" indicator chip.
    assert "ACME" in r.text
    assert "auto-renews" in r.text
    assert "Ops Team" in r.text


def test_certificate_detail_host_info_cert_manager(reload_app, tmp_path):
    app_mod = reload_app()
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
        r = client.get(f"/certificates/{_stored_cert_id(db, 'cm.example.com')}",
                        follow_redirects=False)
    assert r.status_code == 200
    # cert-manager is also an automated renewer → "auto-renews" indicator.
    assert "cert-manager" in r.text
    assert "auto-renews" in r.text


def test_certificate_detail_host_info_manual(reload_app, tmp_path):
    app_mod = reload_app()
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
        r = client.get(f"/certificates/{_stored_cert_id(db, 'man.example.com')}",
                        follow_redirects=False)
    assert r.status_code == 200
    # Manual renewal must be flagged distinctly from the auto-renewers.
    assert "Manual" in r.text
    assert "requires manual action" in r.text
    assert "auto-renews" not in r.text


def test_certificate_detail_host_info_custom_method(reload_app, tmp_path):
    app_mod = reload_app()
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
        r = client.get(f"/certificates/{_stored_cert_id(db, 'cust.example.com')}",
                        follow_redirects=False)
    assert r.status_code == 200
    # An unknown method is title-cased as-is with no auto/manual indicator.
    assert "Terraform" in r.text
    assert "auto-renews" not in r.text
    assert "requires manual action" not in r.text


def test_certificate_detail_with_drift_events(reload_app, tmp_path):
    app_mod = reload_app()
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
    # The detail page computes drift from cert_history (per-scan snapshots), which
    # replace_scanned does not write — seed two snapshots with the issuer change so
    # the comparison fires. Explicit timestamps keep the DESC ordering deterministic.
    from cert_watch.database import record_cert_history

    record_cert_history(db, "drift.example.com", 443, cert1, scanned_at="2026-01-01T00:00:00+00:00")
    record_cert_history(db, "drift.example.com", 443, cert2, scanned_at="2026-02-01T00:00:00+00:00")
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{_stored_cert_id(db, 'drift.example.com')}",
                        follow_redirects=False)
    assert r.status_code == 200
    # The issuer change across the two scans must surface as a drift event.
    assert "Configuration drift" in r.text
    assert "Issuer changed" in r.text
    assert "Old CA → New CA" in r.text


# ---------- certificate delete ----------


def test_delete_certificate_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.post(f"/certificates/{_MISSING}/delete", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/"


# ---------- certificate notes ----------


def test_update_notes_not_found(reload_app):
    app_mod = reload_app()
    _MISSING = "00000000-0000-0000-0000-000000000000"
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{_MISSING}/notes", data={"notes": "test"}, follow_redirects=False
        )
    assert r.status_code == 303
    assert "not+found" in r.headers["location"] or "not%20found" in r.headers["location"]


def test_update_notes_too_long(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
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


# ---------- certificate owner ----------


def test_update_owner_via_certificate(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    cert = Certificate(
        subject="owner.example.com",
        issuer="Test CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        fingerprint_sha256="e" * 64,
    )
    replace_scanned(db, "owner.example.com", 443, cert, [], True)
    host_repo = SqliteHostRepository(db)
    host_repo.add("owner.example.com", 443)
    cert_id = _stored_cert_id(db, "owner.example.com")
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/owner",
            data={
                "owner_name": "Alice",
                "owner_email": "alice@example.com",
                "owner_slack": "#ops",
                "renewal_method": "acme",
                "runbook_url": "https://wiki.example.com/renewal",
            },
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert f"/certificates/{cert_id}" in r.headers["location"]
    # Verify the update persisted
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert "Alice" in r.text
    assert "alice@example.com" in r.text
    assert "ACME" in r.text
    assert "https://wiki.example.com/renewal" in r.text


def test_update_owner_via_certificate_not_found(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.post(
            "/certificates/00000000-0000-0000-0000-000000000000/owner",
            data={"owner_name": "Alice"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "not+found" in r.headers["location"] or "not%20found" in r.headers["location"]


def test_update_owner_via_certificate_no_host(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    cert_id = store_uploaded(upload_certificate(leaf_pem_file), db)
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/owner",
            data={"owner_name": "Alice"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    loc = r.headers["location"]
    assert "no+host" in loc or "no%20host" in loc or "associated" in loc


def test_update_owner_via_certificate_invalid_email(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    cert = Certificate(
        subject="badmail.example.com",
        issuer="Test CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        fingerprint_sha256="f" * 64,
    )
    replace_scanned(db, "badmail.example.com", 443, cert, [], True)
    host_repo = SqliteHostRepository(db)
    host_repo.add("badmail.example.com", 443)
    cert_id = _stored_cert_id(db, "badmail.example.com")
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/owner",
            data={"owner_email": "not-an-email"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "invalid+email" in r.headers["location"] or "invalid%20email" in r.headers["location"]


def test_update_owner_via_certificate_invalid_method(reload_app, tmp_path, leaf_pem_file):
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, replace_scanned

    init_schema(db)
    cert = Certificate(
        subject="badmethod.example.com",
        issuer="Test CA",
        not_before=datetime.now(UTC) - timedelta(days=1),
        not_after=datetime.now(UTC) + timedelta(days=90),
        fingerprint_sha256="g" * 64,
    )
    replace_scanned(db, "badmethod.example.com", 443, cert, [], True)
    host_repo = SqliteHostRepository(db)
    host_repo.add("badmethod.example.com", 443)
    cert_id = _stored_cert_id(db, "badmethod.example.com")
    with TestClient(app_mod.app) as client:
        r = client.post(
            f"/certificates/{cert_id}/owner",
            data={"renewal_method": "invalid"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    loc = r.headers["location"]
    assert "invalid+renewal" in loc or "invalid%20renewal" in loc


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
    assert "error" in r.headers["location"]


def test_upload_pfx(reload_app, tmp_path, pfx_file_no_password):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client, open(pfx_file_no_password, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("bundle.pfx", f, "application/x-pkcs12")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/"


def test_upload_p7b(reload_app, tmp_path, p7b_der_file):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client, open(p7b_der_file, "rb") as f:
        r = client.post(
            "/upload",
            files={"file": ("chain.p7b", f, "application/x-pkcs7-certificates")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers["location"] == "/"


def test_upload_rate_limit(reload_app, tmp_path, monkeypatch, leaf_pem_file):
    app_mod = reload_app()
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


def test_add_trust_anchor_valid(reload_app, tmp_path, chain_pem_file):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client, open(chain_pem_file, "rb") as f:
        r = client.post(
            "/trust-anchors",
            files={"file": ("root.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_add_trust_anchor_invalid_cert(reload_app, tmp_path, leaf_pem_file):
    """Non-CA cert should be rejected as trust anchor."""
    app_mod = reload_app()
    with TestClient(app_mod.app) as client, open(leaf_pem_file, "rb") as f:
        r = client.post(
            "/trust-anchors",
            files={"file": ("leaf.pem", f, "application/x-pem-file")},
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "error" in r.headers["location"]


def test_delete_trust_anchor(reload_app, tmp_path, chain_pem_file):
    app_mod = reload_app()
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
    assert r.headers["location"] == "/"


def test_dashboard_renders_with_trust_anchor(reload_app, tmp_path, chain_pem_file):
    """WI-028 regression: a trust_anchors row must not 500 the dashboard.

    _build_dashboard_rows feeds raw trust_anchors rows to _row_to_cert, which
    reads certificate-only columns (is_leaf). With one anchor present, '/' and
    every non-pivot view crashed with IndexError.
    """
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from cert_watch.database import SqliteTrustAnchorRepository, init_schema
    from cert_watch.upload import upload_certificate

    init_schema(db)
    entry = upload_certificate(chain_pem_file)
    root_cert = entry.chain[-1] if entry.chain else entry.leaf
    SqliteTrustAnchorRepository(db).add(root_cert)
    store_uploaded(entry, db)
    with TestClient(app_mod.app) as client:
        for url in ("/", "/?q=chain-leaf", "/?view=expiry"):
            r = client.get(url)
            assert r.status_code == 200, f"{url} -> {r.status_code}"
        r = client.get("/")
    assert "Trust anchors" in r.text  # anchor panel renders alongside the rows


def test_certificate_detail_scan_form_posts_host_id(reload_app, tmp_path, self_signed_leaf):
    """WI-029 regression: the 'Scan now' form must target the host id.

    It posted /hosts/{cert_id}/scan, and scan_host_now resolves strictly by
    hosts.id — so the button always redirected to 'host not found'.
    """
    app_mod = reload_app()
    db = tmp_path / "cert-watch.sqlite3"
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteCertificateRepository, init_schema
    from cert_watch.database.repo import SqliteHostRepository

    init_schema(db)
    host_id = SqliteHostRepository(db).add("leaf.example.com", 443)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="CN=leaf.example.com",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        raw_der=self_signed_leaf.der,
    )
    repo = SqliteCertificateRepository(
        db, source="scanned", hostname="leaf.example.com", port=443
    )
    cert_id = repo.add(cert)
    with TestClient(app_mod.app) as client:
        r = client.get(f"/certificates/{cert_id}")
    assert r.status_code == 200
    assert f'action="/hosts/{host_id}/scan"' in r.text
    assert f'action="/hosts/{cert_id}/scan"' not in r.text


# ---------- audit page ----------


def test_audit_page_empty(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/audit")
    assert r.status_code == 200
    assert "No audit events" in r.text


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


# ── WI-A.1: Role-differentiated UI ──────────────────────────────────────────


def test_no_auth_dashboard_shows_all_controls(tmp_path, reload_app):
    app_mod = reload_app()

    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "Add host" in r.text
    assert "nav-settings" in r.text


def test_viewer_dashboard_hides_controls_when_rbac(tmp_path):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={"admin": {"groups": ["g-admins"]}},
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("viewer", groups=["g-viewers"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/")
    assert r.status_code == 200
    html = r.text
    assert "Add host" not in html
    assert "nav-settings" not in html


def test_operator_dashboard_has_write_but_no_settings(tmp_path):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={
            "admin": {"groups": ["g-admins"]},
            "operator": {"groups": ["g-operators"]},
        },
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("operator", groups=["g-operators"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/")
    assert r.status_code == 200
    assert "Add host" in r.text
    assert "nav-settings" not in r.text


def test_admin_dashboard_has_mutating_controls_when_rbac(tmp_path):
    from cert_watch.app import create_app
    from cert_watch.config import Settings

    s = Settings(
        db_path=tmp_path / "db.sqlite3",
        data_dir=tmp_path,
        role_map={"admin": {"groups": ["g-admins"]}},
    )

    class _Provider:
        provider_name = "mock"

    app = create_app(auth_provider=_Provider(), settings=s)

    from cert_watch.auth import SESSION_COOKIE, create_session

    token = create_session("admin", groups=["g-admins"])
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE, token)
        r = client.get("/")
    assert r.status_code == 200
    assert "Add host" in r.text
    assert "nav-settings" in r.text


def test_no_auth_settings_nav_visible(reload_app):
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        r = client.get("/")
    assert r.status_code == 200
    assert "nav-settings" in r.text


def test_viewer_alerts_no_settings_link(reload_app, tmp_path):
    import pathlib

    from jinja2 import Environment, FileSystemLoader

    from cert_watch.filters import register_filters as rf

    tpl_dir = pathlib.Path(__file__).parent.parent / "src" / "cert_watch" / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=True)
    rf(type("T", (), {"env": env})())

    _req = type("R", (), {"state": type("S", (), {"csp_nonce": "n"})()})()

    tpl = env.get_template("base.html")
    html = tpl.render(
        is_admin=False,
        auth_user="viewer",
        may_write=False,
        csrf_token="x",
        version="0.0",
        commit="abc",
        active_page="alerts",
        request=_req,
    )
    assert "nav-settings" not in html

    html2 = tpl.render(
        is_admin=True,
        auth_user="admin",
        may_write=True,
        csrf_token="x",
        version="0.0",
        commit="abc",
        active_page="alerts",
        request=_req,
    )
    assert "nav-settings" in html2


def test_viewer_alerts_no_alert_settings_link(reload_app, tmp_path):
    import pathlib

    from jinja2 import Environment, FileSystemLoader

    from cert_watch.filters import register_filters as rf

    tpl_dir = pathlib.Path(__file__).parent.parent / "src" / "cert_watch" / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=True)
    rf(type("T", (), {"env": env})())

    _req = type("R", (), {"state": type("S", (), {"csp_nonce": "n"})()})()
    _counts = {"all": 0, "unread": 0, "critical": 0, "warning": 0}

    tpl = env.get_template("alerts.html")

    html = tpl.render(
        is_admin=False,
        auth_user="viewer",
        may_write=False,
        csrf_token="x",
        version="0.0",
        commit="abc",
        active_page="alerts",
        alerts=[],
        alert_counts=_counts,
        alert_channels=[],
        filter_type="all",
        page=1,
        total_pages=1,
        has_prev=False,
        has_next=False,
        request=_req,
    )
    assert "Alert settings" not in html

    html2 = tpl.render(
        is_admin=True,
        auth_user="admin",
        may_write=True,
        csrf_token="x",
        version="0.0",
        commit="abc",
        active_page="alerts",
        alerts=[],
        alert_counts=_counts,
        alert_channels=[],
        filter_type="all",
        page=1,
        total_pages=1,
        has_prev=False,
        has_next=False,
        request=_req,
    )
    assert "Alert settings" in html2
