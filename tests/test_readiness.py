"""Tests for SC-081 readiness report (WI-2.2): aggregation, margins, workload, routes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from cert_watch.readiness import (
    HostReadiness,
    _compute_margins,
    build_readiness_report,
    readiness_report_to_dict,
)


def _seed_readiness_fleet(db_path: str | Path) -> None:
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import init_schema, store_scan_posture
    from cert_watch.database.connection import _connect
    from tests._helpers import seed_certificate

    _HIST_SQL = (
        "INSERT INTO cert_history"
        " (hostname,fingerprint_sha256,issuer,not_after,not_before,scanned_at)"
        " VALUES (?,?,?,?,?,?)"
    )

    init_schema(db_path)
    now = datetime.now(UTC)

    automated_cert = Certificate(
        subject="CN=auto.example.com",
        issuer="CN=Let's Encrypt Authority X3",
        not_before=now - timedelta(days=60),
        not_after=now + timedelta(days=30),
        san_dns_names=[],
        fingerprint_sha256="fp-auto-1",
        raw_der=b"\x00",
        is_leaf=True,
        notes="",
        source="scanned",
    )
    seed_certificate(db_path, automated_cert, cert_id="cert-auto",
                     hostname="auto.example.com", port=443, source="scanned",
                     chain_valid=True)
    with _connect(db_path) as conn:
        conn.execute(_HIST_SQL, (
            "auto.example.com", "fp-auto-0",
            "CN=Let's Encrypt Authority X3",
            (now - timedelta(days=30)).isoformat(),
            (now - timedelta(days=90)).isoformat(),
            (now - timedelta(days=30)).isoformat(),
        ))
        conn.execute(_HIST_SQL, (
            "auto.example.com", "fp-auto-1",
            "CN=Let's Encrypt Authority X3",
            (now + timedelta(days=30)).isoformat(),
            (now - timedelta(days=60)).isoformat(),
            (now - timedelta(days=1)).isoformat(),
        ))
        conn.commit()
    store_scan_posture(db_path, "cert-auto", "auto.example.com", 443, "A", [],
                       protocol_version="TLSv1.3", hsts=True, chain_status="public")

    manual_cert = Certificate(
        subject="CN=manual.example.com",
        issuer="CN=DigiCert SHA2 Extended Validation Server CA",
        not_before=now - timedelta(days=300),
        not_after=now + timedelta(days=65),
        san_dns_names=[],
        fingerprint_sha256="fp-manual-1",
        raw_der=b"\x00",
        is_leaf=True,
        notes="",
        source="scanned",
    )
    seed_certificate(db_path, manual_cert, cert_id="cert-manual",
                     hostname="manual.example.com", port=443, source="scanned",
                     chain_valid=True)
    with _connect(db_path) as conn:
        conn.execute(_HIST_SQL, (
            "manual.example.com", "fp-manual-0",
            "CN=DigiCert SHA2 Extended Validation Server CA",
            (now + timedelta(days=65)).isoformat(),
            (now - timedelta(days=300)).isoformat(),
            (now - timedelta(days=300)).isoformat(),
        ))
        conn.execute(_HIST_SQL, (
            "manual.example.com", "fp-manual-1",
            "CN=DigiCert SHA2 Extended Validation Server CA",
            (now + timedelta(days=65)).isoformat(),
            (now - timedelta(days=300)).isoformat(),
            (now - timedelta(days=1)).isoformat(),
        ))
        conn.commit()
    store_scan_posture(db_path, "cert-manual", "manual.example.com", 443, "A", [],
                       protocol_version="TLSv1.2", hsts=False, chain_status="public")

    unknown_cert = Certificate(
        subject="CN=new.example.com",
        issuer="CN=GlobalSign",
        not_before=now - timedelta(days=100),
        not_after=now + timedelta(days=265),
        san_dns_names=[],
        fingerprint_sha256="fp-unknown-1",
        raw_der=b"\x00",
        is_leaf=True,
        notes="",
        source="scanned",
    )
    seed_certificate(db_path, unknown_cert, cert_id="cert-unknown",
                     hostname="new.example.com", port=443, source="scanned",
                     chain_valid=True)
    with _connect(db_path) as conn:
        conn.execute(_HIST_SQL, (
            "new.example.com", "fp-unknown-1", "CN=GlobalSign",
            (now + timedelta(days=265)).isoformat(),
            (now - timedelta(days=100)).isoformat(),
            now.isoformat(),
        ))
        conn.commit()
    store_scan_posture(db_path, "cert-unknown", "new.example.com", 443, "A", [],
                       protocol_version="TLSv1.2", hsts=False, chain_status="public")

    private_cert = Certificate(
        subject="CN=internal.corp",
        issuer="CN=Corporate Internal CA",
        not_before=now - timedelta(days=200),
        not_after=now + timedelta(days=165),
        san_dns_names=[],
        fingerprint_sha256="fp-private-1",
        raw_der=b"\x00",
        is_leaf=True,
        notes="",
        source="scanned",
    )
    seed_certificate(db_path, private_cert, cert_id="cert-private",
                     hostname="internal.corp", port=443, source="scanned",
                     chain_valid=True)
    with _connect(db_path) as conn:
        conn.execute(_HIST_SQL, (
            "internal.corp", "fp-private-1",
            "CN=Corporate Internal CA",
            (now + timedelta(days=165)).isoformat(),
            (now - timedelta(days=200)).isoformat(),
            now.isoformat(),
        ))
        conn.commit()
    store_scan_posture(db_path, "cert-private", "internal.corp", 443, "B", [],
                       protocol_version="TLSv1.2", hsts=False,
                       chain_status="private")


class TestMarginAnalysis:
    def test_positive_margin(self):
        margins = _compute_margins(lead_time=15.0, lifetime=365)
        assert len(margins) == 3
        ms_47 = margins[2]
        assert ms_47["milestone"] == "47d"
        assert ms_47["margin_days"] == 15.0
        assert ms_47["margin_pct"] == round(15.0 / 47 * 100, 1)
        assert ms_47["renew_late"] is False

    def test_renew_late_when_lead_exceeds_cap(self):
        margins = _compute_margins(lead_time=50.0, lifetime=365)
        ms_47 = margins[2]
        assert ms_47["margin_days"] == 50.0
        assert ms_47["renew_late"] is True

    def test_lead_fits_some_milestones_not_others(self):
        margins = _compute_margins(lead_time=60.0, lifetime=365)
        assert margins[0]["renew_late"] is False
        assert margins[1]["renew_late"] is False
        assert margins[2]["renew_late"] is True

    def test_no_lead_time_flagged_conservative(self):
        margins = _compute_margins(lead_time=None, lifetime=365)
        for m in margins:
            assert m["margin_days"] is None
            assert m["margin_pct"] is None
            assert m["renew_late"] is True

    def test_margin_pct_calculation(self):
        margins = _compute_margins(lead_time=15.0, lifetime=365)
        ms_100 = margins[1]
        expected_pct = round(15.0 / 100 * 100, 1)
        assert ms_100["margin_pct"] == expected_pct

    def test_small_lead_time_safe_at_200d(self):
        margins = _compute_margins(lead_time=15.0, lifetime=90)
        ms_200 = margins[0]
        assert ms_200["margin_days"] == 15.0
        assert ms_200["renew_late"] is False


class TestBuildReadinessReport:
    def test_report_from_fixture_data(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        assert report.total_hosts == 4
        assert report.public_trust_hosts == 3
        assert report.private_ca_hosts == 1

    def test_private_ca_hosts_separate(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        public_names = [h.hostname for h in report.hosts]
        private_names = [h.hostname for h in report.private_hosts]
        assert "internal.corp" in private_names
        assert "internal.corp" not in public_names
        assert "auto.example.com" in public_names

    def test_private_hosts_no_margins(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        for h in report.private_hosts:
            assert h.margins == []

    def test_public_hosts_have_margins(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        for h in report.hosts:
            if h.classification != "unknown" or h.current_lifetime is not None:
                assert len(h.margins) == 3

    def test_classifications_populated(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        classifications = {h.hostname: h.classification for h in report.hosts}
        assert "auto.example.com" in classifications
        assert classifications["auto.example.com"] in (
            "likely-automated", "manual", "unknown"
        )

    def test_milestones_present(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        assert len(report.milestones) == 3
        labels = [m["label"] for m in report.milestones]
        assert labels == ["200d", "100d", "47d"]

    def test_empty_fleet(self, tmp_path):
        from cert_watch.database import init_schema
        db = tmp_path / "test.sqlite3"
        init_schema(str(db))
        report = build_readiness_report(str(db))
        assert report.total_hosts == 0
        assert report.public_trust_hosts == 0
        assert report.private_ca_hosts == 0
        assert report.hosts == []
        assert report.private_hosts == []


class TestWorkloadForecast:
    def test_forecast_from_fixture(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        wf = report.workload_forecast
        assert wf is not None
        assert wf.current_renewals_per_month > 0
        assert wf.at_100d_renewals_per_month > 0
        assert wf.at_47d_renewals_per_month > 0
        assert wf.at_47d_renewals_per_month > wf.at_100d_renewals_per_month
        assert wf.at_100d_renewals_per_month >= wf.current_renewals_per_month

    def test_forecast_risk_hosts(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        wf = report.workload_forecast
        assert "200d" in wf.hosts_by_milestone_risk
        assert "100d" in wf.hosts_by_milestone_risk
        assert "47d" in wf.hosts_by_milestone_risk

    def test_empty_fleet_forecast(self, tmp_path):
        from cert_watch.database import init_schema
        db = tmp_path / "test.sqlite3"
        init_schema(str(db))
        report = build_readiness_report(str(db))
        wf = report.workload_forecast
        assert wf is not None
        assert wf.current_renewals_per_month == 0.0
        assert wf.at_100d_renewals_per_month == 0.0
        assert wf.at_47d_renewals_per_month == 0.0

    def test_forecast_math_47d(self, tmp_path):
        host = HostReadiness(
            hostname="test.example.com",
            classification="manual",
            current_lead_time=10.0,
            current_lifetime=365,
            margins=_compute_margins(10.0, 365),
        )
        from cert_watch.readiness import _compute_workload_forecast
        wf = _compute_workload_forecast([host])
        expected_47 = round(365.0 / 47 / 12.0, 1)
        assert wf.at_47d_renewals_per_month == expected_47


class TestReadinessReportToDict:
    def test_all_fields_present(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        d = readiness_report_to_dict(report)
        assert "generated_at" in d
        assert "total_hosts" in d
        assert "public_trust_hosts" in d
        assert "private_ca_hosts" in d
        assert "milestones" in d
        assert "hosts" in d
        assert "private_hosts" in d
        assert "workload_forecast" in d

    def test_host_fields(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        d = readiness_report_to_dict(report)
        for h in d["hosts"]:
            assert "hostname" in h
            assert "classification" in h
            assert "current_lead_time" in h
            assert "current_lifetime" in h
            assert "margins" in h

    def test_forecast_fields(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        d = readiness_report_to_dict(report)
        wf = d["workload_forecast"]
        assert "current_renewals_per_month" in wf
        assert "at_100d_renewals_per_month" in wf
        assert "at_47d_renewals_per_month" in wf
        assert "hosts_by_milestone_risk" in wf

    def test_json_serializable(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_readiness_fleet(str(db))
        report = build_readiness_report(str(db))
        d = readiness_report_to_dict(report)
        serialized = json.dumps(d)
        assert len(serialized) > 0


class TestReadinessRoutes:
    def test_readiness_json(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/readiness.json")
        assert r.status_code == 200
        data = r.json()
        assert "total_hosts" in data
        assert "public_trust_hosts" in data
        assert "private_ca_hosts" in data
        assert "milestones" in data
        assert "hosts" in data
        assert "workload_forecast" in data

    def test_readiness_json_content_disposition(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/readiness.json")
        assert "readiness-report.json" in r.headers.get("content-disposition", "")

    def test_readiness_html_view(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/readiness")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "SC-081" in r.text

    def test_readiness_json_auth_gated(self, reload_app):
        app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
        with TestClient(app_mod.app) as client:
            r = client.get("/api/readiness.json")
        assert r.status_code == 401

    def test_readiness_html_with_data(self, tmp_path, reload_app):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_readiness_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/readiness")
        assert r.status_code == 200
        assert "auto.example.com" in r.text and "Public-Trust Host" in r.text

    def test_readiness_json_with_data(self, tmp_path, reload_app):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_readiness_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/api/readiness.json")
        assert r.status_code == 200
        data = r.json()
        assert data["total_hosts"] == 4
        assert data["public_trust_hosts"] == 3
        assert data["private_ca_hosts"] == 1

    def test_private_hosts_never_in_public_risk(self, tmp_path, reload_app):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_readiness_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/api/readiness.json")
        data = r.json()
        public_hostnames = {h["hostname"] for h in data["hosts"]}
        private_hostnames = {h["hostname"] for h in data["private_hosts"]}
        assert public_hostnames.isdisjoint(private_hostnames)
        wf = data["workload_forecast"]
        for _ms_label, risk_hosts in wf["hosts_by_milestone_risk"].items():
            for rh in risk_hosts:
                assert rh not in private_hostnames
