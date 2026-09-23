"""Tests for compliance report (Plan 025): aggregation, signing, routes, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.compliance import (
    ComplianceMetric,
    ComplianceReport,
    RemediationBucket,
    RemediationEntry,
    build_compliance_report,
    report_to_csv_rows,
    report_to_dict,
    sign_report,
    verify_report_signature,
)


def _seed_fleet(db_path: str | Path) -> list[str]:
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import init_schema, store_scan_posture
    from tests._helpers import seed_certificate

    init_schema(db_path)
    cert_ids = []
    now = datetime.now(UTC)

    entries = [
        ("host-a.example.com", 443, "A+", [], "TLSv1.3", True, 365),
        ("host-b.example.com", 443, "A", [], "TLSv1.2", True, 200),
        # Bare "TLSv1" is what both scan paths actually emit for TLS 1.0 — the
        # form the old metric missed. host-e uses the "TLSv1.0" spelling so both
        # are exercised.
        ("host-c.example.com", 443, "B",
         [{"check": "tls_version", "status": "warn", "message": "TLS 1.0"}],
         "TLSv1", False, 90),
        ("host-d.example.com", 443, "C",
         [{"check": "rsa_key_size", "status": "fail", "message": "RSA key < 2048 bits"}],
         "TLSv1.2", False, 45),
        ("host-e.example.com", 443, "F",
         [{"check": "sha1_signature", "status": "fail", "message": "SHA-1 signature"},
          {"check": "rsa_key_size", "status": "fail", "message": "RSA key < 2048 bits"}],
         "TLSv1.0", False, 5),
    ]

    for i, (hostname, port, grade, findings, proto, hsts_val, days_valid) in enumerate(entries):
        cid = f"cert-{hostname.split('.')[0]}"
        tags = "prod" if i % 2 == 0 else ""
        cert = Certificate(
            subject=f"CN={hostname}",
            issuer="CN=Test CA",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=days_valid),
            san_dns_names=[],
            fingerprint_sha256=cid.replace("cert-", "fp-"),
            raw_der=b"\x00",
            is_leaf=True,

            source="scanned",
        )
        seed_certificate(
            db_path, cert,
            cert_id=cid,
            hostname=hostname,
            port=port,
            source="scanned",
            chain_valid=True,
            tags=tags,
        )
        store_scan_posture(
            db_path, cid, hostname, port, grade, findings,
            protocol_version=proto, hsts=hsts_val,
        )
        cert_ids.append(cid)
    return cert_ids


def _seed_empty(db_path: str | Path) -> None:
    from cert_watch.database import init_schema
    init_schema(db_path)


class TestComplianceAggregation:
    def test_empty_fleet(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_empty(db)
        report = build_compliance_report(str(db), signing_key="test-key")
        assert report.total_certs == 0
        assert report.total_hosts == 0
        assert report.fleet_grade == ""
        assert report.content_sha256 != ""
        assert report.signature != ""

    def test_fleet_with_data(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="test-key")
        assert report.total_certs == 5
        assert report.total_hosts == 5
        assert report.fleet_grade == "F"
        assert report.grade_distribution["A+"] == 1
        assert report.grade_distribution["A"] == 1
        assert report.grade_distribution["B"] == 1
        assert report.grade_distribution["C"] == 1
        assert report.grade_distribution["F"] == 1

    def test_compliance_metrics(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="test-key")
        metrics = {m.label: m for m in report.compliance_metrics}
        sha1 = metrics["No SHA-1 signature (SHA-256+)"]
        assert sha1.passing == 4
        assert sha1.total == 5

        strong_key = metrics["Strong key (RSA >= 2048 or ECDSA)"]
        assert strong_key.passing == 3
        assert strong_key.total == 5

        tls = metrics["TLS >= 1.2 at last scan"]
        assert tls.total == 5
        # host-a (1.3), host-b (1.2), host-d (1.2) pass; host-c ("TLSv1") and
        # host-e ("TLSv1.0") are TLS 1.0 and must NOT count as compliant.
        assert tls.passing == 3

        caa = metrics["CAA present for domain"]
        assert caa.collected is False
        assert caa.display == "Not collected"

        hsts = metrics["HSTS present (port 443)"]
        assert hsts.passing == 2
        assert hsts.total == 5

    def test_remediation_buckets(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="test-key")
        buckets = {b.label: b for b in report.remediation_buckets}
        assert len(buckets["Expiring within 7 days"].entries) >= 1
        assert len(buckets["Failed posture checks"].entries) >= 2

    def test_scope_tag_filter(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), scope_tag="prod", signing_key="test-key")
        assert report.scope_tag == "prod"
        assert report.scope_description == "Tag: prod"
        assert report.total_certs == 3

    def test_scope_tag_matches_host_inherited_tags(self, tmp_path):
        """Regression (plan 055 / C9): a scoped report must include certs
        whose tag is inherited from the HOST, matching every other scope
        path's effective-tags (cert ∪ host) semantics."""
        from cert_watch.database import SqliteHostRepository

        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        base = build_compliance_report(str(db), scope_tag="hostonly", signing_key="k")
        assert base.total_certs == 0
        # Tag one seeded host (not its cert) and re-run the scoped report.
        repo = SqliteHostRepository(str(db))
        import sqlite3 as _sql

        with _sql.connect(db) as conn:
            conn.execute(
                "INSERT INTO hosts (id, hostname, port, tags, owner_name,"
                " owner_email, owner_slack, renewal_status, renewal_method,"
                " runbook_url, notes, expected_issuers, starttls_mode, added_at)"
                " SELECT 'h-c9', c.hostname, c.port, 'hostonly', '', '', '',"
                " 'pending', '', '', '', '', '', datetime('now')"
                " FROM certificates c WHERE c.is_leaf = 1 LIMIT 1"
            )
            conn.commit()
        assert repo is not None
        report = build_compliance_report(str(db), scope_tag="hostonly", signing_key="k")
        assert report.total_certs == 1

    def test_scope_tag_like_wildcard_escape(self, tmp_path):
        """Regression (WI-124 #1): LIKE wildcards in scope_tag must be escaped.

        A scope_tag of '%' or '_' must not match every row — it should match
        only certs literally tagged with that exact string.
        """
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report_pct = build_compliance_report(str(db), scope_tag="%", signing_key="k")
        report_und = build_compliance_report(str(db), scope_tag="_", signing_key="k")
        assert report_pct.total_certs == 0
        assert report_und.total_certs == 0

    def test_version_commit_included(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_empty(db)
        report = build_compliance_report(str(db), version="1.2.3", commit="abc123", signing_key="k")
        assert report.version == "1.2.3"
        assert report.commit == "abc123"

    def test_metric_display_na(self):
        m = ComplianceMetric(label="test", passing=0, total=0)
        assert m.display == "N/A"
        assert m.pct == 0.0

    def test_metric_display_normal(self):
        m = ComplianceMetric(label="test", passing=3, total=10)
        assert m.display == "3 of 10 (30.0%)"
        assert m.pct == 30.0


def _seed_fleet_with_revocation(db_path: str | Path) -> list[str]:
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import init_schema, store_scan_posture
    from tests._helpers import seed_certificate

    init_schema(db_path)
    cert_ids = []
    now = datetime.now(UTC)

    entries = [
        ("rev-host-a.example.com", 443, "A",
         [{"check": "ocsp_endpoint", "status": "pass",
           "message": "OCSP responder reachable at http://ocsp.test"},
          {"check": "crl_endpoint", "status": "pass",
           "message": "CRL endpoint reachable at http://crl.test/ca.crl"}],
         "TLSv1.3", True, 365),
        ("rev-host-b.example.com", 443, "A",
         [{"check": "ocsp_endpoint", "status": "warn",
           "message": "OCSP responder unreachable at http://ocsp.test"},
          {"check": "crl_endpoint", "status": "pass",
           "message": "CRL endpoint reachable at http://crl.test/ca.crl"}],
         "TLSv1.2", True, 200),
        ("rev-host-c.example.com", 443, "B",
         [{"check": "ocsp_endpoint", "status": "warn",
           "message": "OCSP responder unreachable"},
          {"check": "crl_endpoint", "status": "warn",
           "message": "CRL endpoint unreachable"}],
         "TLSv1.2", False, 90),
    ]

    for hostname, port, grade, findings, proto, hsts_val, days_valid in entries:
        cid = f"cert-{hostname.split('.')[0]}"
        cert = Certificate(
            subject=f"CN={hostname}",
            issuer="CN=Test CA",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=days_valid),
            san_dns_names=[],
            fingerprint_sha256=cid.replace("cert-", "fp-"),
            raw_der=b"\x00",
            is_leaf=True,

            source="scanned",
        )
        seed_certificate(
            db_path, cert,
            cert_id=cid,
            hostname=hostname,
            port=port,
            source="scanned",
            chain_valid=True,
        )
        store_scan_posture(
            db_path, cid, hostname, port, grade, findings,
            protocol_version=proto, hsts=hsts_val,
        )
        cert_ids.append(cid)
    return cert_ids


class TestRevocationMetric:
    def test_revocation_metric_with_data(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet_with_revocation(str(db))
        report = build_compliance_report(str(db), signing_key="key")
        metrics = {m.label: m for m in report.compliance_metrics}
        revoc = metrics["Revocation endpoint reachable"]
        assert revoc.collected is True
        assert revoc.total == 3
        assert revoc.passing == 2

    def test_revocation_metric_not_collected(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="key")
        metrics = {m.label: m for m in report.compliance_metrics}
        revoc = metrics["Revocation endpoint reachable"]
        assert revoc.collected is False
        assert revoc.display == "Not collected"

    def test_revocation_metric_all_unreachable(self, tmp_path):
        from datetime import UTC, datetime, timedelta

        from cert_watch.certificate_model import Certificate
        from cert_watch.database import init_schema, store_scan_posture
        from tests._helpers import seed_certificate

        db = tmp_path / "test.sqlite3"
        init_schema(str(db))
        now = datetime.now(UTC)
        findings = [
            {"check": "ocsp_endpoint", "status": "warn",
             "message": "OCSP responder unreachable"},
            {"check": "crl_endpoint", "status": "warn",
             "message": "CRL endpoint unreachable"},
        ]
        cert = Certificate(
            subject="CN=bad.example.com", issuer="CN=Test CA",
            not_before=now - timedelta(days=30),
            not_after=now + timedelta(days=100),
            san_dns_names=[], fingerprint_sha256="fp-bad",
            raw_der=b"\x00", is_leaf=True, source="scanned",
        )
        seed_certificate(str(db), cert, cert_id="cert-bad",
                         hostname="bad.example.com", port=443,
                         source="scanned", chain_valid=True)
        store_scan_posture(str(db), "cert-bad", "bad.example.com", 443,
                           "B", findings, protocol_version="TLSv1.2", hsts=False)
        report = build_compliance_report(str(db), signing_key="key")
        metrics = {m.label: m for m in report.compliance_metrics}
        revoc = metrics["Revocation endpoint reachable"]
        assert revoc.collected is True
        assert revoc.total == 1
        assert revoc.passing == 0

    def test_revocation_metric_in_dict_and_csv(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet_with_revocation(str(db))
        report = build_compliance_report(str(db), signing_key="key")
        d = report_to_dict(report)
        labels = [m["label"] for m in d["compliance_metrics"]]
        assert "Revocation endpoint reachable" in labels

        rows = report_to_csv_rows(report)
        flat = [cell for row in rows for cell in row]
        assert "Revocation endpoint reachable" in flat


class TestSigning:
    def test_sign_and_verify_roundtrip(self):
        report = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            version="1.0.0",
            total_certs=10,
            total_hosts=5,
            grade_distribution={"A+": 3, "A": 2, "B": 2, "C": 2, "F": 1},
            fleet_grade="F",
            compliance_metrics=[
                ComplianceMetric("test", 5, 10),
            ],
            remediation_buckets=[
                RemediationBucket("bucket", [
                    RemediationEntry("h", 443, "s", "i", "2026-01-01", 30, "ok", ["bad"]),
                ]),
            ],
        )
        sign_report(report, "my-secret-key")
        assert report.content_sha256
        assert report.signature

        d = report_to_dict(report)
        ok, msg = verify_report_signature(d, "my-secret-key")
        assert ok
        assert msg == "PASS"

    def test_tampered_content_fails(self):
        report = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            total_certs=10,
        )
        sign_report(report, "key")
        d = report_to_dict(report)
        d["total_certs"] = 999
        ok, msg = verify_report_signature(d, "key")
        assert not ok
        assert "mismatch" in msg

    @pytest.mark.parametrize(
        ("section", "field", "value"),
        [
            ("compliance_metrics", "pct", 99.9),
            ("compliance_metrics", "display", "everything passes"),
            ("remediation_buckets", "count", 999),
        ],
    )
    def test_tampered_presentation_values_fail(self, section, field, value):
        report = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            compliance_metrics=[ComplianceMetric("test", 1, 2)],
            remediation_buckets=[RemediationBucket("bucket", [])],
        )
        sign_report(report, "key")
        data = report_to_dict(report)
        data[section][0][field] = value

        ok, _ = verify_report_signature(data, "key")

        assert not ok

    def test_malformed_report_fails_cleanly(self):
        report = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            compliance_metrics=[ComplianceMetric("test", 1, 2)],
        )
        sign_report(report, "key")
        data = report_to_dict(report)
        del data["compliance_metrics"][0]["label"]

        assert verify_report_signature(data, "key") == (False, "malformed report")

    def test_wrong_key_fails(self):
        report = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            total_certs=10,
        )
        sign_report(report, "correct-key")
        d = report_to_dict(report)
        ok, msg = verify_report_signature(d, "wrong-key")
        assert not ok
        assert "signature" in msg.lower()

    def test_missing_signature_fails(self):
        d = {"generated_at": "2026-01-01", "content_sha256": "", "signature": ""}
        ok, msg = verify_report_signature(d, "key")
        assert not ok
        assert "missing" in msg

    def test_deterministic_canonical_json(self):
        r1 = ComplianceReport(
            generated_at="2026-01-01T00:00:00+00:00",
            total_certs=5,
            grade_distribution={"B": 1, "A": 2, "F": 1, "A+": 0, "C": 1},
        )
        from cert_watch.compliance import _canonical_json
        raw = _canonical_json(r1)
        parsed = json.loads(raw)
        assert list(parsed["grade_distribution"].keys()) == sorted(
            ["A+", "A", "B", "C", "F"]
        )


class TestReportFormats:
    def test_report_to_dict(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="key")
        d = report_to_dict(report)
        assert d["total_certs"] == report.total_certs
        assert "compliance_metrics" in d
        assert "remediation_buckets" in d
        assert d["content_sha256"] == report.content_sha256
        assert d["signature"] == report.signature

    def test_csv_rows(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="key")
        rows = report_to_csv_rows(report)
        assert rows[0] == ["cert-watch compliance report"]
        flat = [cell for row in rows for cell in row]
        assert "Content SHA-256" in flat
        assert "HMAC-SHA256 signature" in flat
        assert report.content_sha256 in flat

    def test_csv_tamper_evidence_footer(self, tmp_path):
        db = tmp_path / "test.sqlite3"
        _seed_empty(db)
        report = build_compliance_report(str(db), signing_key="key")
        rows = report_to_csv_rows(report)
        # The signature covers the JSON report, not the CSV bytes; the footer
        # directs the auditor to verify the JSON export.
        assert "verify-report compliance-report.json" in rows[-1][0]


class TestComplianceRoutes:
    def test_compliance_json_empty(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.json")
        assert r.status_code == 200
        data = r.json()
        assert data["total_certs"] == 0
        assert "content_sha256" in data
        assert "signature" in data

    def test_compliance_json_with_data(self, tmp_path, reload_app):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.json")
        assert r.status_code == 200
        data = r.json()
        assert data["total_certs"] == 5
        assert data["fleet_grade"] == "F"
        # SHA-1, strong key, TLS, HSTS, CAA, plus revocation-endpoint metric.
        assert len(data["compliance_metrics"]) == 6

    def test_compliance_csv(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert "cert-watch compliance report" in r.text
        assert "Content SHA-256" in r.text

    def test_compliance_json_tag_filter(self, tmp_path, reload_app):
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.json?tag=prod")
        assert r.status_code == 200
        assert r.json()["scope_tag"] == "prod"

    def test_compliance_html_view(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/reports/compliance")
        assert r.status_code == 200
        assert "text/html" in r.headers["content-type"]
        assert "Compliance Report" in r.text
        assert "Content SHA-256" in r.text

    def test_compliance_html_metrics_coverage_note(self, tmp_path, reload_app):
        """When some certs have no stored posture yet, the metrics card must
        say how many of the fleet are covered — an auditor shouldn't have to
        guess whether 'N/A' means failed, absent, or not-yet-evaluated."""
        from datetime import UTC, datetime, timedelta

        from cert_watch.certificate_model import Certificate
        from tests._helpers import seed_certificate

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_fleet(str(db))  # 5 certs, all with stored posture
        # One uploaded cert with NO stored posture → 5 of 6 covered.
        now = datetime.now(UTC)
        seed_certificate(
            str(db),
            Certificate(
                subject="CN=uploaded.example.com",
                issuer="CN=Test CA",
                not_before=now - timedelta(days=30),
                not_after=now + timedelta(days=90),
                fingerprint_sha256="fp-uploaded",
                raw_der=b"\x00",
                is_leaf=True,
                source="uploaded",
            ),
            cert_id="cert-uploaded",
            source="uploaded",
        )
        with TestClient(app_mod.app) as client:
            r = client.get("/reports/compliance")
        assert r.status_code == 200
        assert 'data-testid="metrics-coverage"' in r.text
        assert "5 of 6" in r.text

    def test_compliance_html_full_coverage_hides_note(self, tmp_path, reload_app):
        """Full posture coverage → no coverage caveat clutters the report."""
        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_fleet(str(db))
        with TestClient(app_mod.app) as client:
            r = client.get("/reports/compliance")
        assert r.status_code == 200
        assert 'data-testid="metrics-coverage"' not in r.text

    def test_compliance_json_auth_gated(self, reload_app):
        # No auth provider + ALLOW_UNAUTH=0 → secure-by-default auto-provisions an
        # admin and the report API rejects the unauthenticated request with 401.
        # (Asserting `in (200, 401)` previously let an ungated 200 pass silently.)
        app_mod = reload_app(AUTH_PROVIDER="none", CERT_WATCH_ALLOW_UNAUTH="0")
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.json")
        assert r.status_code == 401

    def test_compliance_json_content_disposition(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.json")
        assert "compliance-report.json" in r.headers.get("content-disposition", "")

    def test_compliance_csv_content_disposition(self, reload_app):
        app_mod = reload_app()
        with TestClient(app_mod.app) as client:
            r = client.get("/api/reports/compliance.csv")
        assert "compliance-report.csv" in r.headers.get("content-disposition", "")


class TestCLI:
    def test_verify_report_pass(self, tmp_path, monkeypatch):
        from cert_watch.compliance import build_compliance_report, report_to_dict

        db = tmp_path / "test.sqlite3"
        _seed_fleet(str(db))
        report = build_compliance_report(str(db), signing_key="test-auth-secret-for-tests")
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(report_to_dict(report)))

        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-auth-secret-for-tests")

        from cert_watch.__main__ import main
        main(["verify-report", str(report_file)])

    def test_verify_report_fail_tampered(self, tmp_path, monkeypatch):
        from cert_watch.compliance import build_compliance_report, report_to_dict

        db = tmp_path / "test.sqlite3"
        _seed_empty(db)
        report = build_compliance_report(str(db), signing_key="test-auth-secret-for-tests")
        d = report_to_dict(report)
        d["total_certs"] = 9999
        report_file = tmp_path / "report.json"
        report_file.write_text(json.dumps(d))

        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-auth-secret-for-tests")

        from cert_watch.__main__ import main
        try:
            main(["verify-report", str(report_file)])
            raise AssertionError("should have raised SystemExit")
        except SystemExit as e:
            assert e.code == 1

    def test_verify_report_on_csv_fails_cleanly(self, tmp_path, monkeypatch):
        # Handing the CSV export to verify-report must fail with a clear message
        # (not a raw JSON traceback) and a non-zero exit — the signature covers
        # the JSON, not the CSV.
        from cert_watch.compliance import build_compliance_report, report_to_csv_rows

        db = tmp_path / "test.sqlite3"
        _seed_empty(db)
        report = build_compliance_report(str(db), signing_key="test-auth-secret-for-tests")
        csv_file = tmp_path / "report.csv"
        import csv as _csv
        with open(csv_file, "w", newline="") as f:
            w = _csv.writer(f)
            for row in report_to_csv_rows(report):
                w.writerow(row)

        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-auth-secret-for-tests")
        from cert_watch.__main__ import main
        try:
            main(["verify-report", str(csv_file)])
            raise AssertionError("should have raised SystemExit")
        except SystemExit as e:
            assert e.code == 1

    def test_verify_report_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-key")
        from cert_watch.__main__ import main
        try:
            main(["verify-report", str(tmp_path / "nonexistent.json")])
            raise AssertionError("should have raised SystemExit")
        except (SystemExit, FileNotFoundError):
            pass


# ── #66: exported report whose presentation values were altered ─────────────


def _export_signed_report(tmp_path: Path, reload_app) -> dict:
    """Export the signed JSON report through the real API route."""
    app_mod = reload_app()
    _seed_fleet(str(tmp_path / "cert-watch.sqlite3"))
    with TestClient(app_mod.app) as client:
        r = client.get("/api/reports/compliance.json")
    assert r.status_code == 200
    return r.json()


def _cli_verify(tmp_path: Path, data: object, capsys) -> tuple[int, str]:
    report_file = tmp_path / "compliance-report.json"
    report_file.write_text(json.dumps(data))
    from cert_watch.__main__ import main

    capsys.readouterr()  # drop app start-up logging from the export
    try:
        main(["verify-report", str(report_file)])
        code = 0
    except SystemExit as e:
        code = int(e.code or 0)
    return code, capsys.readouterr().out


def _app_signing_key(tmp_path: Path) -> str:
    from cert_watch.config import resolve_or_persist_secret

    return resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", tmp_path, ".auth_secret")


class TestExportedReportTamper:
    def test_untampered_export_verifies(self, tmp_path, reload_app, capsys):
        data = _export_signed_report(tmp_path, reload_app)
        assert verify_report_signature(data, _app_signing_key(tmp_path)) == (True, "PASS")
        code, out = _cli_verify(tmp_path, data, capsys)
        assert code == 0
        assert out.startswith("PASS")

    def test_metric_rewritten_to_false_100_percent_fails(self, tmp_path, reload_app, capsys):
        """The issue's scenario: pct/display claim full compliance while the
        signed passing/total primitives are left untouched."""
        data = _export_signed_report(tmp_path, reload_app)
        metric = next(
            m for m in data["compliance_metrics"]
            if m["collected"] and m["total"] > 0 and m["passing"] < m["total"]
        )
        passing, total = metric["passing"], metric["total"]
        metric["pct"] = 100.0
        metric["display"] = f"{total} of {total} (100.0%)"
        assert (metric["passing"], metric["total"]) == (passing, total)

        ok, msg = verify_report_signature(data, _app_signing_key(tmp_path))
        assert ok is False
        assert msg == "presentation value mismatch"
        code, out = _cli_verify(tmp_path, data, capsys)
        assert code == 1
        assert out.startswith("FAIL")
        assert "PASS" not in out

    @pytest.mark.parametrize("field", ["pct", "display"])
    def test_single_presentation_field_altered_fails(
        self, tmp_path, reload_app, capsys, field
    ):
        data = _export_signed_report(tmp_path, reload_app)
        metric = next(m for m in data["compliance_metrics"] if m["total"])
        metric[field] = 100.0 if field == "pct" else "all passing"
        assert verify_report_signature(data, _app_signing_key(tmp_path))[0] is False
        code, out = _cli_verify(tmp_path, data, capsys)
        assert (code, out[:4]) == (1, "FAIL")

    def test_bucket_count_altered_fails(self, tmp_path, reload_app, capsys):
        data = _export_signed_report(tmp_path, reload_app)
        bucket = next(b for b in data["remediation_buckets"] if b["entries"])
        bucket["count"] = 0
        assert verify_report_signature(data, _app_signing_key(tmp_path)) == (
            False, "presentation value mismatch",
        )
        code, out = _cli_verify(tmp_path, data, capsys)
        assert (code, out[:4]) == (1, "FAIL")


def _drop_entry_host(d: dict) -> None:
    del next(b for b in d["remediation_buckets"] if b["entries"])["entries"][0]["host"]


def _drop_metric_passing(d: dict) -> None:
    del d["compliance_metrics"][0]["passing"]


def _drop_metric_pct(d: dict) -> None:
    del d["compliance_metrics"][0]["pct"]


def _drop_bucket_count(d: dict) -> None:
    del d["remediation_buckets"][0]["count"]


def _metric_not_object(d: dict) -> None:
    d["compliance_metrics"][0] = "SHA-1"


def _metrics_not_list(d: dict) -> None:
    d["compliance_metrics"] = {"label": "x"}


def _entries_not_list(d: dict) -> None:
    d["remediation_buckets"][0]["entries"] = "none"


def _passing_is_string(d: dict) -> None:
    d["compliance_metrics"][0]["passing"] = "1"


def _signature_not_string(d: dict) -> None:
    d["signature"] = ["x"]


class TestMalformedExportedReport:
    @pytest.mark.parametrize(
        "mutate",
        [
            _drop_entry_host, _drop_metric_passing, _drop_metric_pct,
            _drop_bucket_count, _metric_not_object, _metrics_not_list,
            _entries_not_list, _passing_is_string, _signature_not_string,
        ],
    )
    def test_malformed_report_is_clean_fail(self, tmp_path, reload_app, capsys, mutate):
        data = _export_signed_report(tmp_path, reload_app)
        mutate(data)
        ok, msg = verify_report_signature(data, _app_signing_key(tmp_path))
        assert ok is False
        assert msg
        code, out = _cli_verify(tmp_path, data, capsys)
        assert code == 1
        assert out.startswith("FAIL")


class TestUnreadableReportFile:
    """#66 follow-on: a file verify-report can't read or parse is a clean
    FAIL with exit 1, never a traceback."""

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("missing.json", None),
            ("binary.json", b"\xff\xfe\x00not utf-8"),
            ("deep.json", b"[" * 100_000 + b"]" * 100_000),
        ],
        ids=["missing", "not-utf8", "too-deep"],
    )
    def test_unreadable_file_is_clean_fail(self, tmp_path, monkeypatch, capsys, name, content):
        monkeypatch.setenv("CERT_WATCH_DATA_DIR", str(tmp_path))
        monkeypatch.setenv("CERT_WATCH_AUTH_SECRET", "test-key")
        path = tmp_path / name
        if content is not None:
            path.write_bytes(content)
        from cert_watch.__main__ import main

        with pytest.raises(SystemExit) as exc:
            main(["verify-report", str(path)])
        assert exc.value.code == 1
        assert capsys.readouterr().out.startswith("FAIL")


# ── Compliance report fails closed ──────────────────────────────────────────


class TestComplianceFailsClosed:
    def test_missing_security_returns_503_not_empty_signature(self):
        from fastapi import HTTPException

        from cert_watch.routes.api._shared import compliance_signing_key

        class _State:
            security = None

        class _App:
            state = _State()

        class _Req:
            app = _App()

        with pytest.raises(HTTPException) as exc:
            compliance_signing_key(_Req())
        assert exc.value.status_code == 503

    def test_empty_signing_key_returns_503(self):
        from fastapi import HTTPException

        from cert_watch.routes.api._shared import compliance_signing_key

        class _Security:
            signing_key = ""

        class _State:
            security = _Security()

        class _App:
            state = _State()

        class _Req:
            app = _App()

        with pytest.raises(HTTPException) as exc:
            compliance_signing_key(_Req())
        assert exc.value.status_code == 503


def test_added_unsigned_key_fails_verification() -> None:
    """A signed report must not carry claims its signature does not cover."""
    report = ComplianceReport(
        generated_at="2026-01-01T00:00:00+00:00",
        compliance_metrics=[ComplianceMetric("test", 1, 2)],
        remediation_buckets=[RemediationBucket("bucket", [])],
    )
    sign_report(report, "k")
    doc = report_to_dict(report)
    assert verify_report_signature(doc, "k")[0] is True
    doc["auditor_note"] = "reviewed and approved"
    assert verify_report_signature(doc, "k")[0] is False
    nested = report_to_dict(report)
    nested["compliance_metrics"][0]["note"] = "exempted"
    assert verify_report_signature(nested, "k")[0] is False
