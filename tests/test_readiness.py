"""Tests for SC-081 readiness report (WI-2.2): aggregation, margins, workload, routes."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.readiness import (
    HostReadiness,
    _compute_margins,
    build_readiness_report,
    readiness_report_to_dict,
)


def _seed_readiness_fleet(db_path: str | Path) -> None:
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema, store_scan_posture
    from cert_watch.database.connection import _connect
    from tests._helpers import seed_certificate

    _HIST_SQL = (
        "INSERT INTO cert_history"
        " (hostname,port,fingerprint_sha256,issuer,not_after,not_before,scanned_at)"
        " VALUES (?,443,?,?,?,?,?)"
    )

    init_schema(db_path)
    hosts = SqliteHostRepository(db_path)
    for hostname in ("auto.example.com", "manual.example.com", "new.example.com", "internal.corp"):
        hosts.add(hostname, 443)
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
    def test_short_lifetime_compliant_everywhere(self):
        # A 30-day cert fits under every SC-081 cap.
        margins = _compute_margins(lifetime=30)
        assert len(margins) == 3
        assert [m["renew_late"] for m in margins] == [False, False, False]
        assert margins[2]["margin_days"] == 47 - 30
        assert margins[2]["margin_pct"] == round((47 - 30) / 47 * 100, 1)

    def test_lifetime_over_47d_only(self):
        # A 90-day cert fits under 200d/100d but exceeds the 47d cap.
        margins = _compute_margins(lifetime=90)
        assert margins[0]["renew_late"] is False
        assert margins[1]["renew_late"] is False
        assert margins[2]["renew_late"] is True
        assert margins[2]["margin_days"] == 47 - 90  # negative => over cap

    def test_long_lifetime_exceeds_all_caps(self):
        # A 365-day cert is non-compliant at every milestone.
        margins = _compute_margins(lifetime=365)
        assert [m["renew_late"] for m in margins] == [True, True, True]
        assert margins[2]["margin_days"] == 47 - 365

    def test_margin_pct_calculation(self):
        margins = _compute_margins(lifetime=90)
        ms_100 = margins[1]
        expected_pct = round((100 - 90) / 100 * 100, 1)
        assert ms_100["margin_pct"] == expected_pct

    def test_unknown_lifetime_flagged_conservative(self):
        margins = _compute_margins(lifetime=None)
        for m in margins:
            assert m["margin_days"] is None
            assert m["margin_pct"] is None
            assert m["renew_late"] is True


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


def _seed_current_endpoint(db: Path, *, hostname="current.example.test", port=443,
                           lifetime=365, host_tags="", cert_tags="", history=False):
    from cert_watch.certificate_model import Certificate
    from cert_watch.database import (
        SqliteHostRepository,
        init_schema,
        record_cert_history,
        store_scan_posture,
    )
    from tests._helpers import seed_certificate

    init_schema(db)
    SqliteHostRepository(db).add(hostname, port, tags=host_tags)
    now = datetime.now(UTC)
    cert = Certificate(
        subject=f"CN={hostname}", issuer="CN=Test CA",
        not_before=now - timedelta(days=lifetime - 5),
        not_after=now + timedelta(days=5), san_dns_names=[hostname],
        fingerprint_sha256=f"{hostname}:{port}", raw_der=b"", is_leaf=True,
    )
    cert_id = seed_certificate(
        db, cert, cert_id=f"current-{hostname}-{port}", hostname=hostname,
        port=port, source="scanned", tags=cert_tags,
    )
    store_scan_posture(db, cert_id, hostname, port, "A", [], chain_status="public")
    if history:
        record_cert_history(db, hostname, port, cert, scanned_at=now.isoformat())
    return cert_id


class TestCurrentEndpointReadiness:
    @pytest.mark.parametrize("seconds,expected_lifetime", [
        (47 * 86400 + 1, 48), (3600, 1), (0, None), (-1, None),
    ])
    def test_current_and_historical_validity_never_round_under_a_cap(
        self, tmp_path, seconds, expected_lifetime,
    ):
        from cert_watch.database.connection import _connect
        from cert_watch.renewal_analytics import _compute_host_from_entries

        db = tmp_path / "estate.sqlite3"
        cert_id = _seed_current_endpoint(db)
        not_before = datetime(2026, 1, 1, tzinfo=UTC)
        not_after = not_before + timedelta(seconds=seconds)
        with _connect(db) as conn:
            conn.execute(
                "UPDATE certificates SET not_before = ?, not_after = ? WHERE id = ?",
                (not_before.isoformat(), not_after.isoformat(), cert_id),
            )
            conn.commit()

        host = build_readiness_report(db).hosts[0]
        history = _compute_host_from_entries("current.example.test", [{
            "fingerprint_sha256": "current", "issuer": "CA",
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "scanned_at": not_before.isoformat(),
        }])

        assert host.current_lifetime == expected_lifetime
        assert history.observed_lifetimes == (
            [] if expected_lifetime is None else [expected_lifetime]
        )
        if expected_lifetime is not None:
            assert host.margins[-1]["renew_late"] is (expected_lifetime > 47)
        else:
            assert host.margins[-1]["margin_days"] is None

    def test_monitored_unobserved_and_failed_endpoints_remain_unknown(self, tmp_path):
        from cert_watch.database import SqliteHostRepository, init_schema
        from cert_watch.scheduler import ScanHistory, record_scan_history

        db = tmp_path / "estate.sqlite3"
        init_schema(db)
        hosts = SqliteHostRepository(db)
        hosts.add("unobserved.example.test", 443)
        hosts.add("failed.example.test", 636)
        record_scan_history(db, ScanHistory(
            hostname="failed.example.test", port=636, status="failure", error_message="offline",
        ))

        report = build_readiness_report(db)
        assert report.total_hosts == 2
        assert report.unknown_hosts == 2
        assert report.public_trust_hosts == report.private_ca_hosts == 0
        assert {(host.hostname, host.port) for host in report.unknown_hosts_list} == {
            ("unobserved.example.test", 443), ("failed.example.test", 636),
        }
        for host in report.unknown_hosts_list:
            assert host.current_lifetime is None
            assert host.current_lead_time is None
            assert host.classification == "unknown"

    def test_legacy_history_never_substitutes_first_scan_for_issuance(self, tmp_path):
        from cert_watch.database.connection import _connect

        db = tmp_path / "estate.sqlite3"
        _seed_current_endpoint(db, lifetime=365, history=True)
        with _connect(db) as conn:
            conn.execute("UPDATE cert_history SET not_before = NULL")
            conn.commit()

        report = build_readiness_report(db)
        host = report.hosts[0]
        assert host.current_lifetime == 365
        assert [margin["margin_days"] for margin in host.margins] == [-165, -265, -318]
        assert all(margin["renew_late"] for margin in host.margins)
        assert report.workload_forecast.current_renewals_per_month == 0.1

    def test_current_leaf_without_retained_history_still_has_actual_validity(self, tmp_path):
        db = tmp_path / "estate.sqlite3"
        _seed_current_endpoint(db, lifetime=90)

        report = build_readiness_report(db)
        assert report.total_hosts == report.public_trust_hosts == 1
        host = report.hosts[0]
        assert host.current_lifetime == 90
        assert host.current_lead_time is None
        assert host.classification == "unknown"

    def test_history_cannot_replace_missing_current_leaf_or_add_unmonitored_hosts(self, tmp_path):
        from cert_watch.database.connection import _connect

        db = tmp_path / "estate.sqlite3"
        _seed_current_endpoint(db, hostname="monitored.example.test", history=True)
        _seed_current_endpoint(db, hostname="unmonitored.example.test", history=True)
        with _connect(db) as conn:
            conn.execute("DELETE FROM scan_posture WHERE hostname = 'monitored.example.test'")
            conn.execute("DELETE FROM certificates WHERE hostname = 'monitored.example.test'")
            conn.execute("DELETE FROM hosts WHERE hostname = 'unmonitored.example.test'")
            conn.commit()

        report = build_readiness_report(db)
        assert report.total_hosts == report.unknown_hosts == 1
        assert report.public_trust_hosts == 0
        host = report.unknown_hosts_list[0]
        assert host.hostname == "monitored.example.test"
        assert host.current_lifetime is None
        assert host.chain_status is None

    def test_new_population_preserves_host_scopes_and_exact_ports(self, tmp_path):
        from cert_watch.database import SqliteHostRepository, init_schema

        db = tmp_path / "estate.sqlite3"
        init_schema(db)
        hosts = SqliteHostRepository(db)
        hosts.add("dual.example.test", 443, tags="Straße")
        hosts.add("dual.example.test", 636, tags="other-team")
        _seed_current_endpoint(
            db, hostname="dual.example.test", port=8443,
            host_tags="other-team", cert_tags="Straße", history=True,
        )

        report = build_readiness_report(db, scope_tags=("STRASSE",))
        assert report.total_hosts == report.unknown_hosts == 1
        assert [(host.hostname, host.port) for host in report.unknown_hosts_list] == [
            ("dual.example.test", 443),
        ]
        assert report.hosts == []
        assert report.private_hosts == []

    def test_uploaded_leaf_cannot_supply_current_validity_or_trust(self, tmp_path):
        from cert_watch.certificate_model import Certificate
        from cert_watch.database import store_scan_posture
        from tests._helpers import seed_certificate

        db = tmp_path / "estate.sqlite3"
        _seed_current_endpoint(db, lifetime=365, history=True)
        now = datetime.now(UTC)
        uploaded = Certificate(
            subject="CN=current.example.test", issuer="CN=Private CA",
            not_before=now - timedelta(days=5), not_after=now + timedelta(days=5),
            san_dns_names=[], fingerprint_sha256="uploaded", raw_der=b"", is_leaf=True,
        )
        cert_id = seed_certificate(
            db, uploaded, source="uploaded", hostname="current.example.test", port=443,
        )
        store_scan_posture(
            db, cert_id, "current.example.test", 443, "A", [], chain_status="private",
        )

        report = build_readiness_report(db)
        assert report.total_hosts == report.public_trust_hosts == 1
        assert report.private_hosts == []
        assert report.hosts[0].current_lifetime == 365

    @pytest.mark.parametrize("invalid_date", ["", "invalid-date", "2099-01-01T00:00:00+00:00"])
    def test_missing_invalid_or_reversed_current_dates_stay_unknown(self, tmp_path, invalid_date):
        from cert_watch.database.connection import _connect

        db = tmp_path / "estate.sqlite3"
        cert_id = _seed_current_endpoint(db, lifetime=365, history=True)
        with _connect(db) as conn:
            conn.execute(
                "UPDATE certificates SET not_before = ? WHERE id = ?", (invalid_date, cert_id),
            )
            conn.commit()

        report = build_readiness_report(db)
        host = report.hosts[0]
        assert host.current_lifetime is None
        assert all(margin["margin_days"] is None for margin in host.margins)

    def test_unobserved_html_does_not_claim_the_estate_is_exempt(self, tmp_path, reload_app):
        from cert_watch.database import SqliteHostRepository, init_schema

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        init_schema(db)
        SqliteHostRepository(db).add("unobserved.example.test", 443)
        with TestClient(app_mod.app) as client:
            response = client.get("/readiness")
        assert response.status_code == 200
        assert "unobserved.example.test" in response.text
        assert "SC-081 requirements do not apply to your estate" not in response.text
        assert "not applicable" not in response.text


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
            margins=_compute_margins(365),
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
    @pytest.mark.parametrize("known_count,expected_estimate", [(0, "—"), (1, "0.3")])
    def test_workload_discloses_known_lifetime_coverage(
        self, tmp_path, reload_app, known_count, expected_estimate,
    ):
        import re

        from cert_watch.database.connection import _connect

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        for index in range(2):
            cert_id = _seed_current_endpoint(db, hostname=f"endpoint-{index}.test", lifetime=90)
            if index >= known_count:
                with _connect(db) as conn:
                    conn.execute("UPDATE certificates SET not_before = '' WHERE id = ?", (cert_id,))
                    conn.commit()

        with TestClient(app_mod.app) as client:
            response = client.get("/readiness")
            data = client.get("/api/readiness.json").json()

        assert response.status_code == 200
        coverage = (
            f"Current estimate uses {known_count}/2 public-trust endpoints with known validity"
        )
        assert coverage in response.text
        current_stat = re.search(
            r'data-testid="readiness-current-workload">.*?class="cw-stat-val">([^<]*)',
            response.text, re.DOTALL,
        )
        assert current_stat is not None
        assert current_stat.group(1) == expected_estimate
        assert isinstance(data["workload_forecast"]["current_renewals_per_month"], float)

    def test_readiness_labels_inferred_automation_as_likely(self, tmp_path, reload_app):
        from cert_watch.database.connection import _connect

        app_mod = reload_app()
        db = tmp_path / "cert-watch.sqlite3"
        _seed_current_endpoint(db, lifetime=90)
        now = datetime.now(UTC)
        with _connect(db) as conn:
            for index in range(3):
                first_seen = now - timedelta(days=60 * (2 - index))
                conn.execute(
                    "INSERT INTO cert_history (hostname,port,fingerprint_sha256,issuer,"
                    "not_before,not_after,scanned_at) VALUES (?,?,?,?,?,?,?)",
                    ("current.example.test", 443, f"period-{index}", "Let's Encrypt",
                     first_seen.isoformat(), (first_seen + timedelta(days=90)).isoformat(),
                     first_seen.isoformat()),
                )
            conn.commit()

        with TestClient(app_mod.app) as client:
            data = client.get("/api/readiness.json").json()
            response = client.get("/readiness")

        assert data["hosts"][0]["classification"] == "likely-automated"
        assert response.status_code == 200
        assert "Likely automated" in response.text

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
