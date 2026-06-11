"""Tests for renewal_analytics module."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.database.schema import init_schema
from cert_watch.renewal_analytics import (
    _compute_trend,
    _is_acme_issuer,
    compute_fleet_analytics,
    compute_host_analytics,
)


def _insert_history_row(
    conn,
    hostname: str,
    fingerprint: str,
    issuer: str,
    not_after: str,
    scanned_at: str,
    not_before: str | None = None,
    port: int = 443,
) -> None:
    conn.execute(
        """INSERT INTO cert_history
        (id, hostname, port, fingerprint_sha256, issuer, not_after,
         key_algo, sig_algo, posture_grade, protocol_version, san_count,
         scanned_at, not_before)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()),
            hostname,
            port,
            fingerprint,
            issuer,
            not_after,
            "RSA-2048",
            "SHA-256",
            "A",
            "TLSv1.3",
            1,
            scanned_at,
            not_before,
        ),
    )
    conn.commit()


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    db = tmp_path / "test.sqlite3"
    init_schema(db)
    return db


def _iso(dt: datetime) -> str:
    return dt.isoformat()


class TestIsAcmeIssuer:
    def test_lets_encrypt(self):
        assert _is_acme_issuer("Let's Encrypt Authority X3")

    def test_zerossl(self):
        assert _is_acme_issuer("ZeroSSL Domain Validation")

    def test_buypass(self):
        assert _is_acme_issuer("Buypass Class 2 CA")

    def test_acme_in_name(self):
        assert _is_acme_issuer("Custom ACME Server CA")

    def test_non_acme(self):
        assert not _is_acme_issuer("DigiCert SHA2 Extended Validation")

    def test_case_insensitive(self):
        assert _is_acme_issuer("LET'S ENCRYPT AUTHORITY X3")


class TestComputeTrend:
    def test_increasing(self):
        assert _compute_trend([30, 60, 90, 120]) == "increasing"

    def test_decreasing(self):
        assert _compute_trend([120, 90, 60, 30]) == "decreasing"

    def test_stable(self):
        assert _compute_trend([89, 90, 91, 90]) == "stable"

    def test_single_value(self):
        assert _compute_trend([90]) == "unknown"

    def test_empty(self):
        assert _compute_trend([]) == "unknown"

    def test_two_values_stable(self):
        assert _compute_trend([90, 90]) == "stable"


class TestComputeHostAnalyticsEmpty:
    def test_no_history(self, db_path: Path):
        result = compute_host_analytics(db_path, "no-such-host.example.com")
        assert result.hostname == "no-such-host.example.com"
        assert result.observed_lifetimes == []
        assert result.lifetime_trend == "unknown"
        assert result.renewal_lead_times == []
        assert result.median_lead_time is None
        assert result.median_cadence_days is None
        assert result.automation_classification == "unknown"
        assert result.cert_count == 0


class TestComputeHostAnalyticsSingleCert:
    def test_one_cert(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=89)
        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "single.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after),
                _iso(now),
                not_before=_iso(not_before),
            )

        result = compute_host_analytics(db_path, "single.example.com")
        assert result.cert_count == 1
        assert len(result.observed_lifetimes) == 1
        assert result.renewal_lead_times == []
        assert result.median_lead_time is None
        assert result.median_cadence_days is None
        assert result.automation_classification == "unknown"
        assert result.classification_evidence.get("reason") == "fewer than 2 observed renewals"


class TestComputeHostAnalyticsAutomated:
    def test_likely_automated(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=300)

        scan_a = base
        scan_b = base + timedelta(days=60)
        scan_c = base + timedelta(days=120)
        scan_d = base + timedelta(days=180)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "auto.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(scan_a + timedelta(days=90)),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "auto.example.com",
                "fp-B",
                "Let's Encrypt Authority X3",
                _iso(scan_b + timedelta(days=90)),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )
            _insert_history_row(
                conn,
                "auto.example.com",
                "fp-C",
                "Let's Encrypt Authority X3",
                _iso(scan_c + timedelta(days=90)),
                _iso(scan_c),
                not_before=_iso(scan_c),
            )
            _insert_history_row(
                conn,
                "auto.example.com",
                "fp-D",
                "Let's Encrypt Authority X3",
                _iso(scan_d + timedelta(days=90)),
                _iso(scan_d),
                not_before=_iso(scan_d),
            )

        result = compute_host_analytics(db_path, "auto.example.com")
        assert result.cert_count == 4
        assert result.automation_classification == "likely-automated"
        assert result.classification_evidence["has_acme_issuer"] is True
        assert result.classification_evidence["all_lifetimes_le_90"] is True
        assert result.classification_evidence["cadence_stdev_days"] is not None
        assert result.classification_evidence["cadence_stdev_days"] <= 3
        assert result.classification_evidence["renewal_count"] == 3
        assert len(result.renewal_lead_times) == 3
        assert result.median_lead_time is not None
        assert result.median_cadence_days is not None


class TestComputeHostAnalyticsManual:
    def test_manual_long_lived(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=800)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "manual.example.com",
                "fp-X",
                "DigiCert SHA2 Extended Validation Server CA",
                _iso(base + timedelta(days=365)),
                _iso(base),
                not_before=_iso(base),
            )
            _insert_history_row(
                conn,
                "manual.example.com",
                "fp-Y",
                "DigiCert SHA2 Extended Validation Server CA",
                _iso(base + timedelta(days=730)),
                _iso(base + timedelta(days=365)),
                not_before=_iso(base + timedelta(days=365)),
            )

        result = compute_host_analytics(db_path, "manual.example.com")
        assert result.cert_count == 2
        assert result.automation_classification == "manual"
        assert result.classification_evidence["max_lifetime_days"] > 90
        assert result.classification_evidence["has_acme_issuer"] is False

    def test_manual_late_renewal(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=200)

        scan_a = base
        scan_b = base + timedelta(days=100)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "late.example.com",
                "fp-L1",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=90)),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "late.example.com",
                "fp-L2",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=190)),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )

        result = compute_host_analytics(db_path, "late.example.com")
        assert result.automation_classification == "manual"
        assert result.classification_evidence["has_late_renewals"] is True
        assert any(lt <= 0 for lt in result.renewal_lead_times)


class TestComputeHostAnalyticsMixed:
    def test_mixed_issuer_switch(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=400)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "mixed.example.com",
                "fp-M1",
                "DigiCert SHA2 Extended Validation Server CA",
                _iso(base + timedelta(days=365)),
                _iso(base),
                not_before=_iso(base),
            )
            _insert_history_row(
                conn,
                "mixed.example.com",
                "fp-M2",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=665)),
                _iso(base + timedelta(days=300)),
                not_before=_iso(base + timedelta(days=300)),
            )

        result = compute_host_analytics(db_path, "mixed.example.com")
        assert result.cert_count == 2
        assert result.automation_classification == "manual"
        assert result.classification_evidence["has_acme_issuer"] is True
        assert result.classification_evidence["max_lifetime_days"] > 90


class TestComputeHostAnalyticsManyRenewals:
    def test_many_renewals(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=360)

        with sqlite3.connect(str(db_path)) as conn:
            for i in range(6):
                scan_time = base + timedelta(days=i * 60)
                _insert_history_row(
                    conn,
                    "many.example.com",
                    f"fp-{i}",
                    "Let's Encrypt Authority X3",
                    _iso(scan_time + timedelta(days=90)),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        result = compute_host_analytics(db_path, "many.example.com")
        assert result.cert_count == 6
        assert len(result.renewal_lead_times) == 5
        assert len(result.observed_lifetimes) == 6
        assert all(lt == 90 for lt in result.observed_lifetimes)
        assert result.automation_classification == "likely-automated"
        assert result.classification_evidence["renewal_count"] == 5


class TestComputeFleetAnalytics:
    def test_fleet_multiple_hosts(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=200)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "host1.example.com",
                "fp-H1A",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=90)),
                _iso(base),
                not_before=_iso(base),
            )
            _insert_history_row(
                conn,
                "host1.example.com",
                "fp-H1B",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=150)),
                _iso(base + timedelta(days=60)),
                not_before=_iso(base + timedelta(days=60)),
            )
            _insert_history_row(
                conn,
                "host2.example.com",
                "fp-H2A",
                "DigiCert SHA2 Extended Validation Server CA",
                _iso(base + timedelta(days=365)),
                _iso(base),
                not_before=_iso(base),
            )

        results = compute_fleet_analytics(db_path)
        hostnames = {r.hostname for r in results}
        assert "host1.example.com" in hostnames
        assert "host2.example.com" in hostnames
        assert len(results) == 2

    def test_fleet_empty_db(self, db_path: Path):
        results = compute_fleet_analytics(db_path)
        assert results == []


class TestObservedLifetimesAndTrend:
    def test_increasing_lifetimes(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=400)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "trend.example.com",
                "fp-T1",
                "Let's Encrypt Authority X3",
                _iso(base + timedelta(days=90)),
                _iso(base),
                not_before=_iso(base),
            )
            _insert_history_row(
                conn,
                "trend.example.com",
                "fp-T2",
                "DigiCert SHA2 Extended Validation Server CA",
                _iso(base + timedelta(days=60 + 365)),
                _iso(base + timedelta(days=60)),
                not_before=_iso(base + timedelta(days=60)),
            )

        result = compute_host_analytics(db_path, "trend.example.com")
        assert len(result.observed_lifetimes) == 2
        assert result.lifetime_trend in ("increasing", "decreasing", "stable", "unknown")


class TestLeadTimes:
    def test_lead_times_positive(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=180)

        scan_a = base
        scan_b = base + timedelta(days=60)

        with sqlite3.connect(str(db_path)) as conn:
            _insert_history_row(
                conn,
                "lead.example.com",
                "fp-LA",
                "Let's Encrypt Authority X3",
                _iso(scan_a + timedelta(days=90)),
                _iso(scan_a),
                not_before=_iso(scan_a),
            )
            _insert_history_row(
                conn,
                "lead.example.com",
                "fp-LB",
                "Let's Encrypt Authority X3",
                _iso(scan_b + timedelta(days=90)),
                _iso(scan_b),
                not_before=_iso(scan_b),
            )

        result = compute_host_analytics(db_path, "lead.example.com")
        assert len(result.renewal_lead_times) == 1
        assert result.renewal_lead_times[0] > 0
        assert result.median_lead_time is not None
        assert result.median_lead_time > 0


class TestCadence:
    def test_cadence_consistent(self, db_path: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=240)

        with sqlite3.connect(str(db_path)) as conn:
            for i in range(4):
                scan_time = base + timedelta(days=i * 60)
                _insert_history_row(
                    conn,
                    "cadence.example.com",
                    f"fp-C{i}",
                    "Let's Encrypt Authority X3",
                    _iso(scan_time + timedelta(days=90)),
                    _iso(scan_time),
                    not_before=_iso(scan_time),
                )

        result = compute_host_analytics(db_path, "cadence.example.com")
        assert result.median_cadence_days is not None
        assert result.median_cadence_days == 60.0
