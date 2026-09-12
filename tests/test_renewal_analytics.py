"""Tests for renewal_analytics module."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cert_watch.renewal_analytics import (
    _compute_host_from_entries,
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
    def test_no_history(self, db: Path):
        result = compute_host_analytics(db, "no-such-host.example.com")
        assert result.hostname == "no-such-host.example.com"
        assert result.observed_lifetimes == []
        assert result.lifetime_trend == "unknown"
        assert result.renewal_lead_times == []
        assert result.median_lead_time is None
        assert result.median_cadence_days is None
        assert result.automation_classification == "unknown"
        assert result.cert_count == 0


class TestComputeHostAnalyticsSingleCert:
    def test_one_cert(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=89)
        with sqlite3.connect(str(db)) as conn:
            _insert_history_row(
                conn,
                "single.example.com",
                "fp-A",
                "Let's Encrypt Authority X3",
                _iso(not_after),
                _iso(now),
                not_before=_iso(not_before),
            )

        result = compute_host_analytics(db, "single.example.com")
        assert result.cert_count == 1
        assert len(result.observed_lifetimes) == 1
        assert result.renewal_lead_times == []
        assert result.median_lead_time is None
        assert result.median_cadence_days is None
        assert result.automation_classification == "unknown"
        assert result.classification_evidence.get("reason") == "fewer than 2 observed renewals"


class TestComputeHostAnalyticsAutomated:
    def test_likely_automated(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=300)

        scan_a = base
        scan_b = base + timedelta(days=60)
        scan_c = base + timedelta(days=120)
        scan_d = base + timedelta(days=180)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "auto.example.com")
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
    def test_manual_long_lived(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=800)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "manual.example.com")
        assert result.cert_count == 2
        assert result.automation_classification == "manual"
        assert result.classification_evidence["max_lifetime_days"] > 90
        assert result.classification_evidence["has_acme_issuer"] is False

    def test_manual_late_renewal(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=200)

        scan_a = base
        scan_b = base + timedelta(days=100)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "late.example.com")
        assert result.automation_classification == "manual"
        assert result.classification_evidence["has_late_renewals"] is True
        assert any(lt <= 0 for lt in result.renewal_lead_times)


class TestComputeHostAnalyticsMixed:
    def test_mixed_issuer_switch(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=400)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "mixed.example.com")
        assert result.cert_count == 2
        assert result.automation_classification == "manual"
        assert result.classification_evidence["has_acme_issuer"] is True
        assert result.classification_evidence["max_lifetime_days"] > 90


class TestComputeHostAnalyticsPortFiltering:
    """Regression (WI-124 #9): analytics must filter by (hostname, port)."""

    def test_same_host_different_port_not_mixed(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        with sqlite3.connect(str(db)) as conn:
            _insert_history_row(
                conn, "dual.example.com", "fp-443", "Let's Encrypt R3",
                _iso(now + timedelta(days=89)), _iso(now - timedelta(days=1)),
                not_before=_iso(now - timedelta(days=1)), port=443,
            )
            _insert_history_row(
                conn, "dual.example.com", "fp-636", "DC=corp,DC=ad",
                _iso(now + timedelta(days=365)), _iso(now - timedelta(days=30)),
                not_before=_iso(now - timedelta(days=30)), port=636,
            )

        result_443 = compute_host_analytics(db, "dual.example.com", port=443)
        result_636 = compute_host_analytics(db, "dual.example.com", port=636)
        assert result_443.cert_count == 1
        assert result_636.cert_count == 1
        assert result_443.observed_lifetimes != result_636.observed_lifetimes


class TestComputeHostAnalyticsManyRenewals:
    def test_many_renewals(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=360)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "many.example.com")
        assert result.cert_count == 6
        assert len(result.renewal_lead_times) == 5
        assert len(result.observed_lifetimes) == 6
        assert all(lt == 90 for lt in result.observed_lifetimes)
        assert result.automation_classification == "likely-automated"
        assert result.classification_evidence["renewal_count"] == 5


class TestComputeFleetAnalytics:
    def test_fleet_multiple_hosts(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=200)

        with sqlite3.connect(str(db)) as conn:
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

        results = compute_fleet_analytics(db)
        hostnames = {r.hostname for r in results}
        assert "host1.example.com" in hostnames
        assert "host2.example.com" in hostnames
        assert len(results) == 2

    def test_fleet_empty_db(self, db: Path):
        results = compute_fleet_analytics(db)
        assert results == []


class TestObservedLifetimesAndTrend:
    def test_increasing_lifetimes(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=400)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "trend.example.com")
        assert len(result.observed_lifetimes) == 2
        assert result.lifetime_trend in ("increasing", "decreasing", "stable", "unknown")


class TestLeadTimes:
    def test_lead_times_positive(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=180)

        scan_a = base
        scan_b = base + timedelta(days=60)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "lead.example.com")
        assert len(result.renewal_lead_times) == 1
        assert result.renewal_lead_times[0] > 0
        assert result.median_lead_time is not None
        assert result.median_lead_time > 0


class TestCadence:
    def test_cadence_consistent(self, db: Path):
        import sqlite3

        now = datetime.now(UTC)
        base = now - timedelta(days=240)

        with sqlite3.connect(str(db)) as conn:
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

        result = compute_host_analytics(db, "cadence.example.com")
        assert result.median_cadence_days is not None
        assert result.median_cadence_days == 60.0


def _validity_history():
    base = datetime(2026, 1, 1, tzinfo=UTC)
    entries = []
    for index, remaining in enumerate((90, 80, 70)):
        first_seen = base + timedelta(days=60 * index)
        not_after = first_seen + timedelta(days=remaining)
        entries.append({
            "fingerprint_sha256": f"period-{index}", "issuer": "CN=ACME internal CA",
            "not_before": (not_after - timedelta(days=365)).isoformat(),
            "not_after": not_after.isoformat(), "scanned_at": first_seen.isoformat(),
        })
    return entries


class TestHistoricalValidityEvidence:
    def test_missing_issuance_does_not_invent_short_lifetimes_or_automation(self):
        entries = _validity_history()
        for entry in entries:
            entry["not_before"] = None

        result = _compute_host_from_entries("legacy.example.test", entries, port=443)

        assert result.cert_count == 3
        assert result.observed_lifetimes == []
        assert result.lifetime_trend == "unknown"
        assert result.automation_classification == "unknown"
        assert result.classification_evidence["known_validity_count"] == 0
        assert result.classification_evidence["unknown_validity_count"] == 3
        # Missing issuance does not erase independently observed renewal timing.
        assert result.renewal_lead_times == [30.0, 20.0]
        assert result.median_cadence_days == 60.0

    def test_known_long_lifetimes_remain_stable_and_do_not_infer_automation(self):
        result = _compute_host_from_entries("known.example.test", _validity_history())
        assert result.observed_lifetimes == [365, 365, 365]
        assert result.lifetime_trend == "stable"
        assert result.automation_classification == "manual"

    @pytest.mark.parametrize("first_not_before", [None, "invalid-date", "2099-01-01"])
    def test_later_observation_recovers_validity_within_same_deployment(self, first_not_before):
        known = _validity_history()[0]
        first = dict(known, not_before=first_not_before)
        second = dict(known, scanned_at="2026-01-02T00:00:00+00:00")

        result = _compute_host_from_entries("rescanned.example.test", [first, second])

        assert result.cert_count == 1
        assert result.observed_lifetimes == [365]
        assert result.classification_evidence["known_validity_count"] == 1
        assert result.classification_evidence["unknown_validity_count"] == 0

    def test_recovery_does_not_cross_a_rollback_boundary(self):
        a, b, _ = _validity_history()
        unknown_a = dict(a, not_before=None)
        rolled_back_a = dict(a, scanned_at="2026-05-01T00:00:00+00:00")

        result = _compute_host_from_entries("rollback.example.test", [unknown_a, b, rolled_back_a])

        assert result.cert_count == 3
        assert result.observed_lifetimes == [365, 365]
        assert result.lifetime_trend == "unknown"
        assert result.automation_classification == "unknown"
        assert result.classification_evidence["unknown_validity_count"] == 1

    def test_missing_middle_period_cannot_create_a_sparse_lifetime_trend(self):
        entries = _validity_history()
        entries[1]["not_before"] = None
        entries[2]["not_before"] = (
            datetime.fromisoformat(entries[2]["not_after"]) - timedelta(days=90)
        ).isoformat()

        result = _compute_host_from_entries("gapped.example.test", entries)

        assert result.observed_lifetimes == [365, 90]
        assert result.lifetime_trend == "unknown"
        assert result.automation_classification == "unknown"

    @pytest.mark.parametrize("field,value", [
        ("not_before", "invalid-date"), ("not_after", "invalid-date"),
        ("not_before", None), ("not_after", None),
        ("not_before", "2099-01-01T00:00:00+00:00"),
        ("not_before", "same-as-expiry"),
    ])
    def test_invalid_missing_or_nonpositive_validity_stays_unknown(self, field, value):
        entries = _validity_history()
        if value == "same-as-expiry":
            value = entries[1]["not_after"]
        entries[1][field] = value

        result = _compute_host_from_entries("malformed.example.test", entries)

        assert result.observed_lifetimes == [365, 365]
        assert result.lifetime_trend == "unknown"
        assert result.automation_classification == "unknown"
        assert result.classification_evidence["unknown_validity_count"] == 1

    def test_incomplete_scan_chronology_cannot_infer_automation(self):
        entries = _validity_history()
        for entry in entries:
            entry["not_before"] = (
                datetime.fromisoformat(entry["not_after"]) - timedelta(days=90)
            ).isoformat()
        entries[1]["scanned_at"] = "invalid-date"

        result = _compute_host_from_entries("unknown-cadence.example.test", entries)

        assert result.observed_lifetimes == [90, 90, 90]
        assert result.renewal_lead_times == [20.0]
        assert result.median_cadence_days is None
        assert result.automation_classification == "unknown"
