"""Current scan evidence must follow endpoint cadence, not the latest attempt."""
from datetime import UTC, datetime, timedelta

import pytest
from freezegun import freeze_time

from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.scheduler import ScanHistory, record_scan_history


def test_failed_attempt_does_not_refresh_overdue_evidence(tmp_path):
    from cert_watch.scan_freshness import load_scan_evidence

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    host = SqliteHostRepository(db).add("dual.example.test", 443, scan_interval_hours=4)
    other = SqliteHostRepository(db).add("dual.example.test", 636, scan_interval_hours=4)
    now = datetime(2026, 9, 12, 12, tzinfo=UTC)
    record_scan_history(db, ScanHistory("dual.example.test", 443, "success",
                                      scanned_at=now - timedelta(hours=5)))
    record_scan_history(db, ScanHistory("dual.example.test", 443, "failure",
                                      scanned_at=now - timedelta(minutes=10)))
    record_scan_history(db, ScanHistory("dual.example.test", 636, "success", scanned_at=now))
    evidence = load_scan_evidence(db, now=now)
    assert evidence[host].state == "overdue"
    assert evidence[host].due_at == now - timedelta(hours=1)
    assert evidence[host].next_attempt_at == now + timedelta(minutes=50)
    assert evidence[host].last_success == now - timedelta(hours=5)
    assert evidence[host].attempt_status == "failure"
    assert evidence[other].state == "current"


def test_daily_boundary_and_unobserved_scope(tmp_path):
    from cert_watch.scan_freshness import load_scan_evidence, summarize_scan_evidence

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    host = hosts.add("daily.example.test", 443, tags="visible")
    pending = hosts.add("pending.example.test", 443, tags="visible")
    hosts.add("secret.example.test", 443, tags="hidden")
    now = datetime(2026, 9, 12, 6, tzinfo=UTC)
    record_scan_history(db, ScanHistory("daily.example.test", 443, "success",
                                      scanned_at=now - timedelta(minutes=1)))
    evidence = load_scan_evidence(db, now=now, scope_tags=["visible"], hour=6, minute=0)
    assert set(evidence) == {host, pending}
    assert evidence[host].state == "overdue"
    assert evidence[pending].state == "unobserved"
    summary = summarize_scan_evidence(evidence)
    assert summary == {"total": 2, "current": 0, "overdue": 1, "unobserved": 1,
                       "failed": 0, "unknown": 0}


def test_freshness_boundary_matches_scheduler(tmp_path):
    from cert_watch.scan_freshness import load_scan_evidence
    from cert_watch.scheduler import get_hosts_due_for_scan

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    host = SqliteHostRepository(db).add("interval.example.test", 443, scan_interval_hours=2)
    record_scan_history(db, ScanHistory("interval.example.test", 443, "success",
                                      scanned_at=datetime(2026, 9, 12, 10, tzinfo=UTC)))
    with freeze_time("2026-09-12 11:59:59"):
        assert load_scan_evidence(db)[host].state == "current"
        assert get_hosts_due_for_scan(db) == []
    with freeze_time("2026-09-12 12:00:00"):
        assert load_scan_evidence(db)[host].state == "overdue"
        assert get_hosts_due_for_scan(db) == [("interval.example.test", 443)]


@pytest.mark.parametrize("status", ["failure", "partial"])
def test_incomplete_attempt_inside_cadence_is_not_current(tmp_path, status):
    from cert_watch.scan_freshness import load_scan_evidence

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    host = SqliteHostRepository(db).add("retry.example.test", 443, scan_interval_hours=24)
    now = datetime(2026, 9, 12, 12, tzinfo=UTC)
    record_scan_history(db, ScanHistory("retry.example.test", 443, "success",
                                      scanned_at=now - timedelta(hours=1)))
    record_scan_history(db, ScanHistory("retry.example.test", 443, status, scanned_at=now))
    scan = load_scan_evidence(db, now=now)[host]
    assert scan.state == "failed"
    assert scan.due_at == now + timedelta(hours=23)


@pytest.mark.parametrize("timestamp", ["not-a-date", "2099-01-01T00:00:00+00:00"])
def test_invalid_or_future_scan_is_unknown(tmp_path, timestamp):
    from cert_watch.database import _connect
    from cert_watch.scan_freshness import load_scan_evidence

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    host = SqliteHostRepository(db).add("unknown.example.test", 443)
    scan_id = record_scan_history(db, ScanHistory("unknown.example.test", 443, "success"))
    with _connect(db) as conn:
        conn.execute("UPDATE scan_history SET scanned_at = ? WHERE id = ?", (timestamp, scan_id))
        conn.commit()
    scan = load_scan_evidence(db)[host]
    assert scan.state == "unknown"
    assert scan.due_at is None


def test_home_browse_and_detail_expose_overdue_scans(reload_app, tmp_path, chain_triplet):
    from fastapi.testclient import TestClient

    from cert_watch.certificate_model import _from_x509
    from tests._helpers import seed_scanned

    application = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("old.example.test", 443, scan_interval_hours=4)
    cert = _from_x509(chain_triplet["leaf"].cert)
    cert_id = seed_scanned(db, "old.example.test", 443, cert)
    record_scan_history(db, ScanHistory("old.example.test", 443, "success",
                                      scanned_at=datetime.now(UTC) - timedelta(days=3)))
    with TestClient(application) as client:
        home = client.get("/")
        browse = client.get("/browse?grouped=0")
        detail = client.get(f"/certificates/{cert_id}")
    assert home.status_code == browse.status_code == detail.status_code == 200
    assert "0 of 1 monitored endpoints have current observations" in home.text
    assert "Scan overdue" in home.text
    assert "Scan overdue" in browse.text
    assert "Last successful scan" in detail.text
    assert "Scan overdue" in detail.text
    assert "earlier evidence" in detail.text


def test_scoped_coverage_uses_scanned_certificate_tags_not_upload_tags(tmp_path, chain_triplet):
    from cert_watch.certificate_model import _from_x509
    from cert_watch.database import SqliteCertificateRepository
    from cert_watch.scan_freshness import load_scan_evidence
    from tests._helpers import seed_certificate

    db = tmp_path / "freshness.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    visible = hosts.add("visible.example.test", 443)
    hosts.add("hidden.example.test", 443)
    cert = _from_x509(chain_triplet["leaf"].cert)
    scanned = seed_certificate(db, cert, hostname="visible.example.test", port=443)
    uploaded = seed_certificate(db, cert, hostname="hidden.example.test", port=443,
                                source="uploaded")
    for cert_id in [scanned, uploaded]:
        SqliteCertificateRepository(db).set_tags(cert_id, "team")
    assert set(load_scan_evidence(db, scope_tags=["team"])) == {visible}
