"""Tests for the ACME renewal-window alert (Plan 027)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate


def _insert_cert(db, *, cid, days_valid, hostname="h.example.com", port=443, replaces=None):
    from tests._helpers import seed_certificate

    now = datetime.now(UTC)
    cert = Certificate(
        subject=f"CN={cid}",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=days_valid),
        fingerprint_sha256=cid + "-fp",
        raw_der=b"\x00",
    )
    return seed_certificate(
        db,
        cert,
        cert_id=cid,
        hostname=hostname,
        port=port,
        source="scanned",
        chain_valid=True,
        replaces_cert_id=replaces,
    )


def _seed(db):
    _insert_cert(db, cid="stalled", days_valid=20)  # in window, no successor -> alert
    _insert_cert(db, cid="renewed-old", days_valid=15, hostname="r.example.com")
    _insert_cert(  # successor of renewed-old -> renewal worked, no alert
        db, cid="renewed-new", days_valid=300, hostname="r.example.com",
        replaces="renewed-old",
    )
    _insert_cert(db, cid="far", days_valid=100)  # outside window
    _insert_cert(db, cid="expired", days_valid=-5)  # expired -> expiry owns it


def test_only_stalled_cert_alerts(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    created = evaluate_renewal_window(db, repo, 30)
    assert {a.cert_id for a in created} == {"stalled"}
    assert created[0].alert_type == "renewal_stalled"


def test_idempotent(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    assert len(evaluate_renewal_window(db, repo, 30)) == 1
    assert evaluate_renewal_window(db, repo, 30) == []  # no duplicate


def test_window_zero_disables(tmp_path):
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository

    db = str(tmp_path / "t.sqlite3")
    _seed(db)
    repo = SqliteAlertRepository(db)
    assert evaluate_renewal_window(db, repo, 0) == []


def test_renewal_stalled_suppressed_when_in_progress(tmp_path):
    """Regression (WI-124 #11): suppress renewal_stalled when operator flagged it."""
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository, SqliteHostRepository

    db = str(tmp_path / "t.sqlite3")
    _insert_cert(db, cid="stalled-ip", days_valid=20, hostname="ip.example.com")
    SqliteHostRepository(db).add(hostname="ip.example.com", port=443, renewal_status="in_progress")
    alert_repo = SqliteAlertRepository(db)
    created = evaluate_renewal_window(db, alert_repo, 30)
    assert created == [], "in_progress renewal_status should suppress alert"


def test_renewal_stalled_suppressed_when_renewed(tmp_path):
    """Regression (WI-124 #11): suppress renewal_stalled when operator flagged it."""
    from cert_watch.alerts import evaluate_renewal_window
    from cert_watch.database import SqliteAlertRepository, SqliteHostRepository

    db = str(tmp_path / "t.sqlite3")
    _insert_cert(db, cid="stalled-rn", days_valid=20, hostname="rn.example.com")
    SqliteHostRepository(db).add(hostname="rn.example.com", port=443, renewal_status="renewed")
    alert_repo = SqliteAlertRepository(db)
    created = evaluate_renewal_window(db, alert_repo, 30)
    assert created == [], "renewed renewal_status should suppress alert"
