"""Regression coverage for the retired operator-reported ``renewed`` state."""

from datetime import UTC, datetime, timedelta

from cert_watch.alerting.rules.expiry import evaluate_all_certs
from cert_watch.alerting.rules.renewal import evaluate_renewal_window
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.scan import ScanError, scan_host
from tests._helpers import seed_certificate


def _cert(name: str, days: int) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={name}",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=80),
        not_after=now + timedelta(days=days, hours=1),
        san_dns_names=[],
        fingerprint_sha256=(name * 64)[:64],
        raw_der=b"",
        is_leaf=True,
    )


def test_renewed_flag_and_failed_scans_do_not_suppress_expiry_alerts(tmp_path) -> None:
    """Reproduce #117: a claimed renewal must not make scan failure silent."""
    db = tmp_path / "renewed.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    alerts = SqliteAlertRepository(db)
    for hostname, days in (
        ("control.example.test", 2),
        ("flagged.example.test", 2),
        ("expired.example.test", -3),
    ):
        hosts.add(hostname, 1)
        seed_certificate(
            db,
            _cert(hostname[0], days),
            cert_id=hostname,
            hostname=hostname,
            port=1,
        )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE hosts SET renewal_status = 'renewed' "
            "WHERE hostname != 'control.example.test'"
        )
        conn.commit()

    for _ in range(3):
        assert isinstance(
            scan_host("127.0.0.1", 1, timeout=1, retries=0),
            ScanError,
        )

    created = evaluate_all_certs(db, alerts)
    assert {alert.cert_id for alert in created} == {
        "control.example.test",
        "flagged.example.test",
        "expired.example.test",
    }
    assert {alert.alert_type for alert in created} == {"expiry_warning", "expired"}


def test_in_progress_suppresses_only_renewal_stalled_alerts(tmp_path) -> None:
    from cert_watch.services.host_ownership import VALID_RENEWAL_STATUSES

    assert frozenset({"pending", "in_progress"}) == VALID_RENEWAL_STATUSES
    db = tmp_path / "in-progress.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    alerts = SqliteAlertRepository(db)
    for hostname, days in (
        ("warning.example.test", 2),
        ("expired.example.test", -3),
    ):
        hosts.add(hostname, 443, renewal_status="in_progress")
        seed_certificate(
            db,
            _cert(hostname[0], days),
            cert_id=hostname,
            hostname=hostname,
            port=443,
        )

    expiry = evaluate_all_certs(db, alerts)
    assert {alert.cert_id for alert in expiry} == {
        "warning.example.test",
        "expired.example.test",
    }
    assert {alert.alert_type for alert in expiry} == {"expiry_warning", "expired"}
    assert evaluate_renewal_window(db, alerts, 30) == []
