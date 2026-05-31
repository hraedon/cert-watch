import pytest

from cert_watch.alerts import evaluate_all_certs, evaluate_thresholds
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    init_schema,
)


@pytest.fixture
def alert_repo(tmp_path):
    from cert_watch.database.schema import init_schema
    init_schema(tmp_path / "cw.sqlite3")
    return SqliteAlertRepository(tmp_path / "cw.sqlite3")


def test_evaluate_thresholds_custom(alert_repo, expiring_soon_leaf):
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)
    custom = (90, 60, 30)
    alerts = evaluate_thresholds(cert, alert_repo, custom_thresholds=custom)
    assert len(alerts) > 0
    for a in alerts:
        assert a.threshold_days in custom


def test_evaluate_thresholds_custom_no_match(alert_repo, self_signed_leaf):
    cert = parse_certificate(self_signed_leaf.der)
    assert isinstance(cert, Certificate)
    custom = (1,)
    alerts = evaluate_thresholds(cert, alert_repo, custom_thresholds=custom)
    assert alerts == []


def test_evaluate_all_certs_with_host_threshold(tmp_path, expiring_soon_leaf):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)

    cert_repo = SqliteCertificateRepository(
        db, source="scanned", hostname="custom.example.com", port=443
    )
    cert_id = cert_repo.add(cert)

    host_repo = SqliteHostRepository(db)
    host_repo.add("custom.example.com", 443, threshold_days=90)

    alert_repo = SqliteAlertRepository(db)
    alerts = evaluate_all_certs(db, alert_repo)
    assert len(alerts) > 0
    assert any(a.cert_id == cert_id for a in alerts)


def test_evaluate_all_certs_default_threshold(tmp_path, expiring_soon_leaf):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    cert = parse_certificate(expiring_soon_leaf.der)
    assert isinstance(cert, Certificate)

    cert_repo = SqliteCertificateRepository(
        db, source="scanned", hostname="default.example.com", port=443
    )
    cert_repo.add(cert)

    host_repo = SqliteHostRepository(db)
    host_repo.add("default.example.com", 443)

    alert_repo = SqliteAlertRepository(db)
    alerts = evaluate_all_certs(db, alert_repo)
    assert len(alerts) > 0


def test_host_entry_threshold_roundtrip(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("th.example.com", 443, threshold_days=45)
    host = host_repo.get(hid)
    assert host is not None
    assert host.threshold_days == 45


def test_host_entry_no_threshold(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    host_repo = SqliteHostRepository(db)
    hid = host_repo.add("noth.example.com", 443)
    host = host_repo.get(hid)
    assert host is not None
    assert host.threshold_days is None
