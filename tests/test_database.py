from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import parse_certificate
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    init_schema,
)


def test_init_schema_idempotent(tmp_path):
    db = tmp_path / "cw.sqlite3"
    init_schema(db)
    init_schema(db)
    assert db.exists()


def test_add_and_get_certificate(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    cert = parse_certificate(self_signed_leaf.der)
    cert_id = repo.add(cert)
    fetched = repo.get_by_id(cert_id)
    assert fetched is not None
    # Verifies non-trivial dep field survives round-trip per AC-02.
    assert fetched.fingerprint_sha256 == cert.fingerprint_sha256
    assert fetched.subject == cert.subject


def test_list_all_and_expiring_within(tmp_path, self_signed_leaf, expiring_soon_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    repo.add(parse_certificate(self_signed_leaf.der))
    repo.add(parse_certificate(expiring_soon_leaf.der))
    assert len(repo.list_all()) == 2
    soon = repo.list_expiring_within(30)
    assert len(soon) == 1


def test_update_expiry_and_delete(tmp_path, self_signed_leaf):
    db = tmp_path / "cw.sqlite3"
    repo = SqliteCertificateRepository(db, source="uploaded")
    cid = repo.add(parse_certificate(self_signed_leaf.der))
    new = datetime.now(UTC) + timedelta(days=1)
    repo.update_expiry(cid, new)
    got = repo.get_by_id(cid)
    assert abs((got.not_after - new).total_seconds()) < 5
    repo.delete(cid)
    assert repo.get_by_id(cid) is None


def test_alert_repository_lifecycle(tmp_path):
    db = tmp_path / "cw.sqlite3"
    arepo = SqliteAlertRepository(db)
    a = Alert(
        cert_id="cert-1",
        alert_type="expiry_warning",
        status="pending",
        message="expires soon",
        threshold_days=7,
    )
    aid = arepo.create(a)
    pending = arepo.list_pending()
    assert len(pending) == 1 and pending[0].id == aid
    arepo.mark_sent(aid)
    assert arepo.list_pending() == []
    a2 = Alert(cert_id="c", alert_type="expired", status="pending", message="m")
    a2id = arepo.create(a2)
    arepo.mark_failed(a2id, "smtp dead")
    rows = [a for a in arepo.list_all() if a.id == a2id]
    assert rows[0].status == "failed" and rows[0].error_message == "smtp dead"
