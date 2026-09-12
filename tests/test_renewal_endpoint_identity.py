"""Renewal summaries and webhook context belong to an exact endpoint."""

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema, record_cert_history
from cert_watch.database.connection import _connect
from cert_watch.digest import build_renewal_digest
from cert_watch.renewal_analytics import RenewalOverdueSignal
from cert_watch.renewal_webhook import build_renewal_payload
from tests._helpers import seed_certificate


def _endpoint(db, port, *, owner="", days=90, fingerprint=None, source="scanned"):
    init_schema(db)
    SqliteHostRepository(db).add("dual.example.test", port, owner_email=owner)
    now = datetime.now(UTC)
    cert = Certificate(
        subject="CN=dual.example.test", issuer="CN=CA", san_dns_names=[],
        not_before=now - timedelta(days=10), not_after=now + timedelta(days=days),
        fingerprint_sha256=fingerprint or f"fingerprint-{port}", raw_der=b"", is_leaf=True,
    )
    cert_id = seed_certificate(db, cert, hostname="dual.example.test", port=port, source=source)
    record_cert_history(db, "dual.example.test", port, cert, scanned_at=now.isoformat())
    return cert_id, cert


def _event(db, *, port=443, kind="renewal_overdue", missing_port=False):
    import json

    payload = {"hostname": "dual.example.test"}
    if not missing_port:
        payload["port"] = port
    now = datetime.now(UTC).isoformat()
    with _connect(db) as conn:
        conn.execute(
            "INSERT INTO event_log (event_type,timestamp,source,payload,created_at) "
            "VALUES (?,?,?,?,?)", (kind, now, "test", json.dumps(payload), now),
        )
        conn.commit()


def test_digest_uses_affected_port_owner_and_current_expiry(tmp_path):
    db = tmp_path / "estate.sqlite3"
    _, affected = _endpoint(db, 443, owner="alice@example.invalid", days=5)
    _endpoint(db, 636, owner="bob@example.invalid", days=150)
    _event(db, port=443)

    digests = build_renewal_digest(db)

    assert len(digests) == 1
    assert digests[0].owner_email == "alice@example.invalid"
    assert digests[0].overdue_hosts == ["dual.example.test"]
    assert digests[0].host_expiry == {"dual.example.test": affected.not_after.isoformat()}


def test_digest_keeps_two_ports_distinct_for_one_owner(tmp_path):
    db = tmp_path / "estate.sqlite3"
    _, https = _endpoint(db, 443, owner="owner@example.invalid", days=5)
    _, ldaps = _endpoint(db, 636, owner="owner@example.invalid", days=150)
    _event(db, port=443)
    _event(db, port=636)

    digest = build_renewal_digest(db)[0]

    assert digest.overdue_count == 2
    assert set(digest.overdue_hosts) == {"dual.example.test", "dual.example.test:636"}
    assert digest.host_expiry == {
        "dual.example.test": https.not_after.isoformat(),
        "dual.example.test:636": ldaps.not_after.isoformat(),
    }


@pytest.mark.parametrize("port", [None, 0, -1, 65536, "636", True, []])
def test_legacy_or_invalid_digest_port_is_unowned_and_unenriched(tmp_path, port):
    db = tmp_path / "estate.sqlite3"
    _endpoint(db, 443, owner="alice@example.invalid")
    _endpoint(db, 636, owner="bob@example.invalid")
    _event(db, port=port, missing_port=port is None)

    digest = build_renewal_digest(db)[0]

    assert digest.owner_email == ""
    assert digest.overdue_hosts == ["dual.example.test (port unknown)"]
    assert digest.host_expiry == {"dual.example.test (port unknown)": None}
    assert digest.shortened_count == 0


def test_digest_history_cannot_supply_a_missing_current_certificate(tmp_path):
    db = tmp_path / "estate.sqlite3"
    cert_id, _ = _endpoint(db, 443, owner="alice@example.invalid")
    _endpoint(db, 636, owner="bob@example.invalid")
    _event(db, port=443)
    with _connect(db) as conn:
        conn.execute("DELETE FROM certificates WHERE id = ?", (cert_id,))
        conn.commit()

    digest = build_renewal_digest(db)[0]
    assert digest.owner_email == "alice@example.invalid"
    assert digest.host_expiry == {"dual.example.test": None}


def test_webhook_current_certificate_link_does_not_cross_port_or_source(tmp_path):
    db = tmp_path / "estate.sqlite3"
    target_id, target = _endpoint(db, 443, fingerprint="shared")
    _endpoint(db, 636, fingerprint="shared")
    seed_certificate(db, target, hostname="dual.example.test", port=443, source="uploaded")
    signal = RenewalOverdueSignal("dual.example.test", "shared", 5, 30, 25, "low", port=443)

    payload = build_renewal_payload(signal, db, port=443, base_url="https://watch.example.invalid")

    assert payload["cert_watch_url"] == f"https://watch.example.invalid/certificates/{target_id}"
    assert payload["expiry"] == target.not_after.isoformat()


def test_webhook_uses_signal_port_when_override_is_omitted(tmp_path):
    db = tmp_path / "estate.sqlite3"
    cert_id, _ = _endpoint(db, 636)
    signal = RenewalOverdueSignal(
        "dual.example.test", "fingerprint-636", 5, 30, 25, "low", port=636,
    )

    payload = build_renewal_payload(signal, db, base_url="https://watch.example.invalid")

    assert payload["port"] == 636
    assert payload["cert_watch_url"] == f"https://watch.example.invalid/certificates/{cert_id}"


def test_webhook_does_not_enrich_an_obsolete_signal_from_retained_old_leaf(tmp_path):
    db = tmp_path / "estate.sqlite3"
    _, old = _endpoint(db, 443, fingerprint="old")
    seed_certificate(
        db, Certificate(
            subject="CN=new", issuer="CN=CA", san_dns_names=[],
            not_before=old.not_before, not_after=old.not_after,
            fingerprint_sha256="new", raw_der=b"", is_leaf=True,
        ), hostname="dual.example.test", port=443,
    )
    signal = RenewalOverdueSignal("dual.example.test", "old", 5, 30, 25, "low", port=443)

    payload = build_renewal_payload(signal, db, port=443, base_url="https://watch.example.invalid")

    assert "cert_watch_url" not in payload
    assert payload["subject_cn"] == ""
    assert payload["expiry"] == ""


def test_webhook_automation_hint_uses_only_affected_endpoint(tmp_path):
    db = tmp_path / "estate.sqlite3"
    _endpoint(db, 443)
    _endpoint(db, 636)
    now = datetime.now(UTC)
    with _connect(db) as conn:
        conn.execute("DELETE FROM cert_history")
        for port, lifetime in ((443, 90), (636, 365)):
            for index in range(3):
                first = now - timedelta(days=60 * (2 - index))
                conn.execute(
                    "INSERT INTO cert_history (hostname,port,fingerprint_sha256,issuer,"
                    "not_before,not_after,scanned_at) VALUES (?,?,?,?,?,?,?)",
                    ("dual.example.test", port, f"{port}-{index}", "Let's Encrypt",
                     first.isoformat(), (first + timedelta(days=lifetime)).isoformat(),
                     first.isoformat()),
                )
        conn.commit()
    signal = RenewalOverdueSignal(
        "dual.example.test", "fingerprint-443", 5, 30, 25, "low", port=443,
    )

    payload = build_renewal_payload(signal, db, port=443)

    assert payload["automation_hint"] == "likely-automated"


@pytest.mark.parametrize("port", [0, -1, 65536, "636", True, 636])
def test_webhook_rejects_invalid_or_conflicting_port(tmp_path, port):
    db = tmp_path / "estate.sqlite3"
    _endpoint(db, 443)
    signal = RenewalOverdueSignal(
        "dual.example.test", "fingerprint-443", 5, 30, 25, "low", port=443,
    )

    with pytest.raises(ValueError, match="port"):
        build_renewal_payload(signal, db, port=port)
