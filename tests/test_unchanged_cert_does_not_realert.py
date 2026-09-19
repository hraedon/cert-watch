"""A certificate that has not changed must not alert again on the next scan.

The scheduler's daily cycle is scan then alerts. Each scan rewrites the
endpoint's inventory row under a fresh id; `evaluate_thresholds` dedups by that
id. So an unchanged certificate sitting inside its expiry window used to cross
the same threshold again every cycle and produce a new alert — and, wherever a
transport was configured, a new email every day until the cert was renewed.

These tests drive the real scan/alert order over a certificate whose bytes
never change.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.alerts import evaluate_all_certs
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.cert_ops import replace_scanned
from cert_watch.database.connection import _connect
from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

HOST = "steady.example.test"
PORT = 443


def _cert(*, fingerprint: str = "ab" * 32, days_left: int = 10) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={HOST}",
        issuer="CN=Test CA",
        san_dns_names=[HOST],
        not_before=now - timedelta(days=365 - days_left),
        not_after=now + timedelta(days=days_left),
        fingerprint_sha256=fingerprint,
        raw_der=b"steady-der",
        is_leaf=True,
    )


def _estate(tmp_path):
    db = tmp_path / "estate.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, PORT)
    return db, SqliteAlertRepository(db)


def _cycle(db, repo, cert: Certificate) -> list:
    """One scheduler cycle: the scan stores the cert, then alerts are evaluated."""
    replace_scanned(db, HOST, PORT, cert, [], True)
    return evaluate_all_certs(db, repo)


def _alert_rows(db):
    with _connect(db) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, cert_id, alert_type, threshold_days, status, created_at FROM alerts"
        )]


def test_an_unchanged_certificate_alerts_once_across_many_scans(tmp_path):
    db, repo = _estate(tmp_path)

    first = _cycle(db, repo, _cert())
    assert len(first) == 1, "the first crossing must alert"

    for _ in range(4):
        assert _cycle(db, repo, _cert()) == [], "an unchanged cert must not alert again"

    rows = _alert_rows(db)
    assert len(rows) == 1, f"one alert for one certificate, got {len(rows)}"
    assert rows[0]["threshold_days"] == 14


def test_a_delivered_alert_is_not_re_sent_on_the_next_scan(tmp_path):
    """The shape an operator actually sees: one email, not one per day."""
    db, repo = _estate(tmp_path)
    delivered = 0

    for _ in range(3):
        _cycle(db, repo, _cert())
        for alert in repo.list_pending():
            attempt = begin_attempt(db, alert.id, "smtp", {"recipients": ["ops@example.invalid"]})
            complete_attempt(db, attempt, {"outcome": "accepted"})
            repo.mark_sent(alert.id)
            delivered += 1

    assert delivered == 1, f"one unchanged certificate produced {delivered} notifications"


def test_the_carried_alert_keeps_its_original_age(tmp_path):
    """The undelivered-after-24h signal reads created_at, so a rescan must not
    reset it. Re-creating the row each cycle kept every pending alert younger
    than one scan interval, so a daily estate could never reach the threshold."""
    db, repo = _estate(tmp_path)
    _cycle(db, repo, _cert())
    original = _alert_rows(db)[0]
    old = (datetime.now(UTC) - timedelta(days=5)).isoformat()
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?", (old, original["id"]))
        conn.commit()

    _cycle(db, repo, _cert())

    rows = _alert_rows(db)
    assert len(rows) == 1
    assert rows[0]["id"] == original["id"], "the same alert, carried forward"
    assert rows[0]["created_at"] == old, "its age must survive the rescan"


def test_the_carried_alert_follows_the_certificate_row(tmp_path):
    db, repo = _estate(tmp_path)
    _cycle(db, repo, _cert())
    new_leaf, _ = replace_scanned(db, HOST, PORT, _cert(), [], True)

    rows = _alert_rows(db)
    assert len(rows) == 1
    assert rows[0]["cert_id"] == new_leaf, "the alert points at the live certificate row"
    assert repo.list_for_cert(new_leaf), "so the dedup lookup can find it"


def test_a_genuinely_renewed_certificate_may_alert_again(tmp_path):
    """The other half: a real renewal is a different certificate and must not
    inherit the old one's dedup state."""
    db, repo = _estate(tmp_path)
    assert len(_cycle(db, repo, _cert(fingerprint="ab" * 32))) == 1
    assert _cycle(db, repo, _cert(fingerprint="ab" * 32)) == []

    # A new certificate at the same endpoint, still inside the window.
    fresh = _cycle(db, repo, _cert(fingerprint="cd" * 32, days_left=10))

    assert len(fresh) == 1, "a replaced certificate alerts on its own merits"


@pytest.mark.parametrize("status", ["sent", "failed"])
def test_delivery_evidence_survives_a_rescan_of_the_same_certificate(tmp_path, status):
    """Carrying alerts forward must not disturb the append-only ledger."""
    db, repo = _estate(tmp_path)
    _cycle(db, repo, _cert())
    alert = repo.list_pending()[0]
    attempt = begin_attempt(db, alert.id, "smtp", {"recipients": ["ops@example.invalid"]})
    complete_attempt(db, attempt, {"outcome": "accepted"})
    if status == "sent":
        repo.mark_sent(alert.id)
    else:
        repo.mark_failed(alert.id, "relay refused")

    _cycle(db, repo, _cert())

    with _connect(db) as conn:
        events = [dict(r) for r in conn.execute(
            "SELECT attempt_id, event_kind FROM alert_delivery_events WHERE alert_id = ? "
            "ORDER BY id", (alert.id,),
        )]
    assert [e["event_kind"] for e in events] == ["started", "completed"]
    assert {e["attempt_id"] for e in events} == {attempt}


def test_a_failed_alert_is_retried_rather_than_duplicated(tmp_path):
    """The failed-to-pending retry keyed off the same id the rescan was
    discarding, so a failed alert was stranded and a duplicate created."""
    db, repo = _estate(tmp_path)
    _cycle(db, repo, _cert())
    alert = repo.list_pending()[0]
    attempt = begin_attempt(db, alert.id, "smtp", {"recipients": ["ops@example.invalid"]})
    complete_attempt(db, attempt, {"outcome": "failed"})
    repo.mark_failed(alert.id, "relay refused")

    produced = _cycle(db, repo, _cert())

    rows = _alert_rows(db)
    assert len(rows) == 1, "no duplicate row for a failed alert"
    assert rows[0]["id"] == alert.id
    assert rows[0]["status"] == "pending", "it is reset for retry"
    assert [a.id for a in produced] == [alert.id]
