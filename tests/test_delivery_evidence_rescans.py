"""Routine rescans retain delivery history without keeping obsolete work queued."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    SqliteHostRepository,
    _connect,
    init_schema,
    list_alerts_with_subject,
    purge_old_alerts,
    replace_scanned,
)
from cert_watch.database.delivery_evidence import (
    begin_attempt,
    complete_attempt,
    latest_outcomes,
    list_attempts,
)

HOSTNAME = "rescan.example.invalid"


def _certificate(*, changed=False):
    return Certificate(
        subject="CN=replacement.example.invalid" if changed else "CN=original.example.invalid",
        issuer="CN=Synthetic issuer",
        not_before=datetime(2026, 1, 1, tzinfo=UTC),
        not_after=datetime(2027, 1, 1, tzinfo=UTC),
        fingerprint_sha256=("b" if changed else "a") * 64,
    )


def _estate(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOSTNAME, tags="team-a")
    cert_id, _ = replace_scanned(db, HOSTNAME, 443, _certificate(), [], True)
    return db, SqliteAlertRepository(db), cert_id


def _alert(repo, cert_id, *, status="sent", subject="CN=original.example.invalid", old=False):
    return repo.create(Alert(
        cert_id=cert_id,
        alert_type="expiry_warning",
        status=status,
        message="Original certificate expiry notification",
        threshold_days=7,
        hostname=HOSTNAME,
        subject=subject,
        created_at=datetime.now(UTC) - timedelta(days=91 if old else 0),
    ))


def _evidence(db, alert_id, outcome="accepted"):
    attempt_id = begin_attempt(db, alert_id, "smtp", {
        "recipients": ["original-recipient@example.invalid"],
        "groups": [{"id": "original-group", "name": "Original group"}],
    })
    if outcome is not None:
        complete_attempt(db, attempt_id, {"outcome": outcome})
    return attempt_id


def _stored_rows(db, alert_id):
    """Include IDs, timestamps and raw JSON so a re-created snapshot cannot pass."""
    with _connect(db) as conn:
        alert = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        events = conn.execute(
            "SELECT * FROM alert_delivery_events WHERE alert_id = ? ORDER BY id", (alert_id,),
        ).fetchall()
    return dict(alert) if alert is not None else None, [dict(event) for event in events]


@pytest.mark.parametrize("changed", [False, True], ids=["identical-cert", "changed-cert"])
@pytest.mark.parametrize("status,outcome", [
    ("sent", "accepted"), ("sent", "partial"), ("failed", "failed"), ("sent", None),
])
def test_rescan_preserves_original_alert_and_exact_delivery_evidence(
    tmp_path, changed, status, outcome,
):
    db, repo, cert_id = _estate(tmp_path)
    alert_id = _alert(repo, cert_id, status=status)
    _evidence(db, alert_id, outcome)
    original = _stored_rows(db, alert_id)

    new_id, replaced_id = replace_scanned(
        db, HOSTNAME, 443, _certificate(changed=changed), [], True,
    )

    assert replaced_id == cert_id and new_id != cert_id
    assert _stored_rows(db, alert_id) == original
    with _connect(db) as conn:
        assert conn.execute("SELECT id FROM certificates WHERE id = ?", (cert_id,)).fetchone() \
            is None
    assert repo.list_for_cert(new_id) == []
    assert repo.list_pending() == []
    assert latest_outcomes(db, [alert_id]) == {alert_id: outcome or "unknown"}


def test_rescan_removes_pending_and_legacy_alerts_but_leaves_other_port_untouched(tmp_path):
    db, repo, cert_id = _estate(tmp_path)
    pending = _alert(repo, cert_id, status="pending")
    # A crash can leave a start observation before the pending status is finalized.
    _evidence(db, pending, None)
    legacy = [_alert(repo, cert_id, status=status) for status in ("pending", "sent", "failed")]
    other_cert_id, _ = replace_scanned(db, HOSTNAME, 8443, _certificate(), [], True)
    other_pending = _alert(repo, other_cert_id, status="pending")
    other_sent = _alert(repo, other_cert_id)
    _evidence(db, other_sent)
    other_original = {item: _stored_rows(db, item) for item in (other_pending, other_sent)}

    replace_scanned(db, HOSTNAME, 443, _certificate(changed=True), [], True)

    for deleted in [pending, *legacy]:
        assert _stored_rows(db, deleted) == (None, [])
    assert {item: _stored_rows(db, item) for item in other_original} == other_original
    assert [item.id for item in repo.list_pending()] == [other_pending]
    with _connect(db) as conn:
        assert conn.execute("SELECT port FROM certificates WHERE id = ?", (other_cert_id,)) \
            .fetchone()["port"] == 8443


def test_rescan_preserves_chain_alerts_as_historical_without_reparenting(tmp_path):
    db, repo, _ = _estate(tmp_path)
    cert_id, _ = replace_scanned(db, HOSTNAME, 443, _certificate(), [_certificate()], True)
    with _connect(db) as conn:
        chain_id = conn.execute(
            "SELECT id FROM certificates WHERE parent_cert_id = ?", (cert_id,),
        ).fetchone()["id"]
    alert_id = _alert(repo, chain_id)
    _evidence(db, alert_id)
    original = _stored_rows(db, alert_id)

    replace_scanned(db, HOSTNAME, 443, _certificate(), [_certificate()], True)

    assert _stored_rows(db, alert_id) == original
    with _connect(db) as conn:
        assert conn.execute("SELECT id FROM certificates WHERE id = ?", (chain_id,)).fetchone() \
            is None


@pytest.mark.parametrize("limit", [0, 25], ids=["unpaged", "paged"])
@pytest.mark.parametrize("subject", ["CN=original.example.invalid", ""])
def test_historical_alert_uses_snapshot_and_does_not_inherit_current_host_scope(
    tmp_path, limit, subject,
):
    db, repo, cert_id = _estate(tmp_path)
    alert_id = _alert(repo, cert_id, subject=subject)
    _evidence(db, alert_id)
    assert [item["id"] for item in list_alerts_with_subject(db, scope_tags=("team-a",))] \
        == [alert_id]

    replace_scanned(db, HOSTNAME, 443, _certificate(changed=True), [], True)

    rows = list_alerts_with_subject(db, limit=limit)
    assert len(rows) == 1
    assert rows[0]["id"] == alert_id
    assert rows[0]["cert_id"] == cert_id
    assert rows[0]["subject"] == (subject or HOSTNAME)
    assert rows[0]["historical_cert"]
    # The current same-host deployment is not proof of the removed cert's authorization.
    assert list_alerts_with_subject(db, limit=limit, scope_tags=("team-a",)) == []


def test_retention_purge_still_cascades_for_historical_delivery_evidence(tmp_path):
    db, repo, cert_id = _estate(tmp_path)
    old_alert = _alert(repo, cert_id, old=True)
    recent_alert = _alert(repo, cert_id)
    for alert_id in (old_alert, recent_alert):
        _evidence(db, alert_id)
    recent_original = _stored_rows(db, recent_alert)
    replace_scanned(db, HOSTNAME, 443, _certificate(), [], True)
    assert set(list_attempts(db, [old_alert, recent_alert])) == {old_alert, recent_alert}

    assert purge_old_alerts(db, 0) == 0
    assert purge_old_alerts(db, 90) == 1

    assert _stored_rows(db, old_alert) == (None, [])
    assert _stored_rows(db, recent_alert) == recent_original
