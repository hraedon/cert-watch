"""Delivery facts are immutable observations, not current configuration previews."""

from __future__ import annotations

import json
import smtplib
import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from cert_watch.alerts import ALERT_MAX_RETRIES, AlertConfig, WebhookConfig, process_pending
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    _connect,
    init_schema,
    purge_old_alerts,
)
from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt, list_attempts


def _pending(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    alert = Alert(cert_id="synthetic-cert", alert_type="expiry_warning", status="pending",
                  message="Certificate expires within seven days", threshold_days=7,
                  subject="CN=synthetic.invalid", extra_recipients=["queued@example.invalid"])
    alert.id = repo.create(alert)
    return db, repo, alert


def _config():
    return AlertConfig(smtp_host="relay.example.invalid", smtp_user="synthetic-user",
                       smtp_password="synthetic-password", from_addr="watch@example.invalid",
                       recipients=["global@example.invalid"])


def test_process_records_actual_smtp_attempt(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    connection = Mock()
    connection.send_message.return_value = {}
    monkeypatch.setattr("cert_watch.alerts._open_smtp_connection", lambda *a, **kw: connection)

    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT * FROM alert_delivery_events WHERE alert_id = ? ORDER BY id", (alert.id,),
        ).fetchall()
    assert [row["event_kind"] for row in rows] == ["started", "completed"]
    assert json.loads(rows[0]["details"])["recipients"] == [
        "global@example.invalid", "queued@example.invalid",
    ]
    assert json.loads(rows[1]["details"])["outcome"] == "accepted"


def test_old_alert_does_not_claim_current_channels_are_delivery_evidence(
    monkeypatch, tmp_path, reload_app,
):
    _pending(tmp_path)
    monkeypatch.setenv("SMTP_HOST", "configured.example.invalid")
    monkeypatch.setenv("ALERT_FROM", "watch@example.invalid")
    monkeypatch.setenv("ALERT_RECIPIENTS", "current@example.invalid")
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")
    assert response.status_code == 200
    assert "Delivery evidence unavailable" in response.text
    assert "current@example.invalid" not in response.text


def _smtp(monkeypatch, *, refused=None, error=None):
    connection = Mock()
    connection.send_message.return_value = refused or {}
    connection.send_message.side_effect = error
    monkeypatch.setattr("cert_watch.alerts._open_smtp_connection", lambda *a, **kw: connection)
    return connection


def test_partial_smtp_refusal_records_both_sets_without_changing_retry_behavior(
    monkeypatch, tmp_path,
):
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(
        monkeypatch, refused={"queued@example.invalid": (550, b"private diagnostic")},
    )
    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    connection.send_message.assert_called_once()
    result = list_attempts(db, [alert.id])[alert.id][0]["result"]
    assert result["outcome"] == "partial"
    assert result["accepted"] == ["global@example.invalid"]
    assert result["refused"] == ["queued@example.invalid"]
    assert "private diagnostic" not in json.dumps(result)


def test_smtp_failure_then_webhook_records_separate_attempts_and_no_secrets(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    _smtp(monkeypatch, error=smtplib.SMTPAuthenticationError(
        535, b"synthetic-password Authorization=webhook-token response-body-secret",
    ))
    response = Mock(status=204)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("cert_watch.alerts.ssrf_safe_urlopen", Mock(return_value=response))
    webhook = WebhookConfig(url="https://hooks.example.invalid/secret/path?token=private",
                            headers={"Authorization": "webhook-token"})
    assert process_pending(repo, _config(), webhook) == {"sent": 1, "failed": 0, "deferred": 0}
    attempts = list_attempts(db, [alert.id])[alert.id]
    assert [item["channel"] for item in attempts] == ["generic", "smtp"]
    assert attempts[0]["result"]["http_status"] == 204
    assert attempts[1]["result"]["reason"] == "authentication"
    raw = json.dumps(attempts)
    for secret in ("synthetic-password", "webhook-token", "response-body-secret", "secret/path"):
        assert secret not in raw
    assert alert.message not in raw


def test_failed_retries_append_each_attempt(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=TimeoutError("do not retain this diagnostic"))
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 1, "deferred": 0}
    assert connection.send_message.call_count == ALERT_MAX_RETRIES
    attempts = list_attempts(db, [alert.id])[alert.id]
    assert len(attempts) == ALERT_MAX_RETRIES
    assert all(item["result"]["reason"] == "timeout" for item in attempts)
    assert len({item["attempt_id"] for item in attempts}) == ALERT_MAX_RETRIES


def test_missing_configuration_does_not_fabricate_attempts(tmp_path):
    db, repo, alert = _pending(tmp_path)
    assert process_pending(repo, None) == {"sent": 0, "failed": 0, "deferred": 0}
    assert list_attempts(db, [alert.id]) == {}


def test_start_persistence_failure_refuses_send(monkeypatch, tmp_path):
    """Refuse the send, and leave the alert deliverable.

    The database was unavailable, not the destination. Previously this counted
    as a failed delivery, which spent the retry budget on an outage that never
    touched a transport and left the alert permanently `failed` — an expiry
    alert the transport would have accepted, silently dropped.
    """
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.alert_delivery.begin_attempt", Mock(
        side_effect=sqlite3.OperationalError("synthetic-password"),
    ))
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    connection.send_message.assert_not_called()
    assert list_attempts(db, [alert.id]) == {}
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert stored.status == "pending", "a database outage must not consume the alert"
    # The alert is untouched, so no error text is persisted at all — which
    # also means the driver message (and its secret) cannot leak into it.
    assert "synthetic-password" not in (stored.error_message or "")


def test_alert_is_delivered_once_the_database_recovers(monkeypatch, tmp_path):
    """The deferred alert is still there to send on the next cycle."""
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    broken = Mock(side_effect=sqlite3.OperationalError("database is locked"))
    monkeypatch.setattr("cert_watch.alert_delivery.begin_attempt", broken)
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    connection.send_message.assert_not_called()

    monkeypatch.undo()                      # database recovers
    connection = _smtp(monkeypatch)
    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    connection.send_message.assert_called_once()
    assert repo.list_for_cert(alert.cert_id)[0].status == "sent"
    assert len(list_attempts(db, [alert.id])[alert.id]) == 1


def test_a_real_transport_failure_still_fails_the_alert(monkeypatch, tmp_path):
    """Guard the other half: deferral must not swallow genuine delivery failures."""
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    connection.send_message.side_effect = smtplib.SMTPException("mailbox unavailable")
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 1, "deferred": 0}
    assert connection.send_message.call_count == ALERT_MAX_RETRIES
    assert repo.list_for_cert(alert.cert_id)[0].status == "failed"


def test_completion_failure_is_unknown_and_does_not_resend(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.alert_delivery.complete_attempt", Mock(
        side_effect=sqlite3.OperationalError("sensitive database error"),
    ))
    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 0}
    connection.send_message.assert_called_once()
    attempts = list_attempts(db, [alert.id])[alert.id]
    assert len(attempts) == 1
    assert attempts[0]["completed_at"] is None
    assert attempts[0]["result"] is None


def test_evidence_is_immutable_and_deletes_with_parent(tmp_path):
    db, _, alert = _pending(tmp_path)
    attempt = begin_attempt(db, alert.id, "smtp", {"recipients": ["private@example.invalid"]})
    complete_attempt(db, attempt, {"outcome": "accepted"})
    with _connect(db) as conn:
        with pytest.raises(sqlite3.IntegrityError, match="cannot be edited"):
            conn.execute("UPDATE alert_delivery_events SET details = '{}' WHERE attempt_id = ?",
                         (attempt,))
        conn.execute("DELETE FROM alerts WHERE id = ?", (alert.id,))
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM alert_delivery_events").fetchone()[0] == 0


def test_alert_retention_also_purges_recipient_evidence(tmp_path):
    db, _, alert = _pending(tmp_path)
    begin_attempt(db, alert.id, "smtp", {"recipients": ["private@example.invalid"]})
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?",
                     ((datetime.now(UTC) - timedelta(days=91)).isoformat(), alert.id))
        conn.commit()
    assert purge_old_alerts(db, 90) == 1
    assert list_attempts(db, [alert.id]) == {}


def test_evidence_is_not_loaded_or_rendered_for_scoped_operator(monkeypatch, tmp_path):
    from tests.test_tag_scoped_access import _make_scoped_app, _scoped_client, _seed_two_teams

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    _seed_two_teams(db)
    begin_attempt(db, "alert-a", "smtp", {"recipients": ["private@example.invalid"]})
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    evidence = Mock(side_effect=AssertionError("Do not load recipient evidence for operators"))
    monkeypatch.setattr("cert_watch.routes.alerts_view.list_attempts", evidence)
    app, groups = _make_scoped_app(db, tmp_path, scope_tag="team-a")
    with _scoped_client(app, groups) as client:
        response = client.get("/alerts")
    assert response.status_code == 200
    assert 'data-alert-id="alert-a"' in response.text
    assert 'data-alert-id="alert-b"' not in response.text
    assert "private@example.invalid" not in response.text
    evidence.assert_not_called()


def test_group_snapshot_and_envelope_survive_configuration_edits(
    monkeypatch, tmp_path, self_signed_leaf,
):
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import SqliteAlertGroupRepository, SqliteCertificateRepository

    db, repo, alert = _pending(tmp_path)
    cert_id = SqliteCertificateRepository(db).add(parse_certificate(self_signed_leaf.der))
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET cert_id = ? WHERE id = ?", (cert_id, alert.id))
        conn.commit()
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create("Group at attempt", ["new-group@example.invalid"], [])
    groups.assign_cert(group_id, cert_id)
    config = _config()
    config.recipients = ["Global Operator <global@example.invalid>"]
    _smtp(monkeypatch)
    assert process_pending(repo, config) == {"sent": 1, "failed": 0, "deferred": 0}
    groups.update(group_id, name="Renamed afterward", recipients=["later@example.invalid"])
    config.recipients = ["later-global@example.invalid"]

    routing = list_attempts(db, [alert.id])[alert.id][0]["routing"]
    assert routing["recipients"] == ["global@example.invalid", "queued@example.invalid"]
    assert routing["global_recipients"] == ["global@example.invalid"]
    assert routing["queued_recipients"] == ["queued@example.invalid"]
    assert routing["groups"] == [{"id": group_id, "name": "Group at attempt"}]
    assert "new-group@example.invalid" not in routing["recipients"]


@pytest.mark.parametrize("completion_missing", [False, True])
def test_main_row_surfaces_partial_and_unknown_acceptance(
    monkeypatch, tmp_path, reload_app, completion_missing,
):
    _, repo, _ = _pending(tmp_path)
    _smtp(monkeypatch, refused={"queued@example.invalid": (550, b"refused")})
    if completion_missing:
        monkeypatch.setattr("cert_watch.alert_delivery.complete_attempt", Mock(
            side_effect=sqlite3.OperationalError("interrupted"),
        ))
    process_pending(repo, _config())
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")
    summary = response.text.split('<details class="cw-delivery-details"', 1)[0]
    assert ("Delivery outcome unknown" if completion_missing else "Partial acceptance") in summary
    assert "Recorded state: sent" in summary
    assert " UTC" in response.text
    assert "+00:00" not in response.text.split("Started ", 1)[1].split("</p>", 1)[0]


def test_historical_notification_uses_captured_subject(monkeypatch, tmp_path, reload_app):
    _, _, alert = _pending(tmp_path)
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")
    assert alert.subject in response.text
    assert "Historical certificate — no longer in inventory" in response.text


def test_group_snapshot_resolver_limits_resolution_to_requested_certificate(
    tmp_path, self_signed_leaf,
):
    from cert_watch.alerts import _resolve_group_config
    from cert_watch.certificate_model import parse_certificate
    from cert_watch.database import SqliteAlertGroupRepository, SqliteCertificateRepository
    from tests.conftest import _make_cert

    db, _, _ = _pending(tmp_path)
    cert_repo = SqliteCertificateRepository(db)
    first = cert_repo.add(parse_certificate(self_signed_leaf.der))
    second = cert_repo.add(parse_certificate(_make_cert("other.invalid").der))
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create("Shared group", ["operator@example.invalid"], [])
    groups.assign_cert(group_id, first)
    groups.assign_cert(group_id, second)
    full, thresholds = _resolve_group_config(db)
    assert set(full) == {first, second}
    matched = {}
    selected, selected_thresholds = _resolve_group_config(
        db, matched_groups=matched, cert_ids=(first,),
    )
    assert selected == {first: full[first]}
    assert selected_thresholds == {key: value for key, value in thresholds.items() if key == first}
    assert matched == {first: [group_id]}
    assert _resolve_group_config(db, cert_ids=()) == ({}, {})


def test_smtp_evidence_failure_still_tries_the_webhook_fallback(monkeypatch, tmp_path):
    """A refused SMTP attempt must not abandon the other channel.

    begin_attempt failures are per-statement -- typically a transient
    SQLITE_BUSY from a concurrent scan write -- so the webhook's own
    begin_attempt, microseconds later, may well succeed. Guarding the whole
    retry loop instead of each call silently removed the fallback that existed
    before evidence recording was introduced.
    """
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    response = Mock(status=204)
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    monkeypatch.setattr("cert_watch.alerts.ssrf_safe_urlopen", Mock(return_value=response))

    real_begin = begin_attempt

    def only_smtp_is_unwritable(db_path, alert_id, channel, details):
        if channel == "smtp":
            raise sqlite3.OperationalError("database is locked")
        return real_begin(db_path, alert_id, channel, details)

    monkeypatch.setattr("cert_watch.alert_delivery.begin_attempt", only_smtp_is_unwritable)
    webhook = WebhookConfig(url="https://hooks.example.invalid/path")

    assert process_pending(repo, _config(), webhook) == {"sent": 1, "failed": 0, "deferred": 0}
    connection.send_message.assert_not_called()          # SMTP was refused, not attempted
    assert [item["channel"] for item in list_attempts(db, [alert.id])[alert.id]] == ["generic"]
    assert repo.list_for_cert(alert.cert_id)[0].status == "sent"


def test_evidence_outage_mid_retry_does_not_consume_the_alert(monkeypatch, tmp_path):
    """A transport failure then a DB outage must defer, not fail.

    The terminal state has to be judged on the LAST pass. Accumulating "a
    transport was reached at some point" lets an evidence-store outage that
    began after an earlier, retryable failure mark the alert failed -- the
    database consuming an alert the relay might still have accepted, which is
    the exact invariant this path exists to hold. It also reported
    ALERT_MAX_RETRIES attempts when only one had happened.
    """
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("temporary greylist"))

    real_begin = begin_attempt
    calls = {"n": 0}

    def unwritable_after_the_first_attempt(db_path, alert_id, channel, details):
        calls["n"] += 1
        if calls["n"] > 1:
            raise sqlite3.OperationalError("database is locked")
        return real_begin(db_path, alert_id, channel, details)

    monkeypatch.setattr("cert_watch.alert_delivery.begin_attempt",
                        unwritable_after_the_first_attempt)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert connection.send_message.call_count == 1
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert stored.status == "pending", "the database outage must not consume the alert"


def test_failure_message_reports_the_attempts_that_actually_happened(monkeypatch, tmp_path):
    """The operator-visible count must not overstate what was tried."""
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("mailbox unavailable"))
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 1, "deferred": 0}
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert f"after {connection.send_message.call_count} attempts" in stored.error_message
    assert connection.send_message.call_count == ALERT_MAX_RETRIES


def test_total_deferral_stops_instead_of_sleeping_the_whole_retry_budget(monkeypatch, tmp_path):
    """A pass that reached no transport has nothing to back off from.

    Retrying inside the cycle cannot help — no destination was contacted, and
    the same unwritable database will refuse the next attempt microseconds
    later. Looping the full budget would re-pay ALERT_RETRY_DELAY on every
    cycle for as long as the outage lasts, and block the event loop for the
    duration of an operator's manual flush.
    """
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    refusals = Mock(side_effect=sqlite3.OperationalError("database is locked"))
    monkeypatch.setattr("cert_watch.alert_delivery.begin_attempt", refusals)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    connection.send_message.assert_not_called()
    assert refusals.call_count == 1, "a total deferral must not retry within the cycle"


def test_failure_message_counts_both_channels_not_the_retry_budget(monkeypatch, tmp_path):
    """Two channels over three passes is six attempts, not three.

    ALERT_MAX_RETRIES bounds the passes, not the sends. Reporting it as the
    attempt count understates a dual-channel estate by half, and is the value
    the message carried before it was derived from what actually ran.
    """
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("mailbox unavailable"))
    monkeypatch.setattr(
        "cert_watch.alerts.ssrf_safe_urlopen", Mock(side_effect=OSError("webhook unreachable")),
    )
    webhook = WebhookConfig(url="https://hooks.example.invalid/path")

    assert process_pending(repo, _config(), webhook) == {"sent": 0, "failed": 1, "deferred": 0}
    assert connection.send_message.call_count == ALERT_MAX_RETRIES
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert f"after {2 * ALERT_MAX_RETRIES} attempts" in stored.error_message
