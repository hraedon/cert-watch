"""Delivery facts are immutable observations, not current configuration previews."""

from __future__ import annotations

import json
import smtplib
import sqlite3
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock

import pytest
from starlette.testclient import TestClient

from cert_watch.alerts import (
    ALERT_MAX_RETRIES,
    EVIDENCE_DEFERRAL_GIVE_UP_HOURS,
    UNDELIVERED_AFTER_HOURS,
    AlertConfig,
    WebhookConfig,
    process_pending,
)
from cert_watch.database import (
    Alert,
    SqliteAlertRepository,
    _connect,
    init_schema,
    purge_old_alerts,
)
from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt, list_attempts
from cert_watch.database.pagination import UNDELIVERED_RETENTION_MULTIPLIER


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
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", lambda *a, **kw: connection
    )

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
    monkeypatch.setattr(
        "cert_watch.alerting.transports.smtp._open_smtp_connection", lambda *a, **kw: connection
    )
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
    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", Mock(return_value=response)
    )
    webhook = WebhookConfig(url="https://hooks.example.invalid/secret/path?token=private",
                            headers={"Authorization": "webhook-token"})
    assert process_pending(repo, _config(), webhook) == {"sent": 1, "failed": 0, "deferred": 0}
    attempts = list_attempts(db, [alert.id])[alert.id]
    assert [item["channel"] for item in attempts] == ["webhook:generic", "smtp"]
    assert attempts[0]["result"]["http_status"] == 204
    assert attempts[1]["result"]["reason"] == "authentication"
    raw = json.dumps(attempts)
    for secret in ("synthetic-password", "webhook-token", "response-body-secret", "secret/path"):
        assert secret not in raw
    assert alert.message not in raw


def test_failed_round_appends_each_attempt_before_backoff(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=TimeoutError("do not retain this diagnostic"))
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
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
    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt", Mock(
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
    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt", broken)
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    connection.send_message.assert_not_called()

    monkeypatch.undo()                      # database recovers
    connection = _smtp(monkeypatch)
    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    connection.send_message.assert_called_once()
    assert repo.list_for_cert(alert.cert_id)[0].status == "sent"
    assert len(list_attempts(db, [alert.id])[alert.id]) == 1


def test_a_real_transport_failure_schedules_backoff(monkeypatch, tmp_path):
    """A genuine delivery failure spends attempts and schedules another round."""
    _db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    connection.send_message.side_effect = smtplib.SMTPException("mailbox unavailable")
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert connection.send_message.call_count == ALERT_MAX_RETRIES
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert stored.status == "pending"
    assert stored.attempt_count == ALERT_MAX_RETRIES
    assert stored.next_attempt_at is not None


def test_completion_failure_is_unknown_and_does_not_resend(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    monkeypatch.setattr("cert_watch.alerting.evidence.complete_attempt", Mock(
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
        # The alert is still pending, so it is retained on the longer
        # undelivered horizon (#39); age it past that to exercise the cascade.
        undelivered_horizon = 90 * UNDELIVERED_RETENTION_MULTIPLIER
        conn.execute(
            "UPDATE alerts SET created_at = ? WHERE id = ?",
            ((datetime.now(UTC) - timedelta(days=undelivered_horizon + 1)).isoformat(), alert.id),
        )
        conn.commit()
    assert purge_old_alerts(db, 90) == 1
    assert list_attempts(db, [alert.id]) == {}


def test_undelivered_alert_and_its_evidence_outlive_the_delivered_window(tmp_path):
    """Evidence that an alert never reached anyone must not expire on the
    delivered-alert schedule (#39). Here the attempt was started and never
    completed: the alert is still pending and its ledger row is the record."""
    db, repo, alert = _pending(tmp_path)
    begin_attempt(db, alert.id, "smtp", {"recipients": ["private@example.invalid"]})
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?",
                     ((datetime.now(UTC) - timedelta(days=91)).isoformat(), alert.id))
        conn.commit()
    assert purge_old_alerts(db, 90) == 0
    assert [a.id for a in repo.list_pending()] == [alert.id]
    assert len(list_attempts(db, [alert.id])[alert.id]) == 1


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
        monkeypatch.setattr("cert_watch.alerting.evidence.complete_attempt", Mock(
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
    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", Mock(return_value=response)
    )

    real_begin = begin_attempt

    def only_smtp_is_unwritable(db_path, alert_id, channel, details):
        if channel == "smtp":
            raise sqlite3.OperationalError("database is locked")
        return real_begin(db_path, alert_id, channel, details)

    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt", only_smtp_is_unwritable)
    webhook = WebhookConfig(url="https://hooks.example.invalid/path")

    assert process_pending(repo, _config(), webhook) == {"sent": 1, "failed": 0, "deferred": 0}
    connection.send_message.assert_not_called()          # SMTP was refused, not attempted
    assert [item["channel"] for item in list_attempts(db, [alert.id])[alert.id]] == [
        "webhook:generic"
    ]
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
    _db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("temporary greylist"))

    real_begin = begin_attempt
    calls = {"n": 0}

    def unwritable_after_the_first_attempt(db_path, alert_id, channel, details):
        calls["n"] += 1
        if calls["n"] > 1:
            raise sqlite3.OperationalError("database is locked")
        return real_begin(db_path, alert_id, channel, details)

    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt",
                        unwritable_after_the_first_attempt)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert connection.send_message.call_count == 1
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert stored.status == "pending", "the database outage must not consume the alert"


def test_failure_message_reports_the_attempts_that_actually_happened(monkeypatch, tmp_path):
    """The operator-visible count must not overstate what was tried."""
    _db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("mailbox unavailable"))
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
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
    _db, repo, _alert = _pending(tmp_path)
    connection = _smtp(monkeypatch)
    refusals = Mock(side_effect=sqlite3.OperationalError("database is locked"))
    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt", refusals)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    connection.send_message.assert_not_called()
    assert refusals.call_count == 1, "a total deferral must not retry within the cycle"


def test_failure_message_counts_both_channels_not_the_retry_budget(monkeypatch, tmp_path):
    """Two channels over three passes is six attempts, not three.

    ALERT_MAX_RETRIES bounds the passes, not the sends. Reporting it as the
    attempt count understates a dual-channel estate by half, and is the value
    the message carried before it was derived from what actually ran.
    """
    _db, repo, alert = _pending(tmp_path)
    connection = _smtp(monkeypatch, error=smtplib.SMTPException("mailbox unavailable"))
    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen",
        Mock(side_effect=OSError("webhook unreachable")),
    )
    webhook = WebhookConfig(url="https://hooks.example.invalid/path")

    assert process_pending(repo, _config(), webhook) == {"sent": 0, "failed": 0, "deferred": 1}
    assert connection.send_message.call_count == ALERT_MAX_RETRIES
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert f"after {2 * ALERT_MAX_RETRIES} attempts" in stored.error_message


def test_empty_webhook_diagnostic_does_not_erase_smtp_failure(monkeypatch, tmp_path):
    from cert_watch.alerting.dispatch import _attempt_once, _Delivery
    from cert_watch.alerting.model import SendResult

    _db, _repo, alert = _pending(tmp_path)
    results = Mock(side_effect=[
        SendResult("failed", "transport", operator_message="SMTP relay refused"),
        SendResult("failed", "http_rejected", http_status=200),
    ])
    monkeypatch.setattr("cert_watch.alerting.dispatch.attempt_delivery", results)
    item = _Delivery(alert)

    _attempt_once(
        item,
        evidence_db=None,
        config=_config(),
        webhook_config=WebhookConfig(
            url="https://events.pagerduty.com/v2/enqueue",
            kind="pagerduty",
            routing_key="routing-key",
        ),
    )

    assert item.last_error == "SMTP relay refused"


def test_activity_labels_new_and_legacy_delivery_channels(
    monkeypatch, tmp_path, reload_app,
):
    import re

    db, _repo, alert = _pending(tmp_path)
    channels = ["smtp", "webhook", "webhook:unknown", "future-channel"]
    kinds = ("generic", "slack", "discord", "teams", "pagerduty", "alertmanager")
    channels.extend(kinds)
    channels.extend(f"webhook:{kind}" for kind in kinds)
    for channel in channels:
        begin_attempt(db, alert.id, channel, {})

    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    labels = re.findall(r"<strong>([^<]+)</strong>", response.text)
    expected = {
        "Email (SMTP)": 1,
        "Webhook (unspecified)": 1,
        "Webhook (unknown kind)": 1,
        "Delivery channel": 1,
        "Webhook": 2,
        "Slack webhook": 2,
        "Discord webhook": 2,
        "Teams webhook": 2,
        "PagerDuty webhook": 2,
        "Alertmanager webhook": 2,
    }
    for label, count in expected.items():
        assert labels.count(label) == count


def _age_alert(db, alert_id, *, hours):
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET created_at = ? WHERE id = ?",
            ((datetime.now(UTC) - timedelta(hours=hours)).isoformat(), alert_id),
        )
        conn.commit()


# ---------- the deferral clock and its bound (#38, migration 0033) ----------


def _deferred_since(db, alert_id):
    with _connect(db) as conn:
        return conn.execute(
            "SELECT deferred_since FROM alerts WHERE id = ?", (alert_id,),
        ).fetchone()[0]


def _stamp_deferred_since(db, alert_id, *, hours_ago):
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET deferred_since = ? WHERE id = ?",
            ((datetime.now(UTC) - timedelta(hours=hours_ago)).isoformat(), alert_id),
        )
        conn.commit()


def _unwritable_evidence_store(monkeypatch):
    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt", Mock(
        side_effect=sqlite3.OperationalError("database is locked"),
    ))


def test_first_deferral_stamps_the_alert_and_later_ones_keep_the_stamp(monkeypatch, tmp_path):
    """``deferred_since`` is the start of the outage, not the latest cycle."""
    db, repo, alert = _pending(tmp_path)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)
    assert _deferred_since(db, alert.id) is None

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    first = _deferred_since(db, alert.id)
    assert first is not None
    assert datetime.now(UTC) - datetime.fromisoformat(first) < timedelta(minutes=1)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert _deferred_since(db, alert.id) == first
    assert repo.list_for_cert(alert.cert_id)[0].status == "pending"


def test_an_old_alert_deferred_once_is_not_failed(monkeypatch, tmp_path):
    """The bound runs on the deferral clock, never on ``created_at``.

    ``evaluate_all_certs`` resets a failed alert to pending with its original
    ``created_at``, so an age-based bound would fail an old alert on its first
    millisecond-long lock and then flip-flop forever -- the implementation #36
    tried and reverted (#38).
    """
    db, repo, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=10 * 24)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert repo.list_for_cert(alert.cert_id)[0].status == "pending"


def test_a_deferral_past_the_bound_fails_with_an_honest_message(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    _stamp_deferred_since(db, alert.id, hours_ago=EVIDENCE_DEFERRAL_GIVE_UP_HOURS + 1)
    connection = _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 1, "deferred": 0}
    connection.send_message.assert_not_called()
    stored = repo.list_for_cert(alert.cert_id)[0]
    assert stored.status == "failed"
    assert "delivery evidence could not be recorded since" in stored.error_message
    # The stamp was one hour past the bound, and the message reports the real age.
    assert f"({EVIDENCE_DEFERRAL_GIVE_UP_HOURS + 1}h)" in stored.error_message
    assert "database is locked" not in stored.error_message
    assert stored.deferred_since is None


def test_a_deferral_inside_the_bound_stays_pending(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    _stamp_deferred_since(db, alert.id, hours_ago=EVIDENCE_DEFERRAL_GIVE_UP_HOURS - 1)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert repo.list_for_cert(alert.cert_id)[0].status == "pending"


def test_a_refused_give_up_write_does_not_abort_the_cycle(monkeypatch, tmp_path):
    """The give-up UPDATE goes to the database that just refused a write.

    When it is refused too, the alert stays pending (it already is) and the
    cycle carries on to the next alert; #36's first attempt let that UPDATE
    raise, which skipped every later alert and made a manual flush 500 (#38).
    """
    db, repo, first = _pending(tmp_path)
    second = Alert(cert_id="other-cert", alert_type="expiry_warning", status="pending",
                   message="Certificate expires within seven days", threshold_days=7,
                   subject="CN=other.invalid", extra_recipients=["queued@example.invalid"])
    second.id = repo.create(second)
    for alert_id in (first.id, second.id):
        _stamp_deferred_since(db, alert_id, hours_ago=EVIDENCE_DEFERRAL_GIVE_UP_HOURS + 1)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)

    real_mark_failed = SqliteAlertRepository.mark_failed
    refusals = {"n": 0}

    def refuse_the_first_failure_write(self, alert_id, error_message):
        refusals["n"] += 1
        if refusals["n"] == 1:
            raise sqlite3.OperationalError("disk I/O error")
        return real_mark_failed(self, alert_id, error_message)

    monkeypatch.setattr(SqliteAlertRepository, "mark_failed", refuse_the_first_failure_write)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 1, "deferred": 1}
    statuses = sorted(
        a.status for a in repo.list_for_cert(first.cert_id) + repo.list_for_cert(second.cert_id)
    )
    assert statuses == ["failed", "pending"]


def test_a_refused_deferral_stamp_is_tolerated(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)
    monkeypatch.setattr(SqliteAlertRepository, "note_deferral", Mock(
        side_effect=sqlite3.OperationalError("attempt to write a readonly database"),
    ))

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert repo.list_for_cert(alert.cert_id)[0].status == "pending"
    assert _deferred_since(db, alert.id) is None


def test_an_attempt_recorded_this_cycle_restarts_the_deferral_clock(monkeypatch, tmp_path):
    """A transport was reached, then the store became unwritable mid-retry.

    The store was provably writable this cycle, so an old stamp cannot mean
    the outage has lasted since then; the clock restarts instead of failing
    the alert on stale evidence.
    """
    db, repo, alert = _pending(tmp_path)
    _stamp_deferred_since(db, alert.id, hours_ago=EVIDENCE_DEFERRAL_GIVE_UP_HOURS + 10)
    _smtp(monkeypatch, error=smtplib.SMTPException("temporary greylist"))
    real_begin = begin_attempt
    calls = {"n": 0}

    def unwritable_after_the_first_attempt(db_path, alert_id, channel, details):
        calls["n"] += 1
        if calls["n"] > 1:
            raise sqlite3.OperationalError("database is locked")
        return real_begin(db_path, alert_id, channel, details)

    monkeypatch.setattr("cert_watch.alerting.evidence.begin_attempt",
                        unwritable_after_the_first_attempt)

    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    stamped = _deferred_since(db, alert.id)
    assert datetime.now(UTC) - datetime.fromisoformat(stamped) < timedelta(minutes=1)


def test_delivery_and_status_changes_clear_the_deferral_clock(monkeypatch, tmp_path):
    db, repo, alert = _pending(tmp_path)
    _smtp(monkeypatch)
    _unwritable_evidence_store(monkeypatch)
    assert process_pending(repo, _config()) == {"sent": 0, "failed": 0, "deferred": 1}
    assert _deferred_since(db, alert.id) is not None

    monkeypatch.undo()                      # database recovers
    _smtp(monkeypatch)
    assert process_pending(repo, _config()) == {"sent": 1, "failed": 0, "deferred": 0}
    assert _deferred_since(db, alert.id) is None

    repo.note_deferral(alert.id, datetime.now(UTC))     # ignored: not pending
    assert _deferred_since(db, alert.id) is None
    repo.reset_to_pending(alert.id)
    repo.note_deferral(alert.id, datetime.now(UTC))
    assert _deferred_since(db, alert.id) is not None
    repo.mark_failed(alert.id, "relay refused")
    assert _deferred_since(db, alert.id) is None
    repo.reset_to_pending(alert.id)
    assert _deferred_since(db, alert.id) is None
    assert repo.list_pending()[0].deferred_since is None


def test_activity_marks_a_queued_alert_that_missed_its_cycle(monkeypatch, tmp_path, reload_app):
    """A deferral has no attempt row, so only its age distinguishes it.

    ``process_pending`` defers when the database refuses a write, which is
    exactly when a reason cannot be persisted on the alert — the store that
    would hold it is the one that is down. Age is read, not written, and it
    catches a scheduler that has simply stopped flushing too.

    A transport is configured because the chip claims the alert is *late*, and
    only an estate that sends has a cycle to be late for.
    """
    db, _, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=UNDELIVERED_AFTER_HOURS + 1)
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app(SMTP_HOST="relay.example.invalid").app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Not yet delivered" in response.text
    assert "Still queued past the cycle that should have sent it." in response.text


def test_activity_marks_an_abandoned_sending_lease_as_undelivered(
    monkeypatch, tmp_path, reload_app
):
    db, _, alert = _pending(tmp_path)
    from cert_watch.database import AlertStore

    now = datetime.now(UTC)
    AlertStore(db).claim(
        lease_owner="dead-worker",
        lease_expires_at=now - timedelta(minutes=1),
        now=now - timedelta(minutes=2),
    )
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app(SMTP_HOST="relay.example.invalid").app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Sending" in response.text
    assert "Not yet delivered" in response.text
    assert f'data-alert-id="{alert.id}"' in response.text


def test_activity_does_not_call_a_queued_alert_late_when_nothing_sends(
    monkeypatch, tmp_path, reload_app,
):
    """With no transport there is no cycle, so the alert is queued, not late.

    ``process_pending`` returns before doing anything when neither SMTP nor a
    webhook is set, so these alerts stay pending for ever by design. Telling
    the operator they are "past the cycle that should have sent it" describes
    an outage that is not happening; the tab says once that nothing is
    configured to send them instead.
    """
    db, _, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=UNDELIVERED_AFTER_HOURS * 30)
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")
        health = client.get("/api/health").json()

    assert response.status_code == 200
    assert "Not yet delivered" not in response.text
    assert "Recorded: pending" in response.text
    assert 'data-testid="alerts-no-delivery"' in response.text
    assert health["undelivered_alerts"] == 0
    assert health["alert_delivery_configured"] is False


def test_activity_does_not_alarm_over_a_freshly_queued_alert(monkeypatch, tmp_path, reload_app):
    """Every pending alert is briefly undelivered; saying so on all of them is noise."""
    db, _, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=1)
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Not yet delivered" not in response.text
    assert "Recorded: pending" in response.text


def test_activity_does_not_relabel_an_alert_that_already_reached_a_transport(
    monkeypatch, tmp_path, reload_app,
):
    """A failed alert is not undelivered-and-waiting: it is finished, and failed."""
    db, repo, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=UNDELIVERED_AFTER_HOURS + 1)
    attempt_id = begin_attempt(db, alert.id, "smtp", {"recipients": ["queued@example.invalid"]})
    complete_attempt(db, attempt_id, {"outcome": "failed"})
    repo.mark_failed(alert.id, "relay refused")
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Not yet delivered" not in response.text
    assert "Attempt failed" in response.text


def test_activity_reports_both_the_attempt_outcome_and_that_nothing_arrived(
    monkeypatch, tmp_path, reload_app,
):
    """An interrupted attempt leaves an alert both `unknown` and still queued.

    The two chips answer different questions — what the transport said, and
    whether the alert has gone out — so one must not suppress the other. An
    outcome of `unknown` reassuring an operator about an alert that is in fact
    still sitting in the queue is the failure this guards.
    """
    db, _, alert = _pending(tmp_path)
    _age_alert(db, alert.id, hours=UNDELIVERED_AFTER_HOURS + 1)
    # Started, never completed: the process died mid-send. The alert stays pending.
    begin_attempt(db, alert.id, "smtp", {"recipients": ["queued@example.invalid"]})
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app(SMTP_HOST="relay.example.invalid").app) as client:
        response = client.get("/alerts")

    assert response.status_code == 200
    assert "Delivery outcome unknown" in response.text
    assert "Not yet delivered" in response.text


def test_an_unreadable_timestamp_does_not_manufacture_an_undelivered_alert(
    monkeypatch, tmp_path, reload_app,
):
    """A row whose age cannot be read is not evidence of anything.

    Both surfaces must agree on that, and they reach it independently — the
    view parses the timestamp, the health check compares it as a SQL string.
    A row that one treats as overdue and the other ignores would leave an
    operator with a banner and no matching alert, or an alert and a green
    banner, with nothing to reconcile them.
    """
    db, _, alert = _pending(tmp_path)
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET created_at = ? WHERE id = ?", ("not-a-date", alert.id))
        conn.commit()
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    # SMTP is set so this exercises the timestamp path, not the no-transport one.
    with TestClient(reload_app(SMTP_HOST="relay.example.invalid").app) as client:
        page = client.get("/alerts")
        health = client.get("/api/health").json()

    assert "Not yet delivered" not in page.text
    assert health["undelivered_alerts"] == 0


def test_alerts_page_renders_warning_and_error_flash(monkeypatch, reload_app):
    """The flush route reports "delivery already in progress" and failures as
    ?warning= / ?error=; the page must show them rather than drop them."""
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        warned = client.get("/alerts", params={"warning": "Alert delivery already in progress"})
        errored = client.get("/alerts", params={"error": "rate limited"})
    assert 'id="cw-flash-warn"' in warned.text
    assert "Alert delivery already in progress" in warned.text
    assert 'id="cw-flash-error"' in errored.text
