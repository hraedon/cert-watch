"""S4 renewal verification, scheduling and alert lifecycle regressions."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.alerting.model import OutboundMessage, WebhookConfig
from cert_watch.alerting.resolve import resolve_webhook_for_renewed_cert
from cert_watch.alerting.rules.renewal_reports import evaluate_renewal_report_alerts
from cert_watch.alerting.transports.adapters import AlertmanagerAdapter, PagerDutyAdapter
from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import parse_certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.renewal_verification import evaluate_after_scan, mark_verification_blocked
from cert_watch.scheduler import (
    ScanHistory,
    _host_scan_deadlines,
    claim_hosts_due_for_scan,
    record_scan_history,
)
from cert_watch.services.renewal_reports import (
    RenewalReportInput,
    create_report,
    resolve_target,
)
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

NOW = datetime(2026, 9, 28, 12, tzinfo=UTC)
HOST = "verify.example.test"


@pytest.fixture
def estate(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(HOST, 443)
    leaf = parse_certificate(_make_cert(HOST, days_valid=60).der)
    cert_id = seed_scanned(db, HOST, 443, leaf)
    settings = Settings(db_path=db, data_dir=tmp_path)
    return db, host_id, cert_id, leaf.fingerprint_sha256, settings


def _attempt(
    estate,
    *,
    state: str = "verifying",
    received: datetime = NOW,
    not_after: datetime | None = None,
    expected: str | None = None,
) -> str:
    db, host_id, _cert_id, baseline, _settings = estate
    attempt_id = uuid.uuid4().hex
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                baseline_fingerprint,baseline_not_after,new_fingerprint,
                suppresses_stalled,received_at,next_check_at,baseline_lease_claimed)
               VALUES (?,?,1,'test',?,1,?,?,?,0,?,?,1)""",
            (
                attempt_id,
                host_id,
                state,
                baseline,
                not_after.isoformat() if not_after else None,
                expected,
                received.isoformat(),
                received.isoformat() if state in {"verifying", "not_deployed"} else None,
            ),
        )
        conn.commit()
    return attempt_id


def _row(db):
    with _connect(db) as conn:
        return conn.execute(
            "SELECT * FROM renewal_attempts WHERE is_current=1"
        ).fetchone()


@pytest.mark.parametrize(
    ("not_after", "first_offset", "raise_offset", "next_offset"),
    [
        (NOW + timedelta(days=20), timedelta(hours=1), timedelta(hours=24), timedelta(hours=24)),
        (NOW + timedelta(days=10), timedelta(hours=6), timedelta(hours=12), timedelta(hours=6)),
        (NOW + timedelta(days=2), timedelta(minutes=5), timedelta(minutes=5), timedelta(minutes=5)),
        (
            NOW - timedelta(minutes=1), timedelta(minutes=5),
            timedelta(minutes=5), timedelta(minutes=5),
        ),
        (None, timedelta(minutes=5), timedelta(minutes=5), timedelta(minutes=5)),
    ],
)
def test_verification_bands_use_fake_clock(
    estate, not_after, first_offset, raise_offset, next_offset
):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=not_after)
    evaluate_after_scan(
        db, HOST, 443, baseline, started_at=NOW, settings=settings
    )
    first = _row(db)
    assert first["state"] == "verifying"
    assert datetime.fromisoformat(first["next_check_at"]) == NOW + next_offset
    evaluate_after_scan(
        db, HOST, 443, baseline, started_at=NOW + first_offset, settings=settings
    )
    before_raise = _row(db)
    if first_offset < raise_offset:
        assert before_raise["state"] == "verifying"
        evaluate_after_scan(
            db, HOST, 443, baseline, started_at=NOW + raise_offset, settings=settings
        )
    raised = _row(db)
    assert raised["state"] == "not_deployed"
    assert datetime.fromisoformat(raised["next_check_at"]) > NOW + raise_offset


def test_grace_boundary_and_async_deploy_do_not_false_alarm(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=2))
    evaluate_after_scan(
        db, HOST, 443, baseline, started_at=NOW + timedelta(minutes=4, seconds=59),
        settings=settings,
    )
    assert _row(db)["state"] == "verifying"
    evaluate_after_scan(
        db, HOST, 443, "f" * 64, started_at=NOW + timedelta(minutes=5),
        settings=settings,
    )
    assert _row(db)["state"] == "verified"


def test_successful_checks_are_spaced_five_minutes(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=10))
    evaluate_after_scan(db, HOST, 443, baseline, started_at=NOW, settings=settings)
    evaluate_after_scan(
        db, HOST, 443, baseline, started_at=NOW + timedelta(minutes=4),
        settings=settings,
    )
    row = _row(db)
    assert row["checks_done"] == 1
    assert row["last_check_at"] == NOW.isoformat()


def test_scan_failure_is_not_a_check_and_reschedules_by_band(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=10))
    mark_verification_blocked(
        db, HOST, 443, started_at=NOW + timedelta(hours=1), settings=settings
    )
    row = _row(db)
    assert (row["state"], row["checks_done"]) == ("verifying", 0)
    assert row["verification_blocked_at"] == (NOW + timedelta(hours=1)).isoformat()
    assert datetime.fromisoformat(row["next_check_at"]) == NOW + timedelta(hours=7)


def test_immediate_check_verifies_fast_deploy_and_flapping_does_not_reopen(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    successor = "e" * 64
    _attempt(estate, not_after=NOW + timedelta(days=2), expected=successor)
    evaluate_after_scan(db, HOST, 443, successor, started_at=NOW, settings=settings)
    assert _row(db)["state"] == "verified"
    evaluate_after_scan(db, HOST, 443, estate[3], started_at=NOW, settings=settings)
    assert _row(db)["state"] == "verified"


def test_different_successor_is_mismatch(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, expected="e" * 64, not_after=NOW + timedelta(days=20))
    evaluate_after_scan(db, HOST, 443, "d" * 64, started_at=NOW, settings=settings)
    row = _row(db)
    assert (row["state"], row["verification_reason"]) == ("not_deployed", "mismatch")


def test_open_attempt_is_verified_by_observed_successor(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, state="open", not_after=NOW + timedelta(days=20))
    evaluate_after_scan(db, HOST, 443, "d" * 64, started_at=NOW, settings=settings)
    assert (_row(db)["state"], _row(db)["closed_reason"]) == (
        "verified", "observed_successor"
    )


def test_report_storm_keeps_one_immediate_pending_check(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    attempts = set()
    for index in range(4):
        result, _ = create_report(
            db, settings, target,
            RenewalReportInput("succeeded", None, "tool", None, None, None),
            auth=auth, actor="api_key:key", source_ip=None, idempotency_key=None,
            body_sha256=str(index), now=NOW + timedelta(seconds=index),
        )
        attempts.add(result.attempt_id)
    assert len(attempts) == 1
    row = _row(db)
    assert row["next_check_at"] == NOW.isoformat()


def test_long_custom_cadence_is_capped_by_24_hour_verification(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET scan_interval_hours=168 WHERE id=?", (host_id,))
        conn.commit()
    record_scan_history(db, ScanHistory(HOST, 443, "success", scanned_at=NOW))
    _attempt(estate, not_after=NOW + timedelta(days=20))
    with _connect(db) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET next_check_at=? WHERE is_current=1",
            ((NOW + timedelta(hours=24)).isoformat(),),
        )
        conn.commit()
    [deadline] = _host_scan_deadlines(db, 6, 0, NOW)
    assert deadline[2] == NOW + timedelta(hours=24)


def test_cross_process_claims_prevent_double_scan(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=2))
    first = claim_hosts_due_for_scan(db, owner="worker-a", now=NOW)
    second = claim_hosts_due_for_scan(db, owner="worker-b", now=NOW)
    assert first == [(HOST, 443)]
    assert second == []


def test_alert_open_close_and_provider_incident_keys(estate, monkeypatch):
    db, _host_id, cert_id, _baseline, _settings = estate
    attempt_id = _attempt(
        estate, state="not_deployed", not_after=NOW + timedelta(days=2)
    )
    repo = SqliteAlertRepository(db)
    [created] = evaluate_renewal_report_alerts(db, repo, base_url="https://certs.example.test")
    assert created.trigger_cert_id == cert_id
    assert created.threshold_days is None
    assert attempt_id in (created.dedupe_key or "")
    assert "tool" not in created.message
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET status='sent' WHERE id=?", (created.id,))
        conn.execute(
            "UPDATE renewal_attempts SET state='verified' WHERE attempt_id=?",
            (attempt_id,),
        )
        conn.commit()
    closed: list = []
    evaluate_renewal_report_alerts(db, repo, closed_sent=closed)
    assert [item.id for item in closed] == [created.id]

    msg = OutboundMessage.from_alert(created)
    pd = json.loads(PagerDutyAdapter().build(
        msg, WebhookConfig("https://events.example.test", kind="pagerduty", routing_key="rk")
    ).body)
    pd_resolve = json.loads(PagerDutyAdapter().build_resolve(
        cert_id, created.alert_type, None,
        WebhookConfig("https://events.example.test", kind="pagerduty", routing_key="rk"),
        incident_key=created.dedupe_key or "",
    ).body)
    assert pd["dedup_key"] == pd_resolve["dedup_key"] == created.dedupe_key

    am = json.loads(AlertmanagerAdapter().build(
        msg, WebhookConfig("https://alerts.example.test", kind="alertmanager")
    ).body)
    am_resolve = json.loads(AlertmanagerAdapter().build_resolve(
        cert_id, created.alert_type, None,
        WebhookConfig("https://alerts.example.test", kind="alertmanager"),
        incident_key=created.dedupe_key or "",
    ).body)
    assert am["alerts"][0]["labels"]["cert_watch_dedupe_key"] == created.dedupe_key
    assert am_resolve["alerts"][0]["labels"]["cert_watch_dedupe_key"] == created.dedupe_key

    delivered: list[dict] = []

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def send(_url, *, data, **_kwargs):
        delivered.append(json.loads(data))
        return Response()

    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", send
    )
    assert resolve_webhook_for_renewed_cert(
        db,
        cert_id,
        WebhookConfig(
            "https://events.example.test", kind="pagerduty", routing_key="rk"
        ),
        pending_alerts=closed,
    ) == 1
    assert delivered[-1]["dedup_key"] == created.dedupe_key
    assert resolve_webhook_for_renewed_cert(
        db,
        cert_id,
        WebhookConfig("https://alerts.example.test", kind="alertmanager"),
        pending_alerts=closed,
    ) == 1
    assert (
        delivered[-1]["alerts"][0]["labels"]["cert_watch_dedupe_key"]
        == created.dedupe_key
    )
