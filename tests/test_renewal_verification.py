"""S4 renewal verification, scheduling and alert lifecycle regressions."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import pytest
from freezegun import freeze_time

from cert_watch.alerting.model import OutboundMessage, WebhookConfig
from cert_watch.alerting.resolve import resolve_webhook_for_renewed_cert
from cert_watch.alerting.rules.renewal_reports import evaluate_renewal_report_alerts
from cert_watch.alerting.transports.adapters import AlertmanagerAdapter, PagerDutyAdapter
from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import parse_certificate
from cert_watch.config import Settings
from cert_watch.database import Alert, SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.renewal_verification import evaluate_after_scan, mark_verification_blocked
from cert_watch.scan import ScannedEntry, store_scanned
from cert_watch.scheduler import (
    ScanHistory,
    Scheduler,
    _host_scan_deadlines,
    _seconds_until_next_rule_pass,
    _seconds_until_next_scan,
    claim_hosts_due_for_scan,
    get_hosts_due_for_scan,
    record_scan_history,
    wake_scheduler,
)
from cert_watch.scheduler_context import SchedulerContext
from cert_watch.services.host_management import (
    HostSettingsUpdate,
    delete_host,
    update_host_settings,
)
from cert_watch.services.renewal_reports import (
    RenewalReportInput,
    clear_renewal_failure,
    create_report,
    expire_renewal_leases,
    resolve_target,
)
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

NOW = datetime(2026, 9, 28, 12, tzinfo=UTC)
HOST = "verify.example.test"


def _make_estate(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(HOST, 443)
    leaf = parse_certificate(_make_cert(HOST, days_valid=60).der)
    cert_id = seed_scanned(db, HOST, 443, leaf)
    settings = Settings(db_path=db, data_dir=tmp_path)
    return db, host_id, cert_id, leaf.fingerprint_sha256, settings


@pytest.fixture
def estate(tmp_path):
    return _make_estate(tmp_path)


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
        return conn.execute("SELECT * FROM renewal_attempts WHERE is_current=1").fetchone()


@pytest.mark.parametrize(
    ("not_after", "first_offset", "raise_offset", "next_offset"),
    [
        (NOW + timedelta(days=20), timedelta(hours=1), timedelta(hours=24), timedelta(hours=24)),
        (NOW + timedelta(days=10), timedelta(hours=6), timedelta(hours=12), timedelta(hours=6)),
        (NOW + timedelta(days=2), timedelta(minutes=5), timedelta(minutes=5), timedelta(minutes=5)),
        (
            NOW - timedelta(minutes=1),
            timedelta(minutes=5),
            timedelta(minutes=5),
            timedelta(minutes=5),
        ),
        (None, timedelta(minutes=5), timedelta(minutes=5), timedelta(minutes=5)),
    ],
)
def test_verification_bands_use_fake_clock(
    estate, not_after, first_offset, raise_offset, next_offset
):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=not_after)
    evaluate_after_scan(db, HOST, 443, baseline, started_at=NOW, settings=settings)
    first = _row(db)
    assert first["state"] == "verifying"
    assert datetime.fromisoformat(first["next_check_at"]) == NOW + next_offset
    evaluate_after_scan(db, HOST, 443, baseline, started_at=NOW + first_offset, settings=settings)
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
        db,
        HOST,
        443,
        baseline,
        started_at=NOW + timedelta(minutes=4, seconds=59),
        settings=settings,
    )
    assert _row(db)["state"] == "verifying"
    evaluate_after_scan(
        db,
        HOST,
        443,
        "f" * 64,
        started_at=NOW + timedelta(minutes=5),
        settings=settings,
    )
    assert _row(db)["state"] == "verified"


def test_successful_checks_are_spaced_five_minutes(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=10))
    evaluate_after_scan(db, HOST, 443, baseline, started_at=NOW, settings=settings)
    evaluate_after_scan(
        db,
        HOST,
        443,
        baseline,
        started_at=NOW + timedelta(minutes=4),
        settings=settings,
    )
    row = _row(db)
    assert row["checks_done"] == 1
    assert row["last_check_at"] == NOW.isoformat()
    assert datetime.fromisoformat(row["next_check_at"]) >= NOW + timedelta(minutes=5)


def test_unknown_expiry_checks_use_hourly_grace_grid(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=None)
    evaluate_after_scan(
        db,
        HOST,
        443,
        baseline,
        started_at=NOW + timedelta(minutes=6),
        settings=settings,
    )
    assert datetime.fromisoformat(_row(db)["next_check_at"]) == NOW + timedelta(hours=1, minutes=5)


def test_scan_failure_is_not_a_check_and_reschedules_by_band(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, not_after=NOW + timedelta(days=10))
    mark_verification_blocked(db, HOST, 443, started_at=NOW + timedelta(hours=1), settings=settings)
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


def test_different_successor_waits_for_qualifying_check(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, expected="e" * 64, not_after=NOW + timedelta(days=20))
    evaluate_after_scan(db, HOST, 443, "d" * 64, started_at=NOW, settings=settings)
    assert _row(db)["state"] == "verifying"
    evaluate_after_scan(
        db,
        HOST,
        443,
        "d" * 64,
        started_at=NOW + timedelta(hours=24),
        settings=settings,
    )
    row = _row(db)
    assert (row["state"], row["verification_reason"]) == ("not_deployed", "mismatch")


def test_mismatch_at_acceptance_preserves_immediate_check(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    result, _ = create_report(
        db,
        settings,
        target,
        RenewalReportInput("succeeded", None, "tool", None, "d" * 64, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="acceptance-mismatch",
        now=NOW,
    )
    row = _row(db)
    assert row["baseline_fingerprint"] == baseline
    assert (result.state, row["next_check_at"], row["raised_at"]) == (
        "verifying",
        NOW.isoformat(),
        None,
    )


def test_open_attempt_is_verified_by_observed_successor(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, state="open", not_after=NOW + timedelta(days=20))
    evaluate_after_scan(db, HOST, 443, "d" * 64, started_at=NOW, settings=settings)
    assert (_row(db)["state"], _row(db)["closed_reason"]) == ("verified", "observed_successor")


def test_report_storm_limits_immediate_check_to_one_per_five_minutes(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    auth = AuthContext.renewal_report_key("key", principal_id="key", binding="all", bound_tags=())
    target = resolve_target(db, auth, hostname=HOST, port=443)
    attempts = set()
    for index in range(4):
        result, _ = create_report(
            db,
            settings,
            target,
            RenewalReportInput("succeeded", None, "tool", None, None, None),
            auth=auth,
            actor="api_key:key",
            source_ip=None,
            idempotency_key=None,
            body_sha256=str(index),
            now=NOW + timedelta(seconds=index),
        )
        attempts.add(result.attempt_id)
    assert len(attempts) == 1
    row = _row(db)
    assert row["next_check_at"] == NOW.isoformat()
    assert row["success_received_at"] == NOW.isoformat()


def _post(estate, outcome, at, *, new_fingerprint=None, correlation_id=None):
    db, _host_id, _cert_id, _baseline, settings = estate
    auth = AuthContext.renewal_report_key("key", principal_id="key", binding="all", bound_tags=())
    return create_report(
        db,
        settings,
        resolve_target(db, auth, hostname=HOST, port=443),
        RenewalReportInput(
            outcome, None, "tool", correlation_id, new_fingerprint, None
        ),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256=f"{outcome}:{at.isoformat()}:{new_fingerprint}",
        now=at,
    )[0]


def _serve(estate, leaf, observed_at):
    db, _host_id, _cert_id, _baseline, settings = estate
    store_scanned(
        ScannedEntry(
            host=HOST,
            port=443,
            leaf=leaf,
            chain=[],
            scanned_at=observed_at,
        ),
        db,
    )
    return evaluate_after_scan(
        db,
        HOST,
        443,
        leaf.fingerprint_sha256,
        started_at=observed_at,
        settings=settings,
    )


@pytest.mark.parametrize("first_outcome", ["started", "failed"])
def test_grace_is_anchored_to_each_succeeded_report(estate, first_outcome):
    db, _host_id, _cert_id, baseline, settings = estate
    _post(estate, first_outcome, NOW)
    succeeded_at = NOW + timedelta(hours=1)
    _post(estate, "succeeded", succeeded_at)
    assert _row(db)["success_received_at"] == succeeded_at.isoformat()
    evaluate_after_scan(
        db,
        HOST,
        443,
        baseline,
        started_at=succeeded_at + timedelta(seconds=30),
        settings=settings,
    )
    assert _row(db)["state"] == "verifying"


def test_failed_then_succeeded_replaces_reported_fingerprint(estate):
    _post(estate, "succeeded", NOW, new_fingerprint="a" * 64)
    _post(estate, "failed", NOW + timedelta(minutes=1))
    _post(estate, "succeeded", NOW + timedelta(minutes=2), new_fingerprint="b" * 64)
    assert _row(estate[0])["new_fingerprint"] == "b" * 64


def test_baseline_fingerprint_claim_is_stored_but_never_applied(estate):
    db, _host_id, _cert_id, baseline, _settings = estate
    result = _post(estate, "succeeded", NOW, new_fingerprint=baseline)
    assert (result.state, result.effect) == (None, "no_change")
    assert _row(db) is None
    with _connect(db) as conn:
        report = conn.execute(
            "SELECT new_fingerprint,effect FROM renewal_reports WHERE report_id=?",
            (result.report_id,),
        ).fetchone()
    assert tuple(report) == (baseline, "no_change")


def test_claim_cannot_close_not_deployed(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    _attempt(estate, state="not_deployed", expected=None)
    _post(estate, "succeeded", NOW + timedelta(minutes=1), new_fingerprint="b" * 64)
    assert _row(db)["state"] == "not_deployed"


def test_nonqualifying_mismatch_cannot_demote_not_deployed(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    _attempt(estate, state="not_deployed", expected="f" * 64)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET verification_reason='baseline_still_served',"
            "last_check_at=? WHERE is_current=1",
            (NOW.isoformat(),),
        )
        conn.commit()
    evaluate_after_scan(
        db,
        HOST,
        443,
        "d" * 64,
        started_at=NOW + timedelta(minutes=2),
        settings=settings,
    )
    row = _row(db)
    assert (row["state"], row["verification_reason"]) == (
        "not_deployed",
        "baseline_still_served",
    )


def test_cross_attempt_scan_floor_and_single_immediate_exception(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    record_scan_history(db, ScanHistory(HOST, 443, "success", scanned_at=NOW))
    _post(estate, "succeeded", NOW + timedelta(seconds=1))
    assert _seconds_until_next_scan(db, 6, 0, now=NOW + timedelta(seconds=1)) == 299
    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=5)) == [(HOST, 443)]
    record_scan_history(
        db, ScanHistory(HOST, 443, "success", scanned_at=NOW + timedelta(seconds=2))
    )
    _post(estate, "failed", NOW + timedelta(minutes=1))
    _post(estate, "started", NOW + timedelta(minutes=1, seconds=1))
    _post(estate, "succeeded", NOW + timedelta(minutes=1, seconds=2))
    assert _seconds_until_next_scan(db, 6, 0, now=NOW + timedelta(minutes=1, seconds=3)) >= 239


def test_repeat_success_does_not_move_anchor_or_pending_check(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    _post(estate, "succeeded", NOW)
    _post(estate, "succeeded", NOW + timedelta(minutes=4))
    row = _row(db)
    assert (row["success_received_at"], row["next_check_at"]) == (
        NOW.isoformat(),
        NOW.isoformat(),
    )


def test_explicit_recent_predecessor_is_baseline_and_verifies_at_acceptance(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    auth = AuthContext.renewal_report_key("key", principal_id="key", binding="all", bound_tags=())
    target = resolve_target(db, auth, cert_fingerprint=baseline)
    result, _ = create_report(
        db,
        settings,
        target,
        RenewalReportInput("succeeded", None, "tool", None, None, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="predecessor",
        now=NOW,
    )
    row = _row(db)
    assert row["baseline_fingerprint"] == baseline
    assert (result.state, row["verification_reason"]) == (
        "verified",
        "observed_successor",
    )


def test_explicit_stale_predecessor_is_not_used_as_baseline(tmp_path):
    # resolve_target's 7-day predecessor window reads the wall clock. Build the
    # certificates and resolve the target at the fixed report time so their
    # validity agrees with NOW, or the test breaks a week after NOW.
    with freeze_time(NOW):
        db, _host_id, _cert_id, baseline, settings = _make_estate(tmp_path)
        successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    _set_lineage_observed_at(db, NOW - timedelta(days=3))
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    with freeze_time(NOW):
        target = resolve_target(db, auth, cert_fingerprint=baseline)
    result, _ = create_report(
        db,
        settings,
        target,
        RenewalReportInput("succeeded", None, "tool", None, None, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="stale-explicit-predecessor",
        now=NOW,
    )
    row = _row(db)
    assert result.state == "verifying"
    assert row["baseline_fingerprint"] == successor.fingerprint_sha256


def test_explicit_predecessor_is_not_used_after_flap(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    with _connect(db) as conn:
        baseline_der = bytes(
            conn.execute(
                "SELECT raw_der FROM certificates WHERE lower(fingerprint_sha256)=?",
                (baseline.lower(),),
            ).fetchone()[0]
        )
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    store_scanned(
        ScannedEntry(
            host=HOST,
            port=443,
            leaf=parse_certificate(baseline_der),
            chain=[],
        ),
        db,
    )
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    result, _ = create_report(
        db,
        settings,
        resolve_target(db, auth, cert_fingerprint=successor.fingerprint_sha256),
        RenewalReportInput("succeeded", None, "tool", None, None, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="explicit-predecessor-flap",
        now=NOW,
    )
    row = _row(db)
    assert result.state == "verifying"
    assert row["baseline_fingerprint"] == baseline


@pytest.mark.parametrize(
    ("report_fingerprint", "reason"),
    [(None, "observed_successor"), ("successor", "reported_fingerprint")],
)
def test_hostname_success_uses_recent_lineage_predecessor(
    estate, report_fingerprint, reason
):
    db, _host_id, _cert_id, baseline, settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    result, _ = create_report(
        db,
        settings,
        resolve_target(db, auth, hostname=HOST, port=443),
        RenewalReportInput(
            "succeeded",
            None,
            "tool",
            None,
            successor.fingerprint_sha256 if report_fingerprint else None,
            None,
        ),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256=f"hostname-{report_fingerprint}",
        now=NOW,
    )
    row = _row(db)
    assert row["baseline_fingerprint"] == baseline
    assert (result.state, row["verification_reason"]) == ("verified", reason)
    assert row["verified_fingerprint"] == successor.fingerprint_sha256


def _set_lineage_observed_at(db, observed_at):
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificate_lineage SET created_at=? WHERE hostname=? AND port=?",
            (observed_at.isoformat(), HOST, 443),
        )
        conn.commit()


def test_bare_success_ignores_predecessor_observed_three_days_ago(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    current = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=current, chain=[]), db)
    _set_lineage_observed_at(db, NOW - timedelta(days=3))

    result = _post(estate, "succeeded", NOW)
    assert result.state == "verifying"
    assert _row(db)["baseline_fingerprint"] == current.fingerprint_sha256
    evaluate_after_scan(
        db,
        HOST,
        443,
        current.fingerprint_sha256,
        started_at=NOW + timedelta(hours=25),
        settings=settings,
    )
    assert _row(db)["state"] == "not_deployed"


def test_bare_success_uses_predecessor_observed_two_hours_ago(estate):
    db, _host_id, _cert_id, baseline, _settings = estate
    current = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=current, chain=[]), db)
    _set_lineage_observed_at(db, NOW - timedelta(hours=2))

    result = _post(estate, "succeeded", NOW)
    row = _row(db)
    assert row["baseline_fingerprint"] == baseline
    assert (result.state, row["verification_reason"]) == (
        "verified",
        "observed_successor",
    )


def test_bare_success_does_not_verify_a_flap_to_an_old_leaf(estate):
    db, _host_id, _cert_id, baseline, _settings = estate
    with _connect(db) as conn:
        raw = conn.execute(
            "SELECT raw_der FROM certificates WHERE lower(fingerprint_sha256)=?",
            (baseline.lower(),),
        ).fetchone()[0]
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    store_scanned(
        ScannedEntry(host=HOST, port=443, leaf=parse_certificate(bytes(raw)), chain=[]),
        db,
    )

    result = _post(estate, "succeeded", NOW)
    row = _row(db)
    assert result.state == "verifying"
    assert row["baseline_fingerprint"] == baseline


@pytest.mark.parametrize("terminal", ["abandoned", "cancelled", "failed"])
def test_recent_predecessor_applies_after_terminal_attempt(estate, terminal):
    db, _host_id, _cert_id, baseline, _settings = estate
    _post(estate, "started", NOW - timedelta(days=2))
    with _connect(db) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET state=?,suppresses_stalled=0 WHERE is_current=1",
            (terminal,),
        )
        conn.commit()
    current = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=current, chain=[]), db)
    _set_lineage_observed_at(db, NOW - timedelta(hours=2))

    result = _post(estate, "succeeded", NOW)
    row = _row(db)
    assert row["baseline_fingerprint"] == baseline
    assert result.state == "verified"


def _verified_first_cycle(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    first = _post(estate, "succeeded", NOW, correlation_id="cycle-1")
    deployed = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=deployed, chain=[]), db)
    evaluate_after_scan(
        db,
        HOST,
        443,
        deployed.fingerprint_sha256,
        started_at=NOW + timedelta(minutes=5),
        settings=settings,
    )
    assert _row(db)["state"] == "verified"
    return first, deployed


def test_verified_attempt_accepts_and_verifies_a_later_cycle(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    first, deployed = _verified_first_cycle(estate)
    second = _post(estate, "succeeded", NOW + timedelta(days=2))
    assert second.attempt_id != first.attempt_id
    assert _row(db)["baseline_fingerprint"] == deployed.fingerprint_sha256

    replacement = parse_certificate(_make_cert(HOST, days_valid=120).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=replacement, chain=[]), db)
    evaluate_after_scan(
        db,
        HOST,
        443,
        replacement.fingerprint_sha256,
        started_at=NOW + timedelta(days=2, minutes=5),
        settings=settings,
    )
    assert _row(db)["state"] == "verified"


def test_verified_attempt_without_recorded_leaf_accepts_explicit_new_cycle(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    first, deployed = _verified_first_cycle(estate)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET verified_fingerprint=NULL WHERE attempt_id=?",
            (first.attempt_id,),
        )
        conn.commit()

    replacement = parse_certificate(_make_cert(HOST, days_valid=120).der)
    second = _post(
        estate,
        "succeeded",
        NOW + timedelta(hours=1),
        new_fingerprint=replacement.fingerprint_sha256,
    )
    row = _row(db)
    assert (second.state, second.effect) == ("verifying", "applied")
    assert second.attempt_id != first.attempt_id
    assert row["baseline_fingerprint"] == deployed.fingerprint_sha256
    assert row["new_fingerprint"] == replacement.fingerprint_sha256


def test_verified_attempt_later_failed_deploy_raises(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    first, deployed = _verified_first_cycle(estate)
    second = _post(estate, "succeeded", NOW + timedelta(days=2))
    assert second.attempt_id != first.attempt_id
    evaluate_after_scan(
        db,
        HOST,
        443,
        deployed.fingerprint_sha256,
        started_at=NOW + timedelta(days=3, hours=1),
        settings=settings,
    )
    assert _row(db)["state"] == "not_deployed"


def test_verified_attempt_duplicate_window_and_owned_correlation_are_late(estate):
    first, _deployed = _verified_first_cycle(estate)
    bare = _post(estate, "succeeded", NOW + timedelta(hours=1))
    new_correlation = _post(
        estate,
        "succeeded",
        NOW + timedelta(hours=2),
        correlation_id="duplicate-cycle",
    )
    owned = _post(
        estate,
        "succeeded",
        NOW + timedelta(days=2),
        correlation_id="cycle-1",
    )
    assert {
        (bare.attempt_id, bare.effect),
        (new_correlation.attempt_id, new_correlation.effect),
        (owned.attempt_id, owned.effect),
    } == {(first.attempt_id, "ignored_late")}


def test_new_fingerprint_opens_cycle_inside_verified_duplicate_window(estate):
    first, _deployed = _verified_first_cycle(estate)
    result = _post(
        estate,
        "succeeded",
        NOW + timedelta(hours=1),
        new_fingerprint="c" * 64,
        correlation_id="cycle-2",
    )
    assert result.attempt_id != first.attempt_id
    assert result.state == "verifying"


def test_new_fingerprint_verifies_already_stored_leaf_in_next_cycle(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    first, _deployed = _verified_first_cycle(estate)
    replacement = parse_certificate(_make_cert(HOST, days_valid=120).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=replacement, chain=[]), db)
    result = _post(
        estate,
        "succeeded",
        NOW + timedelta(hours=2),
        new_fingerprint=replacement.fingerprint_sha256,
        correlation_id="cycle-2",
    )
    assert result.attempt_id != first.attempt_id
    assert result.state == "verified"


def test_failed_then_succeeded_keeps_unrun_due_check(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    _post(estate, "succeeded", NOW)
    first_check = _row(db)["next_check_at"]
    _post(estate, "failed", NOW + timedelta(minutes=1))
    _post(estate, "succeeded", NOW + timedelta(minutes=30))
    row = _row(db)
    assert row["next_check_at"] == first_check
    assert row["success_received_at"] == (NOW + timedelta(minutes=30)).isoformat()


def test_post_scan_evaluation_errors_back_off_to_band_cadence(estate, monkeypatch):
    from cert_watch.services.host_management import _record_verification_success

    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=NOW - timedelta(minutes=1))

    def fail_evaluation(*_args, **_kwargs):
        raise RuntimeError("evaluation failed")

    monkeypatch.setattr(
        "cert_watch.renewal_verification.evaluate_after_scan", fail_evaluation
    )
    expected_delays = (5, 10, 15, 15)
    failed_at = NOW
    for delay in expected_delays:
        _record_verification_success(
            db,
            HOST,
            443,
            baseline,
            started_at=failed_at,
            settings=settings,
        )
        assert datetime.fromisoformat(_row(db)["next_check_at"]) == failed_at + timedelta(
            minutes=delay
        )
        failed_at += timedelta(minutes=delay)


def test_expired_attempt_scheduler_rechecks_on_fifteen_minute_grid(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    _attempt(estate, not_after=NOW - timedelta(minutes=1))
    record_scan_history(
        db, ScanHistory(HOST, 443, "success", scanned_at=NOW - timedelta(hours=1))
    )

    assert get_hosts_due_for_scan(db, now=NOW) == [(HOST, 443)]
    record_scan_history(db, ScanHistory(HOST, 443, "success", scanned_at=NOW))
    evaluate_after_scan(db, HOST, 443, baseline, started_at=NOW, settings=settings)
    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=4, seconds=59)) == []
    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=5)) == [(HOST, 443)]
    first = NOW + timedelta(minutes=5)
    record_scan_history(db, ScanHistory(HOST, 443, "success", scanned_at=first))
    evaluate_after_scan(db, HOST, 443, baseline, started_at=first, settings=settings)

    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=19, seconds=59)) == []
    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=20)) == [(HOST, 443)]
    second = NOW + timedelta(minutes=20)
    record_scan_history(db, ScanHistory(HOST, 443, "success", scanned_at=second))
    evaluate_after_scan(db, HOST, 443, baseline, started_at=second, settings=settings)
    assert get_hosts_due_for_scan(db, now=NOW + timedelta(minutes=35)) == [(HOST, 443)]


def test_no_baseline_with_expected_fingerprint_is_bounded(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    settings = Settings(db_path=db, data_dir=tmp_path)
    expected = "e" * 64
    auth = AuthContext.renewal_report_key("key", principal_id="key", binding="all", bound_tags=())
    target = resolve_target(db, auth, hostname=HOST, port=443)
    result, _ = create_report(
        db,
        settings,
        target,
        RenewalReportInput("succeeded", None, "tool", None, expected, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="no-baseline",
        now=NOW,
    )
    assert result.state == "verifying"
    evaluate_after_scan(
        db,
        HOST,
        443,
        "d" * 64,
        started_at=NOW + timedelta(minutes=5),
        settings=settings,
    )
    row = _row(db)
    assert (row["state"], row["next_check_at"]) == ("not_deployed", None)
    assert row["host_id"] == host_id


def test_no_baseline_verifies_only_when_expected_leaf_is_scanned(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, 443)
    settings = Settings(db_path=db, data_dir=tmp_path)
    expected = "e" * 64
    auth = AuthContext.renewal_report_key("key", principal_id="key", binding="all", bound_tags=())
    create_report(
        db,
        settings,
        resolve_target(db, auth, hostname=HOST, port=443),
        RenewalReportInput("succeeded", None, "tool", None, expected, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="expected",
        now=NOW,
    )
    evaluate_after_scan(db, HOST, 443, expected, started_at=NOW, settings=settings)
    assert _row(db)["state"] == "verified"


def test_unattempted_host_honors_pending_verification_check(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                new_fingerprint,suppresses_stalled,received_at,success_received_at,
                next_check_at,baseline_lease_claimed)
               VALUES (?, ?, 1, 'test', 'verifying', 1, ?, 0, ?, ?, ?, 1)""",
            (
                uuid.uuid4().hex,
                host_id,
                "e" * 64,
                NOW.isoformat(),
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )
        conn.commit()
    assert _seconds_until_next_scan(db, 6, 0, now=NOW) == 0


@pytest.mark.parametrize("kind", ["pagerduty", "alertmanager"])
@pytest.mark.parametrize(
    "alert_type", ["expiry_warning", "renewal_not_deployed", "renewal_failed"]
)
@pytest.mark.parametrize("status", ["sending", "sent"])
def test_host_delete_resolves_every_sent_alert_type(
    estate, monkeypatch, kind, alert_type, status
):
    db, host_id, cert_id, _baseline, _settings = estate
    dedupe_key = (
        f"{alert_type}:attempt"
        if alert_type in {"renewal_not_deployed", "renewal_failed"}
        else "expiry:key"
    )
    alert = Alert(
        cert_id=cert_id,
        trigger_cert_id=cert_id,
        alert_type=alert_type,
        status=status,
        message="condition",
        hostname=HOST,
        subject=f"CN={HOST}",
        threshold_days=7 if alert_type == "expiry_warning" else None,
        dedupe_key=dedupe_key,
    )
    SqliteAlertRepository(db).create(alert)
    delivered = []

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def send(_url, *, data, **_kwargs):
        delivered.append(json.loads(data))
        return Response()

    monkeypatch.setattr("cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", send)
    config = WebhookConfig(
        "https://alerts.example.test",
        kind=kind,
        routing_key="rk" if kind == "pagerduty" else "",
    )
    assert delete_host(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        webhook_config=config,
    )
    assert len(delivered) == 1
    if kind == "pagerduty":
        assert delivered[0]["event_action"] == "resolve"
    else:
        assert delivered[0]["alerts"][0]["status"] == "resolved"


def test_host_delete_resolves_orphaned_renewal_alert_after_leaf_change(
    estate, monkeypatch
):
    db, host_id, old_cert_id, _baseline, _settings = estate
    failed = _post(estate, "failed", NOW)
    repo = SqliteAlertRepository(db)
    [alert] = evaluate_renewal_report_alerts(db, repo)
    with _connect(db) as conn:
        conn.execute("UPDATE alerts SET status='sent' WHERE id=?", (alert.id,))
        conn.commit()

    replacement = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(
        ScannedEntry(
            host=HOST,
            port=443,
            leaf=replacement,
            chain=[],
            scanned_at=NOW + timedelta(minutes=5),
        ),
        db,
    )
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT count(*) FROM certificates WHERE id=?", (old_cert_id,)
        ).fetchone()[0] == 0

    delivered = []

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def send(_url, *, data, **_kwargs):
        delivered.append(json.loads(data))
        return Response()

    monkeypatch.setattr("cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", send)
    assert delete_host(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        webhook_config=WebhookConfig(
            "https://alerts.example.test", kind="pagerduty", routing_key="rk"
        ),
    )
    assert failed.attempt_id in (alert.dedupe_key or "")
    assert [item["event_action"] for item in delivered] == ["resolve"]
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT closed_at FROM alerts WHERE id=?", (alert.id,)
        ).fetchone()[0] is not None


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
    attempt_id = _attempt(estate, state="not_deployed", not_after=NOW + timedelta(days=2))
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
    pd = json.loads(
        PagerDutyAdapter()
        .build(
            msg, WebhookConfig("https://events.example.test", kind="pagerduty", routing_key="rk")
        )
        .body
    )
    pd_resolve = json.loads(
        PagerDutyAdapter()
        .build_resolve(
            cert_id,
            created.alert_type,
            None,
            WebhookConfig("https://events.example.test", kind="pagerduty", routing_key="rk"),
            incident_key=msg.incident_key,
        )
        .body
    )
    assert pd["dedup_key"] == pd_resolve["dedup_key"] == msg.incident_key

    am = json.loads(
        AlertmanagerAdapter()
        .build(msg, WebhookConfig("https://alerts.example.test", kind="alertmanager"))
        .body
    )
    am_resolve = json.loads(
        AlertmanagerAdapter()
        .build_resolve(
            cert_id,
            created.alert_type,
            None,
            WebhookConfig("https://alerts.example.test", kind="alertmanager"),
            incident_key=msg.incident_key,
        )
        .body
    )
    assert am["alerts"][0]["labels"]["cert_watch_dedupe_key"] == msg.incident_key
    assert am_resolve["alerts"][0]["labels"]["cert_watch_dedupe_key"] == msg.incident_key

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

    monkeypatch.setattr("cert_watch.alerting.transports.webhook.ssrf_safe_urlopen", send)
    assert (
        resolve_webhook_for_renewed_cert(
            db,
            cert_id,
            WebhookConfig("https://events.example.test", kind="pagerduty", routing_key="rk"),
            pending_alerts=closed,
        )
        == 1
    )
    assert delivered[-1]["dedup_key"] == msg.incident_key
    assert (
        resolve_webhook_for_renewed_cert(
            db,
            cert_id,
            WebhookConfig("https://alerts.example.test", kind="alertmanager"),
            pending_alerts=closed,
        )
        == 1
    )
    assert delivered[-1]["alerts"][0]["labels"]["cert_watch_dedupe_key"] == msg.incident_key


def test_failed_report_wakes_rule_pass_and_uses_only_fixed_text(estate):
    db, _host_id, cert_id, _baseline, settings = estate
    auth = AuthContext.renewal_report_key(
        "visible-key-name", principal_id="key-id", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    result, _ = create_report(
        db,
        settings,
        target,
        RenewalReportInput(
            "failed",
            "private failure detail",
            "private-tool",
            "private-correlation",
            None,
            None,
        ),
        auth=auth,
        actor="api_key:key-id",
        source_ip=None,
        idempotency_key=None,
        body_sha256="failure",
        now=NOW,
    )
    row = _row(db)
    assert row["failure_attempt_id"] == result.attempt_id
    assert row["failure_reported_at"] == NOW.isoformat()
    assert _seconds_until_next_rule_pass(db, now=NOW) == 0
    assert _seconds_until_next_scan(db, 6, 0, now=NOW) == 3600

    [created] = evaluate_renewal_report_alerts(
        db, SqliteAlertRepository(db), base_url="https://certs.example.test"
    )
    assert created.alert_type == "renewal_failed"
    assert created.trigger_cert_id == cert_id
    assert result.attempt_id in (created.dedupe_key or "")
    assert created.message == (
        f"Renewal automation reported a failure for {HOST}:443 at {NOW.isoformat()}. "
        f"Details: https://certs.example.test/certificates/{cert_id}"
    )
    for private in (
        "private failure detail",
        "private-tool",
        "private-correlation",
        "visible-key-name",
        "key-id",
    ):
        assert private not in created.message
    assert _row(db)["next_check_at"] is None
    assert _seconds_until_next_rule_pass(db, now=NOW) == float("inf")


def test_not_deployed_failed_report_marks_attempt_and_opens_both_alerts(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    attempt_id = _attempt(
        estate, state="not_deployed", not_after=NOW + timedelta(days=2)
    )
    result = _post(estate, "failed", NOW + timedelta(minutes=1))
    row = _row(db)
    assert (result.state, result.effect) == ("not_deployed", "no_change")
    assert row["failure_reported_at"] == (NOW + timedelta(minutes=1)).isoformat()
    created = evaluate_renewal_report_alerts(db, SqliteAlertRepository(db))
    assert {alert.alert_type for alert in created} == {
        "renewal_failed",
        "renewal_not_deployed",
    }
    assert all(attempt_id in (alert.dedupe_key or "") for alert in created)


def test_failure_alert_survives_success_claim_until_scan_verifies(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    failed = _post(estate, "failed", NOW)
    repo = SqliteAlertRepository(db)
    [created] = evaluate_renewal_report_alerts(db, repo)

    succeeded = _post(estate, "succeeded", NOW + timedelta(minutes=1))
    assert succeeded.attempt_id == failed.attempt_id
    assert _row(db)["state"] == "verifying"
    assert evaluate_renewal_report_alerts(db, repo) == []
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT closed_at FROM alerts WHERE id=?", (created.id,)
        ).fetchone()[0] is None
        conn.execute("UPDATE alerts SET status='sent' WHERE id=?", (created.id,))
        conn.commit()

    evaluate_after_scan(
        db,
        HOST,
        443,
        "e" * 64,
        started_at=NOW + timedelta(minutes=5),
        settings=settings,
    )
    closed: list[Alert] = []
    evaluate_renewal_report_alerts(db, repo, closed_sent=closed)
    assert [alert.id for alert in closed] == [created.id]


def test_started_retry_carries_one_failure_condition_and_alert(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    failed = _post(estate, "failed", NOW, correlation_id="failed-cycle")
    repo = SqliteAlertRepository(db)
    [created] = evaluate_renewal_report_alerts(db, repo)

    started = _post(
        estate,
        "started",
        NOW + timedelta(minutes=1),
        correlation_id="retry-cycle",
    )
    assert started.attempt_id != failed.attempt_id
    row = _row(db)
    assert row["failure_attempt_id"] == failed.attempt_id
    assert row["failure_reported_at"] == NOW.isoformat()
    assert row["failure_cleared_at"] is None
    assert evaluate_renewal_report_alerts(db, repo) == []
    with _connect(db) as conn:
        alerts = conn.execute(
            """SELECT id,dedupe_key,closed_at FROM alerts
               WHERE alert_type='renewal_failed'"""
        ).fetchall()
    assert [(alert["id"], alert["dedupe_key"], alert["closed_at"]) for alert in alerts] == [
        (created.id, f"renewal_failed:{failed.attempt_id}", None)
    ]

    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    observed_at = NOW + timedelta(minutes=5)
    store_scanned(
        ScannedEntry(
            host=HOST,
            port=443,
            leaf=successor,
            chain=[],
            scanned_at=observed_at,
        ),
        db,
    )
    result = evaluate_after_scan(
        db,
        HOST,
        443,
        successor.fingerprint_sha256,
        started_at=observed_at,
        settings=settings,
    )
    assert result is not None and result.state == "verified"
    assert _row(db)["failure_cleared_at"] == observed_at.isoformat()


def test_manual_and_succeeded_attempts_carry_failure_origin(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    failed = _post(estate, "failed", NOW)

    # The manual start stamps the wall clock; pin it between the fixed-time
    # reports, or the test breaks once real time passes NOW + 48 h.
    with freeze_time(NOW + timedelta(hours=1)):
        update_host_settings(
            db,
            host_id,
            HostSettingsUpdate(None, None, "in_progress"),
            auth=AuthContext.system(),
            actor="system",
            source_ip=None,
        )
    manual = _row(db)
    assert manual["attempt_id"] != failed.attempt_id
    assert manual["failure_attempt_id"] == failed.attempt_id
    assert manual["failure_reported_at"] == NOW.isoformat()

    succeeded = _post(estate, "succeeded", NOW + timedelta(hours=48))
    assert succeeded.attempt_id != manual["attempt_id"]
    latest = _row(db)
    assert latest["failure_attempt_id"] == failed.attempt_id
    assert latest["failure_reported_at"] == NOW.isoformat()
    assert latest["failure_cleared_at"] is None


def test_successor_scan_clears_failed_condition_without_verifying_attempt(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    failed = _post(estate, "failed", NOW)
    repo = SqliteAlertRepository(db)
    [created] = evaluate_renewal_report_alerts(db, repo)
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    observed_at = NOW + timedelta(minutes=5)
    store_scanned(
        ScannedEntry(
            host=HOST,
            port=443,
            leaf=successor,
            chain=[],
            scanned_at=observed_at,
        ),
        db,
    )

    result = evaluate_after_scan(
        db,
        HOST,
        443,
        successor.fingerprint_sha256,
        started_at=observed_at,
        settings=settings,
    )
    assert result is not None and result.state == "failed"
    assert result.reason is None
    assert _row(db)["failure_cleared_at"] == observed_at.isoformat()
    row = _row(db)
    assert row["failure_attempt_id"] == failed.attempt_id
    assert row["failure_cleared_at"] == observed_at.isoformat()
    closed: list[Alert] = []
    assert evaluate_renewal_report_alerts(db, repo, closed_sent=closed) == []
    with _connect(db) as conn:
        alerts = conn.execute(
            "SELECT dedupe_key,closed_at FROM alerts WHERE alert_type='renewal_failed'"
        ).fetchall()
    assert len(alerts) == 1
    assert alerts[0]["dedupe_key"] == created.dedupe_key
    assert alerts[0]["closed_at"] is not None


def test_carried_failure_does_not_change_started_or_failed_reduction(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    _post(estate, "failed", NOW)
    started = _post(estate, "started", NOW + timedelta(hours=1))
    first_open = _row(db)
    repeated = _post(estate, "started", NOW + timedelta(hours=20))
    after_repeat = _row(db)

    assert repeated.attempt_id == started.attempt_id
    assert (repeated.state, repeated.effect) == ("open", "duplicate")
    assert after_repeat["lease_expires_at"] == first_open["lease_expires_at"]

    failed = _post(estate, "failed", NOW + timedelta(hours=21))
    assert (failed.state, failed.effect) == ("failed", "applied")
    assert _row(db)["state"] == "failed"


def test_verified_run_owns_late_correlated_failure(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    first = _post(
        estate,
        "succeeded",
        NOW,
        correlation_id="run-1",
        new_fingerprint=successor.fingerprint_sha256,
    )
    assert _serve(estate, successor, NOW + timedelta(minutes=10)).state == "verified"

    late = _post(
        estate,
        "failed",
        NOW + timedelta(minutes=20),
        correlation_id="run-1",
    )
    assert late.attempt_id == first.attempt_id
    assert (late.state, late.effect) == ("verified", "ignored_late")
    with _connect(db) as conn:
        attempts = conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0]
    assert attempts == 1
    assert _row(db)["failure_reported_at"] is None


def test_abandoned_attempt_is_not_verified_to_clear_failure(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    _post(
        estate,
        "failed",
        NOW,
        new_fingerprint=successor.fingerprint_sha256,
    )
    _post(estate, "started", NOW + timedelta(hours=1))
    expire_renewal_leases(db, now=NOW + timedelta(hours=25))

    result = _serve(estate, successor, NOW + timedelta(hours=26))
    row = _row(db)
    assert result is not None and result.state == "abandoned"
    assert row["state"] == "abandoned"
    assert row["verified_fingerprint"] is None
    assert row["failure_cleared_at"] == (NOW + timedelta(hours=26)).isoformat()


def test_explicit_manual_clear_closes_on_rule_pass_without_changing_attempt(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    _post(estate, "failed", NOW)
    repo = SqliteAlertRepository(db)
    [created] = evaluate_renewal_report_alerts(db, repo)

    update_host_settings(
        db,
        host_id,
        HostSettingsUpdate(None, None, "pending"),
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
    )
    assert _row(db)["failure_cleared_at"] is None

    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=2),
    )
    row = _row(db)
    assert row["closed_reason"] == "reported_failed"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=2)).isoformat()
    assert row["rule_due_at"] == row["failure_cleared_at"]
    evaluate_renewal_report_alerts(db, repo)
    with _connect(db) as conn:
        alert = conn.execute(
            "SELECT closed_at FROM alerts WHERE id=?", (created.id,)
        ).fetchone()
        audit = conn.execute(
            "SELECT action FROM audit_log ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    assert alert["closed_at"] is not None
    assert audit["action"] == "renewal_failure.clear"


def test_rule_wake_compare_and_set_preserves_racing_failure(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    other = "rule-race.example.test"
    SqliteHostRepository(db).add(other, 443)
    seed_scanned(db, other, 443, parse_certificate(_make_cert(other).der))
    _post(estate, "failed", NOW)

    repo = SqliteAlertRepository(db)
    real_enqueue = repo.enqueue
    raced: list[str] = []

    def enqueue_with_race(alert, **kwargs):
        if not raced:
            raced.append("reported")
            auth = AuthContext.renewal_report_key(
                "key", principal_id="key", binding="all", bound_tags=()
            )
            create_report(
                db,
                settings,
                resolve_target(db, auth, hostname=other, port=443),
                RenewalReportInput("failed", None, None, None, None, None),
                auth=auth,
                actor="api_key:key",
                source_ip=None,
                idempotency_key=None,
                body_sha256="racing-failure",
                now=NOW + timedelta(seconds=1),
            )
        return real_enqueue(alert, **kwargs)

    repo.enqueue = enqueue_with_race  # type: ignore[method-assign]
    evaluate_renewal_report_alerts(db, repo)
    with _connect(db) as conn:
        wake = conn.execute(
            """SELECT a.rule_due_at FROM renewal_attempts a
               JOIN hosts h ON h.id=a.host_id WHERE h.hostname=?""",
            (other,),
        ).fetchone()[0]
        count = conn.execute(
            """SELECT count(*) FROM alerts
               WHERE hostname=? AND alert_type='renewal_failed'""",
            (other,),
        ).fetchone()[0]
    assert count == 0
    assert wake == (NOW + timedelta(seconds=1)).isoformat()

    repo.enqueue = real_enqueue  # type: ignore[method-assign]
    evaluate_renewal_report_alerts(db, repo)
    with _connect(db) as conn:
        wake = conn.execute(
            """SELECT a.rule_due_at FROM renewal_attempts a
               JOIN hosts h ON h.id=a.host_id WHERE h.hostname=?""",
            (other,),
        ).fetchone()[0]
        count = conn.execute(
            """SELECT count(*) FROM alerts
               WHERE hostname=? AND alert_type='renewal_failed'""",
            (other,),
        ).fetchone()[0]
    assert count == 1
    assert wake is None


def test_failed_report_storm_schedules_zero_extra_scans(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    record_scan_history(
        db,
        ScanHistory(
            hostname=HOST,
            port=443,
            status="success",
            scanned_at=NOW - timedelta(minutes=1),
        ),
    )
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    scan_selections = 0
    for index in range(120):
        at = NOW + timedelta(seconds=index * 30)
        create_report(
            db,
            settings,
            target,
            RenewalReportInput("failed", None, None, None, None, None),
            auth=auth,
            actor="api_key:key",
            source_ip=None,
            idempotency_key=None,
            body_sha256=f"failure-{index}",
            now=at,
        )
        scan_selections += len(get_hosts_due_for_scan(db, now=at))
        evaluate_renewal_report_alerts(db, SqliteAlertRepository(db))
    assert scan_selections == 0
    with _connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM scan_history").fetchone()[0] == 1


def test_failure_mismatch_uses_s4_fingerprint_rule(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    failed = _post(estate, "failed", NOW)
    _post(
        estate,
        "succeeded",
        NOW + timedelta(minutes=1),
        new_fingerprint="a" * 64,
    )

    evaluate_after_scan(
        db,
        HOST,
        443,
        "b" * 64,
        started_at=NOW + timedelta(hours=24, minutes=1),
        settings=settings,
    )

    row = _row(db)
    assert (row["state"], row["verification_reason"]) == (
        "not_deployed",
        "mismatch",
    )
    assert row["failure_attempt_id"] == failed.attempt_id
    assert row["failure_cleared_at"] is None


def test_rule_wake_ignores_noncurrent_and_cleared_attempts(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    due = (NOW - timedelta(minutes=1)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at,failure_cleared_at,rule_due_at)
               VALUES ('dead',?,0,'test','failed',1,0,?,1,'dead',?,?,?)""",
            (host_id, due, due, due, due),
        )
        conn.commit()
    assert _seconds_until_next_rule_pass(db, now=NOW) == float("inf")

    _post(estate, "failed", NOW)
    assert _seconds_until_next_rule_pass(db, now=NOW) == 0


def test_failure_after_manual_clear_opens_new_condition(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    repo = SqliteAlertRepository(db)
    first = _post(estate, "failed", NOW)
    [first_alert] = evaluate_renewal_report_alerts(db, repo)
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=1),
    )
    evaluate_renewal_report_alerts(db, repo)

    second = _post(estate, "failed", NOW + timedelta(minutes=2))
    [second_alert] = evaluate_renewal_report_alerts(db, repo)
    row = _row(db)
    assert second.attempt_id == first.attempt_id
    assert row["failure_attempt_id"] != first.attempt_id
    assert row["failure_reported_at"] == (NOW + timedelta(minutes=2)).isoformat()
    assert row["failure_cleared_at"] is None
    assert second_alert.dedupe_key != first_alert.dedupe_key


def test_failure_restart_updates_condition_without_rewriting_attempt_claim(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    old_expected = parse_certificate(_make_cert(HOST, days_valid=70).der)
    fresh_expected = parse_certificate(_make_cert(HOST, days_valid=80).der)
    unrelated = parse_certificate(_make_cert(HOST, days_valid=90).der)
    _post(
        estate,
        "failed",
        NOW,
        new_fingerprint=old_expected.fingerprint_sha256,
    )
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=1),
    )

    _post(
        estate,
        "failed",
        NOW + timedelta(minutes=2),
        new_fingerprint=fresh_expected.fingerprint_sha256,
    )
    row = _row(db)
    assert row["failure_expected_fingerprint"] == fresh_expected.fingerprint_sha256
    assert row["new_fingerprint"] is None

    unrelated_result = _serve(estate, unrelated, NOW + timedelta(minutes=5))
    row = _row(db)
    assert unrelated_result is not None and unrelated_result.state == "failed"
    assert row["failure_cleared_at"] is None

    fresh_result = _serve(estate, fresh_expected, NOW + timedelta(minutes=10))
    row = _row(db)
    assert fresh_result is not None and fresh_result.state == "failed"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=10)).isoformat()


def test_failure_restart_without_fingerprint_preserves_attempt_claim(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    old_expected = parse_certificate(_make_cert(HOST, days_valid=70).der)
    successor = parse_certificate(_make_cert(HOST, days_valid=80).der)
    _post(
        estate,
        "failed",
        NOW,
        new_fingerprint=old_expected.fingerprint_sha256,
    )
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=1),
    )

    _post(estate, "failed", NOW + timedelta(minutes=2))
    row = _row(db)
    assert row["failure_expected_fingerprint"] is None
    assert row["new_fingerprint"] is None

    result = _serve(estate, successor, NOW + timedelta(minutes=5))
    row = _row(db)
    assert result is not None and result.state == "failed"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=5)).isoformat()


def test_failed_report_on_carrier_changes_only_failure_evidence(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    first = parse_certificate(_make_cert(HOST, days_valid=70).der)
    claim = parse_certificate(_make_cert(HOST, days_valid=80).der)
    latest = parse_certificate(_make_cert(HOST, days_valid=90).der)
    _post(estate, "failed", NOW, new_fingerprint=first.fingerprint_sha256)
    _post(
        estate,
        "succeeded",
        NOW + timedelta(minutes=1),
        new_fingerprint=claim.fingerprint_sha256,
    )
    before = _row(db)
    assert before["state"] == "verifying"

    result = _post(
        estate,
        "failed",
        NOW + timedelta(minutes=2),
        new_fingerprint=latest.fingerprint_sha256,
    )
    after = _row(db)
    assert result.state == "failed"
    assert after["state"] == "failed"
    assert after["new_fingerprint"] == before["new_fingerprint"]
    assert after["closed_reason"] == "reported_failed"
    assert after["failure_expected_fingerprint"] == latest.fingerprint_sha256


def test_failure_after_verified_opens_new_cycle_and_baseline_scan_does_not_clear(
    estate,
):
    db, _host_id, _cert_id, _baseline, _settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=80).der)
    expected = parse_certificate(_make_cert(HOST, days_valid=90).der)
    first = _post(
        estate,
        "succeeded",
        NOW,
        new_fingerprint=successor.fingerprint_sha256,
    )
    verified = _serve(estate, successor, NOW + timedelta(minutes=5))
    assert verified is not None and verified.state == "verified"
    verified_row = _row(db)

    failed = _post(
        estate,
        "failed",
        NOW + timedelta(minutes=10),
        new_fingerprint=expected.fingerprint_sha256,
    )
    failed_row = _row(db)
    assert failed.attempt_id != first.attempt_id
    assert (failed_row["state"], failed_row["baseline_fingerprint"]) == (
        "failed",
        successor.fingerprint_sha256,
    )
    assert failed_row["failure_cleared_at"] is None
    with _connect(db) as conn:
        old = conn.execute(
            "SELECT * FROM renewal_attempts WHERE attempt_id=?", (first.attempt_id,)
        ).fetchone()
    assert old["state"] == "verified"
    assert old["verified_fingerprint"] == verified_row["verified_fingerprint"]

    baseline_result = _serve(estate, successor, NOW + timedelta(minutes=15))
    assert baseline_result is not None and baseline_result.state == "failed"
    assert _row(db)["failure_cleared_at"] is None

    expected_result = _serve(estate, expected, NOW + timedelta(minutes=20))
    assert expected_result is not None and expected_result.state == "failed"
    assert _row(db)["failure_cleared_at"] == (
        NOW + timedelta(minutes=20)
    ).isoformat()


def test_failure_expectation_tracks_latest_failed_or_succeeded_fingerprint(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    first = "a" * 64
    second = "b" * 64
    latest = "c" * 64
    _post(estate, "failed", NOW, new_fingerprint=first)
    _post(estate, "failed", NOW + timedelta(minutes=1), new_fingerprint=second)
    assert _row(db)["failure_expected_fingerprint"] == second

    _post(estate, "succeeded", NOW + timedelta(minutes=2), new_fingerprint=latest)
    assert _row(db)["failure_expected_fingerprint"] == latest

    _post(estate, "failed", NOW + timedelta(minutes=3))
    assert _row(db)["failure_expected_fingerprint"] == latest


def test_started_carrier_observed_successor_verifies_and_clears_failure(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    repo = SqliteAlertRepository(db)
    expected = parse_certificate(_make_cert(HOST, days_valid=90).der)
    third = parse_certificate(_make_cert(HOST, days_valid=100).der)
    _post(estate, "failed", NOW, new_fingerprint=expected.fingerprint_sha256)
    _post(estate, "started", NOW + timedelta(minutes=1))

    result = _serve(estate, third, NOW + timedelta(minutes=10))
    evaluate_renewal_report_alerts(db, repo)
    row = _row(db)
    assert result is not None and result.state == "verified"
    assert result.reason == "observed_successor"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=10)).isoformat()
    with _connect(db) as conn:
        assert conn.execute(
            "SELECT count(*) FROM alerts WHERE alert_type='renewal_not_deployed'"
        ).fetchone()[0] == 0


def test_cleared_failure_fingerprint_does_not_govern_bare_success(estate):
    db, host_id, _cert_id, _baseline, settings = estate
    expected = parse_certificate(_make_cert(HOST, days_valid=90).der)
    successor = parse_certificate(_make_cert(HOST, days_valid=100).der)
    _post(estate, "failed", NOW, new_fingerprint=expected.fingerprint_sha256)
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=1),
    )
    _post(estate, "succeeded", NOW + timedelta(minutes=2))

    result = evaluate_after_scan(
        db,
        HOST,
        443,
        successor.fingerprint_sha256,
        started_at=NOW + timedelta(minutes=10),
        settings=settings,
    )
    assert result is not None and result.state == "verified"
    assert result.reason == "observed_successor"


def test_failure_after_clear_restarts_not_deployed_condition_in_place(estate):
    db, host_id, _cert_id, _baseline, _settings = estate
    attempt_id = _attempt(
        estate, state="not_deployed", not_after=NOW + timedelta(days=2)
    )
    repo = SqliteAlertRepository(db)
    _post(estate, "failed", NOW + timedelta(minutes=1))
    evaluate_renewal_report_alerts(db, repo)
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=NOW + timedelta(minutes=2),
    )
    evaluate_renewal_report_alerts(db, repo)

    _post(estate, "failed", NOW + timedelta(minutes=3))
    evaluate_renewal_report_alerts(db, repo)
    row = _row(db)
    with _connect(db) as conn:
        open_types = {
            str(alert[0])
            for alert in conn.execute(
                "SELECT alert_type FROM alerts WHERE closed_at IS NULL"
            )
        }
        attempts = conn.execute(
            "SELECT attempt_id,state,is_current FROM renewal_attempts"
        ).fetchall()
    assert (row["attempt_id"], row["state"], row["is_current"]) == (
        attempt_id,
        "not_deployed",
        1,
    )
    assert len(attempts) == 1
    assert open_types == {"renewal_failed", "renewal_not_deployed"}


def test_bare_success_observed_successor_verifies_and_clears_failure(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    expected = parse_certificate(_make_cert(HOST, days_valid=90).der)
    successor = parse_certificate(_make_cert(HOST, days_valid=100).der)
    _post(
        estate,
        "failed",
        NOW,
        new_fingerprint=expected.fingerprint_sha256,
    )
    _post(estate, "succeeded", NOW + timedelta(minutes=1))

    result = _serve(estate, successor, NOW + timedelta(minutes=10))
    row = _row(db)
    assert result is not None and result.state == "verified"
    assert result.reason == "observed_successor"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=10)).isoformat()


def test_failed_report_does_not_clear_on_unrelated_leaf_without_new_report(estate):
    db, _host_id, _cert_id, _baseline, _settings = estate
    expected = parse_certificate(_make_cert(HOST, days_valid=90).der)
    unrelated = parse_certificate(_make_cert(HOST, days_valid=100).der)
    _post(
        estate,
        "failed",
        NOW,
        new_fingerprint=expected.fingerprint_sha256,
    )

    result = _serve(estate, unrelated, NOW + timedelta(minutes=5))
    row = _row(db)
    assert result is not None and result.state == "failed"
    assert row["failure_cleared_at"] is None


@pytest.mark.parametrize("state", ["open", "verifying", "failed", "not_deployed"])
def test_unserved_attempt_claim_blocks_unrelated_failure_clear_in_every_state(
    estate, state
):
    db, _host_id, _cert_id, _baseline, settings = estate
    claim = parse_certificate(_make_cert(HOST, days_valid=80).der)
    unrelated = parse_certificate(_make_cert(HOST, days_valid=90).der)
    attempt_id = _attempt(estate, state=state, expected=claim.fingerprint_sha256)
    with _connect(db) as conn:
        conn.execute(
            """UPDATE renewal_attempts
               SET failure_attempt_id=attempt_id,failure_reported_at=?,
                   failure_expected_fingerprint=NULL
               WHERE attempt_id=?""",
            (NOW.isoformat(), attempt_id),
        )
        conn.commit()

    evaluate_after_scan(
        db,
        HOST,
        443,
        unrelated.fingerprint_sha256,
        started_at=NOW + timedelta(minutes=10),
        settings=settings,
    )
    assert _row(db)["failure_cleared_at"] is None


def test_existing_verified_state_is_not_a_new_verification_transition(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    verified_leaf = "a" * 64
    expected = "b" * 64
    attempt_id = _attempt(estate, state="verified", expected=verified_leaf)
    with _connect(db) as conn:
        conn.execute(
            """UPDATE renewal_attempts
               SET verified_fingerprint=?,verification_reason='reported_fingerprint',
                   closed_reason='reported_fingerprint',
                   failure_attempt_id=attempt_id,failure_reported_at=?,
                   failure_expected_fingerprint=?
               WHERE attempt_id=?""",
            (verified_leaf, NOW.isoformat(), expected, attempt_id),
        )
        conn.commit()

    result = evaluate_after_scan(
        db,
        HOST,
        443,
        baseline,
        started_at=NOW + timedelta(minutes=10),
        settings=settings,
    )
    row = _row(db)
    assert result is not None and (result.state, result.reason) == ("verified", None)
    assert row["failure_cleared_at"] is None
    assert row["verified_fingerprint"] == verified_leaf
    assert row["verification_reason"] == "reported_fingerprint"
    assert row["closed_reason"] == "reported_fingerprint"


def test_verification_transition_must_follow_failure_report(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    claim = "a" * 64
    condition_expected = "b" * 64
    attempt_id = _attempt(estate, state="verifying", expected=claim)
    with _connect(db) as conn:
        conn.execute(
            """UPDATE renewal_attempts
               SET failure_attempt_id=attempt_id,failure_reported_at=?,
                   failure_expected_fingerprint=?
               WHERE attempt_id=?""",
            (NOW.isoformat(), condition_expected, attempt_id),
        )
        conn.commit()

    result = evaluate_after_scan(
        db,
        HOST,
        443,
        claim,
        started_at=NOW,
        settings=settings,
    )
    row = _row(db)
    assert result is not None and result.state == "verified"
    assert row["failure_cleared_at"] is None


def test_not_deployed_failure_clears_only_when_condition_expectation_matches(
    estate,
):
    db, _host_id, _cert_id, _baseline, _settings = estate
    attempt_expected = parse_certificate(_make_cert(HOST, days_valid=70).der)
    failure_expected = parse_certificate(_make_cert(HOST, days_valid=80).der)
    unrelated = parse_certificate(_make_cert(HOST, days_valid=90).der)
    _attempt(estate, state="not_deployed", expected=attempt_expected.fingerprint_sha256)
    _post(
        estate,
        "failed",
        NOW + timedelta(minutes=1),
        new_fingerprint=failure_expected.fingerprint_sha256,
    )

    unrelated_result = _serve(estate, unrelated, NOW + timedelta(minutes=5))
    row = _row(db)
    assert unrelated_result is not None and unrelated_result.state == "not_deployed"
    assert row["failure_cleared_at"] is None

    expected_result = _serve(estate, failure_expected, NOW + timedelta(minutes=10))
    row = _row(db)
    assert expected_result is not None and expected_result.state == "not_deployed"
    assert row["failure_cleared_at"] == (NOW + timedelta(minutes=10)).isoformat()


def test_not_deployed_failure_without_expectation_ignores_unrelated_successor(
    estate,
):
    db, _host_id, _cert_id, _baseline, _settings = estate
    attempt_expected = parse_certificate(_make_cert(HOST, days_valid=70).der)
    unrelated = parse_certificate(_make_cert(HOST, days_valid=90).der)
    _attempt(estate, state="not_deployed", expected=attempt_expected.fingerprint_sha256)
    _post(estate, "failed", NOW + timedelta(minutes=1))
    assert _row(db)["failure_expected_fingerprint"] is None

    result = _serve(estate, unrelated, NOW + timedelta(minutes=5))
    row = _row(db)
    assert result is not None and result.state == "not_deployed"
    assert row["failure_cleared_at"] is None


def test_carrier_reported_fingerprint_overrides_failure_expectation(estate):
    db, _host_id, _cert_id, _baseline, settings = estate
    original_expected = "a" * 64
    carrier_expected = "b" * 64
    _post(estate, "succeeded", NOW, new_fingerprint=original_expected)
    _post(estate, "failed", NOW + timedelta(minutes=1))
    _post(estate, "started", NOW + timedelta(minutes=2))
    _post(
        estate,
        "succeeded",
        NOW + timedelta(minutes=3),
        new_fingerprint=carrier_expected,
    )
    row = _row(db)
    assert row["failure_expected_fingerprint"] == carrier_expected
    assert row["new_fingerprint"] == carrier_expected

    result = evaluate_after_scan(
        db,
        HOST,
        443,
        carrier_expected,
        started_at=NOW + timedelta(minutes=10),
        settings=settings,
    )
    assert result is not None and result.state == "verified"
    assert _row(db)["failure_cleared_at"] is not None


def test_manual_clear_wakes_real_scheduler_alert_pass(estate):
    db, host_id, _cert_id, _baseline, settings = estate
    _post(estate, "failed", NOW)
    repo = SqliteAlertRepository(db)
    [alert] = evaluate_renewal_report_alerts(db, repo)

    context = SchedulerContext(settings, None, None)
    alert_passes = 0

    def run_alerts():
        nonlocal alert_passes
        alert_passes += 1
        return evaluate_renewal_report_alerts(db, repo)

    context.run_alerts = run_alerts
    context.scan_all = lambda: {"scanned": 0}
    context.maintenance = lambda: None
    context.maybe_run_weekly_digest = lambda: {}
    scheduler = Scheduler(context)
    assert clear_renewal_failure(
        db,
        host_id,
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
        now=datetime.now(UTC),
    )
    scheduler.start()
    try:
        wake_scheduler(scheduler)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with _connect(db) as conn:
                closed = conn.execute(
                    "SELECT closed_at FROM alerts WHERE id=?", (alert.id,)
                ).fetchone()[0]
            if closed is not None:
                break
            time.sleep(0.01)
        assert closed is not None
        assert alert_passes >= 1
    finally:
        scheduler.stop(timeout=2)


def test_failed_rule_pass_backs_off_instead_of_busy_loop(estate, caplog):
    db, _host_id, _cert_id, _baseline, settings = estate
    record_scan_history(
        db,
        ScanHistory(HOST, 443, "success", scanned_at=NOW - timedelta(hours=1)),
    )
    _post(estate, "failed", NOW - timedelta(minutes=1))
    context = SchedulerContext(settings, None, None)
    runs: list[datetime] = []

    class Clock:
        current = NOW

        def now(self):
            return self.current

        def monotonic(self):
            return self.current.timestamp()

        def wait(self, event, timeout):
            self.current += timedelta(seconds=timeout)
            if self.current >= NOW + timedelta(hours=1):
                scheduler.stop_event.set()
                event.set()
            return False

    def fail_rules():
        runs.append(clock.current)
        raise RuntimeError("rule pass failed")

    clock = Clock()
    context.scan_all = lambda: {}
    context.run_alerts = fail_rules
    context.maybe_run_weekly_digest = lambda: {}
    context.maintenance = lambda: None
    scheduler = Scheduler(context, clock=clock, shutdown_timeout=1)
    with caplog.at_level("ERROR", logger="cert_watch.scheduler"):
        scheduler._run_loop(scheduler.stop_event)

    gaps = [
        (later - earlier).total_seconds()
        for earlier, later in pairwise(runs)
    ]
    assert 2 <= len(runs) <= 7
    assert gaps == sorted(gaps)
    assert gaps[:3] == [60, 120, 240]
    assert caplog.text.count("scheduler alert_fn failed") == len(runs)


def test_unconsumed_rule_wake_backs_off_after_normal_rule_pass(estate, caplog):
    db, _host_id, _cert_id, _baseline, settings = estate
    record_scan_history(
        db,
        ScanHistory(HOST, 443, "success", scanned_at=NOW - timedelta(hours=1)),
    )
    _post(estate, "failed", NOW - timedelta(minutes=1))
    context = SchedulerContext(settings, None, None)
    runs: list[datetime] = []

    class Clock:
        current = NOW

        def now(self):
            return self.current

        def monotonic(self):
            return self.current.timestamp()

        def wait(self, event, timeout):
            self.current += timedelta(seconds=timeout)
            if self.current >= NOW + timedelta(hours=1):
                scheduler.stop_event.set()
                event.set()
            return False

    def leave_wake_unconsumed():
        runs.append(clock.current)
        return {"alerts": 0}

    clock = Clock()
    context.scan_all = lambda: {}
    context.run_alerts = leave_wake_unconsumed
    context.maybe_run_weekly_digest = lambda: {}
    context.maintenance = lambda: None
    scheduler = Scheduler(context, clock=clock, shutdown_timeout=1)
    with caplog.at_level("WARNING", logger="cert_watch.scheduler"):
        scheduler._run_loop(scheduler.stop_event)

    gaps = [
        (later - earlier).total_seconds()
        for earlier, later in pairwise(runs)
    ]
    assert 2 <= len(runs) <= 7
    assert gaps == sorted(gaps)
    assert gaps[:3] == [60, 120, 240]
    assert caplog.text.count("left a renewal rule wake unconsumed") == 1


def test_pre_scan_failure_keeps_one_provider_incident_across_leaf_changes(
    tmp_path, monkeypatch
):
    db = tmp_path / "pre-scan-failure.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, 443)
    settings = Settings(db_path=db, data_dir=tmp_path)
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    create_report(
        db,
        settings,
        target,
        RenewalReportInput("failed", None, None, None, None, None),
        auth=auth,
        actor="api_key:key",
        source_ip=None,
        idempotency_key=None,
        body_sha256="pre-scan-failure",
        now=NOW,
    )
    delivered: list[dict[str, str]] = []

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        "cert_watch.alerting.transports.webhook.ssrf_safe_urlopen",
        lambda _url, *, data, **_kwargs: (
            delivered.append(json.loads(data)),
            Response(),
        )[1],
    )
    webhook = WebhookConfig(
        "https://events.example.test", kind="pagerduty", routing_key="rk"
    )
    context = SchedulerContext(settings, None, webhook)
    first_leaf = parse_certificate(_make_cert(HOST, days_valid=60).der)
    store_scanned(
        ScannedEntry(host=HOST, port=443, leaf=first_leaf, chain=[]),
        db,
        webhook_config=webhook,
    )
    context.run_alerts()
    second_leaf = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(
        ScannedEntry(host=HOST, port=443, leaf=second_leaf, chain=[]),
        db,
        webhook_config=webhook,
    )
    evaluate_after_scan(
        db,
        HOST,
        443,
        second_leaf.fingerprint_sha256,
        started_at=NOW + timedelta(hours=1),
        settings=settings,
    )
    context.run_alerts()

    assert [event["event_action"] for event in delivered] == ["trigger"]
    with _connect(db) as conn:
        alerts = conn.execute(
            "SELECT id,closed_at FROM alerts WHERE alert_type='renewal_failed'"
        ).fetchall()
    assert len(alerts) == 1
    assert alerts[0]["closed_at"] is None


def test_failed_attempt_without_scanned_leaf_has_no_alert(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("unscanned.example.test", 443)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,next_check_at,failure_reported_at,
                baseline_lease_claimed)
               VALUES ('attempt',?,1,'test','failed',1,0,?,?,?,1)""",
            (host_id, NOW.isoformat(), NOW.isoformat(), NOW.isoformat()),
        )
        conn.commit()
    assert evaluate_renewal_report_alerts(db, SqliteAlertRepository(db)) == []
