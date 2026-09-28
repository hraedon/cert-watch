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
from cert_watch.database import Alert, SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.renewal_verification import evaluate_after_scan, mark_verification_blocked
from cert_watch.scan import ScannedEntry, store_scanned
from cert_watch.scheduler import (
    ScanHistory,
    _host_scan_deadlines,
    _seconds_until_next_scan,
    claim_hosts_due_for_scan,
    get_hosts_due_for_scan,
    record_scan_history,
)
from cert_watch.services.host_management import delete_host
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


def test_explicit_stale_predecessor_is_not_used_as_baseline(estate):
    db, _host_id, _cert_id, baseline, settings = estate
    successor = parse_certificate(_make_cert(HOST, days_valid=90).der)
    store_scanned(ScannedEntry(host=HOST, port=443, leaf=successor, chain=[]), db)
    _set_lineage_observed_at(db, NOW - timedelta(days=3))
    auth = AuthContext.renewal_report_key(
        "key", principal_id="key", binding="all", bound_tags=()
    )
    result, _ = create_report(
        db,
        settings,
        resolve_target(db, auth, cert_fingerprint=baseline),
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
    assert row["failure_reported_at"] == NOW.isoformat()
    assert _seconds_until_next_scan(db, 6, 0, now=NOW) == 0

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
