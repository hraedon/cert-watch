"""Normative S2 renewal-report contract and reducer table (#118)."""

from __future__ import annotations

import importlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import parse_certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.services.renewal_reports import (
    RenewalReportConflictError,
    RenewalReportInput,
    RenewalReportNotFoundError,
    create_report,
    expire_renewal_leases,
    list_reports,
    purge_renewal_reports,
    resolve_history_target,
    resolve_target,
)
from tests._helpers import seed_scanned
from tests.conftest import _make_cert

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)
HOST = "renewal.example.test"


def _auth(key_id: str, *tags: str) -> AuthContext:
    return AuthContext.renewal_report_key(
        key_id,
        principal_id=key_id,
        binding="tags" if tags else "all",
        bound_tags=tuple(tags),
    )


@pytest.fixture
def estate(tmp_path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(HOST, 443, tags="prod")
    other_id = repo.add("other.example.test", 443, tags="other")
    cert = _make_cert(HOST, days_valid=60)
    fingerprint = parse_certificate(cert.der).fingerprint_sha256
    seed_scanned(db, HOST, 443, parse_certificate(cert.der))
    seed_scanned(
        db,
        "other.example.test",
        443,
        parse_certificate(_make_cert("other.example.test", days_valid=60).der),
    )
    settings = Settings(db_path=db, data_dir=tmp_path)
    return db, repo, host_id, other_id, fingerprint, settings


def _report(outcome: str, **kwargs) -> RenewalReportInput:
    return RenewalReportInput(
        outcome=outcome,
        message=kwargs.get("message"),
        tool=kwargs.get("tool", "renew-tool"),
        correlation_id=kwargs.get("correlation_id"),
        new_fingerprint=kwargs.get("new_fingerprint"),
        occurred_at=kwargs.get("occurred_at"),
    )


def _create(estate, outcome="started", *, auth=None, now=NOW, **kwargs):
    db, _repo, _host_id, _other, _fp, settings = estate
    auth = auth or _auth("key-a", "prod")
    target = resolve_target(db, auth, hostname=HOST, port=443)
    return create_report(
        db,
        settings,
        target,
        _report(outcome, **kwargs),
        auth=auth,
        actor=f"api_key:{auth.principal_id}",
        source_ip="192.0.2.10",
        idempotency_key=kwargs.get("idempotency_key"),
        body_sha256=kwargs.get("body_sha256", f"hash-{outcome}"),
        now=now,
    )


# The report-driven subset of Opus table B. Scan-driven rows live in the S4
# verification tests; the S3 manual compatibility path remains explicit.
NORMATIVE_TRANSITIONS = (
    (1, "none", "started", "open", "applied"),
    (2, "open", "started", "open", "duplicate"),
    (3, "open", "lease_lapses", "abandoned", "timer"),
    (4, "none", "failed", "failed", "applied"),
    (5, "failed", "failed", "failed", "no_change"),
    (6, "any", "succeeded", "verifying", "applied"),
    (7, "verifying", "succeeded", "verifying", "no_change"),
    (8, "verifying", "failed", "failed", "applied"),
    (15, "live", "cancelled", "unavailable", "S3-manual"),
    (16, "open", "occurred_at_before_failed", "failed", "received-order"),
    (17, "terminal", "same_correlation_started", "abandoned", "ignored_late"),
    (18, "any", "endpoint_deleted", "none", "cascade"),
    (19, "any", "tags_changed", "unchanged", "404-to-old-key"),
    (20, "new_cycle", "old_correlation_started", "failed", "ignored_late"),
    (21, "B-C", "baseline_returns_to_B", "open", "no-remute"),
    (22, "abandoned", "same_correlation_failed_retry", "failed", "no_change"),
)


@pytest.mark.parametrize(("row", "initial", "trigger", "state", "effect"), NORMATIVE_TRANSITIONS)
def test_normative_transition_table_drives_s2_reducer(
    row, initial, trigger, state, effect, estate, report_client
):
    client, headers, _db = report_client
    observed: tuple[str, str]
    if row == 1:
        result, _ = _create(estate)
        observed = (result.state, result.effect)
    elif row == 2:
        _create(estate)
        result, _ = _create(estate)
        observed = (result.state, result.effect)
    elif row == 3:
        _create(estate)
        expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24))
        with _connect(estate[0]) as conn:
            observed = (conn.execute("SELECT state FROM renewal_attempts").fetchone()[0], "timer")
    elif row == 4:
        result, _ = _create(estate, "failed")
        observed = (result.state, result.effect)
    elif row == 5:
        _create(estate, "failed")
        result, _ = _create(estate, "failed")
        observed = (result.state, result.effect)
    elif row in (6, 7):
        if row == 7:
            _create(estate)
            with _connect(estate[0]) as conn:
                conn.execute("UPDATE renewal_attempts SET state='verifying'")
                conn.commit()
        result, _ = _create(estate, "succeeded")
        observed = (result.state, result.effect)
    elif row == 8:
        _create(estate)
        with _connect(estate[0]) as conn:
            conn.execute("UPDATE renewal_attempts SET state='verifying'")
            conn.commit()
        result, _ = _create(estate, "failed")
        observed = (result.state, result.effect)
    elif row == 15:
        _create(estate)
        with _connect(estate[0]) as conn:
            conn.execute("UPDATE renewal_attempts SET state='cancelled',suppresses_stalled=0")
            conn.commit()
        refused = client.post(
            "/api/renewal-reports",
            headers=headers,
            json={"hostname": HOST, "port": 443, "outcome": "cancelled"},
        )
        assert refused.status_code == 422
        observed = ("unavailable", "S3-manual")
    elif row == 16:
        _create(estate, occurred_at="2027-01-01T00:00:00+00:00")
        result, _ = _create(estate, "failed", occurred_at="2025-01-01T00:00:00+00:00")
        observed = (result.state, "received-order")
    elif row == 17:
        _create(estate, correlation_id="late")
        expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24))
        result, _ = _create(
            estate,
            correlation_id="late",
            now=NOW + timedelta(hours=25),
        )
        observed = (result.state, result.effect)
    elif row == 18:
        _create(estate)
        assert estate[1].delete(estate[2])
        with _connect(estate[0]) as conn:
            assert conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0] == 0
        observed = ("none", "cascade")
    elif row == 19:
        _create(estate)
        with _connect(estate[0]) as conn:
            conn.execute("UPDATE hosts SET tags='other' WHERE id=?", (estate[2],))
            conn.commit()
        with pytest.raises(RenewalReportNotFoundError):
            resolve_target(estate[0], _auth("key-a", "prod"), hostname=HOST, port=443)
        observed = ("unchanged", "404-to-old-key")
    elif row == 20:
        _create(estate, correlation_id="old-cycle")
        _create(estate, "failed", correlation_id="old-cycle")
        _create(estate, correlation_id="new-cycle")
        late, _ = _create(estate, correlation_id="old-cycle")
        observed = (late.state, late.effect)
    elif row == 21:
        first, _ = _create(estate, correlation_id="baseline-b")
        expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24))
        with _connect(estate[0]) as conn:
            conn.execute(
                "UPDATE certificates SET fingerprint_sha256=? WHERE hostname=? AND is_leaf=1",
                ("c" * 64, HOST),
            )
            conn.commit()
        _create(estate, correlation_id="baseline-c", now=NOW + timedelta(hours=25))
        expire_renewal_leases(estate[0], now=NOW + timedelta(hours=49))
        with _connect(estate[0]) as conn:
            conn.execute(
                "UPDATE certificates SET fingerprint_sha256=? WHERE hostname=? AND is_leaf=1",
                (estate[4], HOST),
            )
            conn.commit()
        returned, _ = _create(
            estate, correlation_id="baseline-b-again", now=NOW + timedelta(hours=50)
        )
        with _connect(estate[0]) as conn:
            current = conn.execute(
                "SELECT * FROM renewal_attempts WHERE attempt_id=?", (returned.attempt_id,)
            ).fetchone()
        assert returned.attempt_id != first.attempt_id
        assert current["suppresses_stalled"] == 0
        observed = (returned.state, "no-remute")
    else:
        first, _ = _create(estate, correlation_id="lease-lapsed")
        expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24))
        opened, _ = _create(
            estate,
            "failed",
            correlation_id="lease-lapsed",
            now=NOW + timedelta(hours=25),
        )
        retry, _ = _create(
            estate,
            "failed",
            correlation_id="lease-lapsed",
            now=NOW + timedelta(hours=26),
        )
        with _connect(estate[0]) as conn:
            owner = conn.execute(
                "SELECT attempt_id FROM renewal_attempt_correlations "
                "WHERE correlation_id='lease-lapsed'"
            ).fetchone()[0]
        assert opened.attempt_id != first.attempt_id
        assert retry.attempt_id == opened.attempt_id == owner
        observed = (retry.state, retry.effect)

    assert row in {*range(1, 9), *range(15, 23)}
    assert all((initial, trigger))
    assert observed == (state, effect)


def test_started_failed_and_duplicate_reduction(estate):
    first, replay = _create(estate, correlation_id="attempt-1")
    assert not replay
    assert (first.state, first.effect) == ("open", "applied")
    duplicate, _ = _create(estate, correlation_id="another-producer")
    assert duplicate.attempt_id == first.attempt_id
    assert (duplicate.state, duplicate.effect) == ("open", "duplicate")
    failed, _ = _create(estate, "failed", correlation_id="attempt-1")
    assert failed.attempt_id == first.attempt_id
    assert (failed.state, failed.effect) == ("failed", "applied")
    again, _ = _create(estate, "failed", correlation_id="attempt-1")
    assert (again.state, again.effect) == ("failed", "no_change")


def test_failed_without_an_open_attempt_never_suppresses_stalled(estate):
    failed, _ = _create(estate, "failed")
    assert (failed.state, failed.effect) == ("failed", "applied")
    with _connect(estate[0]) as conn:
        attempt = conn.execute("SELECT * FROM renewal_attempts").fetchone()
    assert attempt["lease_expires_at"] is None
    assert attempt["suppresses_stalled"] == 0


def test_lease_never_extends_and_one_suppression_per_baseline(estate):
    first, _ = _create(estate)
    with _connect(estate[0]) as conn:
        before = dict(conn.execute("SELECT * FROM renewal_attempts").fetchone())
    _create(estate, now=NOW + timedelta(hours=12))
    with _connect(estate[0]) as conn:
        repeated = dict(conn.execute("SELECT * FROM renewal_attempts").fetchone())
    assert repeated["lease_expires_at"] == before["lease_expires_at"]
    assert repeated["opened_seq"] == before["opened_seq"]

    assert expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24)) == 1
    second, _ = _create(estate, now=NOW + timedelta(hours=25))
    assert second.attempt_id != first.attempt_id
    with _connect(estate[0]) as conn:
        current = conn.execute("SELECT * FROM renewal_attempts WHERE is_current=1").fetchone()
    assert current["state"] == "open"
    assert current["suppresses_stalled"] == 0


def test_out_of_order_timestamp_never_controls_reduction(estate):
    opened, _ = _create(estate, correlation_id="ordered", occurred_at="2026-09-27T12:00:00+00:00")
    failed, _ = _create(
        estate,
        "failed",
        correlation_id="ordered",
        occurred_at="2025-01-01T00:00:00+00:00",
    )
    auth = _auth("key-a", "prod")
    history = list_reports(
        estate[0],
        resolve_target(estate[0], auth, hostname=HOST, port=443),
        auth=auth,
        page=1,
        limit=50,
        now=NOW,
    )
    assert [item["report_id"] for item in history["items"]] == [
        failed.report_id,
        opened.report_id,
    ]
    assert failed.state == "failed"


def test_terminal_same_correlation_is_late_but_new_work_opens(estate):
    first, _ = _create(estate, correlation_id="cycle-1")
    _create(estate, "failed", correlation_id="cycle-1")
    late, _ = _create(estate, correlation_id="cycle-1")
    assert (late.attempt_id, late.state, late.effect) == (
        first.attempt_id,
        "failed",
        "ignored_late",
    )
    new, _ = _create(estate, correlation_id="cycle-2")
    assert new.attempt_id != first.attempt_id
    assert (new.state, new.effect) == ("open", "applied")


def test_old_correlation_stays_with_finished_attempt_after_new_cycle(estate):
    first, _ = _create(estate, correlation_id="cycle-1")
    _create(estate, "failed", correlation_id="cycle-1")
    second, _ = _create(estate, correlation_id="cycle-2")
    late, _ = _create(estate, correlation_id="cycle-1")

    assert second.attempt_id != first.attempt_id
    assert (late.attempt_id, late.state, late.effect) == (
        first.attempt_id,
        "failed",
        "ignored_late",
    )
    with _connect(estate[0]) as conn:
        attempts = conn.execute(
            "SELECT attempt_id,state,is_current FROM renewal_attempts ORDER BY opened_seq"
        ).fetchall()
    assert [(row["state"], row["is_current"]) for row in attempts] == [
        ("failed", 0),
        ("open", 1),
    ]


def test_correlation_ownership_survives_report_retention(estate):
    first, _ = _create(estate, correlation_id="cycle-1")
    _create(estate, "failed", correlation_id="cycle-1")
    _create(estate, correlation_id="cycle-2")
    with _connect(estate[0]) as conn:
        conn.execute("DELETE FROM renewal_reports WHERE attempt_id=?", (first.attempt_id,))
        conn.commit()

    late, _ = _create(estate, correlation_id="cycle-1")
    assert (late.attempt_id, late.state, late.effect) == (
        first.attempt_id,
        "failed",
        "ignored_late",
    )


def test_history_uses_each_reports_real_attempt_state(estate):
    auth = _auth("key-a", "prod")
    first, _ = _create(estate, correlation_id="cycle-1")
    _create(estate, "failed", correlation_id="cycle-1")
    second, _ = _create(estate, correlation_id="cycle-2")
    target = resolve_target(estate[0], auth, hostname=HOST, port=443)

    history = list_reports(estate[0], target, auth=auth, page=1, limit=50, now=NOW)
    states = {item["attempt_id"]: item["state"] for item in history["items"]}
    assert states[first.attempt_id] == "failed"
    assert states[second.attempt_id] == "open"


def test_cancelled_attempt_cannot_regrant_same_baseline_suppression(estate):
    first, _ = _create(estate, correlation_id="cycle-1")
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET state='cancelled',suppresses_stalled=0 WHERE attempt_id=?",
            (first.attempt_id,),
        )
        conn.commit()
    second, _ = _create(estate, correlation_id="cycle-2")
    with _connect(estate[0]) as conn:
        current = conn.execute(
            "SELECT * FROM renewal_attempts WHERE attempt_id=?", (second.attempt_id,)
        ).fetchone()
    assert current["suppresses_stalled"] == 0


def test_abandoned_failed_report_starts_a_new_failed_attempt(estate):
    first, _ = _create(estate, correlation_id="cycle-1")
    assert expire_renewal_leases(estate[0], now=NOW + timedelta(hours=24)) == 1
    failed, _ = _create(
        estate,
        "failed",
        correlation_id="cycle-1",
        now=NOW + timedelta(hours=25),
    )
    assert failed.attempt_id != first.attempt_id
    assert (failed.state, failed.effect) == ("failed", "applied")
    retry, _ = _create(
        estate,
        "failed",
        correlation_id="cycle-1",
        now=NOW + timedelta(hours=26),
    )
    assert (retry.attempt_id, retry.state, retry.effect) == (
        failed.attempt_id,
        "failed",
        "no_change",
    )


@pytest.mark.parametrize("terminal", ["verified", "cancelled"])
def test_terminal_attempt_new_correlation_starts_new_cycle(estate, terminal):
    first, _ = _create(estate, correlation_id="cycle-1")
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET state=?,suppresses_stalled=0 WHERE host_id=?",
            (terminal, estate[2]),
        )
        conn.commit()
    second, _ = _create(estate, correlation_id="cycle-2")
    assert second.attempt_id != first.attempt_id
    assert (second.state, second.effect) == ("open", "applied")


@pytest.mark.parametrize("initial", ["verifying", "not_deployed"])
def test_future_verification_state_accepts_newer_failure(estate, initial):
    first, _ = _create(estate)
    with _connect(estate[0]) as conn:
        conn.execute("UPDATE renewal_attempts SET state=? WHERE host_id=?", (initial, estate[2]))
        conn.commit()
    failed, _ = _create(estate, "failed")
    assert failed.attempt_id == first.attempt_id
    assert (failed.state, failed.effect) == ("failed", "applied")


def test_source_scoped_idempotency_and_collision(estate):
    a = _auth("key-a", "prod")
    b = _auth("key-b", "prod")
    first, replay = _create(estate, auth=a, idempotency_key="delivery-7", body_sha256="same")
    same, replay = _create(estate, auth=a, idempotency_key="delivery-7", body_sha256="same")
    assert replay and same == first
    with pytest.raises(RenewalReportConflictError, match="idempotency key reused"):
        _create(estate, auth=a, idempotency_key="delivery-7", body_sha256="different")
    cross_key, replay = _create(
        estate, auth=b, idempotency_key="delivery-7", body_sha256="different"
    )
    assert not replay and cross_key.report_id != first.report_id
    with _connect(estate[0]) as conn:
        assert (
            conn.execute(
                "SELECT count(*) FROM audit_log WHERE action='renewal_report.create'"
            ).fetchone()[0]
            == 2
        )


def test_idempotency_key_cannot_move_to_another_resolved_endpoint(estate):
    auth = _auth("key-a", "prod")
    _create(estate, auth=auth, idempotency_key="delivery-7", body_sha256="same")
    other_host = "second.example.test"
    estate[1].add(other_host, 443, tags="prod")
    seed_scanned(
        estate[0],
        other_host,
        443,
        parse_certificate(_make_cert(other_host, days_valid=60).der),
    )
    target = resolve_target(estate[0], auth, hostname=other_host, port=443)
    with pytest.raises(RenewalReportConflictError, match="idempotency key reused"):
        create_report(
            estate[0],
            estate[5],
            target,
            _report("started"),
            auth=auth,
            actor="api_key:key-a",
            source_ip=None,
            idempotency_key="delivery-7",
            body_sha256="same",
            now=NOW,
        )


def test_idempotency_rows_for_hidden_and_deleted_hosts_are_both_replaced(estate, report_client):
    client, headers, db = report_client
    moved_id = estate[1].add("moved.example.test", 443, tags="prod")
    deleted_id = estate[1].add("deleted.example.test", 443, tags="prod")
    replacement_ids = [
        estate[1].add("replacement-a.example.test", 443, tags="prod"),
        estate[1].add("replacement-b.example.test", 443, tags="prod"),
    ]
    for hostname in ("moved.example.test", "deleted.example.test"):
        response = client.post(
            "/api/renewal-reports",
            headers={**headers, "Idempotency-Key": f"old-{hostname}"},
            json={"hostname": hostname, "port": 443, "outcome": "failed"},
        )
        assert response.status_code == 202
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET tags='other' WHERE id=?", (moved_id,))
        conn.commit()
    assert estate[1].delete(deleted_id)

    responses = [
        client.post(
            "/api/renewal-reports",
            headers={**headers, "Idempotency-Key": f"old-{hostname}"},
            json={
                "hostname": replacement,
                "port": 443,
                "outcome": "started",
            },
        )
        for hostname, replacement in zip(
            ("moved.example.test", "deleted.example.test"),
            ("replacement-a.example.test", "replacement-b.example.test"),
            strict=True,
        )
    ]
    assert [response.status_code for response in responses] == [202, 202]
    normalized = [
        {
            key: value
            for key, value in response.json().items()
            if key not in {"report_id", "attempt_id"}
        }
        for response in responses
    ]
    assert normalized == [{"state": "open", "effect": "applied"}] * 2
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT key,host_id FROM renewal_idempotency WHERE key LIKE 'old-%' ORDER BY key"
        ).fetchall()
    assert [(row["key"], row["host_id"]) for row in rows] == [
        ("old-deleted.example.test", replacement_ids[1]),
        ("old-moved.example.test", replacement_ids[0]),
    ]


def test_service_accepts_succeeded_and_schedules_verification(estate):
    auth = _auth("key-a", "prod")
    target = resolve_target(estate[0], auth, hostname=HOST, port=443)
    result, replayed = create_report(
        estate[0], estate[5], target, _report("succeeded"), auth=auth,
        actor="api_key:key-a", source_ip=None, idempotency_key=None,
        body_sha256="succeeded", now=NOW,
    )
    assert replayed is False
    assert (result.state, result.effect) == ("verifying", "applied")
    with _connect(estate[0]) as conn:
        row = conn.execute(
            "SELECT state,next_check_at FROM renewal_attempts WHERE attempt_id=?",
            (result.attempt_id,),
        ).fetchone()
    assert tuple(row) == ("verifying", NOW.isoformat())


def test_succeeded_after_verified_is_stored_late_without_reopening(estate):
    first, _ = _create(estate, "succeeded")
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE renewal_attempts SET state='verified',next_check_at=NULL "
            "WHERE attempt_id=?",
            (first.attempt_id,),
        )
        conn.commit()
    late, _ = _create(estate, "succeeded", now=NOW + timedelta(minutes=1))
    assert (late.attempt_id, late.state, late.effect) == (
        first.attempt_id, "verified", "ignored_late"
    )


def test_binding_is_rechecked_before_replay(estate):
    auth = _auth("key-a", "prod")
    _create(estate, auth=auth, idempotency_key="once", body_sha256="body")
    with _connect(estate[0]) as conn:
        conn.execute("UPDATE hosts SET tags='other' WHERE id=?", (estate[2],))
        conn.commit()
    with pytest.raises(RenewalReportNotFoundError):
        resolve_target(estate[0], auth, hostname=HOST, port=443)


def test_binding_is_rechecked_inside_transition(estate):
    auth = _auth("key-a", "prod")
    target = resolve_target(estate[0], auth, hostname=HOST, port=443)
    with _connect(estate[0]) as conn:
        conn.execute("UPDATE hosts SET tags='other' WHERE id=?", (estate[2],))
        conn.commit()
    with pytest.raises(RenewalReportNotFoundError, match="endpoint not found"):
        create_report(
            estate[0],
            estate[5],
            target,
            _report("started"),
            auth=auth,
            actor="api_key:key-a",
            source_ip=None,
            idempotency_key=None,
            body_sha256="body",
            now=NOW,
        )
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 0


def test_unknown_out_of_binding_and_ambiguous_fingerprint(estate):
    bound = _auth("key", "prod")
    with pytest.raises(RenewalReportNotFoundError) as unknown:
        resolve_target(estate[0], bound, hostname="missing.example.test", port=443)
    with pytest.raises(RenewalReportNotFoundError) as hidden:
        resolve_target(estate[0], bound, hostname="other.example.test", port=443)
    assert str(unknown.value) == str(hidden.value) == "endpoint not found"

    SqliteHostRepository(estate[0]).add("shared.example.test", 443, tags="prod")
    with _connect(estate[0]) as conn:
        row = conn.execute("SELECT * FROM certificates WHERE hostname=?", (HOST,)).fetchone()
        columns = [r[1] for r in conn.execute("PRAGMA table_info(certificates)")]
        values = dict(row)
        values.update(id="shared-cert", hostname="shared.example.test")
        conn.execute(
            f"INSERT INTO certificates ({','.join(columns)}) VALUES "
            f"({','.join('?' for _ in columns)})",
            [values.get(column) for column in columns],
        )
        conn.commit()
    with pytest.raises(RenewalReportConflictError, match="more than one"):
        resolve_target(estate[0], bound, cert_fingerprint=estate[4])


def test_certificate_only_tag_does_not_bind_or_create_fingerprint_ambiguity(estate):
    bound = _auth("key", "prod")
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE certificates SET fingerprint_sha256=?,tags='prod' "
            "WHERE hostname='other.example.test' AND is_leaf=1",
            (estate[4],),
        )
        conn.commit()
    target = resolve_target(estate[0], bound, cert_fingerprint=estate[4])
    assert target.host_id == estate[2]


def test_two_current_leaves_use_newest_head_for_post_and_get(estate, report_client):
    client, headers, _db = report_client
    with _connect(estate[0]) as conn:
        original = dict(
            conn.execute(
                "SELECT * FROM certificates WHERE hostname=? AND is_leaf=1", (HOST,)
            ).fetchone()
        )
        original.update(
            id="newest-leaf",
            fingerprint_sha256="d" * 64,
            created_at="2099-01-01T00:00:00+00:00",
        )
        columns = tuple(original)
        conn.execute(
            f"INSERT INTO certificates ({','.join(columns)}) VALUES "
            f"({','.join('?' for _ in columns)})",
            [original[column] for column in columns],
        )
        conn.commit()

    target = resolve_target(estate[0], _auth("key", "prod"), hostname=HOST, port=443)
    assert target.baseline_fingerprint == "d" * 64
    posted = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    history = client.get(
        "/api/renewal-reports",
        headers=headers,
        params={"hostname": HOST, "port": 443},
    )
    assert posted.status_code == 202
    assert history.status_code == 200


def test_real_0038_alias_merge_remains_reportable(tmp_path):
    from cert_watch.migrations.m0038_canonical_hostnames import upgrade as upgrade_0038

    db = tmp_path / "alias-merge.sqlite3"
    init_schema(db)
    canonical = "alias.example.test"
    variant = "ALIAS.example.test."
    with _connect(db) as conn:
        added_at = NOW.isoformat()
        conn.execute(
            "INSERT INTO hosts (id,hostname,port,tags,added_at) VALUES (?,?,?,?,?)",
            ("alias-a", canonical, 443, "prod", added_at),
        )
        conn.execute(
            "INSERT INTO hosts (id,hostname,port,tags,added_at) VALUES (?,?,?,?,?)",
            ("alias-b", variant, 443, "prod", added_at),
        )
        conn.commit()
    seed_scanned(db, canonical, 443, parse_certificate(_make_cert(canonical).der))
    seed_scanned(db, variant, 443, parse_certificate(_make_cert(variant).der))
    with _connect(db) as conn:
        upgrade_0038(conn)
        conn.commit()
        assert (
            conn.execute(
                "SELECT count(*) FROM certificates WHERE hostname=? AND is_leaf=1",
                (canonical,),
            ).fetchone()[0]
            == 2
        )
    target = resolve_target(db, _auth("key", "prod"), hostname=canonical, port=443)
    assert target.host_id == "alias-a"


def test_recent_lineage_predecessor_fingerprint_targets_endpoint(estate):
    old_fingerprint = estate[4]
    seed_scanned(
        estate[0],
        HOST,
        443,
        parse_certificate(_make_cert(HOST, days_valid=90).der),
    )
    auth = _auth("key", "prod")
    assert resolve_target(estate[0], auth, cert_fingerprint=old_fingerprint).host_id == estate[2]
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE certificate_lineage SET created_at=? WHERE hostname=? AND port=443",
            ((datetime.now(UTC) - timedelta(days=8)).isoformat(), HOST),
        )
        conn.commit()
    with pytest.raises(RenewalReportNotFoundError):
        resolve_target(estate[0], auth, cert_fingerprint=old_fingerprint)


def test_migration_backfills_the_predecessor_not_the_replacement(estate):
    from cert_watch.migrations.m0046_renewal_reports import upgrade

    old_fingerprint = estate[4]
    replacement = parse_certificate(_make_cert(HOST, days_valid=90).der)
    seed_scanned(estate[0], HOST, 443, replacement)
    with _connect(estate[0]) as conn:
        conn.execute("UPDATE certificate_lineage SET old_fingerprint=NULL")
        upgrade(conn)
        value = conn.execute(
            "SELECT old_fingerprint FROM certificate_lineage WHERE hostname=? AND port=443",
            (HOST,),
        ).fetchone()[0]
    assert value == old_fingerprint
    assert value != replacement.fingerprint_sha256


def test_concurrent_keys_serialize_one_attempt(estate):
    def post(key: str):
        return _create(estate, auth=_auth(key, "prod"))[0]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(post, ("key-a", "key-b")))
    assert len({result.attempt_id for result in results}) == 1
    assert sorted(result.effect for result in results) == ["applied", "duplicate"]
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 2
        assert conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0] == 1


def test_history_redaction_and_report_key_ownership(estate):
    a = _auth("key-a", "prod")
    b = _auth("key-b", "prod")
    _create(
        estate,
        auth=a,
        message="private detail",
        tool="hook-a",
        correlation_id="corr-a",
    )
    _create(estate, auth=b, message="other detail", tool="hook-b")
    target = resolve_target(estate[0], a, hostname=HOST, port=443)
    own = list_reports(estate[0], target, auth=a, page=1, limit=50, now=NOW)
    assert own["total"] == 1
    assert own["items"][0]["message"] == "private detail"

    viewer = AuthContext.from_tier("viewer", "viewer", scope_tag="prod")
    redacted = list_reports(estate[0], target, auth=viewer, page=1, limit=50, now=NOW)
    assert redacted["total"] == 2
    assert {"message", "tool", "source", "correlation_id"}.isdisjoint(redacted["items"][0])

    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE certificates SET tags='certteam' WHERE hostname=? AND is_leaf=1",
            (HOST,),
        )
        conn.commit()
    cert_only_operator = AuthContext.from_tier(
        "cert-operator",
        "viewer",
        scope_tag="certteam",
        tag_tiers={"certteam": "operator"},
    )
    visible = resolve_history_target(estate[0], cert_only_operator, HOST, 443)
    cert_redacted = list_reports(
        estate[0], visible, auth=cert_only_operator, page=1, limit=50, now=NOW
    )
    assert {"message", "tool", "source", "correlation_id"}.isdisjoint(cert_redacted["items"][0])


def test_report_ids_are_opaque_across_endpoints_and_teams(estate):
    prod_auth = _auth("key-prod", "prod")
    other_auth = _auth("key-other", "other")
    first, _ = _create(estate, auth=prod_auth)
    other_target = resolve_target(estate[0], other_auth, hostname="other.example.test", port=443)
    other, _ = create_report(
        estate[0],
        estate[5],
        other_target,
        _report("started"),
        auth=other_auth,
        actor="api_key:key-other",
        source_ip=None,
        idempotency_key=None,
        body_sha256="other",
        now=NOW,
    )
    second, _ = _create(estate, auth=prod_auth)

    for result in (first, other, second):
        assert len(result.report_id) == 32
        int(result.report_id, 16)
    assert len({first.report_id, other.report_id, second.report_id}) == 3

    prod_target = resolve_target(estate[0], prod_auth, hostname=HOST, port=443)
    visible = list_reports(estate[0], prod_target, auth=prod_auth, page=1, limit=50, now=NOW)
    assert [item["report_id"] for item in visible["items"]] == [
        second.report_id,
        first.report_id,
    ]
    assert other.report_id not in {item["report_id"] for item in visible["items"]}
    with _connect(estate[0]) as conn:
        rows = conn.execute("SELECT seq,report_id FROM renewal_reports ORDER BY seq").fetchall()
    assert all(str(row["seq"]) != row["report_id"] for row in rows)


def test_report_id_is_not_reused_after_newest_report_is_deleted(estate):
    first, _ = _create(estate)
    with _connect(estate[0]) as conn:
        first_seq = conn.execute(
            "SELECT seq FROM renewal_reports WHERE report_id=?", (first.report_id,)
        ).fetchone()[0]
        conn.execute("DELETE FROM renewal_reports WHERE report_id=?", (first.report_id,))
        conn.commit()
    second, _ = _create(estate)
    with _connect(estate[0]) as conn:
        second_seq = conn.execute(
            "SELECT seq FROM renewal_reports WHERE report_id=?", (second.report_id,)
        ).fetchone()[0]
    assert second.report_id != first.report_id
    assert second_seq > first_seq


def test_renewal_report_sequence_is_internal_autoincrement(estate):
    with _connect(estate[0]) as conn:
        table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='renewal_reports'"
        ).fetchone()[0]
        columns = {row["name"]: row for row in conn.execute("PRAGMA table_info(renewal_reports)")}
        report_id_indexes = [
            row
            for row in conn.execute("PRAGMA index_list(renewal_reports)")
            if [item["name"] for item in conn.execute(f"PRAGMA index_info('{row['name']}')")]
            == ["report_id"]
        ]
    assert "seq INTEGER PRIMARY KEY AUTOINCREMENT" in table_sql
    assert columns["report_id"]["type"] == "TEXT"
    assert columns["report_id"]["notnull"] == 1
    assert len(report_id_indexes) == 1 and report_id_indexes[0]["unique"] == 1


def test_delete_then_readd_has_no_history(estate):
    auth = _auth("key-a", "prod")
    _create(estate, auth=auth, idempotency_key="delete-me", body_sha256="body")
    assert estate[1].delete(estate[2])
    new_id = estate[1].add(HOST, 443, tags="new-team")
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM renewal_attempt_correlations").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM renewal_idempotency").fetchone()[0] == 0
    assert new_id != estate[2]


def test_retention_keeps_newest_fifty_and_recent(estate):
    auth = _auth("key-a", "prod")
    for index in range(55):
        _create(estate, auth=auth, now=NOW - timedelta(days=400, minutes=index))
    _create(estate, auth=auth, now=NOW - timedelta(days=2))
    assert purge_renewal_reports(estate[0], 365, now=NOW) == 6
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 50


def test_retention_keeps_current_and_latest_lease_per_baseline(estate):
    old = NOW - timedelta(days=400)
    _create(estate, "failed", now=old - timedelta(minutes=1))
    _create(estate, correlation_id="baseline-b", now=old)
    _create(estate, "failed", correlation_id="baseline-b", now=old + timedelta(minutes=1))
    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE certificates SET fingerprint_sha256=? WHERE hostname=? AND is_leaf=1",
            ("c" * 64, HOST),
        )
        conn.commit()
    _create(estate, correlation_id="baseline-c", now=old + timedelta(minutes=2))
    _create(
        estate,
        "failed",
        correlation_id="baseline-c",
        now=old + timedelta(minutes=3),
    )

    purge_renewal_reports(estate[0], 30, now=NOW)
    with _connect(estate[0]) as conn:
        attempts = conn.execute(
            "SELECT baseline_fingerprint,is_current,lease_expires_at "
            "FROM renewal_attempts ORDER BY opened_seq"
        ).fetchall()
        assert len(attempts) == 3
        assert [row["baseline_fingerprint"] for row in attempts] == [
            estate[4],
            estate[4],
            "c" * 64,
        ]
        assert [row["is_current"] for row in attempts] == [0, 0, 1]
        assert attempts[0]["lease_expires_at"] is None
        assert all(row["lease_expires_at"] for row in attempts[1:])
        assert (
            conn.execute(
                """SELECT count(*) FROM renewal_reports r
               LEFT JOIN renewal_attempts a ON a.attempt_id=r.attempt_id
               WHERE a.attempt_id IS NULL"""
            ).fetchone()[0]
            == 0
        )
        assert conn.execute("SELECT count(*) FROM renewal_attempt_correlations").fetchone()[0] == 0

    with _connect(estate[0]) as conn:
        conn.execute(
            "UPDATE certificates SET fingerprint_sha256=? WHERE hostname=? AND is_leaf=1",
            (estate[4], HOST),
        )
        conn.commit()
    returned, _ = _create(estate, correlation_id="baseline-b-new", now=NOW)
    with _connect(estate[0]) as conn:
        suppresses = conn.execute(
            "SELECT suppresses_stalled FROM renewal_attempts WHERE attempt_id=?",
            (returned.attempt_id,),
        ).fetchone()[0]
    assert suppresses == 0


def test_aggressive_purge_preserves_retained_report_attempt_states(estate):
    old = NOW - timedelta(days=100)
    failed, _ = _create(estate, "failed", now=old)
    started, _ = _create(estate, correlation_id="current", now=old + timedelta(minutes=1))
    _create(
        estate,
        "failed",
        correlation_id="current",
        now=old + timedelta(minutes=2),
    )
    current, _ = _create(
        estate,
        correlation_id="replacement",
        now=old + timedelta(minutes=3),
    )

    purge_renewal_reports(estate[0], 1, now=NOW)
    auth = _auth("key-a", "prod")
    target = resolve_target(estate[0], auth, hostname=HOST, port=443)
    history = list_reports(estate[0], target, auth=auth, page=1, limit=50, now=NOW)
    states = {item["report_id"]: item["state"] for item in history["items"]}
    assert states[failed.report_id] == "failed"
    assert states[started.report_id] == "failed"
    assert states[current.report_id] == "abandoned"
    with _connect(estate[0]) as conn:
        assert (
            conn.execute(
                """SELECT count(*) FROM renewal_reports r
               LEFT JOIN renewal_attempts a ON a.attempt_id=r.attempt_id
               WHERE a.attempt_id IS NULL"""
            ).fetchone()[0]
            == 0
        )


def test_zero_retention_keeps_reports_but_idempotency_expires(estate):
    _create(
        estate,
        now=NOW - timedelta(days=8),
        idempotency_key="old",
        body_sha256="old-body",
    )
    assert purge_renewal_reports(estate[0], 0, now=NOW) == 0
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM renewal_idempotency").fetchone()[0] == 0


@pytest.fixture
def report_client(estate, monkeypatch):
    from cert_watch.app import create_app
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    db, _repo, _host, _other, _fp, settings = estate
    _, raw = SqliteApiKeyRepository(db).create_key(
        "renewal-hook", "renewal-report", binding="tags", bound_tags="prod"
    )
    app = create_app(settings=settings)
    route_module = importlib.import_module("cert_watch.routes.api.renewal_reports")
    monkeypatch.setattr(route_module, "check_rate_limit", lambda *_a: True)
    with TestClient(app) as client:
        yield client, {"Authorization": f"Bearer {raw}"}, db


@pytest.mark.parametrize(
    "message",
    ["bad\r\nheader", "direction\u202eoverride", "x" * 2001, "nul\x00byte"],
)
def test_route_rejects_hostile_messages(report_client, message):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "failed", "message": message},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("tool", ["bad tool", "x" * 65, 'x"}', "line\r\nbreak", "direction\u202e"])
def test_route_rejects_hostile_tools(report_client, tool):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "failed", "tool": tool},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    "correlation_id",
    ["has space", "line\r\nbreak", "nul\x00byte", "é", "", "x" * 129],
)
def test_route_rejects_non_printable_or_non_ascii_correlations(report_client, correlation_id):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={
            "hostname": HOST,
            "port": 443,
            "outcome": "failed",
            "correlation_id": correlation_id,
        },
    )
    assert response.status_code == 422


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", ""])
def test_route_requires_json_content_type(report_client, content_type):
    client, headers, _db = report_client
    request_headers = {**headers, "Content-Type": content_type}
    response = client.post(
        "/api/renewal-reports",
        headers=request_headers,
        content=json.dumps({"hostname": HOST, "port": 443, "outcome": "started"}),
    )
    assert response.status_code == 415


def test_route_accepts_json_content_type_charset(report_client):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers={**headers, "Content-Type": "application/json; charset=utf-8"},
        content=json.dumps({"hostname": HOST, "port": 443, "outcome": "started"}),
    )
    assert response.status_code == 202


def test_route_rejects_duplicate_idempotency_headers(report_client):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=[
            ("Authorization", headers["Authorization"]),
            ("Content-Type", "application/json"),
            ("Idempotency-Key", "one"),
            ("Idempotency-Key", "two"),
        ],
        content=json.dumps({"hostname": HOST, "port": 443, "outcome": "started"}),
    )
    assert response.status_code == 400
    assert response.json() == {"error": "duplicate Idempotency-Key header"}


def test_route_body_cap_precedes_json_parse(report_client):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers={**headers, "Content-Type": "application/json"},
        content=b"{" + b"x" * (16 * 1024),
    )
    assert response.status_code == 413
    assert response.content == b'{"error":"request body too large"}'


@pytest.mark.parametrize(
    "raw",
    [
        b'{"hostname":"renewal.example.test","hostname":"other.example.test",'
        b'"port":443,"outcome":"started"}',
        b'{"hostname":"renewal.example.test","port":443,"outcome":"started","message":NaN}',
    ],
)
def test_route_preserves_strict_json_rejections(report_client, raw):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers={**headers, "Content-Type": "application/json"},
        content=raw,
    )
    assert response.status_code == 422


def test_succeeded_is_accepted_and_stored(report_client):
    client, headers, db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "succeeded"},
    )
    assert response.status_code == 202
    assert response.json()["state"] == "verifying"
    with _connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 1


def test_succeeded_reserves_idempotency_key(report_client):
    client, headers, _db = report_client
    keyed = {**headers, "Idempotency-Key": "deploy-7"}
    accepted = client.post(
        "/api/renewal-reports",
        headers=keyed,
        json={"hostname": HOST, "port": 443, "outcome": "succeeded"},
    )
    conflict = client.post(
        "/api/renewal-reports",
        headers=keyed,
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    assert accepted.status_code == 202
    assert conflict.status_code == 409


def test_idempotency_hashes_the_canonical_validated_body(report_client):
    client, headers, _db = report_client
    keyed = {**headers, "Idempotency-Key": "canonical-1", "Content-Type": "application/json"}
    first = client.post(
        "/api/renewal-reports",
        headers=keyed,
        content=b'{"hostname":"renewal.example.test","port":443,"outcome":"started"}',
    )
    replay = client.post(
        "/api/renewal-reports",
        headers=keyed,
        content=b'{ "outcome": "started", "port": 443, "hostname": "renewal.example.test" }',
    )
    assert first.status_code == replay.status_code == 202
    assert first.content == replay.content
    report_id = first.json()["report_id"]
    assert len(report_id) == 32
    int(report_id, 16)
    history = client.get(
        "/api/renewal-reports",
        headers=headers,
        params={"hostname": HOST, "port": 443},
    )
    assert history.status_code == 200
    assert history.json()["items"][0]["report_id"] == report_id


def test_message_is_confined_to_report_storage(report_client, caplog):
    client, headers, db = report_client
    secret = 'private "message" <payload>'
    response = client.post(
        "/api/renewal-reports",
        headers={**headers, "Idempotency-Key": "msg-1"},
        json={
            "hostname": HOST,
            "port": 443,
            "outcome": "failed",
            "message": secret,
            "tool": "renew-tool",
        },
    )
    assert response.status_code == 202
    assert secret not in caplog.text
    with _connect(db) as conn:
        audit = conn.execute(
            "SELECT detail FROM audit_log WHERE action='renewal_report.create'"
        ).fetchone()
        assert secret not in audit["detail"]
        assert json.loads(audit["detail"])["message_len"] == len(secret)
        assert (
            conn.execute(
                "SELECT count(*) FROM event_log WHERE payload LIKE ?", (f"%{secret}%",)
            ).fetchone()[0]
            == 0
        )


def test_get_is_newest_first_and_succeeded_does_not_consume_idempotency(report_client):
    client, headers, _db = report_client
    for outcome in ("started", "failed"):
        assert (
            client.post(
                "/api/renewal-reports",
                headers=headers,
                json={"hostname": HOST, "port": 443, "outcome": outcome},
            ).status_code
            == 202
        )
    response = client.get(
        "/api/renewal-reports",
        headers=headers,
        params={"hostname": HOST, "port": 443, "limit": 1},
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert response.json()["items"][0]["outcome"] == "failed"


@pytest.mark.parametrize("params", [{"page": 10_001}, {"limit": 101}])
def test_get_bounds_pagination(report_client, params):
    client, headers, _db = report_client
    response = client.get(
        "/api/renewal-reports",
        headers=headers,
        params={"hostname": HOST, "port": 443, **params},
    )
    assert response.status_code == 422


def test_service_bounds_pagination(estate):
    auth = _auth("key-a", "prod")
    target = resolve_target(estate[0], auth, hostname=HOST, port=443)
    result = list_reports(estate[0], target, auth=auth, page=10**30, limit=10**30, now=NOW)
    assert (result["page"], result["limit"], result["items"]) == (10_000, 100, [])


def test_new_correlation_daily_cap_uses_standard_429_shape(report_client):
    client, headers, db = report_client
    seeded = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={
            "hostname": HOST,
            "port": 443,
            "outcome": "started",
            "correlation_id": "corr-0",
        },
    )
    assert seeded.status_code == 202
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT host_id,source,attempt_id,created_at FROM renewal_attempt_correlations"
        ).fetchone()
        conn.executemany(
            """INSERT INTO renewal_attempt_correlations
               (host_id,source,correlation_id,attempt_id,created_at)
               VALUES (?,?,?,?,?)""",
            [
                (
                    row["host_id"],
                    row["source"],
                    f"corr-{index}",
                    row["attempt_id"],
                    row["created_at"],
                )
                for index in range(1, 1_000)
            ],
        )
        conn.commit()
    limited = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={
            "hostname": HOST,
            "port": 443,
            "outcome": "started",
            "correlation_id": "corr-over-limit",
        },
    )
    assert (limited.status_code, limited.content) == (429, b'{"error":"rate limited"}')


def test_newest_leaf_lookup_index_is_installed(estate):
    with _connect(estate[0]) as conn:
        columns = [
            row["name"]
            for row in conn.execute("PRAGMA index_info('idx_certificates_endpoint_leaf_head')")
        ]
    assert columns == ["hostname", "port", "is_leaf", "source", "created_at"]


@pytest.mark.parametrize("failure_site", ["resolve_history_target", "list_reports"])
def test_get_maps_every_service_refusal_to_404(report_client, monkeypatch, failure_site):
    client, headers, _db = report_client
    route_module = importlib.import_module("cert_watch.routes.api.renewal_reports")

    def refuse(*_args, **_kwargs):
        raise RenewalReportConflictError("deliberately hidden")

    monkeypatch.setattr(route_module, failure_site, refuse)
    response = client.get(
        "/api/renewal-reports",
        headers=headers,
        params={"hostname": HOST, "port": 443},
    )
    assert response.status_code == 404
    assert response.json() == {"error": "endpoint not found"}


def test_delete_readd_under_another_team_has_empty_get_history(report_client):
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    client, headers, db = report_client
    assert (
        client.post(
            "/api/renewal-reports",
            headers=headers,
            json={"hostname": HOST, "port": 443, "outcome": "started"},
        ).status_code
        == 202
    )
    host_repo = SqliteHostRepository(db)
    old = host_repo.get_by_endpoint(HOST, 443)
    assert old is not None and host_repo.delete(old.id)
    host_repo.add(HOST, 443, tags="new-team")
    _, new_raw = SqliteApiKeyRepository(db).create_key(
        "new-team-hook", "renewal-report", binding="tags", bound_tags="new-team"
    )
    response = client.get(
        "/api/renewal-reports",
        headers={"Authorization": f"Bearer {new_raw}"},
        params={"hostname": HOST, "port": 443},
    )
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert response.json()["total"] == 0


def test_route_404s_are_identical_for_missing_hidden_and_lost_binding(report_client):
    client, headers, db = report_client
    missing = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": "missing.example.test", "port": 443, "outcome": "started"},
    )
    hidden = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": "other.example.test", "port": 443, "outcome": "started"},
    )
    accepted = client.post(
        "/api/renewal-reports",
        headers={**headers, "Idempotency-Key": "replay"},
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    assert accepted.status_code == 202
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET tags='other' WHERE hostname=?", (HOST,))
        conn.commit()
    lost = client.post(
        "/api/renewal-reports",
        headers={**headers, "Idempotency-Key": "replay"},
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    assert (missing.status_code, missing.content) == (hidden.status_code, hidden.content)
    assert (hidden.status_code, hidden.content) == (lost.status_code, lost.content)
    assert lost.content == b'{"error":"endpoint not found"}'


def test_rate_limits_charge_key_then_resolved_endpoint(report_client, monkeypatch):
    client, headers, _db = report_client
    route_module = importlib.import_module("cert_watch.routes.api.renewal_reports")
    charged: list[str] = []

    def record(key, *_args):
        charged.append(key)
        return True

    monkeypatch.setattr(route_module, "check_rate_limit", record)
    malformed = client.post("/api/renewal-reports", headers=headers, json={"outcome": "started"})
    assert malformed.status_code == 422
    assert len(charged) == 1 and charged[0].startswith("renewal_report:")
    charged.clear()
    hidden = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": "other.example.test", "port": 443, "outcome": "started"},
    )
    assert hidden.status_code == 404
    assert len(charged) == 1
    charged.clear()
    accepted = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    assert accepted.status_code == 202
    assert len(charged) == 2
    assert charged[1].startswith("renewal_report_endpoint:")
