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


# The S2 subset of Opus table B. Rows needing verification or the S3 manual
# compatibility path remain explicit unavailable rows rather than disappearing
# from the executable design record.
NORMATIVE_TRANSITIONS = (
    (1, "none", "started", "open", "applied"),
    (2, "open", "started", "open", "duplicate"),
    (3, "open", "lease_lapses", "abandoned", "timer"),
    (4, "none", "failed", "failed", "applied"),
    (5, "failed", "failed", "failed", "no_change"),
    (6, "any", "succeeded", "unavailable", "503"),
    (7, "verifying", "succeeded", "unavailable", "503"),
    (8, "verifying", "failed", "failed", "applied"),
    (15, "live", "cancelled", "unavailable", "S3-manual"),
    (16, "open", "occurred_at_before_failed", "failed", "received-order"),
    (17, "terminal", "same_correlation_started", "abandoned", "ignored_late"),
    (18, "any", "endpoint_deleted", "none", "cascade"),
    (19, "any", "tags_changed", "unchanged", "404-to-old-key"),
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
        response = client.post(
            "/api/renewal-reports",
            headers=headers,
            json={"hostname": HOST, "port": 443, "outcome": "succeeded"},
        )
        assert response.status_code == 503
        observed = ("unavailable", "503")
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
        result, _ = _create(
            estate, "failed", occurred_at="2025-01-01T00:00:00+00:00"
        )
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
    else:
        _create(estate)
        with _connect(estate[0]) as conn:
            conn.execute("UPDATE hosts SET tags='other' WHERE id=?", (estate[2],))
            conn.commit()
        with pytest.raises(RenewalReportNotFoundError):
            resolve_target(estate[0], _auth("key-a", "prod"), hostname=HOST, port=443)
        observed = ("unchanged", "404-to-old-key")

    assert row in {*range(1, 9), *range(15, 20)}
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
        current = conn.execute("SELECT * FROM renewal_attempts").fetchone()
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
    assert failed.report_id > opened.report_id
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
        conn.execute(
            "UPDATE renewal_attempts SET state=? WHERE host_id=?", (initial, estate[2])
        )
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
    _create(estate, auth=a, message="private detail", tool="hook-a")
    _create(estate, auth=b, message="other detail", tool="hook-b")
    target = resolve_target(estate[0], a, hostname=HOST, port=443)
    own = list_reports(estate[0], target, auth=a, page=1, limit=50, now=NOW)
    assert own["total"] == 1
    assert own["items"][0]["message"] == "private detail"

    viewer = AuthContext.from_tier("viewer", "viewer", scope_tag="prod")
    redacted = list_reports(estate[0], target, auth=viewer, page=1, limit=50, now=NOW)
    assert redacted["total"] == 2
    assert {"message", "tool", "source"}.isdisjoint(redacted["items"][0])


def test_delete_then_readd_has_no_history(estate):
    auth = _auth("key-a", "prod")
    _create(estate, auth=auth, idempotency_key="delete-me", body_sha256="body")
    assert estate[1].delete(estate[2])
    new_id = estate[1].add(HOST, 443, tags="new-team")
    with _connect(estate[0]) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 0
        assert conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0] == 0
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


@pytest.mark.parametrize(
    "tool", ["bad tool", "x" * 65, 'x"}', "line\r\nbreak", "direction\u202e"]
)
def test_route_rejects_hostile_tools(report_client, tool):
    client, headers, _db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "failed", "tool": tool},
    )
    assert response.status_code == 422


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


def test_succeeded_is_unavailable_and_stores_nothing(report_client):
    client, headers, db = report_client
    response = client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "succeeded"},
    )
    assert response.status_code == 503
    assert response.json() == {"error": "renewal verification is not available yet"}
    with _connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_reports").fetchone()[0] == 0


def test_succeeded_does_not_reserve_idempotency_key(report_client):
    client, headers, _db = report_client
    keyed = {**headers, "Idempotency-Key": "deploy-7"}
    unavailable = client.post(
        "/api/renewal-reports",
        headers=keyed,
        json={"hostname": HOST, "port": 443, "outcome": "succeeded"},
    )
    accepted = client.post(
        "/api/renewal-reports",
        headers=keyed,
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    )
    assert unavailable.status_code == 503
    assert accepted.status_code == 202


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


def test_delete_readd_under_another_team_has_empty_get_history(report_client):
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    client, headers, db = report_client
    assert client.post(
        "/api/renewal-reports",
        headers=headers,
        json={"hostname": HOST, "port": 443, "outcome": "started"},
    ).status_code == 202
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
