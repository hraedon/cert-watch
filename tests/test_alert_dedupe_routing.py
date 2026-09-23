"""Plan 058 PR 4: endpoint dedupe, closure, routing, and event rules."""

from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.alerting.rules.drift import create_drift_alert
from cert_watch.alerting.rules.expiry import evaluate_all_certs, evaluate_thresholds
from cert_watch.alerting.rules.policy import evaluate_policy_alerts
from cert_watch.alerting.rules.renewal import evaluate_renewal_window
from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Alert,
    AlertStore,
    DriftEvent,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteHostRepository,
    delete_certificate_cascade,
    init_schema,
)
from cert_watch.database.cert_ops import replace_scanned
from cert_watch.database.connection import _connect
from cert_watch.database.users_roles import (
    Role,
    SqliteRoleRepository,
    SqliteUserRepository,
    User,
)
from cert_watch.policy import PolicyViolation
from cert_watch.routing_report import build_routing_report
from tests._helpers import seed_certificate

HOST = "matrix.example.test"
PORT = 443


def _cert(fingerprint: str, *, days_left: int = 10) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={HOST}",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=80),
        not_after=now + timedelta(days=days_left),
        san_dns_names=[HOST],
        fingerprint_sha256=fingerprint,
        raw_der=fingerprint.encode(),
        is_leaf=True,
    )


def _count(db, alert_type: str) -> int:
    with _connect(db) as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE alert_type = ?", (alert_type,)
        ).fetchone()[0]


def test_expiry_matrix_never_refires_key_but_new_fingerprint_fires(tmp_path):
    db = tmp_path / "expiry.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    first = _cert("aa" * 32)
    seed_certificate(db, first, cert_id="row-a", hostname=HOST, port=PORT)

    [alert] = evaluate_thresholds(first, repo, cert_id="row-a")
    assert _count(db, "expiry_warning") == 1
    AlertStore(db).set_sent(alert.id)
    assert evaluate_thresholds(first, repo, cert_id="row-a") == []
    assert _count(db, "expiry_warning") == 1

    AlertStore(db).close_keys({alert.dedupe_key or ""})
    assert evaluate_thresholds(first, repo, cert_id="row-a") == []
    assert _count(db, "expiry_warning") == 1

    renewed = _cert("bb" * 32)
    seed_certificate(
        db, renewed, cert_id="row-b", hostname=HOST, port=PORT,
        replaces_cert_id="row-a",
    )
    assert len(evaluate_thresholds(renewed, repo, cert_id="row-b")) == 1
    assert _count(db, "expiry_warning") == 2


def test_renewal_stalled_matrix_fires_once_per_fingerprint(tmp_path):
    db = tmp_path / "renewal.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, PORT)
    first = _cert("cc" * 32, days_left=20)
    seed_certificate(db, first, cert_id="row-c", hostname=HOST, port=PORT)
    repo = SqliteAlertRepository(db)

    [alert] = evaluate_renewal_window(db, repo, 30)
    assert _count(db, "renewal_stalled") == 1
    AlertStore(db).set_sent(alert.id)
    assert evaluate_renewal_window(db, repo, 30) == []
    assert _count(db, "renewal_stalled") == 1

    with _connect(db) as conn:
        conn.execute(
            "UPDATE hosts SET renewal_status = 'in_progress' WHERE hostname = ?",
            (HOST,),
        )
        conn.commit()
    assert evaluate_renewal_window(db, repo, 30) == []
    assert _count(db, "renewal_stalled") == 1
    with _connect(db) as conn:
        closed = conn.execute(
            "SELECT closed_at FROM alerts WHERE id = ?", (alert.id,)
        ).fetchone()[0]
        conn.execute(
            "UPDATE hosts SET renewal_status = 'pending' WHERE hostname = ?", (HOST,)
        )
        conn.commit()
    assert closed is not None
    assert evaluate_renewal_window(db, repo, 30) == []
    assert _count(db, "renewal_stalled") == 1

    second = _cert("dd" * 32, days_left=20)
    seed_certificate(
        db, second, cert_id="row-d", hostname=HOST, port=PORT,
        replaces_cert_id="row-c",
    )
    assert len(evaluate_renewal_window(db, repo, 30)) == 1
    assert _count(db, "renewal_stalled") == 2


def test_policy_matrix_refires_after_clear_and_on_new_fingerprint(tmp_path):
    db = tmp_path / "policy.sqlite3"
    init_schema(db)
    first = _cert("ee" * 32)
    seed_certificate(db, first, cert_id="row-e", hostname=HOST, port=PORT)
    violation = PolicyViolation("rsa", "critical", "small key", "replace")

    [alert] = evaluate_policy_alerts("row-e", HOST, [violation], db)
    AlertStore(db).set_sent(alert.id)
    assert evaluate_policy_alerts("row-e", HOST, [violation], db) == []
    assert _count(db, "policy_violation") == 1
    evaluate_policy_alerts("row-e", HOST, [], db)
    assert _count(db, "policy_violation") == 1
    assert len(evaluate_policy_alerts("row-e", HOST, [violation], db)) == 1
    assert _count(db, "policy_violation") == 2

    second = _cert("ff" * 32)
    seed_certificate(
        db, second, cert_id="row-f", hostname=HOST, port=PORT,
        replaces_cert_id="row-e",
    )
    assert len(evaluate_policy_alerts("row-f", HOST, [violation], db)) == 1
    assert _count(db, "policy_violation") == 3


def test_drift_edge_matrix_and_new_fingerprint(tmp_path):
    db = tmp_path / "drift.sqlite3"
    init_schema(db)
    first = _cert("11" * 32)
    seed_certificate(db, first, cert_id="row-1", hostname=HOST, port=PORT)
    events = [DriftEvent("issuer", "old", "new", "high")]

    first_id = create_drift_alert(db, "row-1", HOST, PORT, events)
    assert first_id is not None
    assert create_drift_alert(db, "row-1", HOST, PORT, events) is None
    AlertStore(db).set_sent(first_id)
    assert create_drift_alert(db, "row-1", HOST, PORT, []) is None
    assert _count(db, "drift") == 1
    assert create_drift_alert(db, "row-1", HOST, PORT, events) is not None
    assert _count(db, "drift") == 2

    second = _cert("22" * 32)
    seed_certificate(
        db, second, cert_id="row-2", hostname=HOST, port=PORT,
        replaces_cert_id="row-1",
    )
    assert create_drift_alert(db, "row-2", HOST, PORT, events) is not None
    assert _count(db, "drift") == 3


def test_renewal_overdue_rule_firing_has_24_hour_cadence(tmp_path):
    db = tmp_path / "overdue.sqlite3"
    init_schema(db)
    store = AlertStore(db)
    start = datetime(2026, 9, 22, tzinfo=UTC)
    key = f"overdue:{HOST}:{PORT}:fingerprint"
    assert store.claim_rule_firing(key, now=start, interval_seconds=86400)
    assert not store.claim_rule_firing(
        key, now=start + timedelta(hours=23), interval_seconds=86400,
    )
    assert store.claim_rule_firing(
        key, now=start + timedelta(hours=24), interval_seconds=86400,
    )
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT first_fired_at, last_fired_at, fire_count FROM rule_firings"
        ).fetchone()
    assert row["first_fired_at"] == start.isoformat()
    assert row["last_fired_at"] == (start + timedelta(hours=24)).isoformat()
    assert row["fire_count"] == 2


def test_racing_enqueue_creates_one_open_row(tmp_path):
    db = tmp_path / "race.sqlite3"
    init_schema(db)

    def enqueue(index: int) -> str | None:
        return AlertStore(db).enqueue(Alert(
            cert_id="row",
            alert_type="policy_violation",
            status="pending",
            message=f"race {index}",
            dedupe_key="policy:fingerprint:rule",
        ))

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(enqueue, range(8)))
    assert sum(result is not None for result in results) == 1
    assert _count(db, "policy_violation") == 1


def test_endpoint_bound_rules_do_not_dedupe_shared_certificate_routes(tmp_path):
    db = tmp_path / "shared-routes.sqlite3"
    init_schema(db)
    repo = SqliteAlertRepository(db)
    fingerprint = "23" * 32
    for hostname, owner in (
        ("first.example.test", "first@example.invalid"),
        ("second.example.test", "second@example.invalid"),
    ):
        SqliteHostRepository(db).add(hostname, PORT, owner_email=owner)
        replace_scanned(db, hostname, PORT, _cert(fingerprint), [], True)

    expiry = evaluate_all_certs(db, repo)
    renewal = evaluate_renewal_window(db, repo, 30)
    violation = PolicyViolation("rsa", "critical", "small key", "replace")
    with _connect(db) as conn:
        leaves = conn.execute(
            "SELECT id, hostname FROM certificates WHERE is_leaf = 1 ORDER BY hostname"
        ).fetchall()
    policy = [
        alert
        for leaf in leaves
        for alert in evaluate_policy_alerts(
            leaf["id"], leaf["hostname"], [violation], db
        )
    ]

    for alerts in (expiry, renewal, policy):
        assert [alert.hostname for alert in alerts] == [
            "first.example.test", "second.example.test",
        ]
        assert [alert.extra_recipients for alert in alerts] == [
            ["first@example.invalid"], ["second@example.invalid"],
        ]
        assert len({alert.dedupe_key for alert in alerts}) == 2

    snapshot = tmp_path / "shared-routes-snapshot.sqlite3"
    with sqlite3.connect(db) as source, sqlite3.connect(snapshot) as target:
        source.backup(target)
    reported = {
        row["hostname"]: row["recipients"]
        for row in build_routing_report(snapshot)["certificates"]
    }
    assert reported == {
        alert.hostname: alert.extra_recipients for alert in expiry
    }


def test_cancelled_lifetime_row_does_not_suppress_recreated_condition(tmp_path):
    db = tmp_path / "cancelled-lifetime.sqlite3"
    init_schema(db)
    store = AlertStore(db)
    key = "expiry:host.example.test:443:fingerprint:expired:1"
    first = Alert(
        cert_id="deleted-row", alert_type="expired", status="pending",
        message="first", dedupe_key=key,
    )
    assert store.enqueue(first, lifetime=True)
    assert store.cancel(first.id, reason="certificate deleted")

    replacement = Alert(
        cert_id="replacement-row", alert_type="expired", status="pending",
        message="replacement", dedupe_key=key,
    )
    assert store.enqueue(replacement, lifetime=True) is not None


def test_unrelated_enqueue_integrity_error_is_not_misreported_as_dedupe(tmp_path):
    db = tmp_path / "integrity.sqlite3"
    init_schema(db)
    store = AlertStore(db)
    first = Alert(
        id="same-id", cert_id="row", alert_type="policy_violation",
        status="pending", message="first", dedupe_key="policy:one:rule",
    )
    second = Alert(
        id="same-id", cert_id="row", alert_type="policy_violation",
        status="pending", message="second", dedupe_key="policy:two:rule",
    )
    assert store.enqueue(first)
    with pytest.raises(sqlite3.IntegrityError, match=r"alerts\.id"):
        store.enqueue(second)


def test_failed_closed_drift_alert_can_be_retried(tmp_path):
    db = tmp_path / "drift-retry.sqlite3"
    init_schema(db)
    cert = _cert("24" * 32)
    seed_certificate(db, cert, cert_id="drift-row", hostname=HOST, port=PORT)
    alert_id = create_drift_alert(
        db, "drift-row", HOST, PORT,
        [DriftEvent("issuer", "old", "new", "high")],
    )
    assert alert_id is not None
    store = AlertStore(db)
    store.set_failed(alert_id, "delivery failed")

    assert store.operator_retry(alert_id, auth=AuthContext.system())
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT status, closed_at FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
    assert row["status"] == "pending"
    assert row["closed_at"] is not None


def test_empty_fingerprint_policy_uses_certificate_identity_for_dedupe(tmp_path):
    db = tmp_path / "empty-fingerprint.sqlite3"
    init_schema(db)
    cert = _cert("")
    seed_certificate(db, cert, cert_id="empty-fp-row", hostname=HOST, port=PORT)
    violation = PolicyViolation("rsa", "warning", "small key", "replace")

    [created] = evaluate_policy_alerts("empty-fp-row", HOST, [violation], db)
    assert created.dedupe_key is not None
    assert evaluate_policy_alerts("empty-fp-row", HOST, [violation], db) == []


def test_policy_and_drift_persist_same_group_owner_role_route(tmp_path):
    db = tmp_path / "routing.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, PORT, owner_email="owner@example.invalid")
    cert = _cert("33" * 32)
    seed_certificate(db, cert, cert_id="route-row", hostname=HOST, port=PORT)
    groups = SqliteAlertGroupRepository(db)
    group_id = groups.create("Ops", ["group@example.invalid"], [])
    groups.assign_cert(group_id, "route-row")
    role_id = SqliteRoleRepository(db).add(
        Role(name="Owners", email="owner@example.invalid")
    )
    SqliteUserRepository(db).add(
        User(username="member", email="member@example.invalid", role_id=role_id)
    )

    violation = PolicyViolation("rsa", "warning", "small key", "replace")
    [policy] = evaluate_policy_alerts("route-row", HOST, [violation], db)
    drift_id = create_drift_alert(
        db, "route-row", HOST, PORT,
        [DriftEvent("issuer", "old", "new", "high")],
    )
    assert drift_id is not None
    drift = next(
        alert for alert in SqliteAlertRepository(db).list_for_cert("route-row")
        if alert.id == drift_id
    )
    for alert in (policy, drift):
        assert alert.extra_recipients == [
            "group@example.invalid", "owner@example.invalid",
            "member@example.invalid",
        ]
        assert alert.routing["groups"] == [{"id": group_id, "name": "Ops"}]
        assert alert.routing["version"] == 1


def test_live_leases_survive_replacement_and_certificate_delete(tmp_path):
    db = tmp_path / "leases.sqlite3"
    init_schema(db)
    first_id, _, _ = replace_scanned(db, HOST, PORT, _cert("44" * 32), [], True)
    store = AlertStore(db)
    first_alert = Alert(
        cert_id=first_id, alert_type="expiry_warning", status="pending",
        message="leased", dedupe_key="expiry:44:expiry_warning:14",
    )
    assert store.enqueue(first_alert)
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET status='sending', lease_owner='worker', "
            "lease_expires_at=? WHERE id=?",
            (future, first_alert.id),
        )
        conn.commit()

    replace_scanned(db, HOST, PORT, _cert("55" * 32), [], True)
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT status, lease_owner, closed_at FROM alerts WHERE id = ?",
            (first_alert.id,),
        ).fetchone()
    assert tuple(row[:2]) == ("sending", "worker")
    assert row["closed_at"] is not None

    other_id, _, _ = replace_scanned(
        db, "delete.example.test", PORT, _cert("66" * 32), [], True,
    )
    other_alert = Alert(
        cert_id=other_id, alert_type="policy_violation", status="pending",
        message="leased delete", dedupe_key="policy:66:rule",
    )
    assert store.enqueue(other_alert)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET status='sending', lease_owner='worker', "
            "lease_expires_at=? WHERE id=?",
            (future, other_alert.id),
        )
        conn.commit()
    assert delete_certificate_cascade(db, other_id)
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT status, lease_owner, closed_at FROM alerts WHERE id = ?",
            (other_alert.id,),
        ).fetchone()
    assert tuple(row[:2]) == ("sending", "worker")
    assert row["closed_at"] is not None

    assert store.complete_pending(
        other_alert.id,
        lease_owner="worker",
        attempts=0,
        now=datetime.now(UTC),
        next_attempt_at=None,
    )
    with _connect(db) as conn:
        settled = conn.execute(
            "SELECT status, closed_at FROM alerts WHERE id = ?",
            (other_alert.id,),
        ).fetchone()
    assert settled["status"] == "cancelled"
    assert settled["closed_at"] is not None


def test_claim_cancels_stale_alert_after_live_lease_expires(tmp_path):
    db = tmp_path / "stale-claim.sqlite3"
    init_schema(db)
    cert_id, _, _ = replace_scanned(db, HOST, PORT, _cert("25" * 32), [], True)
    store = AlertStore(db)
    alert = Alert(
        cert_id=cert_id, alert_type="expiry_warning", status="pending",
        message="leased", dedupe_key="expiry:stale",
    )
    assert store.enqueue(alert)
    lease_expiry = datetime.now(UTC) + timedelta(minutes=1)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET status='sending', lease_owner='dead', "
            "lease_expires_at=? WHERE id=?",
            (lease_expiry.isoformat(), alert.id),
        )
        conn.commit()
    assert delete_certificate_cascade(db, cert_id)

    claimed = store.claim(
        lease_owner="replacement-worker",
        lease_expires_at=lease_expiry + timedelta(minutes=6),
        now=lease_expiry + timedelta(minutes=1),
    )
    assert claimed == []
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT status, closed_at FROM alerts WHERE id = ?", (alert.id,)
        ).fetchone()
    assert row["status"] == "cancelled"
    assert row["closed_at"] is not None


def test_replacement_cancels_stale_pending_instead_of_deleting(tmp_path):
    db = tmp_path / "cancel-replace.sqlite3"
    init_schema(db)
    old_id, _, _ = replace_scanned(db, HOST, PORT, _cert("88" * 32), [], True)
    alert = Alert(
        cert_id=old_id,
        alert_type="policy_violation",
        status="pending",
        message="stale",
        dedupe_key=f"policy:{'88' * 32}:rule",
    )
    assert AlertStore(db).enqueue(alert)

    replace_scanned(db, HOST, PORT, _cert("99" * 32), [], True)

    [closed] = SqliteAlertRepository(db).list_for_cert(old_id)
    assert closed.status == "cancelled"
    assert closed.closed_at is not None


def test_replacement_cancels_abandoned_sending_row_without_a_live_lease(tmp_path):
    db = tmp_path / "cancel-abandoned.sqlite3"
    init_schema(db)
    old_id, _, _ = replace_scanned(db, HOST, PORT, _cert("ab" * 32), [], True)
    alert = Alert(
        cert_id=old_id,
        alert_type="policy_violation",
        status="pending",
        message="abandoned",
        dedupe_key=f"policy:{'ab' * 32}:rule",
    )
    assert AlertStore(db).enqueue(alert)
    with _connect(db) as conn:
        conn.execute(
            "UPDATE alerts SET status='sending', lease_owner='lost', "
            "lease_expires_at=NULL WHERE id=?",
            (alert.id,),
        )
        conn.commit()

    replace_scanned(db, HOST, PORT, _cert("cd" * 32), [], True)

    [closed] = SqliteAlertRepository(db).list_for_cert(old_id)
    assert closed.status == "cancelled"
    assert closed.closed_at is not None

def test_migration_0037_backfills_and_collapses_real_upgraded_database(tmp_path):
    import cert_watch.migrations.registry  # noqa: F401
    from cert_watch.migrations.runner import run_pending_migrations

    db = tmp_path / "pre-0037.sqlite3"
    init_schema(db)
    cert = _cert("77" * 32)
    seed_certificate(db, cert, cert_id="old-a", hostname=HOST, port=PORT)
    seed_certificate(db, cert, cert_id="old-a-duplicate", hostname=HOST, port=PORT)
    seed_certificate(
        db, cert, cert_id="old-b", hostname="second.example.test", port=8443,
    )
    with _connect(db) as conn:
        conn.executemany(
            """INSERT INTO alerts
               (id, cert_id, alert_type, status, message, threshold_days,
                extra_recipients, created_at, hostname, subject, trigger_cert_id)
               VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, '', ?)""",
            [
                ("oldest", "old-a", "expiry_warning", "expiry", 14,
                 '["ops@example.invalid"]', "2026-01-01", HOST, "old-a"),
                ("newer", "old-a-duplicate", "expiry_warning", "expiry", 14,
                 "[]", "2026-01-02", HOST, "old-b"),
                ("shared", "old-b", "expiry_warning", "expiry", 14,
                 '["second@example.invalid"]', "2026-01-02",
                 "second.example.test", "old-b"),
                ("policy", "old-a", "policy_violation",
                 "Policy violation (warning) [rsa]: weak", None,
                 "[]", "2026-01-03", HOST, "old-a"),
                ("policy-duplicate", "old-a-duplicate", "policy_violation",
                 "Policy violation (warning) [rsa]: weak", None,
                 "[]", "2026-01-03", HOST, "old-a-duplicate"),
                ("policy-shared", "old-b", "policy_violation",
                 "Policy violation (warning) [rsa]: weak", None,
                 "[]", "2026-01-03", "second.example.test", "old-b"),
                ("gone-policy", "gone", "policy_violation",
                 "Policy violation (warning) [gone]: weak", None,
                 "[]", "2026-01-04", HOST, "gone"),
            ],
        )
        overdue_payload = json.dumps({
            "hostname": HOST,
            "port": PORT,
            "cert_fingerprint": "overdue-fp",
        })
        conn.execute(
            """INSERT INTO event_log
               (event_type, timestamp, source, payload, created_at)
               VALUES ('renewal_overdue', '2026-01-05', 'test', ?, '2026-01-05')""",
            (overdue_payload,),
        )
        conn.execute("DROP INDEX ux_alerts_open_dedupe")
        conn.execute("DROP TABLE rule_firings")
        conn.execute("ALTER TABLE alerts DROP COLUMN routing")
        conn.execute("ALTER TABLE alerts DROP COLUMN closed_at")
        conn.execute("ALTER TABLE alerts DROP COLUMN dedupe_key")
        conn.execute("DELETE FROM schema_version WHERE id = '0037'")
        conn.commit()

    assert run_pending_migrations(db, backup=False) == ["0037"]
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        expiry = conn.execute(
            "SELECT id, status, dedupe_key, closed_at, routing FROM alerts "
            "WHERE alert_type='expiry_warning' ORDER BY id"
        ).fetchall()
        policies = conn.execute(
            "SELECT id, status, dedupe_key FROM alerts "
            "WHERE id LIKE 'policy%' ORDER BY id"
        ).fetchall()
        gone_policy = conn.execute(
            "SELECT dedupe_key FROM alerts WHERE id='gone-policy'"
        ).fetchone()[0]
        firing = conn.execute(
            "SELECT dedupe_key, fire_count FROM rule_firings"
        ).fetchone()
        index_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='ux_alerts_open_dedupe'"
        ).fetchone()[0]
    expiry_by_id = {row["id"]: row for row in expiry}
    assert expiry_by_id["oldest"]["status"] == "pending"
    assert (
        expiry_by_id["newer"]["status"],
        expiry_by_id["newer"]["closed_at"] is not None,
    ) == (
        "cancelled", True,
    )
    assert (
        expiry_by_id["shared"]["status"], expiry_by_id["shared"]["closed_at"],
    ) == (
        "pending", None,
    )
    assert expiry_by_id["oldest"]["dedupe_key"] == (
        f"expiry:{HOST}:{PORT}:{'77' * 32}:expiry_warning:14"
    )
    assert expiry_by_id["shared"]["dedupe_key"] == (
        f"expiry:second.example.test:8443:{'77' * 32}:expiry_warning:14"
    )
    assert json.loads(expiry_by_id["oldest"]["routing"])["recipients"] == [
        "ops@example.invalid"
    ]
    assert [(row["id"], row["status"]) for row in policies] == [
        ("policy", "pending"),
        ("policy-duplicate", "cancelled"),
        ("policy-shared", "pending"),
    ]
    assert policies[0]["dedupe_key"] == f"policy:{HOST}:{PORT}:{'77' * 32}:rsa"
    assert policies[2]["dedupe_key"] == (
        f"policy:second.example.test:8443:{'77' * 32}:rsa"
    )
    assert gone_policy is None
    assert tuple(firing) == (f"overdue:{HOST}:{PORT}:overdue-fp", 1)
    assert "statusIN('pending','sending')" in index_sql.replace(" ", "")
