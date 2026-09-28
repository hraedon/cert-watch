"""S3 contracts: leased stall suppression and write-through compatibility."""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from cert_watch.alerting.rules.expiry import evaluate_all_certs
from cert_watch.alerting.rules.renewal import evaluate_renewal_window
from cert_watch.auth.rbac import AuthContext
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.certificate_model import Certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteAlertRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.services.host_management import HostSettingsUpdate, update_host_settings
from cert_watch.services.renewal_reports import (
    RenewalReportInput,
    create_report,
    expire_renewal_leases,
    resolve_target,
    write_through_renewal_status_on,
)
from tests._helpers import seed_certificate

NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)
HOST = "lease.example.test"


def _seed_stalled(tmp_path: Path, name: str = "lease.sqlite3") -> tuple[Path, str]:
    db = tmp_path / name
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    cert = Certificate(
        subject=f"CN={HOST}",
        issuer="CN=Test CA",
        not_before=NOW - timedelta(days=60),
        not_after=datetime.now(UTC) + timedelta(days=10),
        fingerprint_sha256="baseline-fingerprint",
    )
    seed_certificate(db, cert, cert_id="lease-cert", hostname=HOST, port=443)
    return db, host_id


def _attempt(
    db: Path,
    host_id: str,
    state: str,
    *,
    lease: datetime | None,
    suppresses: bool,
) -> None:
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                baseline_not_after,new_fingerprint,lease_expires_at,suppresses_stalled,
                received_at,next_check_at,closed_reason)
               VALUES (?, ?, 1, 'user:test', ?, 1, 'baseline-fingerprint', ?, NULL, ?, ?, ?,
                       NULL, NULL)""",
            (
                uuid.uuid4().hex,
                host_id,
                state,
                (NOW + timedelta(days=10)).isoformat(),
                lease.isoformat() if lease else None,
                int(suppresses),
                NOW.isoformat(),
            ),
        )
        conn.commit()


@pytest.mark.parametrize(
    "route",
    ["edit", "host_owner", "certificate_owner", "settings"],
)
@pytest.mark.parametrize("seen", [None, ""])
@pytest.mark.parametrize("current_status", ["pending", "in_progress"])
def test_html_status_change_requires_nonempty_rendered_status(
    tmp_path: Path,
    reload_app,
    route: str,
    seen: str | None,
    current_status: str,
) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    host_id = repo.add(HOST, 443, owner_name="Original", scan_interval_hours=24)
    if current_status == "in_progress":
        _attempt(
            db,
            host_id,
            "open",
            lease=datetime.now(UTC) + timedelta(hours=1),
            suppresses=True,
        )
    submitted_status = "pending" if current_status == "in_progress" else "in_progress"
    cert_id = str(uuid.uuid4())
    seed_certificate(
        db,
        Certificate(
            subject=f"CN={HOST}",
            issuer="CN=Test CA",
            not_before=NOW - timedelta(days=30),
            not_after=NOW + timedelta(days=30),
            fingerprint_sha256="cached-form-fingerprint",
        ),
        cert_id=cert_id,
        hostname=HOST,
        port=443,
    )
    if route == "edit":
        url = f"/hosts/{host_id}/edit"
        form = {
            "owner_name": "Changed",
            "owner_email": "",
            "owner_slack": "",
            "renewal_method": "",
            "runbook_url": "",
            "scan_interval_hours": "6",
            "threshold_days": "21",
            "renewal_status": submitted_status,
            "notes": "changed",
            "tags": "changed",
        }
    elif route == "host_owner":
        url = f"/hosts/{host_id}/owner"
        form = {"owner_name": "Changed", "renewal_status": submitted_status}
    elif route == "certificate_owner":
        url = f"/certificates/{cert_id}/owner"
        form = {"owner_name": "Changed", "renewal_status": submitted_status}
    else:
        url = f"/hosts/{host_id}/settings"
        form = {
            "scan_interval_hours": "6",
            "threshold_days": "21",
            "renewal_status": submitted_status,
        }
    if seen is not None:
        form["renewal_status_seen"] = seen

    with TestClient(reload_app().app) as client:
        response = client.post(url, data=form, follow_redirects=False)

    assert response.status_code == 303
    assert "out%20of%20date" in response.headers["location"].lower()
    assert "saved=1" not in response.headers["location"]
    host = repo.get(host_id)
    assert host is not None
    assert host.owner_name == "Original"
    assert host.scan_interval_hours == 24
    assert host.renewal_status == current_status
    with _connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM renewal_attempts").fetchone()[0] == (
            1 if current_status == "in_progress" else 0
        )


def test_edit_form_highlights_invalid_rendered_status(tmp_path: Path, reload_app) -> None:
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    form = {
        "owner_name": "",
        "owner_email": "",
        "owner_slack": "",
        "renewal_method": "",
        "runbook_url": "",
        "scan_interval_hours": "",
        "threshold_days": "",
        "renewal_status": "pending",
        "renewal_status_seen": "invalid",
        "notes": "",
        "tags": "",
    }
    with TestClient(reload_app().app) as client:
        response = client.post(f"/hosts/{host_id}/edit", data=form)

    assert response.status_code == 422
    assert 'id="endpoint-renewal-status-error"' in response.text
    assert 'id="endpoint-renewal-status"' in response.text
    assert 'aria-invalid="true"' in response.text


@pytest.mark.parametrize(
    ("state", "lease", "suppresses", "is_suppressed"),
    [
        (None, None, False, False),
        ("open", NOW + timedelta(hours=1), True, True),
        ("open", NOW + timedelta(hours=1), False, False),
        ("open", NOW - timedelta(seconds=1), True, False),
        ("abandoned", NOW + timedelta(hours=1), True, False),
        ("failed", NOW + timedelta(hours=1), True, False),
        ("verifying", NOW + timedelta(hours=1), True, False),
        ("not_deployed", NOW + timedelta(hours=1), True, False),
        ("verified", NOW + timedelta(hours=1), True, False),
        ("cancelled", NOW + timedelta(hours=1), True, False),
    ],
)
def test_renewal_stalled_characterises_every_attempt_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str | None,
    lease: datetime | None,
    suppresses: bool,
    is_suppressed: bool,
) -> None:
    db, host_id = _seed_stalled(tmp_path, f"{state or 'none'}.sqlite3")
    if state is not None:
        _attempt(db, host_id, state, lease=lease, suppresses=suppresses)
    monkeypatch.setattr(
        "cert_watch.alerting.rules.renewal.datetime",
        type("Clock", (), {"now": staticmethod(lambda tz=None: NOW)}),
    )
    alerts = SqliteAlertRepository(db)
    expiry = evaluate_all_certs(db, alerts)
    assert [(item.cert_id, item.alert_type) for item in expiry] == [
        ("lease-cert", "expiry_warning")
    ]
    created = evaluate_renewal_window(db, alerts, 30)
    assert (created == []) is is_suppressed


def _run_rule_pass(tmp_path: Path, scenario: str) -> set[tuple[str, str]]:
    db = tmp_path / f"alerts-{scenario}.sqlite3"
    init_schema(db)
    repo = SqliteHostRepository(db)
    now = datetime.now(UTC)
    for index, days in enumerate((-2, 5, 20, 80)):
        hostname = f"estate-{index}.example.test"
        host_id = repo.add(hostname, 443)
        seed_certificate(
            db,
            Certificate(
                subject=f"CN={hostname}",
                issuer="CN=Test CA",
                not_before=now - timedelta(days=30),
                not_after=now + timedelta(days=days),
                fingerprint_sha256=f"fingerprint-{index}",
            ),
            cert_id=f"cert-{index}",
            hostname=hostname,
            port=443,
        )
        if scenario != "none":
            state = "failed" if scenario == "failed" else "open"
            lease = now - timedelta(hours=1) if scenario == "lapsed" else now + timedelta(hours=1)
            _attempt(
                db,
                host_id,
                state,
                lease=lease,
                suppresses=scenario in {"live", "lapsed"},
            )
    alerts = SqliteAlertRepository(db)
    evaluate_all_certs(db, alerts)
    evaluate_renewal_window(db, alerts, 30)
    return {(alert.cert_id, alert.alert_type) for alert in alerts.list_all()}


def test_full_alert_pass_never_changes_expiry_sets_for_report_states(tmp_path: Path) -> None:
    results = {
        name: _run_rule_pass(tmp_path, name)
        for name in ("none", "live", "lapsed", "failed")
    }
    expiry = {
        name: {item for item in alerts if item[1] in {"expiry_warning", "expired"}}
        for name, alerts in results.items()
    }
    assert expiry["none"] == expiry["live"] == expiry["lapsed"] == expiry["failed"]
    assert results["live"] != results["none"]


def test_expiry_layers_never_reference_report_tables() -> None:
    root = Path(__file__).parents[1] / "src" / "cert_watch"
    guarded = (
        root / "alerting" / "rules" / "expiry.py",
        root / "database" / "alert_store.py",
        root / "database" / "cert_ops.py",
    )
    for path in guarded:
        text = path.read_text()
        assert "renewal_attempts" not in text
        assert "renewal_reports" not in text


def test_legacy_column_has_no_runtime_sql_read() -> None:
    root = Path(__file__).parents[1] / "src" / "cert_watch"
    forbidden = re.compile(r"SELECT[^\n]*\brenewal_status\b", re.I)
    hits = []
    for path in root.rglob("*.py"):
        if "migrations" in path.parts:
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if forbidden.search(line):
                hits.append(f"{path.relative_to(root)}:{number}")
            if (
                path.relative_to(root).parts[0] in {"database", "alerting"}
                and re.search(r"\b(?:h|rh)\.renewal_status\b", line)
            ):
                hits.append(f"{path.relative_to(root)}:{number}")
    assert hits == []


def test_manual_status_round_trip_creates_and_cancels_attempt(tmp_path: Path) -> None:
    db, host_id = _seed_stalled(tmp_path)
    auth = AuthContext.from_tier(
        "writer", "operator", principal_id="key-id", principal_kind="api-key"
    )
    settings = Settings(db_path=db, data_dir=tmp_path)
    started = update_host_settings(
        db,
        host_id,
        HostSettingsUpdate(None, None, "in_progress"),
        auth=auth,
        actor="api_key:key-id",
        source_ip=None,
    )
    assert started.renewal_status == "in_progress"
    with _connect(db) as conn:
        stored_status = conn.execute(
            "SELECT renewal_status FROM hosts WHERE id=?", (host_id,)
        ).fetchone()[0]
        assert stored_status == "in_progress"
        # Deliberately desynchronise the compatibility column: every read and
        # expiry-message hint must still come from the current attempt.
        conn.execute("UPDATE hosts SET renewal_status='pending' WHERE id=?", (host_id,))
        conn.commit()
        attempt = conn.execute(
            "SELECT state,source,suppresses_stalled FROM renewal_attempts WHERE host_id=?",
            (host_id,),
        ).fetchone()
        report = conn.execute(
            "SELECT outcome,source,effect FROM renewal_reports WHERE host_id=? ORDER BY seq",
            (host_id,),
        ).fetchall()
    assert SqliteHostRepository(db).get(host_id).renewal_status == "in_progress"  # type: ignore[union-attr]
    [expiry] = evaluate_all_certs(db, SqliteAlertRepository(db))
    assert "(renewal in progress)" in expiry.message
    assert tuple(attempt) == ("open", "api_key:key-id", 1)
    assert [tuple(row) for row in report] == [("started", "api_key:key-id", "applied")]

    cleared = update_host_settings(
        db,
        host_id,
        HostSettingsUpdate(None, None, "pending"),
        auth=auth,
        actor="api_key:key-id",
        source_ip=None,
    )
    assert cleared.renewal_status == "pending"
    with _connect(db) as conn:
        state = conn.execute(
            "SELECT state,suppresses_stalled FROM renewal_attempts WHERE host_id=?",
            (host_id,),
        ).fetchone()
        outcomes = conn.execute(
            "SELECT outcome,effect FROM renewal_reports WHERE host_id=? ORDER BY seq", (host_id,)
        ).fetchall()
        audits = conn.execute(
            "SELECT detail FROM audit_log WHERE action='renewal_report.create' "
            "AND target_id=? ORDER BY ts",
            (host_id,),
        ).fetchall()
        stored_status = conn.execute(
            "SELECT renewal_status FROM hosts WHERE id=?", (host_id,)
        ).fetchone()[0]
    assert tuple(state) == ("cancelled", 0)
    assert [tuple(row) for row in outcomes] == [
        ("started", "applied"),
        ("cancelled", "applied"),
    ]
    assert len(audits) == 2
    assert '"outcome": "cancelled"' in audits[-1][0]
    assert stored_status == "pending"
    assert settings.renewal_report_lease_hours == 24


def test_pending_echo_preserves_a_failed_attempt(tmp_path: Path) -> None:
    db, host_id = _seed_stalled(tmp_path)
    _attempt(db, host_id, "failed", lease=None, suppresses=False)
    result = update_host_settings(
        db,
        host_id,
        HostSettingsUpdate(None, None, "pending"),
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
    )
    assert result.renewal_status == "pending"
    with _connect(db) as conn:
        attempt = conn.execute(
            "SELECT state,closed_reason FROM renewal_attempts WHERE host_id=?", (host_id,)
        ).fetchone()
        report = conn.execute(
            "SELECT outcome,effect FROM renewal_reports WHERE host_id=?", (host_id,)
        ).fetchone()
    assert tuple(attempt) == ("failed", None)
    assert report is None


def test_restart_same_leaf_is_visible_but_never_suppresses_twice(tmp_path: Path) -> None:
    db, host_id = _seed_stalled(tmp_path)
    auth = AuthContext.system()
    for status in ("in_progress", "pending", "in_progress"):
        result = update_host_settings(
            db,
            host_id,
            HostSettingsUpdate(None, None, status),
            auth=auth,
            actor="system",
            source_ip=None,
        )
    assert result.renewal_status == "in_progress"
    with _connect(db) as conn:
        current = conn.execute(
            "SELECT state,suppresses_stalled FROM renewal_attempts "
            "WHERE host_id=? AND is_current=1",
            (host_id,),
        ).fetchone()
    assert tuple(current) == ("open", 0)
    assert evaluate_renewal_window(db, SqliteAlertRepository(db), 30)


@pytest.mark.parametrize("restart", ["report", "manual"])
def test_born_failed_attempt_consumes_baseline_lease_once(
    tmp_path: Path, restart: str
) -> None:
    db, host_id = _seed_stalled(tmp_path)
    settings = Settings(db_path=db, data_dir=tmp_path)
    report_auth = AuthContext.renewal_report_key(
        "reporter", principal_id="report-key", binding="all", bound_tags=()
    )
    target = resolve_target(db, report_auth, hostname=HOST, port=443)

    def send(outcome: str, when: datetime, correlation: str) -> None:
        create_report(
            db,
            settings,
            target,
            RenewalReportInput(outcome, None, "test", correlation, None, None),
            auth=report_auth,
            actor="api_key:report-key",
            source_ip=None,
            idempotency_key=None,
            body_sha256=f"{outcome}-{correlation}",
            now=when,
        )

    send("failed", NOW, "failed-first")
    if restart == "report":
        send("started", NOW + timedelta(minutes=1), "restart")
    else:
        with _connect(db) as conn:
            write_through_renewal_status_on(
                conn,
                db,
                settings,
                host_id,
                "in_progress",
                auth=AuthContext.system(),
                actor="system",
                source_ip=None,
                now=NOW + timedelta(minutes=1),
            )
            conn.commit()
    with _connect(db) as conn:
        rows = conn.execute(
            """SELECT state,is_current,suppresses_stalled,baseline_lease_claimed
               FROM renewal_attempts WHERE host_id=? ORDER BY opened_seq""",
            (host_id,),
        ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("failed", 0, 0, 1),
        ("open", 1, 0, 0),
    ]
    assert evaluate_renewal_window(db, SqliteAlertRepository(db), 30)


def test_repeated_failed_started_cycles_never_regrant_same_baseline(tmp_path: Path) -> None:
    db, host_id = _seed_stalled(tmp_path)
    settings = Settings(db_path=db, data_dir=tmp_path)
    auth = AuthContext.renewal_report_key(
        "reporter", principal_id="report-key", binding="all", bound_tags=()
    )
    target = resolve_target(db, auth, hostname=HOST, port=443)
    for cycle in range(3):
        instant = NOW + timedelta(hours=cycle * 40)
        for outcome, offset in (("failed", 0), ("started", 1)):
            create_report(
                db,
                settings,
                target,
                RenewalReportInput(outcome, None, "test", f"{cycle}-{outcome}", None, None),
                auth=auth,
                actor="api_key:report-key",
                source_ip=None,
                idempotency_key=None,
                body_sha256=f"{cycle}-{outcome}",
                now=instant + timedelta(minutes=offset),
            )
        expire_renewal_leases(db, now=instant + timedelta(hours=25))
    with _connect(db) as conn:
        claims, suppressions = conn.execute(
            """SELECT sum(baseline_lease_claimed),sum(suppresses_stalled)
               FROM renewal_attempts WHERE host_id=?""",
            (host_id,),
        ).fetchone()
    assert claims == 1
    assert suppressions == 0


def test_renewal_report_key_cannot_cancel_an_attempt(tmp_path: Path) -> None:
    db, host_id = _seed_stalled(tmp_path)
    update_host_settings(
        db,
        host_id,
        HostSettingsUpdate(None, None, "in_progress"),
        auth=AuthContext.system(),
        actor="system",
        source_ip=None,
    )
    auth = AuthContext.renewal_report_key(
        "reporter", principal_id="report-key", binding="all", bound_tags=()
    )
    with _connect(db) as conn, pytest.raises(ScopeDeniedError):
        write_through_renewal_status_on(
            conn,
            db,
            Settings(db_path=db, data_dir=tmp_path),
            host_id,
            "pending",
            auth=auth,
            actor="api_key:report-key",
            source_ip=None,
        )


def test_migration_0047_backfills_baseline_lease_and_audit_idempotently(
    tmp_path: Path,
) -> None:
    from cert_watch.migrations.m0047_renewal_status_leases import upgrade

    db, host_id = _seed_stalled(tmp_path)
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET renewal_status='in_progress' WHERE id=?", (host_id,))
        conn.execute(
            """INSERT OR REPLACE INTO kv_store(key,value,updated_at)
               VALUES ('renewal_report_lease_hours','12',?)""",
            (NOW.isoformat(),),
        )
        upgrade(conn)
        upgrade(conn)
        attempt = conn.execute(
            """SELECT source,state,baseline_fingerprint,lease_expires_at,suppresses_stalled,
                      received_at
               FROM renewal_attempts WHERE host_id=? AND source='migration:0047'""",
            (host_id,),
        ).fetchall()
        reports = conn.execute(
            "SELECT outcome FROM renewal_reports WHERE host_id=? AND source='migration:0047'",
            (host_id,),
        ).fetchall()
        audits = conn.execute(
            "SELECT actor FROM audit_log WHERE target_id=? AND actor='migration:0047'",
            (host_id,),
        ).fetchall()
    assert len(attempt) == len(reports) == len(audits) == 1
    assert tuple(attempt[0][:3]) == ("migration:0047", "open", "baseline-fingerprint")
    assert attempt[0][4] == 1
    received = datetime.fromisoformat(attempt[0][5])
    assert datetime.fromisoformat(attempt[0][3]) - received == timedelta(hours=12)


def test_migration_0047_preserves_s2_attempts_and_used_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import cert_watch.migrations.registry  # noqa: F401 — register migrations
    from cert_watch.migrations import runner
    from cert_watch.migrations.m0047_renewal_status_leases import upgrade

    db = tmp_path / "s2.sqlite3"
    migrations = runner.get_migrations()
    monkeypatch.setattr(
        runner, "_MIGRATIONS", [item for item in migrations if item[0] <= "0046"]
    )
    runner.run_pending_migrations(db, backup=False)
    host_ids = {
        name: uuid.uuid4().hex
        for name in ("failed", "used", "open", "demoted", "nulllease", "badlease")
    }
    with _connect(db) as conn:
        for name, host_id in host_ids.items():
            conn.execute(
                """INSERT INTO hosts
                   (id,hostname,port,renewal_status,added_at)
                   VALUES (?,?,443,?,?)""",
                (
                    host_id,
                    f"{name}.example.test",
                    "pending" if name in {"demoted", "nulllease", "badlease"} else "in_progress",
                    NOW.isoformat(),
                ),
            )
        conn.execute(
            """INSERT INTO certificates
               (id,subject,issuer,not_before,not_after,san_dns_names,
                fingerprint_sha256,raw_der,source,hostname,port,is_leaf,
                parent_cert_id,chain_valid,replaces_cert_id,tags,created_at,updated_at)
               VALUES ('used-cert','CN=used.example.test','CN=Test CA',?,?,
                       '[]','used-fp',X'','scanned','used.example.test',443,1,
                       NULL,NULL,NULL,'',?,?)""",
            (
                (NOW - timedelta(days=30)).isoformat(),
                (NOW + timedelta(days=10)).isoformat(),
                NOW.isoformat(),
                NOW.isoformat(),
            ),
        )
        attempts = (
            ("failed-a", "failed", 1, "failed", None, 0, "failed-fp"),
            ("used-a", "used", 0, "abandoned", NOW.isoformat(), 0, "used-fp"),
            (
                "open-a",
                "open",
                1,
                "open",
                datetime(2099, 1, 1, tzinfo=UTC).isoformat(),
                1,
                "open-fp",
            ),
            (
                "demoted-a",
                "demoted",
                0,
                "open",
                datetime(2099, 1, 1, tzinfo=UTC).isoformat(),
                1,
                "demoted-fp",
            ),
            ("nulllease-a", "nulllease", 1, "open", None, 1, "nulllease-fp"),
            ("badlease-a", "badlease", 1, "open", "not-a-date", 1, "badlease-fp"),
        )
        for attempt_id, name, current, state, lease, suppresses, fingerprint in attempts:
            conn.execute(
                """INSERT INTO renewal_attempts
                   (attempt_id,host_id,is_current,source,state,opened_seq,
                    baseline_fingerprint,lease_expires_at,suppresses_stalled,received_at)
                   VALUES (?,?,?,'api_key:s2',?,1,?,?,?,?)""",
                (
                    attempt_id,
                    host_ids[name],
                    current,
                    state,
                    fingerprint,
                    lease,
                    suppresses,
                    NOW.isoformat(),
                ),
            )
        upgrade(conn)
        rows = conn.execute(
            """SELECT h.hostname,a.source,a.state,a.is_current,a.suppresses_stalled,
                      a.baseline_lease_claimed
               FROM renewal_attempts a JOIN hosts h ON h.id=a.host_id
               ORDER BY h.hostname,a.opened_seq"""
        ).fetchall()
        audits = conn.execute(
            """SELECT action,target_id FROM audit_log
               WHERE actor='migration:0047' ORDER BY action,target_id"""
        ).fetchall()
        invalid_open = conn.execute(
            """SELECT count(*) FROM renewal_attempts
               WHERE state='open' AND suppresses_stalled=1
                 AND (is_current=0 OR
                      julianday(lease_expires_at) IS NULL OR
                      julianday(lease_expires_at)<=julianday('now'))"""
        ).fetchone()[0]
        cached = {
            row["hostname"]: row["renewal_status"]
            for row in conn.execute(
                "SELECT hostname,renewal_status FROM hosts ORDER BY hostname"
            ).fetchall()
        }
    by_host: dict[str, list[tuple[object, ...]]] = {}
    for row in rows:
        by_host.setdefault(str(row[0]), []).append(tuple(row[1:]))
    assert by_host["failed.example.test"] == [("api_key:s2", "failed", 1, 0, 1)]
    assert by_host["open.example.test"] == [("api_key:s2", "open", 1, 1, 1)]
    assert by_host["used.example.test"] == [
        ("api_key:s2", "abandoned", 0, 0, 1),
        ("migration:0047", "open", 1, 0, 0),
    ]
    assert by_host["demoted.example.test"] == [("api_key:s2", "open", 0, 0, 1)]
    assert by_host["nulllease.example.test"] == [("api_key:s2", "open", 1, 0, 1)]
    assert by_host["badlease.example.test"] == [("api_key:s2", "open", 1, 0, 1)]
    assert [row[0] for row in audits].count("renewal_report.migration_skip") == 2
    assert [row[0] for row in audits].count("renewal_report.create") == 1
    assert invalid_open == 0
    assert cached == {
        "badlease.example.test": "pending",
        "demoted.example.test": "pending",
        "failed.example.test": "pending",
        "nulllease.example.test": "pending",
        "open.example.test": "in_progress",
        "used.example.test": "in_progress",
    }
