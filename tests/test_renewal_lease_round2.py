"""Round-two regressions for lease-aware compatibility writes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from cert_watch.auth.rbac import AuthContext
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.renewal_attempts import (
    endpoint_stall_suppression_active,
    renewal_attempt_is_live,
    renewal_attempt_is_live_sql,
)
from cert_watch.services.renewal_reports import (
    RenewalReportInput,
    create_report,
    resolve_target,
    write_through_renewal_status_on,
)

HOST = "round-two.example.test"


@pytest.fixture(autouse=True)
def _quiet_scheduler(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    monkeypatch.setattr(
        "cert_watch.scheduler_context.SchedulerContext.maintenance", lambda self: None
    )


def _seed_attempt(db, host_id: str, kind: str) -> str:
    now = datetime.now(UTC)
    state = "failed" if kind == "failed" else "open"
    lease = None
    if kind == "lapsed":
        lease = now - timedelta(hours=1)
    elif kind == "live":
        lease = now + timedelta(hours=1)
    attempt_id = uuid.uuid4().hex
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,baseline_fingerprint,
                lease_expires_at,suppresses_stalled,received_at,baseline_lease_claimed)
               VALUES (?,?,1,'user:test',?,1,'leaf',?,?,?,1)""",
            (
                attempt_id,
                host_id,
                state,
                lease.isoformat() if lease else None,
                int(kind == "live"),
                now.isoformat(),
            ),
        )
        conn.commit()
    return "in_progress" if kind == "live" else "pending"


def _attempt_snapshot(db, host_id: str):
    with _connect(db) as conn:
        attempt = tuple(
            conn.execute(
                """SELECT attempt_id,state,is_current,lease_expires_at,
                          suppresses_stalled,closed_reason
                   FROM renewal_attempts WHERE host_id=? ORDER BY opened_seq""",
                (host_id,),
            ).fetchone()
        )
        reports = conn.execute(
            "SELECT count(*) FROM renewal_reports WHERE host_id=?", (host_id,)
        ).fetchone()[0]
    return attempt, reports


@pytest.mark.parametrize("attempt_kind", ["failed", "lapsed", "live"])
@pytest.mark.parametrize(
    "writer",
    [
        "settings_json",
        "edit_html",
        "edit_json",
        "owner_html",
        "owner_json",
        "csv_html",
    ],
)
def test_unrelated_writers_preserve_attempt_and_report_history(
    tmp_path, reload_app, monkeypatch: pytest.MonkeyPatch, attempt_kind: str, writer: str
) -> None:
    app = reload_app().app
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    displayed = _seed_attempt(db, host_id, attempt_kind)
    before = _attempt_snapshot(db, host_id)

    async def no_scan(*_args, **_kwargs):
        return None

    monkeypatch.setattr(
        "cert_watch.routes.hosts.resolve_and_validate_host",
        lambda *_args, **_kwargs: (None, "192.0.2.10"),
    )
    monkeypatch.setattr("cert_watch.routes.hosts._scan_and_store", no_scan)
    edit = {
        "owner_name": "Updated owner",
        "owner_email": "",
        "owner_slack": "",
        "renewal_method": "manual",
        "runbook_url": "",
        "scan_interval_hours": "",
        "threshold_days": "17",
        "renewal_status": displayed,
        "notes": "unchanged renewal work",
        "tags": "",
    }
    with TestClient(app) as client:
        if writer == "settings_json":
            response = client.patch(
                f"/api/hosts/{host_id}/settings",
                json={
                    "scan_interval_hours": None,
                    "threshold_days": 17,
                    "renewal_status": displayed,
                },
            )
        elif writer == "edit_html":
            response = client.post(
                f"/hosts/{host_id}/edit", data=edit, follow_redirects=False
            )
        elif writer == "edit_json":
            response = client.put(
                f"/api/hosts/{host_id}",
                json={**edit, "scan_interval_hours": None, "threshold_days": 17},
            )
        elif writer == "owner_html":
            response = client.post(
                f"/hosts/{host_id}/owner",
                data={"owner_name": "Updated owner"},
                follow_redirects=False,
            )
        elif writer == "owner_json":
            response = client.patch(
                f"/api/hosts/{host_id}/owner",
                json={"owner_name": "Updated owner", "renewal_status": displayed},
            )
        else:
            response = client.post(
                "/hosts/import",
                files={
                    "file": (
                        "hosts.csv",
                        f"hostname,port,owner_name\n{HOST},443,Updated owner\n",
                        "text/csv",
                    )
                },
                follow_redirects=False,
            )
    assert response.status_code in {200, 303}, response.text
    assert _attempt_snapshot(db, host_id) == before


def test_python_and_sql_lease_predicates_agree_on_offsets_and_boundary(tmp_path) -> None:
    db = tmp_path / "predicate.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    now = datetime(2026, 9, 27, 5, tzinfo=timezone(timedelta(hours=-7)))
    cases = (
        now,
        now + timedelta(microseconds=1),
        now - timedelta(microseconds=1),
        (now + timedelta(hours=1)).astimezone(timezone(timedelta(hours=5, minutes=30))),
    )
    with _connect(db) as conn:
        for lease in cases:
            conn.execute("DELETE FROM renewal_attempts")
            conn.execute(
                """INSERT INTO renewal_attempts
                   (attempt_id,host_id,is_current,source,state,opened_seq,
                    lease_expires_at,suppresses_stalled,received_at)
                   VALUES (?,?,1,'test','open',1,?,1,?)""",
                (uuid.uuid4().hex, host_id, lease.isoformat(), now.isoformat()),
            )
            sql = bool(
                conn.execute(
                    "SELECT " + renewal_attempt_is_live_sql("a", "?")
                    + " FROM renewal_attempts a",
                    (now.isoformat(),),
                ).fetchone()[0]
            )
            python = renewal_attempt_is_live("open", lease.isoformat(), now=now)
            assert sql is python
    assert renewal_attempt_is_live("open", now.isoformat(), now=now) is False


def test_non_current_open_attempt_and_exact_boundary_do_not_suppress(tmp_path) -> None:
    db = tmp_path / "mutants.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    now = datetime.now(UTC).replace(microsecond=0)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,lease_expires_at,
                suppresses_stalled,received_at)
               VALUES ('old',?,0,'test','open',1,?,1,?),
                      ('current',?,1,'test','failed',2,NULL,0,?)""",
            (
                host_id,
                (now + timedelta(hours=1)).isoformat(),
                now.isoformat(),
                host_id,
                now.isoformat(),
            ),
        )
        conn.commit()
    assert not endpoint_stall_suppression_active(db, HOST, 443, now=now)
    with _connect(db) as conn:
        conn.execute("DELETE FROM renewal_attempts")
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,lease_expires_at,
                suppresses_stalled,received_at)
               VALUES ('boundary',?,1,'test','open',1,?,1,?)""",
            (host_id, now.isoformat(), now.isoformat()),
        )
        conn.commit()
    assert not endpoint_stall_suppression_active(db, HOST, 443, now=now)


@pytest.mark.parametrize("writer", ["compatibility", "report"])
def test_lease_writers_normalize_non_utc_now(tmp_path, writer: str) -> None:
    db = tmp_path / f"{writer}.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add(HOST, 443)
    settings = Settings(db_path=db, data_dir=tmp_path)
    now = datetime(2026, 9, 27, 5, tzinfo=timezone(timedelta(hours=-7)))

    if writer == "compatibility":
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
                now=now,
            )
            conn.commit()
    else:
        auth = AuthContext.renewal_report_key(
            "reporter", principal_id="report-key", binding="all", bound_tags=()
        )
        target = resolve_target(db, auth, hostname=HOST, port=443)
        create_report(
            db,
            settings,
            target,
            RenewalReportInput("started", None, "test", None, None, None),
            auth=auth,
            actor="api_key:report-key",
            source_ip=None,
            idempotency_key=None,
            body_sha256="normalized-lease",
            now=now,
        )

    with _connect(db) as conn:
        lease = str(
            conn.execute(
                "SELECT lease_expires_at FROM renewal_attempts WHERE host_id=?",
                (host_id,),
            ).fetchone()[0]
        )
    parsed = datetime.fromisoformat(lease)
    assert parsed.utcoffset() == timedelta(0)
    assert parsed == now.astimezone(UTC) + timedelta(
        hours=settings.renewal_report_lease_hours
    )
