"""The #126 S1 four-axis model agrees between Python, SQL filters and scope."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteAlertGroupRepository, SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_page import list_dashboard_page
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.status_model import AxisSettings, condition_state

NOW = datetime(2026, 9, 25, 12, tzinfo=UTC)


def _cert(host: str, days: int, fingerprint: str) -> Certificate:
    return Certificate(
        subject=f"CN={host}",
        issuer="CN=Example Test CA",
        not_before=NOW - timedelta(days=30),
        not_after=NOW + timedelta(days=days, hours=12),
        fingerprint_sha256=fingerprint,
    )


def _seed(tmp_path, db_name: str = "four-axis.sqlite3"):
    from cert_watch.database import replace_scanned

    db = tmp_path / db_name
    init_schema(db)
    hosts = SqliteHostRepository(db)
    specs = (
        ("failing.example.test", "team-a", 90, "", "pending"),
        ("manual.example.test", "team-a", 7, "manual", "pending"),
        ("stalled.example.test", "team-a", 4, "acme", "pending"),
        ("auto.example.test", "team-b", 31, "cert-manager", "pending"),
        ("progress.example.test", "team-b", None, "", "in_progress"),
    )
    ids: dict[str, str] = {}
    for index, (host, tag, days, method, operator) in enumerate(specs):
        ids[host] = hosts.add(host, 443, tags=tag, renewal_method=method)
        with _connect(db) as conn:
            conn.execute(
                "UPDATE hosts SET renewal_status = ? WHERE id = ?", (operator, ids[host])
            )
            conn.commit()
        if days is not None:
            replace_scanned(db, host, 443, _cert(host, days, f"fp-{index}"), [], True)

    for host in ("manual.example.test", "stalled.example.test", "auto.example.test"):
        record_scan_history(
            db,
            ScanHistory(
                hostname=host,
                port=443,
                status="success",
                scanned_at=NOW - timedelta(hours=1),
            ),
        )
    record_scan_history(
        db,
        ScanHistory(
            hostname="failing.example.test",
            port=443,
            status="success",
            scanned_at=NOW - timedelta(hours=3),
        ),
    )
    for hours in (2, 1):
        record_scan_history(
            db,
            ScanHistory(
                hostname="failing.example.test",
                port=443,
                status="failure",
                error_message="connection refused",
                scanned_at=NOW - timedelta(hours=hours),
            ),
        )

    SqliteAlertGroupRepository(db).create(
        name="Team A operators",
        recipients=["team-a@example.test"],
        match_tags=["team-a"],
    )
    settings = AxisSettings(
        sched_hour=6,
        sched_min=0,
        renewal_window_days=5,
        smtp_configured=True,
    )
    return db, settings


def _by_host(rows):
    return {row["host"].split(":", 1)[0]: row for row in rows}


def test_each_axis_uses_the_documented_mapping(tmp_path):
    db, settings = _seed(tmp_path)
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    got = _by_host(rows)

    assert got["failing.example.test"]["status"]["condition"]["state"] == "ok"
    monitoring = got["failing.example.test"]["status"]["monitoring"]
    assert monitoring == {
        "state": "failing",
        "since": (NOW - timedelta(hours=2)).isoformat(),
        "cause": "Nothing is accepting connections on this port.",
        "raw_error": "connection refused",
    }
    assert got["manual.example.test"]["renewal"] == "manual"
    assert got["stalled.example.test"]["renewal"] == "stalled"
    assert got["auto.example.test"]["renewal"] == "automation_configured"
    assert got["progress.example.test"]["renewal"] == "in_progress"
    assert got["manual.example.test"]["delivery"] == "ok"
    assert got["auto.example.test"]["delivery"] == "unrouted"


def test_sql_filters_agree_with_every_built_row_and_respect_scope(tmp_path):
    db, settings = _seed(tmp_path)
    all_rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)

    filters = {
        "condition": ("expired", "le7", "8to30", "ok"),
        "monitoring": ("current", "failing", "never_scanned"),
        "renewal": (
            "automation_configured", "manual", "stalled", "in_progress", "unknown"
        ),
        "delivery": ("ok", "failing", "unrouted"),
    }
    for axis, states in filters.items():
        for state in states:
            rows, total = list_dashboard_page(
                db,
                per_page=0,
                now=NOW,
                axis_settings=settings,
                **{axis: state},
            )
            expected = [row for row in all_rows if row[axis] == state]
            assert {row["id"] for row in rows} == {row["id"] for row in expected}
            assert total == len(expected)

    scoped, total = list_dashboard_page(
        db,
        condition="ok",
        monitoring="failing",
        scope_tags=("TEAM-A",),
        per_page=0,
        now=NOW,
        axis_settings=settings,
    )
    assert total == 1
    assert scoped[0]["host"] == "failing.example.test:443"


def test_condition_python_and_sql_share_boundaries():
    assert [condition_state(days) for days in (-1, 0, 7, 8, 30, 31, None)] == [
        "expired", "le7", "le7", "8to30", "8to30", "ok", None
    ]


def test_delivery_filter_uses_last_channel_outcome(tmp_path):
    from cert_watch.database import Alert, AlertStore
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

    db, settings = _seed(tmp_path)
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    cert_id = _by_host(rows)["manual.example.test"]["id"]
    alert = Alert(
        cert_id=cert_id,
        alert_type="expiry_warning",
        status="pending",
        message="test delivery evidence",
    )
    alert_id = AlertStore(db).enqueue(alert)
    assert alert_id is not None
    attempt_id = begin_attempt(db, alert_id, "smtp", {"recipients": []})
    complete_attempt(db, attempt_id, {"outcome": "failed", "reason": "transport"})

    failing, total = list_dashboard_page(
        db,
        delivery="failing",
        per_page=0,
        now=NOW,
        axis_settings=settings,
    )
    assert total == 1
    assert failing[0]["id"] == cert_id
    smtp = failing[0]["status"]["delivery"]["channels"][0]
    assert smtp["last_outcome"] == "failed"
    assert smtp["can_deliver"] is True


def test_html_and_json_lists_accept_the_same_combinable_filters(
    tmp_path, reload_app, monkeypatch
):
    from fastapi.testclient import TestClient

    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        api = client.get("/api/certificates?condition=ok&monitoring=failing&limit=1")
        hosts = client.get("/api/hosts?renewal=in_progress")
        browse = client.get("/browse?condition=ok&monitoring=failing&grouped=0")

    assert api.status_code == 200
    body = api.json()
    assert [row["host"] for row in body["certificates"]] == [
        "failing.example.test:443"
    ]
    assert "condition=ok" in body["pagination"]["self"]
    assert "monitoring=failing" in body["pagination"]["self"]
    assert [row["hostname"] for row in hosts.json()["hosts"]] == [
        "progress.example.test"
    ]
    assert "failing.example.test" in browse.text
    assert "auto.example.test" not in browse.text
    assert "Condition: ok" in browse.text
    assert "Monitoring: failing" in browse.text
