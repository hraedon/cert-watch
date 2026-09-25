"""The #126 S1 four-axis model agrees between Python, SQL filters and scope."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.certificate_model import Certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteAlertGroupRepository, SqliteHostRepository, init_schema
from cert_watch.database.chain_status_cache import StatusContext, prepare_status
from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_page import list_dashboard_page
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.status_model import (
    AxisSettings,
    StatusModelContext,
    attach_status_models,
    condition_state,
    monitoring_since,
    monitoring_state,
    overall_state,
    renewal_state,
    renewal_state_for_row,
)

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
        ("history-manual.example.test", "team-b", 200, "", "pending"),
        ("history-auto.example.test", "team-b", 200, "", "pending"),
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

    for host in (
        "manual.example.test",
        "stalled.example.test",
        "auto.example.test",
        "history-manual.example.test",
        "history-auto.example.test",
    ):
        record_scan_history(
            db,
            ScanHistory(
                hostname=host,
                port=443,
                status="success",
                scanned_at=NOW - timedelta(hours=1),
            ),
        )

    # Three contiguous deployment periods are two observed renewals.  Keep
    # this history in the independent SQL/row agreement fixture: long-lived
    # certificates classify as manual, while regular ACME-like short-lived
    # periods classify as likely automated.
    with _connect(db) as conn:
        for host, issuer, lifetime, offsets, current_fp in (
            (
                "history-manual.example.test",
                "CN=Example Test CA",
                365,
                (800, 450, 100),
                "fp-5",
            ),
            (
                "history-auto.example.test",
                "CN=Let's Encrypt Test CA",
                90,
                (180, 120, 60),
                "fp-6",
            ),
        ):
            for period, days_ago in enumerate(offsets):
                first_seen = NOW - timedelta(days=days_ago)
                not_before = first_seen - timedelta(days=1)
                not_after = not_before + timedelta(days=lifetime)
                fingerprint = current_fp if period == 2 else f"{host}-old-{period}"
                conn.execute(
                    """INSERT INTO cert_history
                       (id, hostname, port, fingerprint_sha256, issuer,
                        not_after, scanned_at, not_before)
                       VALUES (?, ?, 443, ?, ?, ?, ?, ?)""",
                    (
                        str(uuid.uuid4()), host, fingerprint, issuer,
                        not_after.isoformat(), first_seen.isoformat(),
                        not_before.isoformat(),
                    ),
                )
            from cert_watch.renewal_analytics import refresh_endpoint_analytics

            refresh_endpoint_analytics(conn, host, 443)
        conn.commit()
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
    assert got["history-auto.example.test"]["renewal"] == "automation_configured"
    assert got["history-auto.example.test"]["renewal_source"] == "renewal_analytics"
    assert got["history-manual.example.test"]["renewal"] == "manual"
    assert got["history-manual.example.test"]["renewal_source"] == "renewal_analytics"
    assert got["progress.example.test"]["renewal"] == "in_progress"
    assert got["manual.example.test"]["delivery"] == "ok"
    assert got["auto.example.test"]["delivery"] == "unrouted"


def test_sql_filters_agree_with_every_built_row_and_respect_scope(tmp_path):
    db, settings = _seed(tmp_path)
    # Independent oracle from the seed facts above.  Do not derive expected
    # membership from the rows under test: that lets a matching SQL/Python bug
    # pass both sides of an agreement assertion.
    oracle = {
        "condition": {
            "le7": {"manual.example.test", "stalled.example.test"},
            "ok": {
                "failing.example.test", "auto.example.test",
                "history-manual.example.test", "history-auto.example.test",
            },
        },
        "monitoring": {
            "current": {
                "manual.example.test", "stalled.example.test", "auto.example.test",
                "history-manual.example.test", "history-auto.example.test",
            },
            "failing": {"failing.example.test"},
            "never_scanned": {"progress.example.test"},
        },
        "renewal": {
            "automation_configured": {
                "auto.example.test", "history-auto.example.test",
            },
            "manual": {"manual.example.test", "history-manual.example.test"},
            "stalled": {"stalled.example.test"},
            "in_progress": {"progress.example.test"},
            "unknown": {"failing.example.test"},
        },
        "delivery": {
            "ok": {
                "failing.example.test", "manual.example.test", "stalled.example.test"
            },
            "unrouted": {
                "auto.example.test", "progress.example.test",
                "history-manual.example.test", "history-auto.example.test",
            },
        },
    }
    all_states = {
        "condition": ("expired", "le7", "8to30", "ok"),
        "monitoring": ("current", "failing", "never_scanned"),
        "renewal": (
            "automation_configured", "manual", "stalled", "in_progress", "unknown"
        ),
        "delivery": ("ok", "failing", "unrouted"),
    }
    for axis, states in all_states.items():
        for state in states:
            rows, total = list_dashboard_page(
                db,
                per_page=0,
                now=NOW,
                axis_settings=settings,
                **{axis: state},
            )
            got = {row["host"].split(":", 1)[0] for row in rows}
            expected = oracle[axis].get(state, set())
            assert got == expected, (axis, state)
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


def test_monitoring_boundaries_future_evidence_and_failure_since():
    now = NOW
    due_now = (now - timedelta(hours=2)).isoformat()
    assert monitoring_state(due_now, due_now, "success", 2, 6, 0, now) == "failing"
    assert monitoring_state(
        (now + timedelta(seconds=1)).isoformat(),
        (now + timedelta(seconds=1)).isoformat(),
        "success",
        24,
        6,
        0,
        now,
    ) == "failing"
    assert monitoring_state(
        (now - timedelta(minutes=5)).isoformat(),
        now.isoformat(),
        "partial",
        24,
        6,
        0,
        now,
    ) == "failing"
    assert monitoring_state(None, now.isoformat(), "failure", 24, 6, 0, now) == "failing"
    first = (now - timedelta(minutes=4)).isoformat()
    assert monitoring_since(
        "failing", due_now, "failure", 24, 6, 0, first
    ) == first


def test_renewal_precedence_window_edges_and_successor():
    assert renewal_state("manual", "in_progress", True, "likely-automated") == (
        "in_progress", "operator_report"
    )
    assert renewal_state("acme", "pending", True, "manual") == (
        "stalled", "renewal_window"
    )
    assert renewal_state("manual", "pending", False, "likely-automated") == (
        "manual", "renewal_method"
    )
    context = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(renewal_window_days=5),
        renewal_analytics={("edge.example.test", 443): "likely-automated"},
        delivery={},
    )
    at_edge = (NOW + timedelta(days=5, hours=12)).isoformat()
    before_window = (NOW - timedelta(seconds=1)).isoformat()
    assert renewal_state_for_row(
        hostname="edge.example.test", port=443, renewal_method="acme",
        operator_status="pending", not_after=at_edge, has_successor=False,
        context=context,
    )[0] == "stalled"
    assert renewal_state_for_row(
        hostname="edge.example.test", port=443, renewal_method="acme",
        operator_status="pending", not_after=at_edge, has_successor=True,
        context=context,
    )[0] == "automation_configured"
    assert renewal_state_for_row(
        hostname="edge.example.test", port=443, renewal_method="",
        operator_status="pending", not_after=before_window, has_successor=False,
        context=context,
    )[0] == "automation_configured"


def test_group_rollup_uses_worst_condition_and_monitoring(tmp_path):
    db = tmp_path / "rollup.sqlite3"
    init_schema(db)
    children = [
        {
            "id": "a", "host_id": "ha", "kind": "scanned", "condition": "ok",
            "monitoring": "never_scanned", "renewal": "unknown", "delivery": "ok",
            "urgency": "healthy", "chain_status": "public",
        },
        {
            "id": "b", "host_id": "hb", "kind": "scanned", "condition": "expired",
            "monitoring": "failing", "renewal": "manual", "delivery": "unrouted",
            "urgency": "expired", "chain_status": "public",
        },
    ]
    context = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(),
        renewal_analytics={},
        delivery={
            "a": {"state": "ok", "recipients": [], "matching_groups": [], "channels": []},
            "b": {
                "state": "unrouted", "recipients": [], "matching_groups": [], "channels": []
            },
        },
    )
    group = {"hosts": children, "urgency": "expired", "host_id": "group"}
    attach_status_models(db, [group], context)
    assert group["condition"] == "expired"
    assert group["monitoring"] == "failing"


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
    assert failing[0]["delivery"] == "failing"
    smtp = failing[0]["status"]["delivery"]["channels"][0]
    assert smtp["last_outcome"] == "failed"
    assert smtp["can_deliver"] is True

    # The latest completed outcome wins: recovery after a failure returns the
    # route to OK, while partial/unknown outcomes remain visible failures.
    recovered = begin_attempt(db, alert_id, "smtp", {"recipients": []})
    complete_attempt(db, recovered, {"outcome": "accepted"})
    ok, total = list_dashboard_page(
        db, delivery="ok", per_page=0, now=NOW, axis_settings=settings
    )
    recovered_row = next(row for row in ok if row["id"] == cert_id)
    assert recovered_row["delivery"] == "ok"
    assert recovered_row["status"]["delivery"]["channels"][0]["last_outcome"] == "accepted"
    assert total == 3

    partial = begin_attempt(db, alert_id, "smtp", {"recipients": []})
    complete_attempt(db, partial, {"outcome": "partial"})
    failing, total = list_dashboard_page(
        db, delivery="failing", per_page=0, now=NOW, axis_settings=settings
    )
    assert total == 1
    assert failing[0]["id"] == cert_id
    assert failing[0]["delivery"] == "failing"
    assert failing[0]["status"]["delivery"]["channels"][0]["last_outcome"] == "partial"

    unknown = begin_attempt(db, alert_id, "smtp", {"recipients": []})
    complete_attempt(db, unknown, {"outcome": "unexpected"})
    failing, total = list_dashboard_page(
        db, delivery="failing", per_page=0, now=NOW, axis_settings=settings
    )
    assert total == 1
    assert failing[0]["id"] == cert_id
    assert failing[0]["delivery"] == "failing"
    assert failing[0]["status"]["delivery"]["channels"][0]["last_outcome"] == "unknown"


def test_delivery_uses_latest_outcome_per_normalized_channel(tmp_path):
    """A failure on another webhook kind must not poison the configured route."""
    from cert_watch.database import Alert, AlertStore
    from cert_watch.database.dashboard_axes import dashboard_axis_stats
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

    db, _settings = _seed(tmp_path)
    settings = AxisSettings(webhook_configured=True, webhook_kind="generic")
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    cert_id = _by_host(rows)["history-manual.example.test"]["id"]
    alert_id = AlertStore(db).enqueue(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status="pending",
            message="normalized channel evidence",
        )
    )
    assert alert_id is not None

    old_slack = begin_attempt(db, alert_id, "webhook:slack", {})
    complete_attempt(db, old_slack, {"outcome": "failed"})
    current_generic = begin_attempt(db, alert_id, "webhook:generic", {})
    complete_attempt(db, current_generic, {"outcome": "accepted"})

    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    row = next(item for item in rows if item["id"] == cert_id)
    generic = next(
        channel for channel in row["status"]["delivery"]["channels"]
        if channel["channel"] == "webhook:generic"
    )
    assert row["delivery"] == "ok"
    assert generic["last_outcome"] == "accepted"
    assert list_dashboard_page(
        db, delivery="ok", per_page=0, now=NOW, axis_settings=settings
    )[1] == len([item for item in rows if item.get("kind") != "pending"])
    assert dashboard_axis_stats(
        db, status=prepare_status(db, NOW), axis_settings=settings
    )["delivery"]["ok"] == len([item for item in rows if item.get("kind") != "pending"])

    # Legacy ``generic`` and unified ``webhook:generic`` are one channel; the
    # later legacy failure must win in both the row and SQL count/filter path.
    legacy_generic = begin_attempt(db, alert_id, "generic", {})
    complete_attempt(db, legacy_generic, {"outcome": "failed"})
    failing, total = list_dashboard_page(
        db, delivery="failing", per_page=0, now=NOW, axis_settings=settings
    )
    assert total == 1
    assert failing[0]["id"] == cert_id
    assert failing[0]["status"]["delivery"]["channels"][1]["last_outcome"] == "failed"
    assert dashboard_axis_stats(
        db, status=prepare_status(db, NOW), axis_settings=settings
    )["delivery"]["failing"] == 1


def test_python_delivery_keeps_webhook_outcome_and_ignores_disabled_smtp(tmp_path):
    from cert_watch.database import Alert, AlertStore
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

    db, _settings = _seed(tmp_path)
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW)
    cert_id = _by_host(rows)["manual.example.test"]["id"]
    alert_id = AlertStore(db).enqueue(
        Alert(cert_id=cert_id, alert_type="expiry_warning", status="pending", message="m")
    )
    assert alert_id is not None

    smtp = begin_attempt(db, alert_id, "smtp", {})
    complete_attempt(db, smtp, {"outcome": "failed"})
    webhook_only = AxisSettings(webhook_configured=True, webhook_kind="generic")
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=webhook_only)
    row = next(item for item in rows if item["id"] == cert_id)
    assert row["delivery"] == "ok"
    assert row["status"]["delivery"]["channels"][0]["last_outcome"] == "failed"

    webhook = begin_attempt(db, alert_id, "webhook:generic", {})
    complete_attempt(db, webhook, {"outcome": "partial"})
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=webhook_only)
    row = next(item for item in rows if item["id"] == cert_id)
    assert row["delivery"] == "failing"
    assert row["status"]["delivery"]["channels"][1]["last_outcome"] == "partial"


def test_grouped_delivery_filter_and_overall_counts_use_required_axes(tmp_path):
    from cert_watch.database import Alert, AlertStore, list_dashboard_grouped_page
    from cert_watch.database.dashboard_axes import dashboard_axis_stats
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt

    db, settings = _seed(tmp_path)
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    cert_id = _by_host(rows)["manual.example.test"]["id"]
    alert_id = AlertStore(db).enqueue(
        Alert(cert_id=cert_id, alert_type="expiry_warning", status="pending", message="m")
    )
    assert alert_id is not None
    attempt = begin_attempt(db, alert_id, "smtp", {})
    complete_attempt(db, attempt, {"outcome": "failed"})

    grouped, total = list_dashboard_grouped_page(
        db, delivery="failing", per_page=0, now=NOW, axis_settings=settings
    )
    assert total == 1
    assert grouped[0]["delivery"] == "failing"
    assert grouped[0]["hosts"][0]["id"] == cert_id

    overall = dashboard_axis_stats(
        db,
        status=prepare_status(db, NOW),
        axis_settings=settings,
        axis_columns=frozenset({"overall"}),
    )["overall"]
    assert overall["failing"] == 1


@pytest.mark.parametrize(
    ("case", "settings", "owner", "tag", "group", "role", "expected"),
    [
        ("owner-no-smtp", AxisSettings(), "owner@example.test", "owner", None, None, "failing"),
        ("blank-owner", AxisSettings(smtp_configured=True), "   ", "blank", None, None, "unrouted"),
        (
            "role-linked",
            AxisSettings(smtp_configured=True),
            "",
            "role",
            ("Role route", ["role@example.test"], []),
            ("role-viewers", "role"),
            "ok",
        ),
        (
            "empty-group",
            AxisSettings(smtp_configured=True),
            "",
            "empty",
            ("Empty route", [], ["empty"]),
            None,
            "failing",
        ),
        (
            "webhook-only",
            AxisSettings(webhook_configured=True),
            "",
            "webhook",
            None,
            None,
            "ok",
        ),
    ],
)
def test_delivery_route_shapes_agree_between_row_filter_and_count(
    tmp_path, case, settings, owner, tag, group, role, expected
):
    from cert_watch.database import (
        Role,
        SqliteRoleRepository,
        replace_scanned,
    )
    from cert_watch.database.dashboard_axes import dashboard_axis_stats

    db = tmp_path / f"{case}.sqlite3"
    init_schema(db)
    host = f"{case}.example.test"
    host_id = SqliteHostRepository(db).add(host, 443, tags=tag)
    with _connect(db) as conn:
        conn.execute("UPDATE hosts SET owner_email = ? WHERE id = ?", (owner, host_id))
        conn.commit()
    replace_scanned(db, host, 443, _cert(host, 200, f"fp-{case}"), [], True)
    record_scan_history(
        db,
        ScanHistory(
            hostname=host,
            port=443,
            status="success",
            scanned_at=NOW - timedelta(hours=1),
        ),
    )
    if group is not None:
        group_id = SqliteAlertGroupRepository(db).create(
            name=group[0], recipients=group[1], match_tags=group[2]
        )
        if role is not None:
            SqliteRoleRepository(db).add(
                Role(
                    name=role[0], permission_tier="viewer",
                    scope_tag=role[1], alert_group_id=group_id,
                )
            )

    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=settings)
    assert rows[0]["delivery"] == expected
    filtered, total = list_dashboard_page(
        db, delivery=expected, per_page=0, now=NOW, axis_settings=settings
    )
    assert total == 1
    assert filtered[0]["delivery"] == expected
    stats = dashboard_axis_stats(
        db, status=prepare_status(db, NOW), axis_settings=settings
    )["delivery"]
    assert stats[expected] == 1


def test_delivery_requires_a_working_channel_and_accepts_global_routes(tmp_path):
    from cert_watch.status_model import load_delivery_statuses

    db, _settings = _seed(tmp_path)
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW, axis_settings=AxisSettings())
    ids = {row["host"].split(":", 1)[0]: row["id"] for row in rows if row.get("id")}

    no_transport = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(smtp_configured=False),
        renewal_analytics={}, delivery={},
    )
    load_delivery_statuses(db, (ids["manual.example.test"],), no_transport)
    assert no_transport.delivery[ids["manual.example.test"]]["state"] == "failing"

    SqliteAlertGroupRepository(db).create(
        name="Team B route without recipients", recipients=[], match_tags=["team-b"]
    )
    no_recipient = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(smtp_configured=True),
        renewal_analytics={}, delivery={},
    )
    load_delivery_statuses(db, (ids["auto.example.test"],), no_recipient)
    assert no_recipient.delivery[ids["auto.example.test"]]["state"] == "failing"

    global_mail = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(
            smtp_configured=True, global_recipients=("fleet@example.test",)
        ),
        renewal_analytics={}, delivery={},
    )
    load_delivery_statuses(db, (ids["auto.example.test"],), global_mail)
    assert global_mail.delivery[ids["auto.example.test"]]["state"] == "ok"

    global_webhook = StatusModelContext(
        certificate_status=StatusContext(NOW, "test"),
        settings=AxisSettings(webhook_configured=True),
        renewal_analytics={}, delivery={},
    )
    load_delivery_statuses(db, (ids["auto.example.test"],), global_webhook)
    assert global_webhook.delivery[ids["auto.example.test"]]["state"] == "ok"

    pending_rows, total = list_dashboard_page(
        db,
        delivery="unrouted",
        per_page=0,
        now=NOW,
        axis_settings=AxisSettings(
            smtp_configured=True, global_recipients=("fleet@example.test",)
        ),
    )
    assert total == 1
    assert pending_rows[0]["host"].startswith("progress.example.test")
    assert pending_rows[0]["delivery"] == "unrouted"


def test_axis_settings_require_an_smtp_sender(tmp_path):
    base = {"db_path": tmp_path / "db.sqlite3", "data_dir": tmp_path}
    assert not AxisSettings.from_settings(
        Settings(**base, smtp_host="smtp.example.test")
    ).smtp_configured
    assert AxisSettings.from_settings(
        Settings(
            **base,
            smtp_host="smtp.example.test",
            alert_from="alerts@example.test",
        )
    ).smtp_configured


def test_overall_never_scanned_is_gray_even_with_a_healthy_certificate():
    assert overall_state(
        {"host_id": "host", "monitoring": "never_scanned", "urgency": "healthy"}
    ) == "gray"


def test_monitoring_failure_run_starts_after_latest_success_with_id_tiebreak(tmp_path):
    from cert_watch.database import replace_scanned

    db = tmp_path / "failure-run.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("tie.example.test", 443, scan_interval_hours=24)
    replace_scanned(
        db, "tie.example.test", 443, _cert("tie.example.test", 90, "tie"), [], True
    )
    tied = NOW - timedelta(hours=2)
    later = NOW - timedelta(hours=1)
    # This failure precedes the success at the same instant and therefore is
    # not part of the current failure run.  The later failure is its start.
    record_scan_history(
        db, ScanHistory("tie.example.test", 443, "failure", id="a", scanned_at=tied)
    )
    record_scan_history(
        db,
        ScanHistory(
            "tie.example.test",
            443,
            "success",
            id="b",
            error_message="stale error from the second-latest attempt",
            scanned_at=tied,
        ),
    )
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW)
    assert rows[0]["monitoring"] == "current"
    record_scan_history(
        db,
        ScanHistory(
            "tie.example.test",
            443,
            "partial",
            id="c",
            error_message="latest connection failure",
            scanned_at=later,
        ),
    )
    rows, _ = list_dashboard_page(db, per_page=0, now=NOW)
    assert rows[0]["monitoring"] == "failing"
    assert rows[0]["status"]["monitoring"]["since"] == later.isoformat()
    assert rows[0]["status"]["monitoring"]["raw_error"] == "latest connection failure"


def test_ungrouped_page_touches_scan_history_only_for_selected_endpoints(
    tmp_path, monkeypatch
):
    import cert_watch.database.dashboard_page as dashboard_page
    from cert_watch.database import replace_scanned

    db = tmp_path / "bounded-history.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    for index in range(40):
        hostname = f"bounded-{index:02d}.example.test"
        hosts.add(hostname, 443)
        replace_scanned(db, hostname, 443, _cert(hostname, 90, f"fp-{index}"), [], True)
        for attempt in range(3):
            record_scan_history(
                db,
                ScanHistory(
                    hostname,
                    443,
                    "success",
                    scanned_at=NOW - timedelta(hours=attempt + 1),
                ),
            )

    touched = 0

    def count_touch(_row_id):
        nonlocal touched
        touched += 1
        return 1

    with _connect(db) as conn:
        conn.create_function("cw_touch_scan_history", 1, count_touch)

    real_history_where = dashboard_page._history_where

    def instrumented_history_where(alias, endpoints):
        where, params = real_history_where(alias, endpoints)
        clause = f"cw_touch_scan_history({alias}.id)"
        return (f"{where} AND {clause}" if where else f" WHERE {clause}"), params

    monkeypatch.setattr(dashboard_page, "_history_where", instrumented_history_where)
    rows, total = list_dashboard_page(db, per_page=5, page=1, now=NOW)

    assert total == 40
    assert len(rows) == 5
    assert touched <= 15


def test_self_referential_lineage_does_not_count_as_a_successor(tmp_path):
    from cert_watch.database import replace_scanned

    db = tmp_path / "self-successor.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("self.example.test", 443, renewal_method="acme")
    cert_id, _, _ = replace_scanned(
        db, "self.example.test", 443, _cert("self.example.test", 3, "self"), [], True
    )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET replaces_cert_id = ? WHERE id = ?", (cert_id, cert_id)
        )
        conn.commit()
    rows, total = list_dashboard_page(
        db,
        renewal="stalled",
        per_page=0,
        now=NOW,
        axis_settings=AxisSettings(renewal_window_days=5),
    )
    assert total == 1
    assert rows[0]["renewal"] == "stalled"


def test_grouped_pagination_filter_and_whole_group_membership(tmp_path):
    from cert_watch.database import list_dashboard_grouped_page, replace_scanned

    db = tmp_path / "grouped.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    for index in range(30):
        hostname = f"page-{index:02d}.example.test"
        hosts.add(hostname, 443, tags="visible")
        replace_scanned(db, hostname, 443, _cert(hostname, 90, f"page-{index:02d}"), [], True)
        record_scan_history(
            db, ScanHistory(hostname, 443, "success", scanned_at=NOW - timedelta(hours=1))
        )

    def keys(page: int) -> list[str]:
        rows, total = list_dashboard_grouped_page(
            db, page=page, per_page=5, sort_by="days", sort_order="asc", now=NOW
        )
        assert total == 30
        return [row["hosts"][0]["host"] for row in rows]

    first, second, last, clamped = keys(1), keys(2), keys(6), keys(999)
    assert len(first) == len(second) == 5
    assert set(first).isdisjoint(second)
    assert first == sorted(first)
    assert second == sorted(second)
    assert clamped == last

    # A filter chooses groups, but once selected all in-scope endpoints with
    # that fingerprint remain visible.  The matching count is therefore one
    # group, not one endpoint.
    shared = _cert("shared.example.test", 90, "shared")
    for hostname in ("needle.example.test", "companion.example.test"):
        hosts.add(hostname, 443, tags="visible")
        replace_scanned(db, hostname, 443, shared, [], True)
        record_scan_history(
            db, ScanHistory(hostname, 443, "success", scanned_at=NOW - timedelta(hours=1))
        )
    groups, total = list_dashboard_grouped_page(
        db, q="needle", per_page=5, now=NOW, scope_tags=("visible",)
    )
    assert total == 1
    assert {row["host"] for row in groups[0]["hosts"]} == {
        "needle.example.test:443", "companion.example.test:443"
    }
    record_scan_history(
        db,
        ScanHistory(
            "needle.example.test", 443, "failure", scanned_at=NOW - timedelta(minutes=1)
        ),
    )
    groups, total = list_dashboard_grouped_page(
        db, monitoring="failing", per_page=5, now=NOW, scope_tags=("visible",)
    )
    assert total == 1
    assert {row["host"] for row in groups[0]["hosts"]} == {
        "needle.example.test:443", "companion.example.test:443"
    }


def test_grouped_order_has_an_explicit_stable_tiebreak():
    import inspect

    from cert_watch.database import dashboard_grouped

    source = inspect.getsource(dashboard_grouped.list_dashboard_grouped_page)
    assert "ORDER BY sort_val {direction}, group_key ASC" in source


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


def test_unknown_axis_filters_are_rejected_by_json_and_ignored_with_notice(
    tmp_path, reload_app, monkeypatch
):
    from fastapi.testclient import TestClient

    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        for path in ("/api/certificates", "/api/hosts"):
            for name in ("condition", "monitoring", "renewal", "delivery"):
                response = client.get(f"{path}?{name}=bogus")
                assert response.status_code == 400
                assert response.json() == {"error": f"invalid {name} filter: bogus"}

        browse = client.get("/browse?monitoring=bogus&grouped=0")

    assert browse.status_code == 200
    assert "Ignored unknown filter: monitoring=bogus" in browse.text
    assert "failing.example.test" in browse.text
    assert "Monitoring: bogus" not in browse.text


def test_no_surface_calls_failing_or_never_scanned_endpoints_healthy(
    tmp_path, reload_app, monkeypatch
):
    import csv
    import io
    import re

    from fastapi.testclient import TestClient

    db, _ = _seed(tmp_path, "cert-watch.sqlite3")
    with _connect(db) as conn:
        conn.execute(
            "UPDATE certificates SET not_after = ? WHERE hostname = ? AND is_leaf = 1",
            ((NOW + timedelta(days=20)).isoformat(), "failing.example.test"),
        )
        conn.commit()
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        listed = client.get("/api/certificates?limit=50").json()["certificates"]
        pivot = client.get("/api/pivot/owner/Unassigned").json()["entries"]
        csv_rows = list(
            csv.DictReader(io.StringIO(client.get("/api/reports/expiring.csv?days=365").text))
        )
        compliance = client.get("/api/reports/compliance.json").json()
        metrics = client.get("/metrics").text
        html = client.get("/browse?grouped=0").text

    by_host = {row["host"].split(":", 1)[0]: row for row in listed}
    assert by_host["failing.example.test"]["urgency"] == "failing"
    assert by_host["progress.example.test"]["urgency"] == "gray"
    assert all(
        row["urgency"] != "healthy"
        for row in listed
        if row["monitoring"] in {"failing", "never_scanned"}
    )
    assert all(
        row["urgency"] != "healthy"
        for row in pivot
        if row["monitoring"] in {"failing", "never_scanned"}
    )
    failing_csv = next(row for row in csv_rows if row["host"].startswith("failing."))
    assert failing_csv["overall_status"] == "failing"

    compliance_entries = [
        entry
        for bucket in compliance["remediation_buckets"]
        for entry in bucket["entries"]
        if "failing.example.test" in entry["subject"]
    ]
    assert compliance_entries
    assert all(entry["urgency"] == "failing" for entry in compliance_entries)
    values = {
        line.split('urgency="', 1)[1].split('"', 1)[0]: int(float(line.rsplit(" ", 1)[1]))
        for line in metrics.splitlines()
        if line.startswith("cert_watch_certificates_by_urgency{")
    }
    assert values["failing"] >= 1
    failing_row = re.search(
        r"<tr[^>]*>.*?failing\.example\.test.*?</tr>", html, flags=re.DOTALL
    )
    assert failing_row is not None
    assert "Monitoring failing" in failing_row.group(0)
    assert ">Healthy<" not in failing_row.group(0)


def test_every_home_status_number_matches_the_linked_rows(
    tmp_path, reload_app, monkeypatch
):
    import re
    from html import unescape

    from fastapi.testclient import TestClient

    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    app_mod = reload_app()
    with TestClient(app_mod.app) as client:
        home = client.get("/").text
        links = re.findall(
            r'<a[^>]+href="(/browse\?(?:condition|monitoring)=[^"]+)"[^>]*>(.*?)</a>',
            home,
            flags=re.DOTALL,
        )
        assert links
        for href, label in links:
            stat_value = re.search(r'class="cw-stat-val[^\"]*">(\d+)</div>', label)
            visible = re.sub(r"<[^>]+>", "", label)
            raw_count = (
                stat_value.group(1) if stat_value else re.search(r"\d+", visible).group()
            )
            expected = int(raw_count)
            page = client.get(unescape(href)).text
            actual = page.count('data-testid="cert-row"')
            assert actual == expected, (href, expected, actual)

    # Uploaded files have a condition but no monitoring lifecycle.
    assert "not_monitored" not in home


def test_delivery_identities_are_admin_only_across_read_apis(
    tmp_path, reload_app, monkeypatch, login_csrf
):
    import json

    from fastapi.testclient import TestClient

    from cert_watch.auth import SESSION_COOKIE, _scrypt_hash
    from cert_watch.database import (
        Role,
        SqliteRoleRepository,
        SqliteUserRepository,
        User,
        kv_set,
    )
    from cert_watch.database.api_keys import SqliteApiKeyRepository

    db, _ = _seed(tmp_path, "cert-watch.sqlite3")
    password = "example-password"
    password_hash = _scrypt_hash(password, n=2**4, r=1, p=1)
    kv_set(db, "local_admin_user", "admin")
    kv_set(db, "local_admin_password_hash", password_hash)
    kv_set(db, "setup_complete", "1")
    group = SqliteAlertGroupRepository(db).get_by_name("Team A operators")
    assert group is not None
    roles = SqliteRoleRepository(db)
    users = SqliteUserRepository(db)
    viewer_role = roles.add(
        Role(
            name="team-a-viewers", permission_tier="viewer", scope_tag="team-a",
            alert_group_id=group.id, email="team-role@example.test",
        )
    )
    operator_role = roles.add(
        Role(name="operators", permission_tier="operator", scope_tag="team-a")
    )
    users.add(
        User(
            username="viewer", email="member@example.test",
            password_hash=password_hash, role_id=viewer_role,
        )
    )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE hosts SET owner_email = ? WHERE hostname = ?",
            ("team-role@example.test", "manual.example.test"),
        )
        conn.commit()
    users.add(
        User(
            username="operator", email="operator@example.test",
            password_hash=password_hash, role_id=operator_role,
        )
    )
    monkeypatch.setenv("SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("ALERT_FROM", "alerts@example.test")
    monkeypatch.setenv("ALERT_RECIPIENTS", "global@example.test")
    monkeypatch.setenv("CERT_WATCH_COOKIE_SECURE", "0")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    app_mod = reload_app()
    key_repo = SqliteApiKeyRepository(db)
    api_keys = {
        scope: key_repo.create_key(f"status-{scope}", scope)[1]
        for scope in ("read", "write", "admin")
    }

    secrets = {
        "Team A operators", "team-a@example.test", "global@example.test",
        "member@example.test",
    }

    def login(client, username):
        client.cookies.delete(SESSION_COOKIE)
        response = client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "_csrf_token": login_csrf(client),
            },
            follow_redirects=False,
        )
        assert response.status_code == 303

    with TestClient(app_mod.app) as client:
        login(client, "admin")
        admin_list = client.get("/api/certificates?limit=50").json()["certificates"]
        cert_id = next(
            row["id"] for row in admin_list if row["host"].startswith("manual.")
        )
        paths = (
            "/api/certificates?limit=50",
            "/api/hosts?limit=50",
            "/api/export/certificates.json",
            f"/api/certificates/{cert_id}",
            f"/api/certificates/{cert_id}/alert-routing",
        )
        admin_bodies = [client.get(path).json() for path in paths]
        for username in ("viewer", "operator"):
            login(client, username)
            for path in paths:
                response = client.get(path)
                assert response.status_code == 200
                serialized = json.dumps(response.json(), sort_keys=True)
                assert all(secret not in serialized for secret in secrets)
                delivery_blocks = []

                def collect(value, blocks):
                    if isinstance(value, dict):
                        if "delivery" in value.get("status", {}):
                            blocks.append(value["status"]["delivery"])
                        for child in value.values():
                            collect(child, blocks)
                    elif isinstance(value, list):
                        for child in value:
                            collect(child, blocks)

                collect(response.json(), delivery_blocks)
                if path.endswith("/alert-routing"):
                    delivery_blocks.append(response.json()["delivery"])
                assert delivery_blocks
                for delivery in delivery_blocks:
                    assert "recipients" not in delivery
                    assert "matching_groups" not in delivery
                    assert set(delivery) == {
                        "state", "recipient_count", "matching_group_count", "channels"
                    }
                    assert all(set(channel) == {"channel", "route_count"}
                               for channel in delivery["channels"])

        for scope in ("read", "write"):
            client.cookies.delete(SESSION_COOKIE)
            response = client.get(
                f"/api/certificates/{cert_id}/alert-routing",
                headers={"Authorization": f"Bearer {api_keys[scope]}"},
            )
            assert response.status_code == 200
            serialized = json.dumps(response.json(), sort_keys=True)
            assert all(secret not in serialized for secret in secrets)
            delivery = response.json()["delivery"]
            assert set(delivery) == {
                "state", "recipient_count", "matching_group_count", "channels"
            }
            assert all(
                set(channel) == {"channel", "route_count"}
                for channel in delivery["channels"]
            )

        response = client.get(
            f"/api/certificates/{cert_id}/alert-routing",
            headers={"Authorization": f"Bearer {api_keys['admin']}"},
        )
        assert response.status_code == 200
        admin_bodies.append(response.json())

    admin_text = json.dumps(admin_bodies, sort_keys=True)
    assert secrets <= {secret for secret in secrets if secret in admin_text}
