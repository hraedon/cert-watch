"""Home A's three-block and linked-count contracts (#126 S3)."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from tests.test_four_axis_status import _seed


def _anchor(html: str, testid: str) -> tuple[str, int]:
    match = re.search(
        rf'<a[^>]*data-testid="{re.escape(testid)}"[^>]*href="([^"]+)"[^>]*>'
        rf'(.*?)</a>|<a[^>]*href="([^"]+)"[^>]*data-testid="{re.escape(testid)}"[^>]*>'
        rf"(.*?)</a>",
        html,
        flags=re.DOTALL,
    )
    assert match is not None, testid
    href = unescape(match.group(1) or match.group(3))
    body = match.group(2) or match.group(4)
    count = re.search(r"\d+", re.sub(r"<[^>]+>", "", body))
    assert count is not None, testid
    return href, int(count.group())


def _row_count(client: TestClient, href: str) -> int:
    response = client.get(href)
    assert response.status_code == 200, href
    return response.text.count('data-testid="cert-row"')


def test_home_a_structure_wording_and_empty_estate(reload_app, monkeypatch) -> None:
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
    assert response.status_code == 200
    html = response.text
    for testid in (
        "certificate-risk-block",
        "monitoring-gaps-block",
        "delivery-routing-block",
        "horizon-panel",
    ):
        assert f'data-testid="{testid}"' in html
    assert 'data-testid="empty-onboarding"' in html
    assert html.count('data-testid="home-week-link"') == 12
    assert "No alerts to route yet" in html
    assert "Email not configured" not in html
    assert "No scans yet" in html
    assert "Last run" not in html
    assert "alerts undelivered" not in html
    for retired in (
        "Monitoring pipeline healthy",
        'data-testid="attention-item"',
        "renewal unknown",
        "1/1 current scans",
        "private root",
    ):
        assert retired not in html


def test_home_copy_describes_delivery_and_missing_owners(reload_app, tmp_path, monkeypatch) -> None:
    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "can\u2019t be delivered" in html
    assert "alerts undelivered" not in html
    assert "No owner" in html
    assert "Last scan activity" in html
    assert "Never scanned since" not in html


def test_every_home_number_opens_exactly_the_rows_it_counts(
    reload_app, tmp_path, monkeypatch
) -> None:
    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
        assert response.status_code == 200
        html = response.text

        summary_links = (
            "home-condition-count-expired",
            "home-condition-count-le7",
            "home-condition-count-8to30",
            "home-condition-count-ok",
            "home-renewal-count-failed",
            "home-renewal-count-not-deployed",
            "home-monitoring-count-failing",
            "home-monitoring-count-never",
            "home-monitoring-count-current",
            "home-delivery-count-failing",
            "home-delivery-count-unrouted",
        )
        for testid in summary_links:
            href, expected = _anchor(html, testid)
            assert _row_count(client, href) == expected, testid

        tracked_href, tracked = _anchor(html, "home-tracked-count")
        assert _row_count(client, tracked_href) == tracked

        for group in response.context["chain_groups"]:
            assert _row_count(client, group.browse_url) == group.count
        if response.context["chain_problem_total"]:
            chain_href, chain_total = _anchor(html, "home-chain-total-link")
            assert chain_total == response.context["chain_problem_total"]
            assert _row_count(client, chain_href) == chain_total

        for line in response.context["delivery_lines"]:
            if line.action_url and line.action_url.startswith("/browse?"):
                expected = int(re.search(r"\d+", line.action_label).group())
                assert _row_count(client, line.action_url) == expected

        week_links = re.findall(
            r'<a href="([^"]+)"[^>]*data-testid="home-week-link"[^>]*data-count="(\d+)"',
            html,
        )
        assert len(week_links) == 12
        for href, expected in week_links:
            parsed = parse_qs(urlparse(unescape(href)).query)
            assert set(parsed) == {"expiry_week", "grouped"}
            assert _row_count(client, unescape(href)) == int(expected), href


def test_home_rows_are_bounded_and_ranked_by_expiry(reload_app, tmp_path, monkeypatch) -> None:
    from cert_watch.database import SqliteHostRepository, replace_scanned
    from tests.test_four_axis_status import _cert

    db, _settings = _seed(tmp_path, "cert-watch.sqlite3")
    hosts = SqliteHostRepository(db)
    for index in range(12):
        host = f"rank-{index:02d}.example.test"
        hosts.add(host, 443)
        replace_scanned(db, host, 443, _cert(host, -20 + index, f"rank-fp-{index}"), [], True)

    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
    expired = [row for row in response.context["risk_rows"] if row.condition == "expired"]
    assert len(expired) == 6
    assert [row.name for row in expired] == [f"rank-{index:02d}.example.test" for index in range(6)]


def test_home_renewal_outcomes_follow_expiry_rows_and_link_exact_population(
    reload_app, tmp_path, monkeypatch
) -> None:
    from cert_watch.database.connection import _connect

    db, _settings = _seed(tmp_path, "cert-watch.sqlite3")
    now = "2026-09-28T12:00:00+00:00"
    with _connect(db) as conn:
        hosts = conn.execute("SELECT id,hostname FROM hosts ORDER BY hostname LIMIT 2").fetchall()
        for index, (host, state) in enumerate(zip(hosts, ("failed", "not_deployed"), strict=True)):
            attempt_id = f"home-renewal-{index}"
            conn.execute(
                """INSERT INTO renewal_attempts
                   (attempt_id,host_id,is_current,source,state,opened_seq,
                    received_at,raised_at,failure_attempt_id,failure_reported_at)
                   VALUES (?,?,1,'test',?,?,?, ?,?,?)""",
                (
                    attempt_id,
                    host["id"],
                    "verifying" if state == "failed" else state,
                    index + 1,
                    now,
                    now if state == "not_deployed" else None,
                    attempt_id if state == "failed" else None,
                    now if state == "failed" else None,
                ),
            )
        conn.commit()

    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
        rows = response.context["risk_rows"]
        renewal_rows = [row for row in rows if row.condition in {"failed", "not_deployed"}]
        assert [row.condition for row in renewal_rows] == ["failed", "not_deployed"]
        assert rows.index(renewal_rows[0]) >= sum(
            row.condition in {"expired", "le7", "8to30"} for row in rows
        )
        assert renewal_rows[0].condition_label == "Renewal failed"
        assert renewal_rows[0].difference == "Reported 2026-09-28 12:00 UTC"
        assert renewal_rows[1].condition_label == "Deployment not confirmed"
        assert renewal_rows[1].difference == "Raised 2026-09-28 12:00 UTC"
        for testid in (
            "home-renewal-count-failed",
            "home-renewal-count-not-deployed",
        ):
            href, expected = _anchor(response.text, testid)
            assert _row_count(client, href) == expected == 1


def test_home_keeps_expiry_headline_when_renewal_also_failed(
    reload_app, tmp_path, monkeypatch
) -> None:
    from cert_watch.database.connection import _connect

    db, _settings = _seed(tmp_path, "cert-watch.sqlite3")
    with _connect(db) as conn:
        target = conn.execute(
            """SELECT h.id AS host_id,c.id AS cert_id FROM hosts h JOIN certificates c
               ON c.hostname=h.hostname AND c.port=h.port
               ORDER BY c.not_after LIMIT 1"""
        ).fetchone()
        conn.execute(
            "UPDATE certificates SET not_after='2026-09-24T12:00:00+00:00' WHERE id=?",
            (target["cert_id"],),
        )
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,received_at,
                failure_reported_at)
               VALUES ('expiry-failure',?,1,'test','verifying',1,?,?)""",
            (
                target["host_id"],
                "2026-09-28T12:00:00+00:00",
                "2026-09-28T12:00:00+00:00",
            ),
        )
        conn.commit()

    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
    matching = [
        item
        for item in response.context["risk_rows"]
        if item.detail_url.endswith(target["cert_id"])
    ]
    assert len(matching) == 1
    assert matching[0].condition == "expired"
    assert matching[0].condition_label.startswith("Expired ")
    assert matching[0].condition_label.endswith(" days ago")
    # The renewal line leads; the row keeps its other details (review R2-1).
    assert matching[0].difference.startswith("Renewal failed · 2026-09-28 12:00 UTC")


def test_home_escapes_an_unmapped_scan_error(reload_app, tmp_path, monkeypatch) -> None:
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.scheduler import ScanHistory, record_scan_history

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add("odd.example.test", 443)
    raw = '<img src=x onerror="alert(1)"> unexpected scanner failure'
    record_scan_history(
        db,
        ScanHistory(
            hostname="odd.example.test",
            port=443,
            status="failure",
            error_message=raw,
        ),
    )
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert raw not in response.text
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in response.text


def test_home_webhook_failure_uses_scoped_delivery_evidence(tmp_path) -> None:
    from cert_watch.database import Alert, SqliteAlertRepository, dashboard_axis_stats
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.connection import _connect
    from cert_watch.database.delivery_evidence import begin_attempt, complete_attempt
    from cert_watch.status_model import AxisSettings, prepare_status_model_context

    db, _settings = _seed(tmp_path, "cert-watch.sqlite3")
    with _connect(db) as conn:
        cert_id = str(
            conn.execute(
                "SELECT id FROM certificates WHERE is_leaf = 1 ORDER BY id LIMIT 1"
            ).fetchone()["id"]
        )
    alert_id = SqliteAlertRepository(db).create(
        Alert(
            cert_id=cert_id,
            alert_type="expiry_warning",
            status="pending",
            message="Example delivery",
        )
    )
    attempt = begin_attempt(db, alert_id, "webhook:slack", {"target": "redacted"})
    complete_attempt(db, attempt, {"outcome": "failed", "error": "HTTP 500"})
    status = prepare_status(db)
    settings = AxisSettings(webhook_configured=True, webhook_kind="slack")
    axes = prepare_status_model_context(db, certificate_status=status, settings=settings)

    result = dashboard_axis_stats(
        db,
        status=status,
        axes=axes,
        axis_columns=frozenset({"condition", "monitoring", "delivery", "routing"}),
        home=True,
    )

    assert result["_home"]["webhook_outcome"] == "failed"
    assert result["_home"]["webhook_failed_at"]
    assert "redacted" not in str(result["_home"])


def test_renewal_count_matches_browse_total_with_duplicate_scanned_leaves(tmp_path) -> None:
    """An alias merge can leave one endpoint with two scanned leaves. The Home
    renewal count must equal the population its Browse link lists (review of
    #150, round 2)."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard_axes import dashboard_axis_stats
    from cert_watch.database.dashboard_page import list_dashboard_page
    from cert_watch.status_model import AxisSettings, prepare_status_model_context
    from tests._helpers import seed_scanned

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    stamp = now.isoformat()
    host_id = SqliteHostRepository(db).add("merge.example.test", 443, tags="t")
    seed_scanned(
        db,
        "merge.example.test",
        443,
        Certificate(
            subject="CN=merge.example.test",
            issuer="CN=Test CA",
            not_before=now - timedelta(days=5),
            not_after=now + timedelta(days=200),
            fingerprint_sha256="a1".ljust(64, "0"),
        ),
    )
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO certificates
               (id,subject,issuer,not_before,not_after,san_dns_names,fingerprint_sha256,
                raw_der,source,hostname,port,is_leaf,parent_cert_id,tags,created_at,updated_at)
               VALUES ('dup-leaf','CN=merge-alt.example.test','CN=Test CA',?,?,'[]',?,x'00',
                       'scanned','merge.example.test',443,1,NULL,'t',?,?)""",
            (
                (now - timedelta(days=4)).isoformat(),
                (now + timedelta(days=200)).isoformat(),
                "b2".ljust(64, "0"),
                stamp,
                stamp,
            ),
        )
        conn.execute(
            "INSERT INTO renewal_attempts(attempt_id,host_id,is_current,source,state,"
            "opened_seq,received_at,failure_attempt_id,failure_reported_at)"
            " VALUES('dup-a',?,1,'test','verifying',1,?,?,?)",
            (host_id, stamp, "dup-a", stamp),
        )
        conn.commit()

    status = prepare_status(db, now)
    axes = prepare_status_model_context(db, certificate_status=status, settings=AxisSettings())
    for columns in (frozenset({"condition", "renewal"}), frozenset({"renewal_risks"})):
        counts = dashboard_axis_stats(
            db, status=status, axes=axes, axis_columns=columns, home=True
        )["renewal"]
        _rows, total = list_dashboard_page(
            db, renewal="failed", per_page=0, status=status, axes=axes
        )
        assert counts["failed"] == total


def test_home_risk_block_survives_a_caller_without_the_renewal_axis(tmp_path) -> None:
    """Pin the NULL-renewal guard: Home without the renewal axis must still list
    expiry risk rows (review of #150, B3)."""
    from datetime import UTC, datetime, timedelta

    from cert_watch.certificate_model import Certificate
    from cert_watch.database import SqliteHostRepository, init_schema
    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.dashboard_axes import dashboard_axis_stats
    from cert_watch.status_model import AxisSettings, prepare_status_model_context
    from tests._helpers import seed_scanned

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    now = datetime.now(UTC)
    SqliteHostRepository(db).add("soon.example.test", 443)
    seed_scanned(
        db,
        "soon.example.test",
        443,
        Certificate(
            subject="CN=soon.example.test",
            issuer="CN=Test CA",
            not_before=now - timedelta(days=80),
            not_after=now - timedelta(days=1),
            fingerprint_sha256="c3".ljust(64, "0"),
        ),
    )
    status = prepare_status(db, now)
    axes = prepare_status_model_context(db, certificate_status=status, settings=AxisSettings())
    columns = frozenset({"condition", "monitoring", "delivery", "chain", "routing"})
    stats = dashboard_axis_stats(db, status=status, axes=axes, axis_columns=columns, home=True)
    home = stats.pop("_home")
    assert stats["condition"]["expired"] == 1
    assert "risk:expired" in home["rows"]


def _strip(html: str) -> str:
    match = re.search(
        r'<div class="cw-home-strip-status" data-testid="home-status-strip">(.*?)\n    </div>',
        html,
        flags=re.DOTALL,
    )
    return match.group(1) if match else ""


def test_home_strip_holds_only_healthy_monitoring_and_delivery(reload_app, monkeypatch) -> None:
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    with TestClient(reload_app().app) as client:
        html = client.get("/").text
    strip = _strip(html)
    assert 'data-testid="monitoring-gaps-block"' in strip
    assert 'data-testid="delivery-routing-block"' in strip
    assert html.count('data-testid="monitoring-gaps-block"') == 1
    assert html.count('data-testid="delivery-routing-block"') == 1
    assert 'data-testid="certificate-hygiene-block"' in html


@pytest.mark.parametrize(
    ("monitoring_open", "delivery_open"),
    [(True, True), (True, False), (False, True)],
    ids=["both-open", "monitoring-open", "delivery-open"],
)
def test_home_problem_blocks_open_out_of_the_strip(
    reload_app, tmp_path, monkeypatch, monitoring_open, delivery_open
) -> None:
    _seed(tmp_path, "cert-watch.sqlite3")
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.start", lambda self: None)
    monkeypatch.setattr("cert_watch.scheduler.Scheduler.stop", lambda self: None)
    # The seed has both monitoring and delivery problems; quiet one of them
    # so the strip renders with the other opened out of it.
    from cert_watch.presenters import home as home_presenter

    if not monitoring_open:
        monkeypatch.setattr(home_presenter, "_monitoring_rows", lambda _rows: ())
    if not delivery_open:
        quiet = home_presenter.DeliveryLine(
            label="All configured channels are delivering", detail="", tone="",
            action_url=None, action_label="", admin_only=False,
        )
        monkeypatch.setattr(home_presenter, "_delivery_lines", lambda **_: (quiet,))
    with TestClient(reload_app().app) as client:
        response = client.get("/")
        html = response.text
        assert bool(response.context["monitoring_rows"]) is monitoring_open
        assert any(line.tone for line in response.context["delivery_lines"]) is delivery_open
        strip = _strip(html)
        both_open = monitoring_open and delivery_open
        assert ('data-testid="home-status-strip"' in html) is not both_open
        assert ('data-testid="monitoring-gaps-block"' in strip) is not monitoring_open
        assert ('data-testid="delivery-routing-block"' in strip) is not delivery_open
        assert html.count('data-testid="monitoring-gaps-block"') == 1
        assert html.count('data-testid="delivery-routing-block"') == 1
        if monitoring_open:
            assert html.count('data-testid="home-monitoring-row"') == len(
                response.context["monitoring_rows"]
            )

        chain_rows = [row for row in response.context["risk_rows"] if row.chain_url]
        assert html.count('data-testid="home-risk-chain"') == len(chain_rows)
        for row in chain_rows:
            assert _row_count(client, row.chain_url) >= 1, row.chain_url
        assert html.count('data-testid="home-chain-row"') == len(response.context["chain_groups"])
