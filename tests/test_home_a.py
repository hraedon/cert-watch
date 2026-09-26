"""Home A's three-block and linked-count contracts (#126 S3)."""

from __future__ import annotations

import re
from html import unescape
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.test_four_axis_status import _seed


def _anchor(html: str, testid: str) -> tuple[str, int]:
    match = re.search(
        rf'<a[^>]*data-testid="{re.escape(testid)}"[^>]*href="([^"]+)"[^>]*>'
        rf'(.*?)</a>|<a[^>]*href="([^"]+)"[^>]*data-testid="{re.escape(testid)}"[^>]*>'
        rf'(.*?)</a>',
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


def test_home_copy_describes_delivery_and_missing_owners(
    reload_app, tmp_path, monkeypatch
) -> None:
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


def test_home_rows_are_bounded_and_ranked_by_expiry(
    reload_app, tmp_path, monkeypatch
) -> None:
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
    assert [row.name for row in expired] == [
        f"rank-{index:02d}.example.test" for index in range(6)
    ]


def test_home_escapes_an_unmapped_scan_error(
    reload_app, tmp_path, monkeypatch
) -> None:
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
        cert_id = str(conn.execute(
            "SELECT id FROM certificates WHERE is_leaf = 1 ORDER BY id LIMIT 1"
        ).fetchone()["id"])
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
    axes = prepare_status_model_context(
        db, certificate_status=status, settings=settings
    )

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
