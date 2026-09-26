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
    for retired in (
        "Monitoring pipeline healthy",
        'data-testid="attention-item"',
        "renewal unknown",
        "1/1 current scans",
        "private root",
    ):
        assert retired not in html


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
