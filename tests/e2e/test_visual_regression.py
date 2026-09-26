"""Visual-regression baselines for the core pages (WS-C4).

Catches unintended visual changes. Volatile regions (the build version string
and the async health banner) are masked so the baselines are deterministic.

Run:    pytest -m visual tests/e2e --no-cov -n0
Reseed: pytest -m visual tests/e2e --no-cov -n0 --update-snapshots

Baselines live in tests/e2e/__screenshots__/. A deliberate UI change is
re-baselined with --update-snapshots; an accidental one fails the diff.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def visual_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A dedicated, empty-state server so baselines are deterministic regardless
    of what the functional suite did to the shared session server."""
    data_dir: Path = tmp_path_factory.mktemp("cw-visual-data")
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_ALLOW_UNAUTH": "1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    break
        except Exception:  # noqa: BLE001 — startup polling tolerates transient HTTP failures
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("visual server did not become ready")
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

# Regions that legitimately vary between runs/builds.
_MASKS = ["[data-testid=auth-user]", ".cw-ver", "#cw-health"]

# Empty-state pages with stable layout (no certs/dates seeded).
_VISUAL_PAGES = {
    "home": ("/", "home-heading"),
    "dashboard": ("/browse", "dashboard-heading"),
    "alerts": ("/alerts", "alerts-heading"),
    "posture": ("/posture", "insights-heading"),
    "audit": ("/audit", "audit-heading"),
    "settings": ("/settings/auth", "settings-heading"),
    "api-keys": ("/settings/api-keys", "api-keys-heading"),
    # This server explicitly disables auth: /login redirects to Home.
    "login": ("/login", "home-heading"),
}


@pytest.mark.visual
@pytest.mark.parametrize("name,spec", list(_VISUAL_PAGES.items()))
def test_page_visual(
    page: Page, visual_server: str, assert_snapshot, name, spec
) -> None:
    path, heading = spec
    page.goto(f"{visual_server}{path}")
    if heading:
        expect(page.get_by_test_id(heading)).to_be_visible()
    # Settle async chrome (health banner poll) and webfonts before the shot.
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(400)
    assert_snapshot(page, name=f"{name}.png", mask_elements=_MASKS)


# ---------------------------------------------------------------------------
# Populated-dashboard baseline (2026-06-11 review): the empty-state shots
# above cannot catch bugs that only render on rows — wrong plurals, broken
# relative-time strings, chip/pill regressions. Seed a fixed demo estate and
# baseline the dashboard with data in it.
#
# The seed uses fixed day-offsets, so stat counts, status pills, urgency-bar
# widths, and row order are deterministic. Rendered dates and "in N days"
# strings are NOT (they move with the wall clock), so the expiry column is
# masked alongside the standard volatile chrome.
# ---------------------------------------------------------------------------

_POPULATED_MASKS = [*_MASKS, "tbody td:nth-child(4)"]  # Expires column (dates + relative strings)
_HOME_POPULATED_MASKS = [*_MASKS, ".cw-home-state", ".cw-home-foot", ".cw-home-strip"]


@pytest.fixture(scope="module")
def populated_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    from _seed import seed_demo_certs

    data_dir: Path = tmp_path_factory.mktemp("cw-visual-populated")
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_ALLOW_UNAUTH": "1",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    break
        except Exception:  # noqa: BLE001 — startup polling tolerates transient HTTP failures
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("populated visual server did not become ready")
    try:
        seed_demo_certs(data_dir)
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.visual
def test_dashboard_populated_visual(
    page: Page, populated_server: str, assert_snapshot
) -> None:
    page.goto(f"{populated_server}/browse")
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    # All five seeded rows rendered before the shot.
    expect(page.locator("tbody tr")).to_have_count(5)
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(400)
    assert_snapshot(
        page, name="dashboard-populated.png", mask_elements=_POPULATED_MASKS
    )


@pytest.mark.visual
def test_home_populated_visual(
    page: Page, populated_server: str, assert_snapshot
) -> None:
    page.goto(populated_server)
    expect(page.get_by_test_id("home-heading")).to_be_visible()
    # The seed has three expiring/expired leaves and two issuing-CA groups.
    expect(page.get_by_test_id("home-risk-row")).to_have_count(3)
    expect(page.get_by_test_id("home-chain-row")).to_have_count(2)
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(400)
    assert_snapshot(
        page, name="home-populated.png", mask_elements=_HOME_POPULATED_MASKS
    )


def test_home_a_blocks_layout_and_every_filtered_link(
    page: Page, populated_server: str
) -> None:
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.goto(populated_server)
    blocks = [
        page.get_by_test_id("certificate-risk-block"),
        page.get_by_test_id("monitoring-gaps-block"),
        page.get_by_test_id("delivery-routing-block"),
    ]
    boxes = [block.bounding_box() for block in blocks]
    assert all(box is not None for box in boxes)
    assert max(box["y"] for box in boxes if box) - min(box["y"] for box in boxes if box) < 2

    summary_ids = (
        "home-tracked-count",
        "home-condition-count-expired",
        "home-condition-count-le7",
        "home-condition-count-8to30",
        "home-condition-count-ok",
        "home-monitoring-count-failing",
        "home-monitoring-count-never",
        "home-monitoring-count-current",
        "home-delivery-count-failing",
        "home-delivery-count-unrouted",
        "home-chain-total-link",
    )
    links: list[tuple[str, int]] = []
    for testid in summary_ids:
        link = page.get_by_test_id(testid)
        count = int(next(part for part in link.inner_text().split() if part.isdigit()))
        href = link.get_attribute("href")
        assert href is not None
        links.append((href, count))
    for link in page.get_by_test_id("home-chain-row").locator("a").all():
        href = link.get_attribute("href")
        assert href is not None
        links.append((href, int(link.inner_text().split()[-1])))
    for link in page.get_by_test_id("home-week-link").all():
        href = link.get_attribute("href")
        assert href is not None
        links.append((href, int(link.get_attribute("data-count") or "0")))

    all_home_hrefs = set(page.locator("main a").evaluate_all(
        "els => els.map(el => el.getAttribute('href')).filter(Boolean)"
    ))
    assert len(links) == 25
    for href, expected in links:
        page.goto(f"{populated_server}{href}")
        expect(page.get_by_test_id("cert-row")).to_have_count(expected)
    for href in sorted(all_home_hrefs):
        response = page.goto(f"{populated_server}{href}")
        assert response is not None and response.status < 400, href

    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(populated_server)
    boxes = [page.get_by_test_id(testid).bounding_box() for testid in (
        "certificate-risk-block", "monitoring-gaps-block", "delivery-routing-block",
    )]
    assert all(box is not None for box in boxes)
    assert [box["y"] for box in boxes if box] == sorted(box["y"] for box in boxes if box)
