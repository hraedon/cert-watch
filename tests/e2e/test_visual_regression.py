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

from cert_watch.database.api_keys import SqliteApiKeyRepository
from cert_watch.database.connection import _connect
from tests.e2e._seed import seed_detail_estate


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
_MASKS = [
    "[data-testid=auth-user]",
    ".cw-ver",
    "#cw-health",
    ".cw-home-foot span:nth-child(2)",  # Next run crosses at the configured schedule.
    ".cw-home-strip",  # Twelve calendar weeks roll at each UTC week boundary.
]

# Empty-state pages with stable layout (no certs/dates seeded).
_VISUAL_PAGES = {
    "home": ("/", "home-heading"),
    "dashboard": ("/browse", "dashboard-heading"),
    "alerts": ("/alerts", "alerts-heading"),
    "posture": ("/posture", "insights-heading"),
    "audit": ("/audit", "audit-heading"),
    "settings": ("/settings/auth", "settings-heading"),
    "settings-policy": ("/settings/policy", "settings-heading"),
    "settings-access": ("/settings/access", "settings-heading"),
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


@pytest.mark.visual
def test_add_drawer_visual(
    page: Page, visual_server: str, assert_snapshot,
) -> None:
    page.goto(f"{visual_server}/browse")
    page.get_by_test_id("add-host-btn").click()
    drawer = page.locator("#add-drawer")
    expect(drawer).to_be_visible()
    # The drawer slides over the pointer's click position, which can leave the
    # Bulk import tab hovered depending on when Chromium updates hit testing.
    # Park the pointer on the inert backdrop, then wait through compositing and
    # two paint frames so the snapshot always sees the final drawer state.
    page.mouse.move(0, 0)
    drawer.evaluate(
        """async element => {
            await document.fonts.ready;
            const backdrop = document.getElementById(`${element.id}-bg`);
            const animations = [
                ...element.getAnimations({subtree: true}),
                ...backdrop.getAnimations({subtree: true}),
            ].filter(animation =>
                animation.effect?.getTiming().iterations !== Infinity
            );
            await Promise.all(
                animations.map(
                    animation => animation.finished.catch(() => {})
                )
            );
            await new Promise(resolve =>
                requestAnimationFrame(() => requestAnimationFrame(resolve))
            );
        }"""
    )
    assert not page.get_by_test_id("tab-bulk-btn").evaluate(
        "element => element.matches(':hover')"
    )
    assert_snapshot(page, name="add-drawer.png", mask_elements=_MASKS)


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

_POPULATED_MASKS = [*_MASKS, "tbody td:nth-child(3)"]  # Condition column (dates + relative strings)
_HOME_POPULATED_MASKS = [*_MASKS, ".cw-home-state", ".cw-home-foot"]


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


@pytest.fixture(scope="module")
def renewal_visual_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[str, str]]:
    """A deterministic renewal failure shown across all changed pages."""
    data_dir: Path = tmp_path_factory.mktemp("cw-visual-renewal")
    ids = seed_detail_estate(data_dir)
    db = data_dir / "cert-watch.sqlite3"
    key, _token = SqliteApiKeyRepository(db).create_key(
        "deployment-hook", "renewal-report", binding="all"
    )
    now = "2026-09-28T12:00:00+00:00"
    with _connect(db) as conn:
        host = conn.execute(
            "SELECT h.id FROM hosts h JOIN certificates c "
            "ON c.hostname=h.hostname AND c.port=h.port WHERE c.id=?",
            (ids["current"],),
        ).fetchone()
        assert host is not None
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                baseline_fingerprint,received_at,next_check_at,
                failure_attempt_id,failure_reported_at)
               VALUES ('visual-attempt',?,1,?,'verifying',1,'old-leaf',?,?,
                       'visual-attempt',?)""",
            (host["id"], f"api_key:{key.id}", now, now, now),
        )
        conn.execute(
            """INSERT INTO renewal_reports
               (report_id,host_id,hostname_snapshot,port_snapshot,outcome,
                message,tool,correlation_id,received_at,source,effect,attempt_id)
               SELECT 'visual-report',h.id,h.hostname,h.port,'failed',
                      'Deployment command returned a non-zero status.',
                      'deployment-hook','run-2048',?,?,'applied','visual-attempt'
               FROM hosts h WHERE h.id=?""",
            (now, f"api_key:{key.id}", host["id"]),
        )
        conn.commit()
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_ALLOW_UNAUTH": "1",
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "tests.e2e._detail_app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as response:
                if response.status == 200:
                    break
        except Exception:  # noqa: BLE001 - startup polling is transient
            time.sleep(0.1)
    else:
        proc.kill()
        raise RuntimeError("renewal visual server did not become ready")
    try:
        yield base, ids["current"]
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.visual
@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("width,height", [(1440, 900), (390, 844)])
@pytest.mark.parametrize("surface", ["home", "browse", "detail", "api-keys"])
def test_renewal_ui_visuals(
    page: Page,
    renewal_visual_server: tuple[str, str],
    assert_snapshot,
    theme: str,
    width: int,
    height: int,
    surface: str,
) -> None:
    base, cert_id = renewal_visual_server
    path = {
        "home": "/",
        "browse": "/browse",
        "detail": f"/certificates/{cert_id}",
        "api-keys": "/settings/api-keys",
    }[surface]
    page.set_viewport_size({"width": width, "height": height})
    page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
    page.goto(f"{base}{path}")
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(400)
    if surface == "detail":
        page.get_by_test_id("renewal-panel").scroll_into_view_if_needed()
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    assert_snapshot(
        page,
        name=f"renewal-{surface}-{theme}-{width}.png",
        mask_elements=_HOME_POPULATED_MASKS if surface == "home" else _MASKS,
    )


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
        "home-renewal-count-failed",
        "home-renewal-count-not-deployed",
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
    assert len(links) == 27
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
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    page.evaluate("window.scrollTo(500, 0)")
    assert page.evaluate("window.scrollX") == 0


def _assert_home_mobile_never_scrolls(page: Page, base: str) -> None:
    page.set_viewport_size({"width": 390, "height": 900})
    page.goto(base)
    expect(page.get_by_test_id("home-week-link")).to_have_count(12)
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    page.evaluate("window.scrollTo(500, 0)")
    assert page.evaluate("window.scrollX") == 0
    strip = page.locator(".cw-home-horizon-body")
    assert strip.evaluate("el => el.scrollWidth === el.clientWidth")


def test_empty_home_mobile_never_scrolls_the_document(
    page: Page, visual_server: str
) -> None:
    _assert_home_mobile_never_scrolls(page, visual_server)


def test_populated_home_mobile_never_scrolls_the_document(
    page: Page, populated_server: str
) -> None:
    _assert_home_mobile_never_scrolls(page, populated_server)
