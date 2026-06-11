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
        except Exception:
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
_MASKS = ["[data-testid=auth-user]", ".cw-ver", "#cw-health-banner"]

# Empty-state pages with stable layout (no certs/dates seeded).
_VISUAL_PAGES = {
    "dashboard": ("/", "dashboard-heading"),
    "alerts": ("/alerts", "alerts-heading"),
    "insights": ("/insights", "insights-heading"),
    "discover": ("/discover", "discover-heading"),
    "audit": ("/audit", "audit-heading"),
    "settings": ("/settings", "settings-heading"),
    "api-keys": ("/settings/api-keys", "api-keys-heading"),
    "login": ("/login", None),
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
    # Settle async chrome (health banner poll) before the shot.
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

_POPULATED_MASKS = [*_MASKS, "td.cw-td-minw-150"]


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
        except Exception:
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
    page.goto(populated_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    # All five seeded rows rendered before the shot.
    expect(page.locator("tbody tr")).to_have_count(5)
    page.wait_for_timeout(400)
    assert_snapshot(
        page, name="dashboard-populated.png", mask_elements=_POPULATED_MASKS
    )
