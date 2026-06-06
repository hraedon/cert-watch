"""Visual-regression baselines for the core pages (WS-C4).

Catches unintended visual changes. Volatile regions (the build version string
and the async health banner) are masked so the baselines are deterministic.

Run:    pytest -m visual tests/e2e --no-cov -n0
Reseed: pytest -m visual tests/e2e --no-cov -n0 --update-snapshots

Baselines live in tests/e2e/__screenshots__/. A deliberate UI change is
re-baselined with --update-snapshots; an accidental one fails the diff.
"""

from __future__ import annotations

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect

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
    page: Page, cert_watch_server: str, assert_snapshot, name, spec
) -> None:
    path, heading = spec
    page.goto(f"{cert_watch_server}{path}")
    if heading:
        expect(page.get_by_test_id(heading)).to_be_visible()
    # Settle async chrome (health banner poll) before the shot.
    page.wait_for_timeout(400)
    assert_snapshot(page, name=f"{name}.png", mask_elements=_MASKS)
