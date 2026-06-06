"""Shared helpers for the E2E Playwright suite.

Keeps selectors centralised on the stable ``data-testid`` hooks (BC-132) so a
markup change only needs updating in one place.
"""

from __future__ import annotations

from playwright.sync_api import Page

# Page identity: nav test-id → heading test-id rendered on that page.
# (Settings nav is only shown to authenticated users, so it's tested directly.)
PAGES = {
    "nav-dashboard": "dashboard-heading",
    "nav-alerts": "alerts-heading",
    "nav-scans": "scans-heading",
    "nav-insights": "insights-heading",
    "nav-discover": "discover-heading",
    "nav-audit": "audit-heading",
}


def open_add_slide(page: Page) -> None:
    """Open the dashboard Add-host slide-over."""
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()


def switch_add_tab(page: Page, tab: str) -> None:
    """Switch the slide-over tab (scan | upload | bulk)."""
    page.get_by_test_id(f"tab-{tab}-btn").click()
    page.locator(f"#tab-{tab}").wait_for()
