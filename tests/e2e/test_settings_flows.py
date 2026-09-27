"""E2E tests: settings page load, display, and save round-trips."""

from __future__ import annotations

import re

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


def test_settings_page_loads_with_tabs(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings")
    expect(page.get_by_test_id("settings-heading")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Authentication")
    expect(page.locator("body")).to_contain_text("Channels")
    expect(page.locator("body")).to_contain_text("Alert groups")


def test_settings_auth_tab_default_no_provider(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings?tab=auth")
    expect(page.locator("#auth_provider")).to_be_visible()
    expect(page.locator("#auth_provider")).to_have_value("")


def test_settings_smtp_tab_shows_fields(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings?tab=smtp")
    expect(page.locator("#smtp_host")).to_be_visible()
    expect(page.locator("#smtp_port")).to_be_visible()


def test_settings_alerts_tab_shows_fields(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings?tab=alerts")
    expect(page.locator("#webhook_url")).to_be_visible()


def test_settings_save_smtp_roundtrip(page: Page, cert_watch_server: str) -> None:
    """Save SMTP config via the settings page and verify it persists."""
    page.goto(f"{cert_watch_server}/settings?tab=smtp")

    smtp_host = page.locator("#smtp_host")
    smtp_host.fill("")
    smtp_host.fill("mail.example.com")

    smtp_port = page.locator("#smtp_port")
    smtp_port.fill("587")

    smtp_user = page.locator("#smtp_user")
    smtp_user.fill("certwatch@example.com")

    alert_from = page.locator("#alert_from")
    alert_from.fill("certwatch@example.com")

    form = page.locator("form[action='/settings/smtp']")
    form.locator('button[type="submit"]').click()

    expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

    expect(page.locator("body")).to_contain_text("Settings saved")

    page.goto(f"{cert_watch_server}/settings?tab=smtp")
    expect(page.locator("#smtp_host")).to_have_value("mail.example.com")
    expect(page.locator("#smtp_user")).to_have_value("certwatch@example.com")


def test_settings_save_alerts_roundtrip(page: Page, cert_watch_server: str) -> None:
    """Save alert config via the settings page and verify it persists."""
    page.goto(f"{cert_watch_server}/settings?tab=alerts")

    webhook_url = page.locator("#webhook_url")
    webhook_url.fill("")
    webhook_url.fill("https://hooks.example.com/alert")

    form = page.locator("form[action='/settings/alerts']")
    form.locator('button[type="submit"]').click()

    expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)
    expect(page.locator("body")).to_contain_text("Settings saved")

    page.goto(f"{cert_watch_server}/settings?tab=alerts")
    expect(page.locator("#webhook_url")).to_have_value("https://hooks.example.com/alert")


def test_scan_schedule_roundtrip_under_policy(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings/policy#daily-scan-time")
    page.locator("#sched_hour").fill("22")
    page.locator("#sched_min").fill("15")
    page.get_by_test_id("scan-schedule-form").locator('button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r"/settings/policy\?saved=1"), timeout=5000)
    expect(page.locator("#sched_hour")).to_have_value("22")
    expect(page.locator("#sched_min")).to_have_value("15")

    page.goto(f"{cert_watch_server}/settings/channels#daily-scan-time")
    expect(page.locator("#sched_hour")).to_have_count(0)
    expect(page.locator('a[href="/settings/policy#daily-scan-time"]')).to_be_visible()
    expect(page.locator('a[href="/settings/policy#daily-scan-time"]')).to_have_class(
        re.compile(r"\bcw-link\b")
    )


def test_access_page_combines_roles_mapping_and_local_users(
    page: Page, cert_watch_server: str,
) -> None:
    page.goto(f"{cert_watch_server}/settings/access")
    expect(page.locator("#roles")).to_be_visible()
    expect(page.locator("#roles")).to_contain_text("IdP mapping")
    expect(page.locator("#local-users")).to_be_visible()
    expect(page.locator("#local-users")).to_contain_text("Local users")

    page.goto(f"{cert_watch_server}/settings/roles")
    expect(page).to_have_url(re.compile(r"/settings/access#roles$"))
    page.goto(f"{cert_watch_server}/settings/users")
    expect(page).to_have_url(re.compile(r"/settings/access#local-users$"))


def test_access_tabs_follow_hash_and_expose_current_location(
    page: Page,
    cert_watch_server: str,
) -> None:
    page.goto(f"{cert_watch_server}/settings/access#local-users")
    roles = page.locator('[data-access-tabs] a[href="#roles"]')
    users = page.locator('[data-access-tabs] a[href="#local-users"]')
    expect(users).to_have_class(re.compile(r"\bon\b"))
    expect(users).to_have_attribute("aria-current", "location")
    expect(roles).not_to_have_class(re.compile(r"\bon\b"))
    expect(roles).not_to_have_attribute("aria-current", "location")

    roles.click()
    expect(page).to_have_url(re.compile(r"#roles$"))
    expect(roles).to_have_class(re.compile(r"\bon\b"))
    expect(roles).to_have_attribute("aria-current", "location")
    expect(users).not_to_have_attribute("aria-current", "location")


@pytest.mark.parametrize("path", ["/settings/policy", "/settings/access"])
def test_reorganized_settings_have_no_horizontal_scroll_at_mobile_width(
    page: Page, cert_watch_server: str, path: str,
) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{cert_watch_server}{path}")
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    assert page.locator(".cw-page").evaluate("el => el.scrollWidth === el.clientWidth")
    page.evaluate("window.scrollTo(500, 0)")
    assert page.evaluate("window.scrollX") == 0
