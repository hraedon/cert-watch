"""E2E tests: settings page load, display, and save round-trips."""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect


def test_settings_page_loads_with_tabs(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings")
    expect(page.locator("h1, .cw-page")).to_be_visible()
    expect(page.locator("body")).to_contain_text("Authentication")
    expect(page.locator("body")).to_contain_text("SMTP")
    expect(page.locator("body")).to_contain_text("Alerts")


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