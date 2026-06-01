from playwright.sync_api import Page, expect


def test_health_banner_shows_on_dashboard(page: Page, cert_watch_server: str) -> None:
    """The health banner should appear and show operational status."""
    page.goto(cert_watch_server)
    expect(page.locator("h1")).to_have_text("Certificates")

    # Banner should be visible after the JS fetch completes
    banner = page.locator("#cw-health-banner")
    expect(banner).to_be_visible()

    # Should contain operational text (scheduler is running, no failed scans)
    text = page.locator("#cw-health-text")
    expect(text).to_have_text("All systems operational")

    # Should have the ok tone class
    expect(banner).to_have_class("cw-health-banner cw-health-ok")
