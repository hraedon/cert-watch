import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


def test_health_banner_shows_on_dashboard(page: Page, cert_watch_server: str) -> None:
    """The health banner should appear and show operational status."""
    page.goto(f"{cert_watch_server}/browse")
    expect(page.locator("h1")).to_have_text("Certificates")

    # Banner should be visible after the JS fetch completes
    banner = page.locator("#cw-health")
    expect(banner).to_be_visible()

    # Should contain pipeline-health text (scheduler is running, no failed
    # scans). Wording names the *monitoring pipeline* — not certificate
    # health — so a green banner can't be misread as "all certs are fine".
    text = page.locator("#cw-health-text")
    expect(text).to_have_text("Monitoring pipeline healthy")

    # Should have the ok tone class
    expect(banner).to_have_class("cw-health")  # ok state carries no tone class


def test_health_banner_names_a_broken_directory_configuration(
    page: Page, cert_watch_server: str,
) -> None:
    """A directory misconfiguration reaches the banner, not only the server log."""
    import json

    reason = "the LDAP user search filter '(uid=(username))' must contain {username}"
    page.route(
        "**/api/health",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps({
                "overall": "warning", "scheduler_running": True,
                "failed_alerts_24h": 0, "undelivered_alerts": 0,
                "endpoints_without_successful_scan": 0, "auth_config_error": reason,
            }),
        ),
    )
    page.goto(f"{cert_watch_server}/browse")
    text = page.locator("#cw-health-text")
    expect(text).to_have_text(f"Directory sign-in is misconfigured: {reason}")
    expect(page.locator("#cw-health")).to_have_class("cw-health t-warn")
