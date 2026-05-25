from playwright.sync_api import Page, expect


def test_dashboard_loads_empty_state(page: Page, cert_watch_server: str) -> None:
    page.goto(cert_watch_server)
    expect(page.locator("h1")).to_have_text("cert-watch")
    # Multiple .empty regions exist (hosts section + cert list); assert both present.
    expect(page.locator(".empty")).to_have_count(2)
