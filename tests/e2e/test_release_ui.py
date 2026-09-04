"""Release-critical responsive and operator-language browser checks."""

from __future__ import annotations

from playwright.sync_api import Page, expect

MOBILE = {"width": 390, "height": 844}


def _inside_viewport(page: Page, selector: str) -> None:
    box = page.locator(selector).bounding_box()
    assert box is not None
    assert box["x"] >= 0
    assert box["x"] + box["width"] <= MOBILE["width"] + 1


def test_mobile_primary_navigation_is_compact_and_identifies_section(
    page: Page, cert_watch_server: str
) -> None:
    page.set_viewport_size(MOBILE)
    page.goto(f"{cert_watch_server}/browse")

    expect(page.locator(".cw-nav-desktop")).to_be_hidden()
    section = page.locator(".cw-mobile-nav")
    expect(section).to_be_visible()
    expect(section.locator("summary")).to_contain_text("Browse")
    assert page.locator(".cw-topbar").bounding_box()["height"] <= 60

    section.locator("summary").click()
    browse_link = section.get_by_role("link", name="Browse", exact=True)
    expect(browse_link).to_have_attribute("aria-current", "page")
    _inside_viewport(page, ".cw-nav-mobile")


def test_mobile_tables_and_page_actions_stay_reachable(
    page: Page, cert_watch_server: str
) -> None:
    page.set_viewport_size(MOBILE)
    page.goto(f"{cert_watch_server}/browse")
    clip = page.locator(".cw-panel > .cw-table-clip").first
    expect(clip).to_have_css("overflow-x", "auto")
    expect(page.locator(".cw-inventory-table")).to_have_css("min-width", "0px")

    page.goto(f"{cert_watch_server}/activity")
    _inside_viewport(page, ".cw-page-actions")
    expect(page.locator('[data-action="mark-all-read"]')).to_be_disabled()
    expect(page.locator('[data-action="flush-queue"]')).to_be_disabled()


def test_mobile_report_menu_is_not_clipped(page: Page, cert_watch_server: str) -> None:
    page.set_viewport_size(MOBILE)
    page.goto(f"{cert_watch_server}/posture")
    page.get_by_role("button", name="Generate report").click()
    _inside_viewport(page, "#reports-menu")


def test_browse_expiry_language_does_not_claim_operational_health(
    page: Page, cert_watch_server: str
) -> None:
    page.goto(f"{cert_watch_server}/browse")
    expect(page.locator(".cw-stats")).to_contain_text("Expiry healthy")
    expect(page.locator(".cw-stats")).to_contain_text("30+ days remaining")


def test_dense_mobile_rows_and_authenticated_chrome_fit(
    page: Page, cert_watch_server: str
) -> None:
    page.set_viewport_size(MOBILE)
    page.set_content(
        f'''<link rel="stylesheet" href="{cert_watch_server}/static/css/tokens.css">
        <link rel="stylesheet" href="{cert_watch_server}/static/css/cw.css">
        <header class="cw-topbar">
        <a class="cw-wordmark">
        <span class="cw-mark">
        </span>
        <span class="cw-name">cert·watch</span>
        </a>
        <span class="cw-scope">scope: production-services</span>
        <div class="cw-user">
        <span data-testid="auth-user">long.operator.name@example.invalid</span>
        <button class="cw-btn sm">Logout</button>
        </div>
        <button class="cw-iconbtn">theme</button>
        <details class="cw-mobile-nav cw-nav">
        <summary>Section Home</summary>
        </details>
        </header>
        <main class="cw-wrap">
        <div class="cw-att-row">
        <div class="cw-att-sev">Critical</div>
        <div class="cw-att-main">
        <span class="cw-id">api.production.example:443</span>
        <div class="cw-sub">expires soon · scan failing · issuer unavailable</div>
        </div>
        <div class="cw-chiprow">
        <span class="cw-chip">Platform Reliability Engineering</span>
        </div>
        <div class="cw-rowact">
        <button class="cw-btn sm">Review</button>
        </div>
        </div>
        <table class="cw-table cw-inventory-table">
        <tbody>
        <tr>
        <td data-label="Certificate">*.production.example</td>
        <td data-label="Expires">
        <div class="cw-expiry">
        <div class="mono tnum">2026-09-18</div>
        <div class="cw-sub">in 14 days</div>
        <div class="cw-expiry-track">
        <span class="cw-bar">
        </span>
        </div>
        </div>
        </td>
        <td data-label="Status">Warning</td>
        <td data-label="Grade">B</td>
        <td data-label="Action">›</td>
        </tr>
        </tbody>
        </table>
        </main>'''
    )
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    expiry = page.locator(".cw-expiry").bounding_box()
    assert expiry is not None and expiry["width"] >= 88
    expect(page.locator(".cw-att-row")).to_contain_text("Platform Reliability Engineering")
