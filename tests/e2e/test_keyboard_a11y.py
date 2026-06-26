"""E2E tests for keyboard-accessibility behaviors (WI-068).

These lock in the keyboard interactions that were implemented but had zero
test coverage:

- Enter/Space activation on ``[data-action]`` rows with ``tabindex``
- Escape-to-close on the slide-over dialog
- Focus trap within the slide-over dialog
- Arrow-key navigation in the reports dropdown menu (WAI-ARIA menu pattern)
- Arrow-key tab switching on the dashboard tablist (WAI-ARIA tab pattern)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


def _make_cert_pem(cn: str, days: int = 60) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


@pytest.fixture
def pem_path(tmp_path: Path) -> Path:
    p = tmp_path / "kb-cert.pem"
    p.write_bytes(_make_cert_pem("kb-test.example.com"))
    return p


@pytest.fixture
def pem_path_space(tmp_path: Path) -> Path:
    """Distinct CN so the Space test verifies its own cert, not the Enter test's."""
    p = tmp_path / "kb-cert-space.pem"
    p.write_bytes(_make_cert_pem("kb-space.example.com"))
    return p


def _upload_cert(page: Page, base_url: str, pem: Path, cn: str) -> None:
    """Upload a PEM via the slide-over so a cert row exists on the dashboard."""
    page.goto(base_url)
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()
    page.get_by_test_id("tab-upload-btn").click()
    page.get_by_test_id("upload-file-input").set_input_files(str(pem))
    page.get_by_test_id("upload-submit-btn").click()
    expect(page.locator("body")).to_contain_text(cn)


# ---------------------------------------------------------------------------
# Enter / Space activation on data-action rows
# ---------------------------------------------------------------------------

def test_enter_activates_cert_row(page: Page, cert_watch_server: str, pem_path: Path) -> None:
    """Enter on a tabindex'd cert row (role=link) navigates to detail page."""
    _upload_cert(page, cert_watch_server, pem_path, "kb-test.example.com")
    page.goto(cert_watch_server)
    row = page.locator('[data-testid="cert-row"]').first
    expect(row).to_be_visible()
    row.focus()
    row.press("Enter")
    # data-action="open-link" navigates to /certificates/<id>
    page.wait_for_url("**/certificates/*", timeout=5000)


def test_space_activates_cert_row(page: Page, cert_watch_server: str, pem_path_space: Path) -> None:
    """Space on a tabindex'd cert row (role=link) navigates to detail page."""
    _upload_cert(page, cert_watch_server, pem_path_space, "kb-space.example.com")
    page.goto(cert_watch_server)
    row = page.locator('[data-testid="cert-row"]', has_text="kb-space.example.com")
    expect(row).to_be_visible()
    row.focus()
    row.press("Space")
    page.wait_for_url("**/certificates/*", timeout=5000)


# ---------------------------------------------------------------------------
# Escape-to-close slide-over
# ---------------------------------------------------------------------------

def test_escape_closes_slide_over(page: Page, cert_watch_server: str) -> None:
    """Escape closes the slide-over and returns focus to the trigger."""
    page.goto(cert_watch_server)
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()
    # Escape should close (the .on class is removed; panel slides off-screen)
    page.keyboard.press("Escape")
    page.locator("#slide-panel.on").wait_for(state="hidden", timeout=3000)
    # Focus should return to the trigger button
    expect(page.get_by_test_id("add-host-btn")).to_be_focused()


# ---------------------------------------------------------------------------
# Focus trap within slide-over
# ---------------------------------------------------------------------------

def test_focus_trapped_in_slide_over(page: Page, cert_watch_server: str) -> None:
    """Tab cycles within the open dialog (focus trap), not escaping to the page."""
    page.goto(cert_watch_server)
    page.get_by_test_id("add-host-btn").click()
    panel = page.locator("#slide-panel")
    panel.wait_for(state="visible")
    # Tab several times — focus should stay inside the panel
    for _ in range(15):
        page.keyboard.press("Tab")
        in_panel = page.evaluate(
            "document.activeElement"
            " ? document.activeElement.closest('#slide-panel') !== null"
            " : false"
        )
        assert in_panel, "Focus escaped the slide-over dialog (trap broken)"


# ---------------------------------------------------------------------------
# Reports dropdown: arrow-key navigation (WAI-ARIA menu)
# ---------------------------------------------------------------------------

def test_reports_menu_arrow_key_nav(page: Page, cert_watch_server: str) -> None:
    """Arrow Down moves focus between menuitems; Escape closes and restores focus."""
    page.goto(cert_watch_server)
    page.get_by_test_id("dashboard-heading").wait_for()
    btn = page.locator("#reports-btn")
    btn.click()
    items = page.locator('#reports-menu-wrap [role="menuitem"]')
    expect(items).to_have_count(3)
    # Menu open → first item should be focused (roving tabindex)
    expect(items.first).to_be_focused()
    # Arrow Down → second item
    page.keyboard.press("ArrowDown")
    expect(items.nth(1)).to_be_focused()
    # Arrow Down wraps to first (3 items: CSV-inv, JSON-inv, CSV-hosts)
    page.keyboard.press("ArrowDown")
    page.keyboard.press("ArrowDown")
    expect(items.first).to_be_focused()
    # Arrow Up wraps to last
    page.keyboard.press("ArrowUp")
    expect(items.last).to_be_focused()
    # Escape closes, focus returns to trigger
    page.keyboard.press("Escape")
    expect(btn).to_be_focused()


# ---------------------------------------------------------------------------
# Dashboard tablist: arrow-key tab switching (WAI-ARIA tab pattern)
# ---------------------------------------------------------------------------

def test_add_tabs_arrow_key_switching(page: Page, cert_watch_server: str) -> None:
    """Arrow Right/Left switches tabs in the Add-certificates tablist."""
    page.goto(cert_watch_server)
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()
    scan_tab = page.get_by_test_id("tab-scan-btn")
    upload_tab = page.get_by_test_id("tab-upload-btn")
    bulk_tab = page.get_by_test_id("tab-bulk-btn")
    # Start on scan tab (aria-selected=true)
    scan_tab.focus()
    expect(scan_tab).to_have_attribute("aria-selected", "true")
    # Arrow Right → upload
    page.keyboard.press("ArrowRight")
    expect(upload_tab).to_have_attribute("aria-selected", "true")
    # Arrow Right → bulk
    page.keyboard.press("ArrowRight")
    expect(bulk_tab).to_have_attribute("aria-selected", "true")
    # Arrow Right wraps → scan
    page.keyboard.press("ArrowRight")
    expect(scan_tab).to_have_attribute("aria-selected", "true")
    # Arrow Left wraps → bulk
    page.keyboard.press("ArrowLeft")
    expect(bulk_tab).to_have_attribute("aria-selected", "true")


# ---------------------------------------------------------------------------
# Insights page tablist: arrow-key switching (navigation-based tabs)
# ---------------------------------------------------------------------------

def test_insights_tabs_arrow_key_switching(page: Page, cert_watch_server: str) -> None:
    """Arrow Right/Left switches between Insights tabs via URL navigation."""
    page.goto(f"{cert_watch_server}/insights?tab=calendar")
    page.get_by_test_id("insights-heading").wait_for()
    tabs = page.locator('[role="tablist"][aria-label="Insights view"] [role="tab"]')
    expect(tabs).to_have_count(2)
    # Start on calendar tab (first tab, aria-selected=true)
    expect(tabs.first).to_have_attribute("aria-selected", "true")
    tabs.first.focus()
    # Arrow Right → trends (navigates to ?tab=trends)
    page.keyboard.press("ArrowRight")
    page.wait_for_url("**/insights?tab=trends", timeout=5000)
    trends_tab = page.locator('[role="tablist"][aria-label="Insights view"] [role="tab"]').nth(1)
    expect(trends_tab).to_have_attribute("aria-selected", "true")
    # Arrow Left → back to calendar
    trends_tab.focus()
    page.keyboard.press("ArrowLeft")
    page.wait_for_url("**/insights?tab=calendar", timeout=5000)
