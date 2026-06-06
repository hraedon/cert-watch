"""E2E: every page renders and its primary surface is present.

Functional regression coverage (WS-C2) built on stable data-testid hooks so a
broken route or template surfaces here rather than in production.
"""

from __future__ import annotations

import pytest

pytest.importorskip("playwright")
from _helpers import PAGES, open_add_slide, switch_add_tab
from playwright.sync_api import Page, expect


@pytest.mark.parametrize("nav_testid,heading_testid", list(PAGES.items()))
def test_every_page_renders_from_nav(
    page: Page, cert_watch_server: str, nav_testid: str, heading_testid: str
) -> None:
    """Click each nav item; the destination page's heading must render."""
    page.goto(cert_watch_server)
    page.get_by_test_id(nav_testid).click()
    expect(page.get_by_test_id(heading_testid)).to_be_visible()


def test_settings_page_renders(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings")
    expect(page.get_by_test_id("settings-heading")).to_be_visible()


def test_compliance_report_renders(page: Page, cert_watch_server: str) -> None:
    """The compliance report page (linked from Insights) renders + offers exports."""
    page.goto(f"{cert_watch_server}/reports/compliance")
    expect(page.get_by_test_id("compliance-heading")).to_be_visible()


def test_dashboard_search_box_present(page: Page, cert_watch_server: str) -> None:
    page.goto(cert_watch_server)
    expect(page.get_by_test_id("dashboard-search")).to_be_visible()


def test_add_slide_tabs_switch(page: Page, cert_watch_server: str) -> None:
    """The Add-host slide-over opens and its tabs switch (scan/upload/bulk)."""
    page.goto(cert_watch_server)
    open_add_slide(page)
    switch_add_tab(page, "upload")
    expect(page.get_by_test_id("upload-file-input")).to_be_attached()
    switch_add_tab(page, "scan")
    expect(page.get_by_test_id("scan-hostname-input")).to_be_visible()


# ── API keys management UI (Plan 039) ──────────────────────────────────────


def test_api_keys_create_list_revoke(page: Page, cert_watch_server: str) -> None:
    """Create a key (token shown once), see it listed, then revoke it."""
    page.goto(f"{cert_watch_server}/settings/api-keys")
    expect(page.get_by_test_id("api-keys-heading")).to_be_visible()
    expect(page.get_by_test_id("api-keys-empty")).to_be_visible()

    page.get_by_test_id("api-key-name-input").fill("ci-pipeline")
    page.get_by_test_id("api-key-scope-select").select_option("write")
    page.get_by_test_id("api-key-create-btn").click()

    # The raw token is shown exactly once, prefixed cwk_.
    token_box = page.get_by_test_id("api-key-token")
    expect(token_box).to_be_visible()
    assert token_box.input_value().startswith("cwk_")

    # It now appears in the table; revoke it.
    expect(page.get_by_test_id("api-keys-table")).to_contain_text("ci-pipeline")
    page.get_by_test_id("api-key-revoke-btn").first.click()
    expect(page.get_by_test_id("api-keys-empty")).to_be_visible()


def test_api_keys_reachable_from_settings(page: Page, cert_watch_server: str) -> None:
    page.goto(f"{cert_watch_server}/settings")
    page.get_by_test_id("settings-api-keys-link").click()
    expect(page.get_by_test_id("api-keys-heading")).to_be_visible()


# ── Certificate detail page (C2) ───────────────────────────────────────────


def test_cert_detail_page_renders(
    page: Page, cert_watch_server: str, tmp_path
) -> None:
    """Uploading a cert and clicking through shows its detail page + download."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    cn = "detail-render.example.com"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "detail.pem"
    p.write_bytes(cert.public_bytes(Encoding.PEM))

    page.goto(cert_watch_server)
    open_add_slide(page)
    switch_add_tab(page, "upload")
    page.get_by_test_id("upload-file-input").set_input_files(str(p))
    page.get_by_test_id("upload-submit-btn").click()
    expect(page.locator("body")).to_contain_text(cn)

    page.get_by_test_id("cert-row").filter(has_text=cn).click()
    page.wait_for_url("**/certificates/*")
    expect(page.get_by_test_id("cert-detail-heading")).to_be_visible()
    expect(page.get_by_test_id("cert-download-pem")).to_be_visible()
