"""E2E tests: upload PEM, upload PFX, add host (with scan stub)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    pkcs12,
)
from cryptography.x509.oid import NameOID

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


def _make_cert(cn: str, issuer_cert=None, issuer_key=None, days=365, san=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = issuer_cert.subject if issuer_cert else subject
    sign = issuer_key or key
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=days))
    )
    if san:
        b = b.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    return key, b.sign(sign, hashes.SHA256())


@pytest.fixture
def pem_path(tmp_path: Path) -> Path:
    _, cert = _make_cert("e2e-pem.example.com", san=["e2e-pem.example.com"])
    p = tmp_path / "e2e.pem"
    p.write_bytes(cert.public_bytes(Encoding.PEM))
    return p


@pytest.fixture
def pfx_path(tmp_path: Path) -> Path:
    root_key, root_cert = _make_cert("E2E Root", days=3650)
    inter_key, inter_cert = _make_cert(
        "E2E Intermediate", issuer_cert=root_cert, issuer_key=root_key, days=1825
    )
    leaf_key, leaf_cert = _make_cert(
        "e2e-pfx.example.com",
        issuer_cert=inter_cert,
        issuer_key=inter_key,
        days=90,
        san=["e2e-pfx.example.com"],
    )
    data = pkcs12.serialize_key_and_certificates(
        name=b"e2e",
        key=leaf_key,
        cert=leaf_cert,
        cas=[inter_cert, root_cert],
        encryption_algorithm=NoEncryption(),
    )
    p = tmp_path / "e2e.pfx"
    p.write_bytes(data)
    return p


def _open_slide(page: Page) -> None:
    """Open the Add-host slide-over panel."""
    page.locator("button:has-text('Add host')").click()
    page.locator(".cw-slide.on").wait_for()


def _switch_tab(page: Page, tab: str) -> None:
    """Switch to a tab in the slide-over (scan, upload, bulk)."""
    page.locator(f"#add-tabs button[data-tab='{tab}']").click()
    page.locator(f"#tab-{tab}").wait_for()


def test_upload_pem_appears_on_dashboard(
    page: Page, cert_watch_server: str, pem_path: Path
) -> None:
    page.goto(cert_watch_server)
    _open_slide(page)
    _switch_tab(page, "upload")
    page.locator("#tab-upload input[name='file']").set_input_files(str(pem_path))
    page.locator("#tab-upload button[type=submit]").click()
    expect(page.locator("body")).to_contain_text("e2e-pem.example.com")


def test_upload_pfx_shows_leaf_and_chain(
    page: Page, cert_watch_server: str, pfx_path: Path
) -> None:
    page.goto(cert_watch_server)
    _open_slide(page)
    _switch_tab(page, "upload")
    page.locator("#tab-upload input[name='file']").set_input_files(str(pfx_path))
    page.locator("#tab-upload button[type=submit]").click()
    body = page.locator("body")
    expect(body).to_contain_text("e2e-pfx.example.com")
    # Chain info is on the detail page; click through to verify
    page.locator("tr.cw-row-link", has_text="e2e-pfx.example.com").click()
    page.wait_for_url("**/certificates/*")
    expect(body).to_contain_text("E2E Intermediate")
    expect(body).to_contain_text("E2E Root")


def test_add_host_creates_row(page: Page, cert_watch_server: str) -> None:
    hostname = "nonexistent.invalid"
    page.goto(cert_watch_server)
    _open_slide(page)
    # Scan host tab is active by default
    page.locator("#tab-scan input[name='hostname']").fill(hostname)
    page.locator("#tab-scan input[name='port']").fill("443")
    page.locator("#tab-scan button[type=submit]").click()
    # The scan will fail (host doesn't exist) — the dashboard should still load
    # without 500. The host is stored even though no cert is captured.
    expect(page.locator("h1")).to_have_text("Certificates")
    # Assert the host appears in the table
    expect(page.locator("body")).to_contain_text(hostname)
    # Navigate to scan-history and assert a failure entry exists. Scan results are
    # grouped into collapsible batches (collapsed by default); expand them to reveal
    # the per-host rows before asserting.
    page.goto(f"{cert_watch_server}/scan-history")
    for toggle in page.locator("button[data-action='toggle-batch']").all():
        toggle.click()
    expect(page.get_by_text("nonexistent.invalid:443", exact=True).first).to_be_visible()
    expect(page.get_by_role("table").get_by_text("failure").first).to_be_visible()
