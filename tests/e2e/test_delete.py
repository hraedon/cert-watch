"""E2E: upload a cert, click delete, confirm it's gone."""

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


@pytest.fixture
def delete_pem_path(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "e2e-delete.example.com")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("e2e-delete.example.com")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    p = tmp_path / "e2e-delete.pem"
    p.write_bytes(cert.public_bytes(Encoding.PEM))
    return p


def _open_slide(page: Page) -> None:
    """Open the Add-host slide-over panel."""
    page.get_by_test_id("add-host-btn").click()
    page.locator(".cw-slide.on").wait_for()


def _switch_tab(page: Page, tab: str) -> None:
    """Switch to a tab in the slide-over."""
    page.get_by_test_id(f"tab-{tab}-btn").click()
    page.locator(f"#tab-{tab}").wait_for()


def test_upload_then_delete_removes_cert(
    page: Page, cert_watch_server: str, delete_pem_path: Path
) -> None:
    page.goto(cert_watch_server)
    _open_slide(page)
    _switch_tab(page, "upload")
    page.get_by_test_id("upload-file-input").set_input_files(
        str(delete_pem_path),
    )
    page.get_by_test_id("upload-submit-btn").click()
    body = page.locator("body")
    expect(body).to_contain_text("e2e-delete.example.com")

    # Click the cert row to go to detail page
    page.get_by_test_id("cert-row").filter(has_text="e2e-delete.example.com").click()
    page.wait_for_url("**/certificates/*")

    # Click the delete button on the detail page
    page.on("dialog", lambda dialog: dialog.accept())
    page.get_by_test_id("cert-delete-btn").click()

    # After delete, should redirect to dashboard and cert should be gone
    expect(page.locator("body")).not_to_contain_text("e2e-delete.example.com")
