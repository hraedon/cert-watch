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


def test_upload_then_delete_removes_cert(
    page: Page, cert_watch_server: str, delete_pem_path: Path
) -> None:
    page.goto(cert_watch_server)
    upload_form = 'form.upload[action="/upload"]'
    page.locator(f'{upload_form} input[name="file"]').set_input_files(
        str(delete_pem_path),
    )
    page.locator(f'{upload_form} button[type=submit]').click()
    body = page.locator("body")
    expect(body).to_contain_text("e2e-delete.example.com")

    # Click the first cert-row delete button inside the unified table.
    page.on("dialog", lambda dialog: dialog.accept())
    page.locator('[data-testid="delete-cert-btn"]').first.click()

    # After delete, the dashboard should no longer contain the cert subject.
    expect(page.locator("body")).not_to_contain_text("e2e-delete.example.com")
