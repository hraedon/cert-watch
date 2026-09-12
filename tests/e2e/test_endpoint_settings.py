"""Edit a monitored endpoint from either the pending or certificate detail page."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

pytest.importorskip("playwright")
from _helpers import boot_server
from _seed import make_cert_pem
from playwright.sync_api import Page, expect

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository, init_schema


@pytest.fixture(params=["pending", "scanned"])
def editable_endpoint(request, tmp_path: Path):
    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    host_id = hosts.add(
        "editor.example.test", 443, scan_interval_hours=48, threshold_days=14,
        owner_name="Operations", renewal_method="manual", expected_issuers="Legacy CA",
    )
    detail_id = host_id
    if request.param == "scanned":
        pem = make_cert_pem("editor.example.test", "Editor CA", 90)
        cert = parse_certificate(x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER))
        assert isinstance(cert, Certificate)
        detail_id = SqliteCertificateRepository(
            db, source="scanned", hostname="editor.example.test", port=443,
        ).add(cert)
    proc, base = boot_server(tmp_path, {"CERT_WATCH_ALLOW_UNAUTH": "1"})
    try:
        yield base, detail_id, hosts, host_id, request.param
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_endpoint_settings_save_reopen_and_restore_defaults(
    page: Page, editable_endpoint,
) -> None:
    base, detail_id, hosts, host_id, kind = editable_endpoint
    if kind == "pending":
        page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{base}/certificates/{detail_id}")
    page.get_by_test_id("endpoint-settings-edit").click()
    interval = page.get_by_label("Scan interval (hours)", exact=True)
    threshold = page.get_by_label("Alert threshold (days)", exact=True)
    status = page.get_by_label("Renewal status reported by operator", exact=True)
    expect(interval).to_have_value("48")
    expect(threshold).to_have_value("14")
    expect(page.locator("#endpoint-renewal-help")).to_contain_text(
        "suppresses new expiry alerts until the next successful scan"
    )
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    interval.fill("6")
    threshold.fill("45")
    status.select_option("renewed")
    page.get_by_test_id("endpoint-settings-save").click()
    expect(page.get_by_test_id("endpoint-settings-saved")).to_be_visible()
    saved = hosts.get(host_id)
    assert (saved.scan_interval_hours, saved.threshold_days, saved.renewal_status) == (
        6, 45, "renewed",
    )
    assert saved.owner_name == "Operations"
    assert saved.renewal_method == "manual"
    assert saved.expected_issuers == "Legacy CA"

    page.get_by_test_id("endpoint-settings-edit").click()
    expect(interval).to_have_value("6")
    expect(threshold).to_have_value("45")
    expect(status).to_have_value("renewed")
    interval.fill("")
    threshold.fill("")
    status.select_option("pending")
    page.get_by_test_id("endpoint-settings-save").click()
    expect(page.get_by_test_id("endpoint-settings-saved")).to_be_visible()
    page.reload()
    page.get_by_test_id("endpoint-settings-edit").click()
    expect(interval).to_have_value("")
    expect(threshold).to_have_value("")
    expect(status).to_have_value("pending")
    saved = hosts.get(host_id)
    assert saved.scan_interval_hours is None
    assert saved.threshold_days is None
