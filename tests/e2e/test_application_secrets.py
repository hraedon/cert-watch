"""Exercise metadata entry and retirement in both themes and narrow layouts."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect


@pytest.mark.parametrize("theme,width", [("light", 1280), ("dark", 1280),
                                         ("light", 375), ("dark", 375)])
def test_add_and_retire_application_secret(
    page: Page, cert_watch_server: str, theme: str, width: int, tmp_path: Path,
) -> None:
    page.set_viewport_size({"width": width, "height": 900})
    page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
    page.goto(cert_watch_server + "/application-secrets")
    expect(page.get_by_role("heading", name="Application credentials", exact=True)).to_be_visible()
    page.screenshot(path=str(tmp_path / f"credentials-before-{theme}-{width}.png"), full_page=True)
    identity = uuid4().hex
    page.get_by_label("Application name", exact=True).fill("Example " + identity)
    page.get_by_label("Application (client) ID").fill("example-client-" + identity)
    page.get_by_label("Credential (key) ID").fill("example-key")
    page.get_by_label("Credential label").fill("Deployment key")
    page.get_by_label("Tenant ID (optional)").fill("example-tenant")
    page.get_by_label("Expiry (UTC)").fill(
        (datetime.now(UTC) + timedelta(days=5)).strftime("%Y-%m-%dT%H:%M"),
    )
    page.get_by_label("Owner email (optional)").fill("owner@example.invalid")
    page.get_by_role("button", name="Add credential", exact=True).click()
    expect(page.get_by_role("status")).to_have_text("Credential added.")
    record = page.locator("article").filter(has_text="Example " + identity)
    expect(record.get_by_text("Expires within 7 days", exact=True)).to_be_visible()
    assert page.locator("input[type=password]").count() == 0
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.screenshot(path=str(tmp_path / f"credentials-added-{theme}-{width}.png"), full_page=True)
    record.get_by_role("button", name="Retire credential").click()
    expect(record.get_by_text("Retired", exact=True)).to_be_visible()
    expect(record.get_by_role("button", name="Retire credential")).to_have_count(0)
