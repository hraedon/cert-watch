"""Browser qualification of notification details with bounded synthetic evidence."""

from __future__ import annotations

from unittest.mock import Mock
from urllib.parse import urlsplit

import pytest
from playwright.sync_api import expect
from starlette.testclient import TestClient

from cert_watch.database.delivery_evidence import begin_attempt
from tests.test_alert_delivery_evidence import _config, _pending, _smtp


@pytest.mark.parametrize("theme,width", [("dark", 375), ("light", 375),
                                         ("dark", 1280), ("light", 1280)])
def test_delivery_details_expand_and_wrap(page, monkeypatch, tmp_path, reload_app, theme, width):
    from cert_watch.alerts import process_pending

    db, repo, alert = _pending(tmp_path)
    address = "operator" * 8 + "@" + "long-domain." * 7 + "invalid"
    config = _config()
    config.recipients = [address]
    _smtp(monkeypatch, refused={"queued@example.invalid": (550, b"refused")})
    assert process_pending(repo, config) == {"sent": 1, "failed": 0, "deferred": 0}
    # Include the crash/in-progress state independently of the completed row.
    unknown = repo.list_for_cert(alert.cert_id)[0]
    unknown.id = "unknown-attempt-alert"
    unknown.subject = "CN=unknown.invalid"
    repo.create(unknown)
    begin_attempt(db, unknown.id, "generic", {
        "recipients": [], "global_recipients": [], "queued_recipients": [],
        "groups": [], "groups_available": True,
    })
    monkeypatch.setattr("cert_watch.app.start_scheduler", Mock())
    monkeypatch.setattr("cert_watch.app.stop_scheduler", Mock())
    with TestClient(reload_app().app) as client:
        def respond(route):
            parsed = urlsplit(route.request.url)
            response = client.get(parsed.path + ("?" + parsed.query if parsed.query else ""))
            headers = {key: value for key, value in response.headers.items()
                       if key.lower() not in {"content-length", "content-encoding"}}
            route.fulfill(status=response.status_code, headers=headers, body=response.content)

        page.route("http://evidence.test/**", respond)
        page.set_viewport_size({"width": width, "height": 1000})
        page.goto("http://evidence.test/alerts")
        page.evaluate("theme => document.documentElement.dataset.theme = theme", theme)
        partial = page.locator(f'[data-alert-id="{alert.id}"]')
        expect(partial.get_by_text("Partial acceptance", exact=True)).to_be_visible()
        disclosure = partial.get_by_test_id("notification-details")
        disclosure.locator("summary").click()
        expect(disclosure).to_have_attribute("open", "")
        expect(disclosure.get_by_text(f"Accepted by relay: {address}", exact=True)).to_be_visible()
        expect(disclosure.get_by_text("Refused by relay: queued@example.invalid")).to_be_visible()
        unknown_row = page.locator('[data-alert-id="unknown-attempt-alert"]')
        expect(unknown_row.get_by_text("Delivery outcome unknown", exact=True)).to_be_visible()
        unknown_row.locator("summary").click()
        expect(unknown_row.get_by_text("Completion was not recorded.", exact=False)).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        page.screenshot(path=str(tmp_path / f"delivery-{theme}-{width}.png"), full_page=True)
