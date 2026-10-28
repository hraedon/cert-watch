"""Urgent credential reminders remain visible when the Critical tab is selected."""

import subprocess
from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import expect

from cert_watch.alerting.rules.application_secrets import evaluate_application_secrets
from cert_watch.auth.rbac import AuthContext
from cert_watch.database import SqliteAlertRepository, init_schema
from cert_watch.services.application_secrets import create_application_secret
from tests.e2e._helpers import boot_server


@pytest.fixture(scope="module")
def credential_alert_server(tmp_path_factory):
    data_dir = tmp_path_factory.mktemp("credential-alert-filter")
    database = data_dir / "cert-watch.sqlite3"
    init_schema(database)
    now = datetime.now(UTC)
    for label, days in [("Urgent", 5), ("Later", 10), ("Expired", -1)]:
        create_application_secret(
            database,
            {
                "application_name": label + " example credential",
                "application_id": "synthetic-app-" + label.lower(),
                "credential_id": "synthetic-key",
                "expires_at": (now + timedelta(days=days)).isoformat(),
            },
            auth=AuthContext.system(),
            actor="test",
        )
    assert len(evaluate_application_secrets(database, now=now)) == 3
    identifiers = {alert.subject: alert.id for alert in SqliteAlertRepository(database).list_all()}
    process, base = boot_server(
        data_dir,
        env_extra={
            "CERT_WATCH_ALLOW_UNAUTH": "1",
            "SMTP_HOST": "",
            "ALERT_FROM": "",
            "ALERT_RECIPIENTS": "",
            "ALERT_WEBHOOK_URL": "",
        },
    )
    try:
        yield base, identifiers
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_critical_filter_agrees_with_credential_urgency(page, credential_alert_server, theme):
    base, identifiers = credential_alert_server
    page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
    page.goto(base + "/alerts")
    critical = page.locator('.cw-filterbar a[href="/alerts?filter_type=critical"]')
    warnings = page.locator('.cw-filterbar a[href="/alerts?filter_type=warning"]')
    expect(critical).to_have_text("Critical 2")
    expect(warnings).to_have_text("Warnings 1")
    critical.click()
    for label in ("Urgent", "Expired"):
        expect(
            page.locator(f'[data-alert-id="{identifiers[label + " example credential"]}"]')
        ).to_be_visible()
    expect(
        page.locator(f'[data-alert-id="{identifiers["Later example credential"]}"]')
    ).to_have_count(0)
    warnings.click()
    expect(
        page.locator(f'[data-alert-id="{identifiers["Later example credential"]}"]')
    ).to_be_visible()
    expect(
        page.locator(f'[data-alert-id="{identifiers["Urgent example credential"]}"]')
    ).to_have_count(0)
