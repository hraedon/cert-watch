"""E2E tests: authed POST to every settings form + readiness page (P2.4).

Covers the WI-027 defect class — form wiring that unit tests cannot see.  The
GET-half is baselined in test_pages_render.py / test_settings_flows.py; this
file closes the POST-half by driving every settings form end-to-end and
asserting the persisted round-trip.

Two fixture scopes:
- ``cert_watch_server`` (session, ALLOW_UNAUTH=1) for open-access form POSTs.
- ``authed_server`` (module, local admin configured) for password rotation and
  the unauthed-redirect guard.
"""

from __future__ import annotations

import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Browser, Page, expect

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_server(
    data_dir: Path, extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.Popen, str]:
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_HOST": "127.0.0.1",
        "CERT_WATCH_PORT": str(port),
        **(extra_env or {}),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    return proc, base
        except Exception:
            time.sleep(0.1)
    proc.kill()
    out = proc.stdout.read().decode() if proc.stdout else ""
    raise RuntimeError(f"cert-watch server did not become ready:\n{out}")


def _login(
    page: Page,
    base: str,
    username: str = "e2eadmin",
    password: str = "e2eTestPass1",
) -> None:
    page.goto(f"{base}/login")
    page.get_by_test_id("login-username").fill(username)
    page.get_by_test_id("login-password").fill(password)
    page.get_by_test_id("login-submit-btn").click()
    page.wait_for_url("**/*", timeout=5000)


# ---------------------------------------------------------------------------
# Module-scoped authed server fixture (starts in needs_setup mode)
# ---------------------------------------------------------------------------

def _spawn_authed_server(
    data_dir: Path, browser: Browser,
) -> tuple[subprocess.Popen, str]:
    """Start a server and create a local admin (e2eadmin / newE2ePass1) via the
    setup wizard, driven through a throwaway browser context so credentials are
    persisted to kv_store and the server's auth_provider is updated in-process.
    """
    proc, base = _start_server(data_dir)
    ctx = browser.new_context()
    pg = ctx.new_page()
    pg.goto(f"{base}/setup")
    pg.locator('input[name="username"]').fill("e2eadmin")
    pg.locator('input[name="password"]').fill("newE2ePass1")
    pg.locator('input[name="password_confirm"]').fill("newE2ePass1")
    pg.get_by_test_id("setup-submit-btn").click()
    pg.wait_for_url("**/*", timeout=5000)
    ctx.close()
    return proc, base


def _terminate(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module")
def authed_server(
    tmp_path_factory: pytest.TempPathFactory, browser: Browser,
) -> Iterator[str]:
    """Server with a local admin, used by tests that depend on the admin
    password staying at ``newE2ePass1`` for the lifetime of the module.

    Password-mutating tests must NOT use this fixture — rotating the admin
    password here breaks every later login-dependent test sharing it. Those
    tests use ``authed_server_mutable`` instead, which is isolated for exactly
    that reason.
    """
    data_dir: Path = tmp_path_factory.mktemp("cw-settings-auth-data")
    proc, base = _spawn_authed_server(data_dir, browser)
    try:
        yield base
    finally:
        _terminate(proc)


@pytest.fixture(scope="module")
def authed_server_mutable(
    tmp_path_factory: pytest.TempPathFactory, browser: Browser,
) -> Iterator[str]:
    """Isolated authed server for tests that rotate the admin password.

    Kept separate from ``authed_server`` so a password change cannot pollute
    the login-dependent form tests (the order-dependent failure mode this
    suite is meant to guard against, not reproduce).
    """
    data_dir: Path = tmp_path_factory.mktemp("cw-settings-auth-mutable-data")
    proc, base = _spawn_authed_server(data_dir, browser)
    try:
        yield base
    finally:
        _terminate(proc)


# ===================================================================
# Tests against the open-access (ALLOW_UNAUTH=1) session server
# ===================================================================


class TestSettingsAuthPost:
    """POST /settings/auth — save authentication provider config."""

    def test_save_auth_no_provider_roundtrip(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/settings?tab=auth")
        # Ensure "None (open access)" is selected
        page.locator("#auth_provider").select_option("")
        page.locator("form[action='/settings/auth']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)
        expect(page.locator("body")).to_contain_text("Settings saved")

        # Round-trip: reload and verify the value persists
        page.goto(f"{cert_watch_server}/settings?tab=auth")
        expect(page.locator("#auth_provider")).to_have_value("")

    def test_save_auth_oauth_fields_roundtrip(self, page: Page, cert_watch_server: str) -> None:
        """Save OAuth config fields (provider stays empty so auth state is unchanged)."""
        page.goto(f"{cert_watch_server}/settings?tab=auth")
        # Reveal the OAuth section temporarily by selecting oauth, then fill
        page.locator("#auth_provider").select_option("oauth")
        page.locator("#oauth_client_id").fill("00000000-0000-0000-0000-000000000000")
        page.locator("#oauth_issuer_url").fill("https://login.example.com/v2.0")
        page.locator("#oauth_scope").fill("openid profile email")
        # Set provider back to empty before submitting to keep server open
        page.locator("#auth_provider").select_option("")
        page.locator("form[action='/settings/auth']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        # Round-trip: verify OAuth fields persisted (section hidden, select oauth
        # to make it visible again before asserting values)
        page.goto(f"{cert_watch_server}/settings?tab=auth")
        page.locator("#auth_provider").select_option("oauth")
        expect(page.locator("#oauth_client_id")).to_have_value(
            "00000000-0000-0000-0000-000000000000"
        )
        expect(page.locator("#oauth_issuer_url")).to_have_value(
            "https://login.example.com/v2.0"
        )
        expect(page.locator("#oauth_scope")).to_have_value("openid profile email")


class TestSettingsEventsPost:
    """POST /settings/events — save event streaming config."""

    def test_save_events_config_roundtrip(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/settings/events")
        expect(page.get_by_test_id("events-heading")).to_be_visible()

        # Fill webhook URL (use example.com — resolvable public domain)
        webhook = page.get_by_test_id("events-webhook-url")
        webhook.fill("")
        webhook.fill("https://example.com/cert-events")

        # Select kind
        page.get_by_test_id("events-webhook-kind").select_option("generic")

        # Set rate limit
        page.get_by_test_id("events-rate-limit").fill("50")

        # Submit
        page.get_by_test_id("events-save-btn").click()

        # Verify saved (events page doesn't render a "Settings saved" banner,
        # but the redirect URL confirms the POST succeeded)
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        # Round-trip
        page.goto(f"{cert_watch_server}/settings/events")
        expect(page.get_by_test_id("events-webhook-url")).to_have_value(
            "https://example.com/cert-events"
        )
        expect(page.get_by_test_id("events-webhook-kind")).to_have_value("generic")


class TestSettingsPolicyPost:
    """POST /settings/policy — initialize and save policy rules."""

    def test_initialize_default_policy(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/settings?tab=policy")
        # First visit: no policy exists, click "Initialize default policy"
        page.locator("form[action='/settings/policy']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        # After initialization, the policy table should be visible
        page.goto(f"{cert_watch_server}/settings?tab=policy")
        expect(page.locator("table.cw-table")).to_be_visible()

    def test_save_policy_with_modified_rules(self, page: Page, cert_watch_server: str) -> None:
        # Ensure policy is initialized
        page.goto(f"{cert_watch_server}/settings?tab=policy")
        if page.locator(
            "form[action='/settings/policy'] button[type='submit']"
        ).first.is_visible():
            text = (
                page.locator(
                    "form[action='/settings/policy'] button[type='submit']"
                )
                .first.text_content()
                or ""
            )
            if "Initialize" in text:
                page.locator("form[action='/settings/policy']").locator('button[type="submit"]').click()
                expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        page.goto(f"{cert_watch_server}/settings?tab=policy")
        # The policy table with rules should be present; submit the form
        page.locator("form[action='/settings/policy']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)


class TestSettingsRolesPost:
    """POST /settings/roles — create a role."""

    def test_create_role(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/settings/roles")
        page.locator("#role_name").fill("operators")
        page.locator("#role_email").fill("ops@example.com")
        page.locator("#role_description").fill("Certificate operators")
        page.locator("form[action='/settings/roles']").locator('button[type="submit"]').click()

        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)
        expect(page.locator("body")).to_contain_text("operators")


class TestSettingsUsersPost:
    """POST /settings/users — create a local user."""

    def test_create_user(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/settings/users")
        page.locator("#user_username").fill("testuser")
        page.locator("#user_email").fill("test@example.com")
        page.locator("#user_password").fill("testPass123")
        page.locator("form[action='/settings/users']").locator('button[type="submit"]').click()

        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)
        expect(page.locator("body")).to_contain_text("testuser")


class TestReadinessPage:
    """/readiness — SC-081 readiness report page."""

    def test_readiness_page_renders(self, page: Page, cert_watch_server: str) -> None:
        page.goto(f"{cert_watch_server}/readiness")
        expect(page.get_by_test_id("readiness-heading")).to_be_visible()
        # The milestone timeline and stats boxes should render
        expect(page.locator(".cw-milestone-box")).to_be_visible()
        expect(page.locator(".cw-stats")).to_be_visible()
        # Host table or empty-state message must be present
        assert page.locator(".cw-table").count() + page.locator(".cw-empty").count() >= 1

    def test_readiness_json_api(self, page: Page, cert_watch_server: str) -> None:
        resp = page.request.get(f"{cert_watch_server}/api/readiness.json")
        assert resp.status == 200
        body = resp.json()
        assert "milestones" in body
        assert "total_hosts" in body


# ===================================================================
# Tests against the authed server (local admin configured)
# ===================================================================


class TestUnauthedSettingsRedirect:
    """Without a session, /settings must redirect to /login."""

    def test_unauthenticated_settings_redirects_to_login(
        self, page: Page, authed_server: str
    ) -> None:
        page.goto(f"{authed_server}/settings")
        expect(page.get_by_test_id("login-heading")).to_be_visible()

    def test_unauthenticated_settings_smtp_redirects_to_login(
        self, page: Page, authed_server: str
    ) -> None:
        page.goto(f"{authed_server}/settings?tab=smtp")
        expect(page.get_by_test_id("login-heading")).to_be_visible()

    def test_unauthenticated_settings_events_redirects_to_login(
        self, page: Page, authed_server: str
    ) -> None:
        page.goto(f"{authed_server}/settings/events")
        expect(page.get_by_test_id("login-heading")).to_be_visible()


class TestSettingsPasswordPost:
    """POST /settings/change-password — local admin password rotation.

    Both tests share the module-scoped ``authed_server_mutable`` fixture. The
    non-mutating wrong-current test is defined first so it runs against the
    original password; ``test_change_password_roundtrip`` runs last because it
    permanently rotates the admin password on that server.
    """

    def test_change_password_wrong_current_fails(
        self, page: Page, authed_server_mutable: str
    ) -> None:
        authed_server = authed_server_mutable
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        page.goto(f"{authed_server}/settings?tab=auth")

        page.locator("#current_password").fill("wrongPassword")
        page.locator("#new_password").fill("anotherPass1")
        page.locator("#confirm_password").fill("anotherPass1")
        page.locator("form[action='/settings/change-password']").locator('button[type="submit"]').click()

        expect(page).to_have_url(re.compile(r"error="), timeout=5000)
        expect(page.locator("body")).to_contain_text("incorrect")

    def test_change_password_roundtrip(
        self, page: Page, authed_server_mutable: str
    ) -> None:
        authed_server = authed_server_mutable
        # Login with current password
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        # Verify login succeeded
        expect(page.locator("body")).to_contain_text("Certificates", timeout=5000)

        # Navigate to auth tab
        page.goto(f"{authed_server}/settings?tab=auth")

        # Verify password form is present
        expect(page.locator("#current_password")).to_be_visible()

        # Fill password change form
        page.locator("#current_password").fill("newE2ePass1")
        page.locator("#new_password").fill("rotatedPass1")
        page.locator("#confirm_password").fill("rotatedPass1")
        page.locator("form[action='/settings/change-password']").locator('button[type="submit"]').click()

        # Password change bumps the session version (BC-081), invalidating the
        # current session. The 303 redirect targets /settings?password_changed=1
        # but the session check on that GET fails, landing on /login instead.
        expect(page.get_by_test_id("login-heading")).to_be_visible(timeout=5000)

        # Verify the new password works
        _login(page, authed_server, "e2eadmin", "rotatedPass1")
        expect(page.locator("body")).to_contain_text("Certificates")


class TestAuthedSettingsPostForms:
    """Settings form POSTs work after login on the authed server."""

    def test_smtp_save_after_login(self, page: Page, authed_server: str) -> None:
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        page.goto(f"{authed_server}/settings?tab=smtp")
        page.locator("#smtp_host").fill("")
        page.locator("#smtp_host").fill("smtp.authed.example.com")
        page.locator("#smtp_port").fill("465")
        page.locator("form[action='/settings/smtp']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        page.goto(f"{authed_server}/settings?tab=smtp")
        expect(page.locator("#smtp_host")).to_have_value("smtp.authed.example.com")

    def test_alerts_save_after_login(self, page: Page, authed_server: str) -> None:
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        page.goto(f"{authed_server}/settings?tab=alerts")
        page.locator("#webhook_url").fill("")
        page.locator("#webhook_url").fill("https://example.com/alert")
        page.locator("form[action='/settings/alerts']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        page.goto(f"{authed_server}/settings?tab=alerts")
        expect(page.locator("#webhook_url")).to_have_value("https://example.com/alert")

    def test_events_save_after_login(self, page: Page, authed_server: str) -> None:
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        page.goto(f"{authed_server}/settings/events")
        page.get_by_test_id("events-webhook-url").fill("")
        page.get_by_test_id("events-webhook-url").fill("https://example.com/hook")
        page.get_by_test_id("events-save-btn").click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)

        page.goto(f"{authed_server}/settings/events")
        expect(page.get_by_test_id("events-webhook-url")).to_have_value(
            "https://example.com/hook"
        )

    def test_auth_save_after_login(self, page: Page, authed_server: str) -> None:
        """Auth form save works after login (provider stays empty to avoid
        changing the server's auth state mid-session)."""
        _login(page, authed_server, "e2eadmin", "newE2ePass1")
        page.goto(f"{authed_server}/settings?tab=auth")
        # Reveal OAuth section, fill a field, then revert provider to empty
        page.locator("#auth_provider").select_option("oauth")
        page.locator("#oauth_client_id").fill("11111111-2222-3333-4444-555555555555")
        page.locator("#auth_provider").select_option("")
        page.locator("form[action='/settings/auth']").locator('button[type="submit"]').click()
        expect(page).to_have_url(re.compile(r"saved=1"), timeout=5000)
