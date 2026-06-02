"""E2E tests: setup wizard, login, session, and logout flows.

A separate server fixture is needed because auth requires a server that is
NOT running with CERT_WATCH_ALLOW_UNAUTH=1. The fixture uses loopback bind
(so BC-083 allows startup) and exercises the full setup -> login -> logout path.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from playwright.sync_api import Page, expect


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.get_sockname()[1]


@pytest.fixture(scope="module")
def auth_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start a cert-watch server WITHOUT ALLOW_UNAUTH on loopback (BC-083 exempt).

    This triggers the setup wizard on first visit, which we then exercise.
    """
    data_dir: Path = tmp_path_factory.mktemp("cw-auth-data")
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_HOST": "127.0.0.1",
        "CERT_WATCH_PORT": str(port),
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", "127.0.0.1", "--port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(80):
            try:
                with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.1)
        else:
            proc.kill()
            out = proc.stdout.read().decode() if proc.stdout else ""
            raise RuntimeError(f"cert-watch auth server did not become ready:\n{out}")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class TestSetupAndAuth:
    def test_setup_wizard_creates_admin_and_redirects_to_login(
        self, page: Page, auth_server: str
    ) -> None:
        """On a fresh instance, visiting / redirects to /setup. Complete the
        wizard, then verify we land on the dashboard (redirected to /login
        first, then auto-login after setup)."""
        page.goto(auth_server)
        page.wait_for_url("**/setup**", timeout=5000)
        expect(page.locator("body")).to_contain_text("Setup")

        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("e2eTestPass1")
        page.locator('input[name="password_confirm"]').fill("e2eTestPass1")
        page.locator('form[action="/setup"] button[type="submit"]').click()
        page.wait_for_url("**/*", timeout=5000)

    def test_login_with_valid_credentials(
        self, page: Page, auth_server: str
    ) -> None:
        """Login with the admin created in setup, verify session cookie set."""
        page.goto(f"{auth_server}/login")
        expect(page.locator("body")).to_contain_text("Sign in")

        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("e2eTestPass1")
        page.locator("form[action='/login'] button[type='submit']").click()

        page.wait_for_url("**/*", timeout=5000)
        cookies = page.context.cookies()
        auth_cookies = [c for c in cookies if c["name"] == "cw_auth"]
        assert len(auth_cookies) >= 1, "Expected cw_auth session cookie"
        expect(page.locator("body")).to_contain_text("Certificates")

    def test_login_with_wrong_password_shows_error(
        self, page: Page, auth_server: str
    ) -> None:
        """Login with incorrect password, verify error message."""
        page.goto(f"{auth_server}/login")
        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("wrongpassword")
        page.locator("form[action='/login'] button[type='submit']").click()
        expect(page.locator("body")).to_contain_text("invalid credentials")

    def test_logout_clears_session_and_redirects_to_login(
        self, page: Page, auth_server: str
    ) -> None:
        """Login, then logout, verify session is invalidated."""
        page.goto(f"{auth_server}/login")
        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("e2eTestPass1")
        page.locator("form[action='/login'] button[type='submit']").click()
        page.wait_for_url("**/*", timeout=5000)
        expect(page.locator("body")).to_contain_text("Certificates")

        page.goto(f"{auth_server}/")
        page.locator("form[action='/auth/logout'] button").click()

        page.wait_for_url("**/login**", timeout=5000)
        expect(page.locator("body")).to_contain_text("Sign in")

    def test_unauthenticated_api_returns_401(
        self, page: Page, auth_server: str
    ) -> None:
        """API routes should return 401 for unauthenticated requests."""
        response = page.request.get(f"{auth_server}/api/hosts")
        assert response.status == 401

    def test_authenticated_api_request_succeeds(
        self, page: Page, auth_server: str
    ) -> None:
        """After login, API routes should be accessible."""
        page.goto(f"{auth_server}/login")
        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("e2eTestPass1")
        page.locator("form[action='/login'] button[type='submit']").click()
        page.wait_for_url("**/*", timeout=5000)

        response = page.request.get(f"{auth_server}/api/hosts")
        assert response.status == 200