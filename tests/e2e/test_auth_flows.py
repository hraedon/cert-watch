"""E2E tests: login, session, logout, and setup wizard flows.

Two fixtures:
- ``auth_server``: starts with a pre-configured local admin so the login form
  is available immediately. Used by login/logout/API tests.
- ``setup_server``: starts truly open (ALLOW_UNAUTH=1) so the setup wizard
  appears on first visit.
"""

from __future__ import annotations

import base64
import hashlib
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
        return s.getsockname()[1]


def _scrypt_hash(password: str) -> str:
    """Generate a scrypt hash in cert-watch's format: scrypt$n$r$p$b64salt$b64dk."""
    n, r, p = 2**14, 8, 1
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=32)
    return f"scrypt${n}${r}${p}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


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


@pytest.fixture(scope="module")
def auth_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Server with a pre-configured local admin (login form available)."""
    data_dir: Path = tmp_path_factory.mktemp("cw-auth-data")
    proc, base = _start_server(data_dir, extra_env={
        "CERT_WATCH_LOCAL_ADMIN_USER": "e2eadmin",
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("e2eTestPass1"),
    })
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def setup_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Server with needs_setup=True (no auth, no ALLOW_UNAUTH) for setup wizard."""
    data_dir: Path = tmp_path_factory.mktemp("cw-setup-data")
    proc, base = _start_server(data_dir)
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class TestSetupWizard:
    def test_setup_wizard_creates_admin(
        self, page: Page, setup_server: str
    ) -> None:
        """On a fresh open instance, the setup wizard is accessible at /setup."""
        page.goto(f"{setup_server}/setup")
        expect(page.locator("body")).to_contain_text("Welcome to cert-watch")

        page.locator('input[name="username"]').fill("setupadmin")
        page.locator('input[name="password"]').fill("setupPass123")
        page.locator('input[name="password_confirm"]').fill("setupPass123")
        page.locator('form[action="/setup"] button[type="submit"]').click()
        page.wait_for_url("**/*", timeout=5000)


class TestLoginAndSession:
    def test_login_with_valid_credentials(
        self, page: Page, auth_server: str
    ) -> None:
        """Login with pre-configured admin, verify session cookie set."""
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
        ctx = page.context.browser.new_context()
        blank_page = ctx.new_page()
        response = blank_page.request.get(f"{auth_server}/api/hosts")
        assert response.status == 401
        ctx.close()

    def test_authenticated_api_request_succeeds(
        self, page: Page, auth_server: str
    ) -> None:
        """After login, API routes should be accessible."""
        page.goto(f"{auth_server}/login")
        page.locator('input[name="username"]').fill("e2eadmin")
        page.locator('input[name="password"]').fill("e2eTestPass1")
        page.locator("form[action='/login'] button[type='submit']").click()
        page.wait_for_url("**/*", timeout=5000)

        # page.request shares the browser context's cookie jar, but httpOnly
        # cookies may not be forwarded. Build a Cookie header from the context.
        cookies = page.context.cookies()
        cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        response = page.request.get(
            f"{auth_server}/api/hosts",
            headers={"Cookie": cookie_header},
        )
        assert response.status == 200
