"""LDAP E2E tests — run only when CW_LDAP_E2E=1.

These tests spin up a cert-watch instance pointed at a real LDAP/AD
server and verify login / rejection flows.  They are skipped unless
CW_LDAP_E2E=1 is set in the environment.

Usage:
    CW_LDAP_E2E=1 pytest tests/e2e/test_ldap_login_real.py -m ldap_e2e -n0

Required environment variables when enabled: LDAP_SERVER, LDAP_BASE_DN,
LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_TEST_USER, and LDAP_TEST_PASSWORD.
The out-of-group test additionally requires LDAP_REQUIRED_GROUPS,
LDAP_OUT_GROUP_USER, and LDAP_OUT_GROUP_PASSWORD.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator

import pytest
from playwright.sync_api import expect

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.integration,
    pytest.mark.ldap_e2e,
    pytest.mark.skipif(
        not os.environ.get("CW_LDAP_E2E"),
        reason="CW_LDAP_E2E not set",
    ),
]

# ── helpers ──────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 10) -> bool:
    for _ in range(int(timeout * 10)):
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.1)
    return False


@pytest.fixture(scope="module")
def ldap_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start cert-watch with LDAP auth and yield its base URL."""
    required = (
        "LDAP_SERVER",
        "LDAP_BASE_DN",
        "LDAP_BIND_DN",
        "LDAP_BIND_PASSWORD",
        "LDAP_TEST_USER",
        "LDAP_TEST_PASSWORD",
    )
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        pytest.fail(
            "CW_LDAP_E2E=1 requires explicit real-directory configuration; "
            f"missing: {', '.join(missing)}"
        )

    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(tmp_path_factory.mktemp("cw-ldap-real")),
        "CERT_WATCH_PORT": str(port),
        "AUTH_PROVIDER": "ldap",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if not _wait_for(f"{base}/healthz"):
        proc.kill()
        raise RuntimeError("cert-watch did not start")
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class TestLDAPLogin:
    """Login and rejection scenarios against a real LDAP server."""

    def test_valid_login(self, page, ldap_server):
        """A user in the allowed group can log in."""
        page.goto(f"{ldap_server}/login")
        page.get_by_test_id("login-username").fill(os.environ["LDAP_TEST_USER"])
        page.get_by_test_id("login-password").fill(os.environ["LDAP_TEST_PASSWORD"])
        page.get_by_test_id("login-submit-btn").click()
        page.wait_for_url(f"{ldap_server}/", timeout=10000)
        expect(page.get_by_test_id("dashboard-heading")).to_be_visible()

    def test_wrong_password(self, page, ldap_server):
        """Wrong password yields an error, not a crash."""
        page.goto(f"{ldap_server}/login")
        page.get_by_test_id("login-username").fill(os.environ["LDAP_TEST_USER"])
        page.get_by_test_id("login-password").fill(
            f"{os.environ['LDAP_TEST_PASSWORD']}-incorrect"
        )
        page.get_by_test_id("login-submit-btn").click()
        expect(page.locator("body")).to_contain_text("invalid", timeout=5000)

    @pytest.mark.skipif(
        not all(
            os.environ.get(name)
            for name in (
                "LDAP_REQUIRED_GROUPS",
                "LDAP_OUT_GROUP_USER",
                "LDAP_OUT_GROUP_PASSWORD",
            )
        ),
        reason=(
            "real out-of-group credentials and LDAP_REQUIRED_GROUPS are not configured"
        ),
    )
    def test_user_not_in_group_rejected(self, page, ldap_server):
        """A user outside the required group is denied."""
        page.goto(f"{ldap_server}/login")
        page.get_by_test_id("login-username").fill(os.environ["LDAP_OUT_GROUP_USER"])
        page.get_by_test_id("login-password").fill(
            os.environ["LDAP_OUT_GROUP_PASSWORD"]
        )
        page.get_by_test_id("login-submit-btn").click()
        expect(page.locator("body")).to_contain_text(
            "not in required group", timeout=5000
        )
