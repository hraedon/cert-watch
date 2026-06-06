"""LDAP E2E tests — run only when CW_LDAP_E2E=1.

These tests spin up a cert-watch instance pointed at a real LDAP/AD
server and verify login / rejection flows.  They are skipped unless
CW_LDAP_E2E=1 is set in the environment.

Usage:
    CW_LDAP_E2E=1 pytest tests/e2e/test_ldap_login_real.py -m ldap_e2e
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

pytestmark = [pytest.mark.e2e, pytest.mark.ldap_e2e]

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
def ldap_server() -> Iterator[str]:
    """Start cert-watch with LDAP auth and yield its base URL."""
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": "/tmp/cw-ldap-e2e",
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_AUTH_PROVIDER": "ldap",
        "CERT_WATCH_LDAP_URL": os.environ.get(
            "LDAP_URL", "ldap://ad.example.com"
        ),
        "CERT_WATCH_LDAP_BIND_DN": os.environ.get("LDAP_BIND_DN", ""),
        "CERT_WATCH_LDAP_PASSWORD": os.environ.get("LDAP_BIND_PASSWORD", ""),
        "CERT_WATCH_LDAP_BASE_DN": os.environ.get(
            "LDAP_BASE_DN", "DC=example,DC=com"
        ),
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


@pytest.fixture(autouse=True)
def _skip_unless_enabled():
    if not os.environ.get("CW_LDAP_E2E"):
        pytest.skip("CW_LDAP_E2E not set")


class TestLDAPLogin:
    """Login and rejection scenarios against a real LDAP server."""

    def test_valid_login(self, page, ldap_server):
        """A user in the allowed group can log in."""
        page.goto(f"{ldap_server}/login")
        page.fill('input[name="username"]', os.environ["LDAP_TEST_USER"])
        page.fill('input[name="password"]', os.environ["LDAP_TEST_PASSWORD"])
        page.click('button[type="submit"]')
        page.wait_for_url("**/certificates**", timeout=10000)
        assert "Certificates" in page.inner_text("body")

    def test_wrong_password(self, page, ldap_server):
        """Wrong password yields an error, not a crash."""
        page.goto(f"{ldap_server}/login")
        page.fill('input[name="username"]', os.environ.get("LDAP_TEST_USER", "user"))
        page.fill('input[name="password"]', "wrong-password")
        page.click('button[type="submit"]')
        page.wait_for_selector("text=invalid", timeout=5000)

    def test_user_not_in_group_rejected(self, page, ldap_server):
        """A user outside the required group is denied."""
        page.goto(f"{ldap_server}/login")
        page.fill('input[name="username"]', "no-group-user")
        page.fill('input[name="password"]', "irrelevant")
        page.click('button[type="submit"]')
        page.wait_for_selector("text=invalid", timeout=5000)
