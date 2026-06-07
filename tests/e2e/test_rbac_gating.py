"""E2E: RBAC access-gating in the browser (WS-C3, guards BC-145).

Proves the headline 0.6.0 behaviour through the real UI: with a role map
configured, an admin sees write controls and a viewer gets a read-only
dashboard. Uses crafted session cookies (the signing key is pinned via
``CERT_WATCH_AUTH_SECRET``) so it runs in CI without a live IdP — the
full IdP-login path is covered by the opt-in real-LDAP test.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page, expect

from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.auth.session import create_session
from cert_watch.security import SecurityContext

_AUTH_SECRET = "e2e-rbac-pinned-secret-0123456789abcdef"
# Use real comma-containing group DNs (not bare names) so this exercises the
# session group encode/decode round-trip end-to-end — a ,-join encoding would
# shred these and silently downgrade the admin to viewer (BC-150).
_ADMIN_DN = "CN=cert-watch-admins,OU=Groups,DC=cw,DC=test"
_VIEWER_DN = "CN=cert-watch-users,OU=Groups,DC=cw,DC=test"
_ROLE_MAP = {
    "admin": {"groups": [_ADMIN_DN]},
    "viewer": {"groups": [_VIEWER_DN]},
}
_SEC = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret="e2e-rbac-csrf")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def rbac_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    data_dir: Path = tmp_path_factory.mktemp("cw-rbac-data")
    port = _free_port()
    env = {
        **os.environ,
        "CERT_WATCH_DATA_DIR": str(data_dir),
        "CERT_WATCH_HOST": "127.0.0.1",
        "CERT_WATCH_PORT": str(port),
        "CERT_WATCH_AUTH_SECRET": _AUTH_SECRET,
        "CERT_WATCH_ROLE_MAP": json.dumps(_ROLE_MAP),
        "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("rbac-admin-pw-1"),
        "CERT_WATCH_COOKIE_SECURE": "0",
    }
    proc = subprocess.Popen(
        [sys.executable, "-m", "cert_watch", "--host", "127.0.0.1", "--port", str(port)],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
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
        raise RuntimeError(f"rbac server did not become ready:\n{out}")
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _login_as(page: Page, base: str, groups: list[str]) -> None:
    token = create_session("e2e-user", _SEC, groups=groups)
    page.context.add_cookies([{"name": "cw_auth", "value": token, "url": base}])


def test_unauthenticated_redirects_to_login(page: Page, rbac_server: str) -> None:
    """With auth enforced and no cookie, the dashboard redirects to login."""
    page.goto(rbac_server)
    expect(page.get_by_test_id("login-heading")).to_be_visible()


def test_admin_sees_write_controls(page: Page, rbac_server: str) -> None:
    _login_as(page, rbac_server, groups=[_ADMIN_DN])
    page.goto(rbac_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    expect(page.get_by_test_id("add-host-btn")).to_be_visible()
    expect(page.get_by_test_id("readonly-notice")).to_have_count(0)


def test_viewer_gets_readonly_dashboard(page: Page, rbac_server: str) -> None:
    _login_as(page, rbac_server, groups=[_VIEWER_DN])
    page.goto(rbac_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    # The viewer must NOT see the Add-host control, and must see the notice.
    expect(page.get_by_test_id("add-host-btn")).to_have_count(0)
    expect(page.get_by_test_id("readonly-notice")).to_be_visible()


def test_viewer_write_route_forbidden(page: Page, rbac_server: str) -> None:
    """A viewer's write request to the API is rejected by RBAC (BC-145)."""
    _login_as(page, rbac_server, groups=[_VIEWER_DN])
    # A JSON-API write must be denied for a viewer role (403), proving the
    # gating is enforced server-side, not just hidden in the UI.
    resp = page.request.patch(
        f"{rbac_server}/api/hosts/none/owner", data=json.dumps({"owner_name": "x"}),
        headers={"content-type": "application/json"},
    )
    assert resp.status == 403
