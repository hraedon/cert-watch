"""E2E: Role-differentiated UI tests (WI-A.3, Plan 047 Workstream A).

Proves the three-tier RBAC surface through a real browser by injecting
crafted session cookies with pinned ``CERT_WATCH_AUTH_SECRET`` and a
``CERT_WATCH_ROLE_MAP`` that maps admin/operator/viewer to distinct groups.
No real IdP is needed.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from _helpers import boot_server, inject_session
from playwright.sync_api import Page, expect

from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.auth.session import create_session
from cert_watch.security import SecurityContext

_AUTH_SECRET = "e2e-rbac-ui-pinned-secret-abcdef0123456789"
_ADMIN_DN = "CN=cw-admins,OU=Groups,DC=cw,DC=test"
_OPERATOR_DN = "CN=cw-ops,OU=Groups,DC=cw,DC=test"
_VIEWER_DN = "CN=cw-viewers,OU=Groups,DC=cw,DC=test"
_ROLE_MAP = {
    "admin": {"groups": [_ADMIN_DN]},
    "operator": {"groups": [_OPERATOR_DN]},
    "viewer": {"groups": [_VIEWER_DN]},
}
_SEC = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret="e2e-rbac-ui-csrf")


@pytest.fixture(scope="module")
def rbac_ui_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    data_dir: Path = tmp_path_factory.mktemp("cw-rbac-ui-data")
    proc, base = boot_server(data_dir, env_extra={
        "CERT_WATCH_AUTH_SECRET": _AUTH_SECRET,
        "CERT_WATCH_ROLE_MAP": json.dumps(_ROLE_MAP),
        "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("rbac-ui-admin-pw"),
        "CERT_WATCH_COOKIE_SECURE": "0",
    })
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _as_admin(page: Page, base: str) -> None:
    inject_session(page, base, create_session("e2e-admin", _SEC, groups=[_ADMIN_DN]))


def _as_operator(page: Page, base: str) -> None:
    inject_session(page, base, create_session("e2e-operator", _SEC, groups=[_OPERATOR_DN]))


def _as_viewer(page: Page, base: str) -> None:
    inject_session(page, base, create_session("e2e-viewer", _SEC, groups=[_VIEWER_DN]))


def test_viewer_sees_readonly_dashboard(
    page: Page, rbac_ui_server: str,
) -> None:
    _as_viewer(page, rbac_ui_server)
    page.goto(rbac_ui_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    expect(page.get_by_test_id("add-host-btn")).to_have_count(0)
    expect(page.get_by_test_id("nav-settings")).to_have_count(0)
    expect(page.get_by_test_id("scan-now-btn")).to_have_count(0)
    expect(page.get_by_test_id("readonly-notice")).to_be_visible()
    expect(page.get_by_test_id("nav-alerts")).to_be_visible()


def test_operator_sees_write_but_no_settings(
    page: Page, rbac_ui_server: str,
) -> None:
    _as_operator(page, rbac_ui_server)
    page.goto(rbac_ui_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    expect(page.get_by_test_id("add-host-btn")).to_be_visible()
    expect(page.get_by_test_id("nav-settings")).to_have_count(0)
    expect(page.get_by_test_id("readonly-notice")).to_have_count(0)


def test_admin_sees_everything(
    page: Page, rbac_ui_server: str,
) -> None:
    _as_admin(page, rbac_ui_server)
    page.goto(rbac_ui_server)
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    expect(page.get_by_test_id("add-host-btn")).to_be_visible()
    expect(page.get_by_test_id("nav-settings")).to_be_visible()
    page.get_by_test_id("nav-settings").click()
    expect(page.get_by_test_id("settings-heading")).to_be_visible()


def test_viewer_api_write_forbidden(
    page: Page, rbac_ui_server: str,
) -> None:
    _as_viewer(page, rbac_ui_server)
    cookies = page.context.cookies()
    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    resp = page.request.patch(
        f"{rbac_ui_server}/api/hosts/1/owner",
        data=json.dumps({"owner_name": "forbidden"}),
        headers={"content-type": "application/json", "Cookie": cookie_header},
    )
    assert resp.status == 403
    body = resp.text()
    assert "read-only" in body


def test_viewer_direct_settings_blocked(
    page: Page, rbac_ui_server: str,
) -> None:
    _as_viewer(page, rbac_ui_server)
    cookies = page.context.cookies()
    cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
    resp = page.request.get(
        f"{rbac_ui_server}/settings",
        headers={"Cookie": cookie_header},
        max_redirects=0,
    )
    assert resp.status in (303, 302)
    location = resp.headers.get("location", "")
    assert "admin" in location.lower()
