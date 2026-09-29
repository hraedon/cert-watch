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
from cert_watch.database.api_keys import SqliteApiKeyRepository
from cert_watch.database.connection import _connect
from cert_watch.security import SecurityContext
from tests.e2e._seed import seed_detail_estate

_AUTH_SECRET = "e2e-rbac-pinned-secret-0123456789abcdef"
# Use real comma-containing group DNs (not bare names) so this exercises the
# session group encode/decode round-trip end-to-end — a ,-join encoding would
# shred these and silently downgrade the admin to viewer (BC-150).
_ADMIN_DN = "CN=cert-watch-admins,OU=Groups,DC=cw,DC=test"
_VIEWER_DN = "CN=cert-watch-users,OU=Groups,DC=cw,DC=test"
_WRITER_DN = "CN=cert-watch-operators,OU=Groups,DC=cw,DC=test"
_ROLE_MAP = {
    "admin": {"groups": [_ADMIN_DN]},
    "operator": {"groups": [_WRITER_DN]},
    "viewer": {"groups": [_VIEWER_DN]},
}
_SEC = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret="e2e-rbac-csrf")
_RENEWAL_CERT_ID = ""
_RENEWAL_KEY = ""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def rbac_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    global _RENEWAL_CERT_ID, _RENEWAL_KEY
    data_dir: Path = tmp_path_factory.mktemp("cw-rbac-data")
    ids = seed_detail_estate(data_dir)
    _RENEWAL_CERT_ID = ids["current"]
    db = data_dir / "cert-watch.sqlite3"
    key, _RENEWAL_KEY = SqliteApiKeyRepository(db, security=_SEC).create_key(
        "renewal-e2e-key",
        "renewal-report",
        binding="all",
    )
    now = "2026-09-28T12:00:00+00:00"
    with _connect(db) as conn:
        conn.execute(
            "UPDATE api_keys SET name=? WHERE id=?",
            ('<img src=x onerror="window.renewalXss=1">', key.id),
        )
        host = conn.execute(
            "SELECT h.id FROM hosts h JOIN certificates c "
            "ON c.hostname=h.hostname AND c.port=h.port WHERE c.id=?",
            (_RENEWAL_CERT_ID,),
        ).fetchone()
        assert host is not None
        attempt_id = "e2e-renewal-attempt"
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                baseline_fingerprint,received_at,next_check_at,
                failure_attempt_id,failure_reported_at)
               VALUES (?,?,1,?,'verifying',1,'old-leaf',?,?,?,?)""",
            (attempt_id, host["id"], f"api_key:{key.id}", now, now, attempt_id, now),
        )
        conn.execute(
            """INSERT INTO renewal_reports
               (report_id,host_id,hostname_snapshot,port_snapshot,outcome,
                message,tool,correlation_id,received_at,source,effect,attempt_id)
               SELECT 'e2e-renewal-report',h.id,h.hostname,h.port,'failed',
                      '<img src=x onerror="window.renewalXss=2">\nsecond line',
                      '<script>tool</script>','<svg onload=renewalXss=3>',?,?,'applied',?
               FROM hosts h WHERE h.id=?""",
            (now, f"api_key:{key.id}", attempt_id, host["id"]),
        )
        conn.commit()
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
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"{base}/healthz", timeout=0.5) as r:
                if r.status == 200:
                    break
        except Exception:  # noqa: BLE001 — startup polling tolerates transient HTTP failures
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
    page.goto(f"{rbac_server}/browse")
    expect(page.get_by_test_id("dashboard-heading")).to_be_visible()
    expect(page.get_by_test_id("add-host-btn")).to_be_visible()
    expect(page.get_by_test_id("readonly-notice")).to_have_count(0)


def test_viewer_gets_readonly_dashboard(page: Page, rbac_server: str) -> None:
    _login_as(page, rbac_server, groups=[_VIEWER_DN])
    page.goto(f"{rbac_server}/browse")
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
        f"{rbac_server}/api/hosts/none/owner",
        data=json.dumps({"owner_name": "x"}),
        headers={"content-type": "application/json"},
    )
    assert resp.status == 403


@pytest.mark.parametrize("groups", [[_ADMIN_DN], [_WRITER_DN]])
def test_admin_and_writer_see_renewal_report_details_and_controls(
    page: Page, rbac_server: str, groups: list[str]
) -> None:
    _login_as(page, rbac_server, groups=groups)
    page.goto(f"{rbac_server}/certificates/{_RENEWAL_CERT_ID}")

    panel = page.get_by_test_id("renewal-panel")
    expect(panel).to_contain_text("Renewal failed")
    expect(panel).to_contain_text("A new attempt is in progress")
    expect(panel).to_contain_text("Failed")
    expect(panel).to_contain_text("Reported by automation")
    expect(panel).to_contain_text("second line")
    expect(panel).to_contain_text("Source key")
    clear = page.get_by_test_id("clear-renewal-failure")
    expect(clear).to_be_visible()
    clear_form = clear.locator("xpath=ancestor::form")
    expect(clear_form).to_have_attribute("method", "post")
    expect(clear_form.locator("input[name='_csrf_token']")).not_to_have_value("")
    expect(page.get_by_test_id("edit-host")).to_be_visible()
    assert panel.locator("img, script, svg[onload]").count() == 0
    assert page.evaluate("window.renewalXss === undefined")

    for path in (
        "/",
        "/browse?renewal=failed&grouped=0",
        "/browse?view=owner",
        "/settings/api-keys",
    ):
        page.goto(f"{rbac_server}{path}")
        assert page.locator("img[src='x'], svg[onload]").count() == 0
        assert "second line" not in page.locator("body").inner_text()
        assert page.evaluate("window.renewalXss === undefined")
        assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")
    inventory = page.request.get(f"{rbac_server}/api/certificates?renewal=failed")
    assert inventory.status == 200
    assert "renewalXss" not in inventory.text()
    payload = inventory.json()
    assert payload["pagination"]["total"] == 1
    assert {item["renewal"] for item in payload["certificates"]} == {"failed"}


def test_viewer_sees_only_renewal_outcome_and_time(page: Page, rbac_server: str) -> None:
    _login_as(page, rbac_server, groups=[_VIEWER_DN])
    page.goto(f"{rbac_server}/certificates/{_RENEWAL_CERT_ID}")

    panel = page.get_by_test_id("renewal-panel")
    expect(panel).to_contain_text("Failed")
    expect(panel).not_to_contain_text("Reported by automation")
    expect(panel).not_to_contain_text("second line")
    expect(panel).not_to_contain_text("Source key")
    expect(page.get_by_test_id("clear-renewal-failure")).to_have_count(0)
    expect(page.get_by_test_id("edit-host")).to_have_count(0)
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")


@pytest.mark.parametrize(
    "path",
    ["/", "/browse", "/settings/api-keys", "/certificates/"],
)
def test_renewal_report_key_is_forbidden_from_every_changed_page(
    page: Page, rbac_server: str, path: str
) -> None:
    suffix = _RENEWAL_CERT_ID if path.endswith("/") and path.startswith("/certificates") else ""
    response = page.request.get(
        f"{rbac_server}{path}{suffix}",
        headers={"Authorization": f"Bearer {_RENEWAL_KEY}"},
    )
    assert response.status == 403
