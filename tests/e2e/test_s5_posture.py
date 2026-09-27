"""Browser coverage for the S5 Posture headline, including tag scope."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from _helpers import boot_server, inject_session
from _seed import seed_demo_certs
from playwright.sync_api import Page, expect

from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.auth.session import create_session
from cert_watch.database import Role, SqliteRoleRepository, _connect
from cert_watch.security import SecurityContext

_AUTH_SECRET = "e2e-s5-scope-secret-0123456789abcdef"
_GROUP_DN = "CN=blue-viewers,OU=Groups,DC=example,DC=test"
_SECURITY = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret="e2e-s5-csrf")


def test_posture_distribution_replaces_fleet_grade(
    page: Page, cert_watch_server: str,
) -> None:
    page.goto(f"{cert_watch_server}/posture")
    expect(page.get_by_test_id("insights-heading")).to_be_visible()
    expect(page.get_by_text("Fleet grade", exact=True)).to_have_count(0)
    for testid in (
        "grade-count-Aplus",
        "grade-count-A",
        "grade-count-B",
        "grade-count-C",
        "grade-count-F",
    ):
        expect(page.get_by_test_id(testid)).to_be_visible()
    expect(page.get_by_test_id("posture-trends-waiting")).to_be_visible()


def test_posture_has_no_horizontal_scroll_at_mobile_width(
    page: Page, cert_watch_server: str,
) -> None:
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{cert_watch_server}/posture")
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    assert page.locator(".cw-page").evaluate("el => el.scrollWidth === el.clientWidth")
    page.evaluate("window.scrollTo(500, 0)")
    assert page.evaluate("window.scrollX") == 0


@pytest.fixture(scope="module")
def scoped_posture_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[str, str, str]]:
    data_dir: Path = tmp_path_factory.mktemp("cw-s5-scoped-posture")
    seed_demo_certs(data_dir)
    db = data_dir / "cert-watch.sqlite3"
    with _connect(db) as conn:
        rows = conn.execute(
            "SELECT id, subject FROM certificates WHERE is_leaf = 1 ORDER BY subject"
        ).fetchall()
        assert len(rows) >= 2
        visible_name = str(rows[0]["subject"])
        hidden_name = str(rows[1]["subject"])
        conn.execute("UPDATE certificates SET tags = 'blue' WHERE id = ?", (rows[0]["id"],))
        conn.execute("UPDATE certificates SET tags = 'red' WHERE id != ?", (rows[0]["id"],))
        conn.commit()
    SqliteRoleRepository(db).add(
        Role(name="blue-viewer", permission_tier="viewer", scope_tag="blue")
    )
    role_map = {"blue-viewer": {"groups": [_GROUP_DN]}}
    proc, base = boot_server(
        data_dir,
        env_extra={
            "CERT_WATCH_AUTH_SECRET": _AUTH_SECRET,
            "CERT_WATCH_ROLE_MAP": json.dumps(role_map),
            "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
            "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("s5-admin-password"),
            "CERT_WATCH_COOKIE_SECURE": "0",
        },
    )
    try:
        yield base, visible_name, hidden_name
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_posture_distribution_and_offenders_respect_tag_scope(
    page: Page, scoped_posture_server: tuple[str, str, str],
) -> None:
    base, visible_name, hidden_name = scoped_posture_server
    inject_session(
        page,
        base,
        create_session("blue-user", _SECURITY, groups=[_GROUP_DN]),
    )
    page.goto(f"{base}/posture")
    expect(page.get_by_test_id("insights-heading")).to_be_visible()
    expect(page.locator("body")).to_contain_text(visible_name)
    expect(page.locator("body")).not_to_contain_text(hidden_name)
    counts = page.locator("[data-testid^='grade-count-'] .cw-stat-val")
    assert sum(int(counts.nth(i).inner_text()) for i in range(counts.count())) == 1
