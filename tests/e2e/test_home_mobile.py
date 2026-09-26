"""Authenticated Home regressions at the approved 390px mobile width."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from _helpers import boot_server, inject_session
from playwright.sync_api import Page, expect

from cert_watch.auth import create_session
from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.database import Role, SqliteRoleRepository
from cert_watch.security import SecurityContext
from tests.test_four_axis_status import _seed

_AUTH_SECRET = "home-mobile-pinned-secret-abcdef0123456789"
_ADMIN_GROUP = "CN=home-admins,OU=Groups,DC=cw,DC=test"
_SCOPED_GROUP = "CN=home-team-a,OU=Groups,DC=cw,DC=test"
_EMPTY_GROUP = "CN=home-empty,OU=Groups,DC=cw,DC=test"
_SECURITY = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret="home-mobile-csrf")


@pytest.fixture(scope="module")
def home_mobile_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[str]:
    data_dir: Path = tmp_path_factory.mktemp("cw-home-mobile")
    db, _settings = _seed(data_dir, "cert-watch.sqlite3")
    roles = SqliteRoleRepository(db)
    roles.add(Role(name="team-a-viewer", permission_tier="viewer", scope_tag="team-a"))
    roles.add(Role(name="empty-viewer", permission_tier="viewer", scope_tag="no-match"))
    role_map = {
        "admin": {"groups": [_ADMIN_GROUP]},
        "team-a-viewer": {"groups": [_SCOPED_GROUP]},
        "empty-viewer": {"groups": [_EMPTY_GROUP]},
    }
    proc, base = boot_server(
        data_dir,
        env_extra={
            "CERT_WATCH_AUTH_SECRET": _AUTH_SECRET,
            "CERT_WATCH_ROLE_MAP": json.dumps(role_map),
            "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
            "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("home-mobile-pw"),
            "CERT_WATCH_COOKIE_SECURE": "0",
            "CERT_WATCH_NO_SCHEDULER": "1",
        },
    )
    try:
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _assert_no_horizontal_page_scroll(page: Page, base: str) -> None:
    page.set_viewport_size({"width": 390, "height": 900})
    page.goto(base)
    expect(page.get_by_test_id("home-week-link")).to_have_count(12)
    assert page.evaluate("document.documentElement.scrollWidth === innerWidth")
    page.evaluate("window.scrollTo(500, 0)")
    assert page.evaluate("window.scrollX") == 0
    assert page.locator(".cw-home-horizon-body").evaluate(
        "el => el.scrollWidth === el.clientWidth"
    )
    visible_labels = page.locator(
        ".cw-home-strip > li:nth-child(odd) .cw-home-bar-label"
    )
    expect(visible_labels).to_have_count(6)
    labels = visible_labels.evaluate_all(
        "els => els.map(el => ({text: el.textContent.trim(), "
        "clipped: el.scrollWidth > el.clientWidth}))"
    )
    assert all(not label["clipped"] for label in labels)
    assert len({label["text"] for label in labels}) == len(labels)
    expect(page.locator(".cw-wordmark")).to_have_attribute(
        "aria-label", "cert-watch home"
    )


@pytest.mark.parametrize(
    "username,groups,expected_count,scope",
    [
        ("home-admin", [_ADMIN_GROUP], 7, ""),
        ("team-a-user", [_SCOPED_GROUP], 3, "team-a"),
        ("empty-user", [_EMPTY_GROUP], 0, "no-match"),
    ],
)
def test_home_admin_scoped_and_empty_fit_mobile_viewport(
    page: Page,
    home_mobile_server: str,
    username: str,
    groups: list[str],
    expected_count: int,
    scope: str,
) -> None:
    inject_session(
        page,
        home_mobile_server,
        create_session(username, _SECURITY, groups=groups),
    )
    _assert_no_horizontal_page_scroll(page, home_mobile_server)
    expect(page.get_by_test_id("home-tracked-count")).to_contain_text(
        f"{expected_count} tracked"
    )
    if scope:
        indicator = page.get_by_test_id("scope-indicator")
        expect(indicator).to_contain_text(scope)
        expect(indicator.locator(".cw-scope-prefix")).to_be_hidden()
        assert indicator.evaluate("el => el.innerText.trim()") == scope
