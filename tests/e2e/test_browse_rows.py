"""Browser coverage for #126 S6 Browse row facts and grouped views."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("playwright")
from _helpers import boot_server, inject_session
from playwright.sync_api import Page, expect

from cert_watch.auth.local_admin import _scrypt_hash
from cert_watch.auth.session import create_session
from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
    init_schema,
    replace_scanned,
)
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.security import SecurityContext

_AUTH_SECRET = "e2e-browse-rows-secret-0123456789abcdef"
_CSRF_SECRET = "e2e-browse-rows-csrf-0123456789abcdef"
_ADMIN_GROUP = "CN=admins,OU=Groups,DC=example,DC=test"
_ALPHA_GROUP = "CN=alpha-viewers,OU=Groups,DC=example,DC=test"
_SECURITY = SecurityContext(signing_key=_AUTH_SECRET, csrf_secret=_CSRF_SECRET)


def _cert(name: str, days: int, *, fingerprint: str | None = None) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=f"CN={name}",
        issuer="CN=Example Test CA",
        not_before=now - timedelta(days=300),
        not_after=now + timedelta(days=days),
        fingerprint_sha256=fingerprint or f"fp-{name}",
    )


def _history(db: Path, name: str, status: str, hours_ago: int, error: str | None = None) -> None:
    record_scan_history(
        db,
        ScanHistory(
            hostname=name,
            port=443,
            status=status,
            scanned_at=datetime.now(UTC) - timedelta(hours=hours_ago),
            error_message=error,
        ),
    )


@pytest.fixture(scope="module")
def browse_rows_server(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[str]:
    data_dir = tmp_path_factory.mktemp("cw-browse-rows")
    db = data_dir / "cert-watch.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)

    hosts.add(
        "current.alpha.example.test",
        tags="alpha",
        owner_name="Alpha team",
        owner_email="alpha@example.test",
        renewal_status="in_progress",
        renewal_method="acme",
    )
    replace_scanned(
        db,
        "current.alpha.example.test",
        443,
        _cert("current.alpha.example.test", 60, fingerprint="fp-shared-alpha"),
        [],
        True,
    )
    _history(db, "current.alpha.example.test", "success", 0)

    hosts.add(
        "peer.alpha.example.test",
        tags="alpha",
        owner_name="Alpha team",
        owner_email="alpha@example.test",
        renewal_status="in_progress",
        renewal_method="acme",
    )
    replace_scanned(
        db,
        "peer.alpha.example.test",
        443,
        _cert("peer.alpha.example.test", 60, fingerprint="fp-shared-alpha"),
        [],
        True,
    )
    _history(db, "peer.alpha.example.test", "success", 80)
    _history(db, "peer.alpha.example.test", "failure", 3, "connection refused")

    hosts.add(
        "critical.alpha.example.test",
        tags="alpha",
        owner_email="alpha@example.test",
        renewal_method="manual",
    )
    replace_scanned(
        db,
        "critical.alpha.example.test",
        443,
        _cert("critical.alpha.example.test", 5),
        [],
        True,
    )
    _history(db, "critical.alpha.example.test", "success", 0)

    hosts.add("overdue.alpha.example.test", tags="alpha")
    replace_scanned(
        db,
        "overdue.alpha.example.test",
        443,
        _cert("overdue.alpha.example.test", 20),
        [],
        True,
    )
    _history(db, "overdue.alpha.example.test", "success", 76)

    hosts.add("never.alpha.example.test", tags="alpha")
    hosts.add("hidden.beta.example.test", tags="beta")
    replace_scanned(
        db,
        "hidden.beta.example.test",
        443,
        _cert("hidden.beta.example.test", -3),
        [],
        True,
    )
    _history(db, "hidden.beta.example.test", "success", 0)

    SqliteCertificateRepository(db, source="uploaded").add(
        _cert("upload.example.test", 90)
    )
    SqliteAlertGroupRepository(db).create(
        name="alpha-routes",
        recipients=["alerts@example.test"],
        match_tags=["alpha"],
    )

    roles = SqliteRoleRepository(db)
    roles.add(Role(name="browse-admin", permission_tier="admin"))
    roles.add(Role(name="alpha-viewer", permission_tier="viewer", scope_tag="alpha"))
    role_map = {
        "browse-admin": {"groups": [_ADMIN_GROUP]},
        "alpha-viewer": {"groups": [_ALPHA_GROUP]},
    }
    proc, base = boot_server(
        data_dir,
        env_extra={
            "CERT_WATCH_AUTH_SECRET": _AUTH_SECRET,
            "CERT_WATCH_CSRF_SECRET": _CSRF_SECRET,
            "CERT_WATCH_ROLE_MAP": json.dumps(role_map),
            "CERT_WATCH_LOCAL_ADMIN_USER": "admin",
            "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH": _scrypt_hash("browse-admin-password"),
            "CERT_WATCH_COOKIE_SECURE": "0",
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


def _session(page: Page, base: str, *, groups: list[str]) -> None:
    inject_session(page, base, create_session("browse-user", _SECURITY, groups=groups))


def _row(page: Page, name: str):
    return page.get_by_test_id("cert-row").filter(has_text=name)


def test_ungrouped_rows_show_condition_and_only_exception_facts(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    page.goto(f"{browse_rows_server}/browse?grouped=0")

    current = _row(page, "current.alpha.example.test")
    expect(current).to_contain_text("days left")
    expect(current).to_contain_text("Renewal in progress")
    expect(current).not_to_contain_text("Current scan")
    expect(current).not_to_contain_text("Healthy")

    expect(_row(page, "peer.alpha.example.test")).to_contain_text("Failing since")
    expect(_row(page, "critical.alpha.example.test")).to_contain_text("Renewal stalled")
    expect(_row(page, "overdue.alpha.example.test")).to_contain_text("Monitoring overdue")
    expect(_row(page, "never.alpha.example.test")).to_contain_text("Never scanned")

    upload = _row(page, "upload.example.test")
    expect(upload).to_contain_text("Uploaded")
    expect(upload).not_to_contain_text("Not monitored")
    expect(page.get_by_test_id("cert-row")).to_have_count(7)
    expect(page.locator(".cw-stat").first.locator(".cw-stat-val")).to_have_text("7")


def test_grouped_and_pivot_expansions_use_the_same_four_fact_presentation(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    page.goto(f"{browse_rows_server}/browse?grouped=1")
    shared = _row(page, "current.alpha.example.test")
    expect(shared).to_contain_text("2 hosts")
    expect(shared).to_contain_text("Last seen OK")
    expect(shared).not_to_contain_text("No certificate")
    expect(shared).to_contain_text("1 of 2 failing since")
    shared.get_by_role("button", name="Show endpoints").click()
    expansion = page.locator("tr[id^='group-hosts-']:not(.cw-hidden)")
    expect(expansion).to_contain_text("peer.alpha.example.test")
    expect(expansion).to_contain_text("Failing since")

    page.goto(f"{browse_rows_server}/browse?view=owner")
    alpha = page.get_by_role("button", name="Alpha team")
    expect(alpha).to_be_visible()
    alpha_row = alpha.locator("xpath=ancestor::tr[1]")
    expect(alpha_row).to_contain_text("Last seen OK")
    expect(alpha_row.locator(".cw-status")).to_have_class(re.compile(r"\bt-muted\b"))
    expect(alpha_row).to_contain_text("1 of 2 failing since")
    alpha.click()
    pivot = page.locator("tr[data-group-key='Alpha team']")
    expect(pivot).to_contain_text("current.alpha.example.test")
    expect(pivot).to_contain_text("days left")
    expect(pivot).to_contain_text("Failing since")
    expect(pivot).not_to_contain_text("Healthy")


def test_server_and_js_pivot_rows_render_the_same_condition_and_metadata(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    page.goto(f"{browse_rows_server}/browse?grouped=0")
    server = page.locator("tr[data-testid='cert-row']").evaluate_all(
        """rows => Object.fromEntries(rows.map(row => {
          const link = row.querySelector('a[href^="/certificates/"]');
          const id = link && link.getAttribute('href').split('/')[2];
          const status = row.querySelector('.cw-condition .cw-status');
          const date = row.querySelector('.cw-condition-date');
          const meta = [...row.querySelectorAll('.cw-metarow .cw-chip')]
            .map(chip => chip.textContent.trim());
          return [id, {
            condition: status && status.textContent.trim(),
            tone: status && [...status.classList].find(name => name.startsWith('t-')),
            date: date && date.textContent.trim().replace(/\\s+/g, ' '),
            meta,
          }];
        }))"""
    )

    for view in ("issuer", "owner", "renewal_method"):
        page.goto(f"{browse_rows_server}/browse?view={view}")
        for toggle in page.locator(".cw-pivot-table .cw-expand-toggle").all():
            toggle.click()
        expect(page.locator(".cw-pivot-table .cw-browse-subrow")).to_have_count(7)
        pivot = page.locator(".cw-pivot-table .cw-browse-subrow").evaluate_all(
            """rows => Object.fromEntries(rows.map(row => {
              const link = row.querySelector('a[href^="/certificates/"]');
              const id = link && link.getAttribute('href').split('/')[2];
              const status = row.querySelector('.cw-condition .cw-status');
              const date = row.querySelector('.cw-condition-date');
              const meta = [...row.querySelectorAll('.cw-metarow .cw-chip')]
                .map(chip => chip.textContent.trim());
              return [id, {
                condition: status && status.textContent.trim(),
                tone: status && [...status.classList].find(name => name.startsWith('t-')),
                date: date && date.textContent.trim().replace(/\\s+/g, ' '),
                meta,
              }];
            }))"""
        )

        assert pivot == server, view

    for cert_id, expected in server.items():
        page.goto(f"{browse_rows_server}/certificates/{cert_id}")
        detail = page.get_by_test_id("detail-state-axes").locator(
            ".cw-detail-axis"
        ).first
        value = detail.locator(".cw-detail-axis-value")
        assert value.inner_text().strip() == expected["condition"]
        assert next(
            name for name in value.get_attribute("class").split() if name.startswith("t-")
        ) == expected["tone"]


def test_pending_delivery_chip_agrees_in_every_browse_path(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    api = page.request.get(f"{browse_rows_server}/api/certificates?limit=200").json()
    pending_api = next(
        row for row in api["certificates"]
        if row["host"].startswith("never.alpha.example.test:")
    )
    assert pending_api["delivery"] == "failing"

    page.goto(f"{browse_rows_server}/certificates/{pending_api['id']}")
    alerts_axis = page.get_by_test_id("detail-state-axes").locator(
        ".cw-detail-axis"
    ).filter(has_text="Alerts")
    expect(alerts_axis).to_contain_text("Delivery failing")

    for path in ("/browse?grouped=0", "/browse", "/browse?delivery=failing"):
        page.goto(f"{browse_rows_server}{path}")
        expect(_row(page, "never.alpha.example.test")).to_contain_text(
            "Can't be delivered"
        )

    page.goto(f"{browse_rows_server}/browse?view=owner")
    page.get_by_role("button", name="Unassigned").click()
    pending = page.locator(".cw-browse-subrow").filter(
        has_text="never.alpha.example.test"
    )
    expect(pending).to_contain_text("Can't be delivered")

    for state, chip in (("failing", "Can't be delivered"), ("unrouted", "Unrouted")):
        page.goto(f"{browse_rows_server}/browse?delivery={state}")
        rows = page.get_by_test_id("cert-row")
        assert rows.count() > 0
        for row in rows.all():
            expect(row).to_contain_text(chip)


def test_scoped_browse_rows_counts_groups_and_pivots_stay_in_scope(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ALPHA_GROUP])
    page.goto(f"{browse_rows_server}/browse?grouped=0")
    expect(page.get_by_test_id("cert-row")).to_have_count(5)
    expect(page.locator(".cw-stat").first.locator(".cw-stat-val")).to_have_text("5")
    expect(page.locator("body")).not_to_contain_text("hidden.beta.example.test")
    expect(page.locator("body")).not_to_contain_text("upload.example.test")

    page.goto(f"{browse_rows_server}/browse?view=issuer")
    page.get_by_role("button", name="Example Test CA").click()
    expanded = page.locator("tr[data-group-key='Example Test CA']")
    expect(expanded.locator(".cw-browse-subrow")).to_have_count(4)
    expect(expanded).not_to_contain_text("hidden.beta.example.test")


def test_browse_and_alert_groups_do_not_scroll_document_at_390(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    page.set_viewport_size({"width": 390, "height": 844})
    for path in ("/browse", "/browse?grouped=0", "/browse?view=owner", "/settings/alert-groups"):
        page.goto(f"{browse_rows_server}{path}")
        if path == "/settings/alert-groups":
            expect(page.get_by_test_id("alert-groups-table")).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth === innerWidth"), path
        assert page.locator(".cw-page").evaluate("el => el.scrollWidth === el.clientWidth"), path


def test_browse_expanders_are_not_nested_interactive_controls(
    page: Page, browse_rows_server: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    for path in ("/browse", "/browse?view=issuer"):
        page.goto(f"{browse_rows_server}{path}")
        expect(page.locator("tr[role='button'], tr[role='link']")).to_have_count(0)
        expect(page.locator("button a, button button, a button, a a")).to_have_count(0)


_STATUS_CONTRAST = """element => {
  const rgba = value => {
    const parts = value.match(/[\\d.]+/g).map(Number);
    const scale = value.startsWith('color(srgb') ? 255 : 1;
    return [parts[0] * scale, parts[1] * scale, parts[2] * scale,
      parts.length > 3 ? parts[3] : 1];
  };
  const over = (front, back) => {
    const alpha = front[3] + back[3] * (1 - front[3]);
    if (!alpha) return [0, 0, 0, 0];
    return [0, 1, 2].map(i =>
      (front[i] * front[3] + back[i] * back[3] * (1 - front[3])) / alpha
    ).concat(alpha);
  };
  const ancestors = [];
  for (let node = element; node; node = node.parentElement) ancestors.push(node);
  let background = [0, 0, 0, 0];
  ancestors.reverse().forEach(node => {
    background = over(rgba(getComputedStyle(node).backgroundColor), background);
  });
  const foreground = rgba(getComputedStyle(element).color);
  const luminance = color => {
    const linear = color.slice(0, 3).map(channel => {
      channel /= 255;
      return channel <= .04045 ? channel / 12.92 : Math.pow((channel + .055) / 1.055, 2.4);
    });
    return .2126 * linear[0] + .7152 * linear[1] + .0722 * linear[2];
  };
  const a = luminance(foreground);
  const b = luminance(background);
  return (Math.max(a, b) + .05) / (Math.min(a, b) + .05);
}"""


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_hovered_row_critical_text_meets_the_axe_contrast_floor(
    page: Page, browse_rows_server: str, theme: str,
) -> None:
    _session(page, browse_rows_server, groups=[_ADMIN_GROUP])
    page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
    page.goto(f"{browse_rows_server}/browse?grouped=0")
    row = _row(page, "critical.alpha.example.test")
    row.hover()
    ratios = row.locator(".cw-status.t-crit, .t-expired, .cw-chip.t-crit").evaluate_all(
        f"elements => elements.map(element => ({_STATUS_CONTRAST})(element))"
    )
    assert ratios and min(ratios) >= 4.5, ratios

    if theme == "light":
        page.set_viewport_size({"width": 390, "height": 844})
        page.goto(f"{browse_rows_server}/browse?view=owner")
        page.get_by_role("button", name="Unassigned").click()
        subrow = page.locator(".cw-browse-subrow").filter(
            has_text="critical.alpha.example.test"
        )
        subrow.hover()
        ratios = subrow.locator(
            ".cw-status.t-crit, .t-expired, .cw-chip.t-crit"
        ).evaluate_all(
            f"elements => elements.map(element => ({_STATUS_CONTRAST})(element))"
        )
        assert ratios and min(ratios) >= 4.5, ratios
