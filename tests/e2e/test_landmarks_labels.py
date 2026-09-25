"""Page-level accessibility floors from the #126 S2 visual-system pass.

The UI review measured every page with axe-core: no ``<main>`` landmark
anywhere, form fields whose ``<label>`` was not associated with them, and
hundreds of text nodes in ``--text-3``, which fails 4.5:1 on ``--panel`` in both
themes. These checks keep each of those from coming back without needing axe
in CI:

- exactly one ``<main>`` per page;
- every form field, including ones in closed drawers and editors, has an
  associated label (``<label for>``, a wrapping ``<label>``, ``aria-label`` or
  ``aria-labelledby``);
- no visible text is rendered in the ``--text-3`` colour, in either theme.
"""

from __future__ import annotations

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import Page

_PAGES = [
    "/",
    "/browse",
    "/browse?grouped=0",
    "/posture",
    "/activity",
    "/alerts",
    "/audit",
    "/readiness",
    "/reports/compliance",
    "/settings/auth",
    "/settings/policy",
    "/settings/channels",
    "/settings/alert-groups",
    "/settings/tags",
    "/settings/roles",
    "/settings/users",
    "/settings/api-keys",
    "/settings/trust-anchors",
    "/settings/events",
]

_UNLABELLED_FIELDS = """() => [...document.querySelectorAll('input, select, textarea')]
  .filter(el => {
    if (['hidden', 'submit', 'button', 'reset', 'image'].includes(el.type)) return false;
    if (el.getAttribute('aria-label') || el.getAttribute('aria-labelledby')) return false;
    if (el.closest('label')) return false;
    if (el.id && document.querySelector('label[for="' + CSS.escape(el.id) + '"]')) return false;
    return true;
  })
  .map(el => el.outerHTML.slice(0, 120))"""

_TEXT3_NODES = """() => {
  const probe = document.createElement('span');
  probe.style.color = 'var(--text-3)';
  document.body.appendChild(probe);
  const text3 = getComputedStyle(probe).color;
  probe.remove();
  const out = [];
  for (const el of document.body.querySelectorAll('*')) {
    const own = [...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim());
    if (!own || !el.checkVisibility()) continue;
    if (getComputedStyle(el).color === text3) out.push(el.outerHTML.slice(0, 120));
  }
  return out;
}"""


@pytest.mark.parametrize("path", _PAGES)
def test_page_has_one_main_landmark_and_labelled_fields(
    page: Page, cert_watch_server: str, path: str
) -> None:
    page.goto(f"{cert_watch_server}{path}")
    assert page.locator("main").count() == 1, f"{path}: expected exactly one <main>"
    unlabelled = page.evaluate(_UNLABELLED_FIELDS)
    assert not unlabelled, f"{path}: form fields without a label:\n" + "\n".join(unlabelled)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_no_visible_text_uses_text_3(page: Page, cert_watch_server: str, theme: str) -> None:
    page.add_init_script(f"localStorage.setItem('cw-theme', '{theme}')")
    offenders: list[str] = []
    for path in _PAGES:
        page.goto(f"{cert_watch_server}{path}")
        offenders += [f"{path}: {html}" for html in page.evaluate(_TEXT3_NODES)]
    assert not offenders, (
        "--text-3 is below 4.5:1 on --panel; use --text-2 for readable text:\n"
        + "\n".join(offenders)
    )

