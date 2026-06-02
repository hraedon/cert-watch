"""Guardrail: no *new* inline event-handler attributes in templates (BC-075).

Inline ``on*=`` handlers (``onclick=``, ``onchange=``, …) are the one thing a
nonce-based CSP ``script-src`` cannot whitelist — only ``<script>`` blocks. They
are why ``'unsafe-inline'`` is still in the CSP and why the Plan 020 S4 nonce
attempt was reverted. The CSP nonce is already plumbed (``_build_csp`` +
``csp_nonce`` context processor); the only thing standing between us and dropping
``'unsafe-inline'`` is getting these counts to zero.

This test is a *ratchet*: each template has a budget of tolerated inline handlers
and may not exceed it. New handlers (or a brand-new template with any) fail the
build, so the upcoming design rewrite stays compliant by construction. As
templates are converted to ``data-*`` + delegated ``addEventListener`` (see the
reference conversion in ``base.html``), lower the budget. When every budget is
zero, delete this allowlist, assert a flat zero, and flip the CSP in
``_build_csp`` to ``script-src 'self' 'nonce-…'``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "src" / "cert_watch" / "templates"

# Matches an HTML inline event-handler attribute: a whitespace/quote boundary,
# then on<word>, then '='. Standard non-event attributes don't start with "on".
_INLINE_HANDLER = re.compile(r"""[\s"']on[a-z]+\s*=""", re.IGNORECASE)

# Strip <script> bodies first: inline handlers are always HTML *attributes*, so
# legitimate JS (addEventListener, or a comment that mentions "onclick=") must
# not count against the budget.
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)

# Max inline handlers tolerated per template. ONLY GOES DOWN. A template not
# listed here must have zero (that's the point — base.html was converted, so it
# is absent and pinned to zero).
INLINE_HANDLER_BUDGET = {
    "dashboard.html": 16,
    "certificate_detail.html": 4,
    "settings.html": 3,
}


def _count(path: Path) -> int:
    html = _SCRIPT_BLOCK.sub("", path.read_text(encoding="utf-8"))
    return len(_INLINE_HANDLER.findall(html))


def _templates() -> list[Path]:
    return sorted(TEMPLATES_DIR.rglob("*.html"))


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.name)
def test_inline_handlers_within_budget(path: Path):
    budget = INLINE_HANDLER_BUDGET.get(path.name, 0)
    count = _count(path)
    assert count <= budget, (
        f"{path.name} has {count} inline on*= handler(s), budget is {budget}. "
        f"Use data-* attributes + delegated addEventListener (see base.html), "
        f"not inline handlers — a nonce CSP can't whitelist them (BC-075)."
    )


def test_budget_has_no_stale_entries():
    """Keep the ratchet honest: if a template was converted below its budget,
    tighten the budget so it can't silently regress."""
    for name, budget in INLINE_HANDLER_BUDGET.items():
        actual = _count(TEMPLATES_DIR / name)
        assert actual == budget, (
            f"{name} now has {actual} inline handlers but the budget is {budget}. "
            f"Lower INLINE_HANDLER_BUDGET[{name!r}] to {actual} (the ratchet only "
            f"goes down)."
        )
