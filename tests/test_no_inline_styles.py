"""Guardrail: track inline ``style=`` attributes that block full CSP tightening.

``style-src`` keeps ``'unsafe-inline'`` because the UI binds dynamic CSS custom
properties via inline ``style=`` attributes, which nonces can't cover. This test
is a *ratchet*: each template has a budget of tolerated inline styles and may not
exceed it. As templates are converted to utility classes or CSS custom properties,
lower the budget. When every budget is zero, delete this allowlist, assert a flat
zero, and tighten ``style-src`` in ``_build_csp``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "src" / "cert_watch" / "templates"

# Matches an inline style attribute: a whitespace/quote boundary, then style,
# then '='. Uses either double or single quotes.
_INLINE_STYLE = re.compile(r"""[\s"']style\s*=\s*["']""", re.IGNORECASE)

# Strip <script> and <style> bodies first — inline styles are HTML attributes,
# not JS or CSS content.
_SCRIPT_BLOCK = re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL)
_STYLE_BLOCK = re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL)

# Max inline styles tolerated per template. ONLY GOES DOWN.
INLINE_STYLE_BUDGET: dict[str, int] = {
    "alerts.html": 3,
    "base.html": 5,
    "certificate_detail.html": 9,
    "compliance.html": 1,
    "dashboard.html": 15,
    "host_detail.html": 2,
    "insights.html": 28,
    "readiness.html": 0,
    "settings.html": 2,
    "setup.html": 2,
    "team_dashboard.html": 1,
    # Timeline ticks + markers bind data-driven left:% and --tone via inline
    # style (2 tick lines + 2 marker lines in template source); nothing else.
    "triage.html": 4,
}


def _count(path: Path) -> int:
    html = path.read_text(encoding="utf-8")
    html = _SCRIPT_BLOCK.sub("", html)
    html = _STYLE_BLOCK.sub("", html)
    return len(_INLINE_STYLE.findall(html))


def _templates() -> list[Path]:
    return sorted(TEMPLATES_DIR.rglob("*.html"))


@pytest.mark.parametrize("path", _templates(), ids=lambda p: p.name)
def test_inline_styles_within_budget(path: Path):
    budget = INLINE_STYLE_BUDGET.get(path.name, 0)
    count = _count(path)
    assert count <= budget, (
        f"{path.name} has {count} inline style= attribute(s), budget is {budget}. "
        f"Convert inline styles to utility classes or CSS custom properties so "
        f"style-src 'unsafe-inline' can eventually be removed."
    )


def test_budget_has_no_stale_entries():
    """Keep the ratchet honest: if a template was converted below its budget,
    tighten the budget so it can't silently regress."""
    for name, budget in INLINE_STYLE_BUDGET.items():
        actual = _count(TEMPLATES_DIR / name)
        assert actual == budget, (
            f"{name} now has {actual} inline styles but the budget is {budget}. "
            f"Lower INLINE_STYLE_BUDGET[{name!r}] to {actual} (the ratchet only "
            f"goes down)."
        )
