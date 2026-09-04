"""Guardrail: every ``var(--token)`` outside the stylesheets must resolve.

``scripts/patina-check.py`` already validates token references, but the
conformance gate (``test_patina_conformance.py``) points it at
``src/cert_watch/static`` only. CSS custom properties are also written in
Python (``filters.py``'s urgency-tone map hands templates a ``var(--x)``
string) and in templates (``style=`` attributes and ``<style>`` blocks).
Those references were never checked, so a token rename could silently leave
a dangling ``var()`` behind — which is exactly how ``var(--expired)``
survived the ``--cw-expired`` rename and rendered as the empty string.

An unresolved ``var()`` fails silently in the browser: the declaration is
invalid at computed-value time and the property falls back to its inherited
or initial value. Nothing errors; the colour is just wrong. Hence a test.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "src" / "cert_watch"
CSS_DIR = PKG / "static" / "css"

# Stylesheets that define the token vocabulary: the vendored patina contract
# block plus cert-watch's own --cw- locals and tone variables.
CSS_SOURCES = (CSS_DIR / "tokens.css", CSS_DIR / "cw.css")

# `--name:` in a declaration position. Mirrors scripts/patina-check.py so the
# two agree on what counts as a definition.
_TOKEN_DEF = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")
# `var(--name` — covers `var(--x)` and `var(--x, fallback)`.
_TOKEN_REF = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)")
_CSS_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _defined_tokens() -> set[str]:
    names: set[str] = set()
    for path in CSS_SOURCES:
        text = _CSS_COMMENT.sub("", path.read_text(encoding="utf-8"))
        names.update(_TOKEN_DEF.findall(text))
    return names


def _reference_sites() -> list[tuple[Path, int, str]]:
    """Every (path, line number, token) referenced outside the stylesheets.

    Whole-file scan by design: it catches ``style="..."`` attributes and
    ``<style>`` blocks, but also ``var()`` written into a Python string, a
    docstring, or a ``<script>`` body — all of which reach the browser or
    describe what does.
    """
    sites: list[tuple[Path, int, str]] = []
    files = sorted(PKG.rglob("*.py")) + sorted((PKG / "templates").rglob("*.html"))
    for path in files:
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in _TOKEN_REF.finditer(line):
                sites.append((path, lineno, match.group(1)))
    return sites


def test_token_references_resolve():
    defined = _defined_tokens()
    unresolved = [
        f"{path.relative_to(ROOT)}:{lineno}: var({token}) is not defined in "
        f"tokens.css or cw.css"
        for path, lineno, token in _reference_sites()
        if token not in defined
    ]
    assert not unresolved, (
        "Unresolved CSS custom property reference(s) — these compute to the "
        "empty string in the browser, silently. Rename the reference to the "
        "current token, or define the token.\n  " + "\n  ".join(unresolved)
    )


def test_scan_is_not_vacuous():
    """Keep the test above honest: if the globs ever stop matching, the
    resolve test would pass on an empty set instead of failing."""
    assert len(_defined_tokens()) > 20, "token definitions not being parsed"
    sites = _reference_sites()
    assert sites, "no var() references found outside CSS — check the globs"
    assert any(path.suffix == ".py" for path, _, _ in sites), (
        "no var() references found in Python — cert_watch/filters.py maps "
        "urgency buckets to var() strings; the .py glob has stopped matching"
    )
