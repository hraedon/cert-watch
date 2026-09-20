"""Guardrail: e2e modules must not break collection without Playwright installed.

The default pytest run deselects e2e by marker, but markers are applied *after*
collection — an e2e module that imports ``playwright`` at top level turns the
documented dev command (``.venv/bin/pytest -q`` with only the ``dev`` extra
installed) into a red run with collection errors. CI hides this because it
passes ``--ignore=tests/e2e``.

The established convention is ``pytest.importorskip("playwright")`` before the
import. This test enforces it so a new e2e module cannot reintroduce the
breakage — including the indirect form, where the module imports a local e2e
helper that pulls in Playwright itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).resolve().parent / "e2e"


def _module_roots(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name.split(".")[0] for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [(node.module or "").split(".")[-1], (node.module or "").split(".")[0]]
    return []


# Helper modules in tests/e2e that import Playwright at top level: importing one
# of them fails collection exactly as a direct Playwright import does.
_HELPERS_NEEDING_PLAYWRIGHT = frozenset(
    path.stem
    for path in E2E_DIR.glob("*.py")
    if not path.name.startswith("test_") and "playwright" in path.read_text(encoding="utf-8")
)

_TRIGGERS = _HELPERS_NEEDING_PLAYWRIGHT | {"playwright"}


def _guard_line(tree: ast.Module) -> int | None:
    """Line number of a module-level ``pytest.importorskip("playwright")``."""
    for node in tree.body:
        if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "importorskip"
            and isinstance(func.value, ast.Name)
            and func.value.id == "pytest"
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and node.value.args[0].value == "playwright"
        ):
            return node.lineno
    return None


def _first_triggering_import(tree: ast.Module) -> tuple[int, str] | None:
    """Line and name of the earliest import that needs Playwright installed.

    Only module-level imports matter: an import inside a function body runs at
    call time, long after collection.
    """
    for node in tree.body:
        for root in _module_roots(node):
            if root in _TRIGGERS:
                return node.lineno, root
    return None


@pytest.mark.parametrize("path", sorted(E2E_DIR.glob("test_*.py")), ids=lambda p: p.name)
def test_playwright_import_is_guarded(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    triggering = _first_triggering_import(tree)
    if triggering is None:
        return
    line, name = triggering

    guard = _guard_line(tree)
    assert guard is not None, (
        f"{path.name} imports {name} at module level without a preceding "
        'pytest.importorskip("playwright") — a bare `pytest -q` on a dev-extra-only '
        "checkout fails collection instead of skipping."
    )
    assert guard < line, (
        f"{path.name} calls importorskip after importing {name} (line {line}), which "
        "does not prevent the collection error."
    )
