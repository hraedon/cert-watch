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
import functools
import sys
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).resolve().parent / "e2e"


def _imported_names(node: ast.AST) -> set[str]:
    """Every module name a single import statement can reach.

    Each dotted component counts, because the helper a module needs may be
    named anywhere in the path: ``import tests.e2e._helpers``,
    ``from tests.e2e import _helpers`` and ``from ._helpers import x`` all pull
    in the same file, and only matching on the first or last component sees
    some of them.
    """
    names: set[str] = set()
    if isinstance(node, ast.Import):
        for alias in node.names:
            names.update(alias.name.split("."))
    elif isinstance(node, ast.ImportFrom):
        names.update((node.module or "").split("."))
        names.update(alias.name.split(".")[0] for alias in node.names)
    return names - {""}


@functools.cache
def _triggers() -> frozenset[str]:
    """Names whose module-level import needs Playwright installed.

    Playwright itself, plus the ``tests/e2e`` helpers that import it — directly
    or through another helper. Detected by reading their imports rather than by
    looking for the string "playwright" anywhere in the file, which also fires
    on a helper that merely mentions it in a comment or a skip message.
    """
    helper_imports = {
        path.stem: {
            name
            for node in ast.parse(path.read_text(encoding="utf-8")).body
            for name in _imported_names(node)
        }
        for path in E2E_DIR.glob("*.py")
        if not path.name.startswith("test_")
    }

    triggers = {"playwright"}
    while True:
        reached = {
            stem for stem, imports in helper_imports.items() if imports & triggers
        } - triggers
        if not reached:
            return frozenset(triggers)
        triggers |= reached


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
        triggering = sorted(_imported_names(node) & _triggers())
        if triggering:
            return node.lineno, triggering[0]
    return None


@pytest.mark.parametrize(
    "source",
    [
        "import tests.e2e._helpers",
        "import tests.e2e._helpers as helpers",
        "from tests.e2e import _helpers",
        "from tests.e2e._helpers import login",
        "from ._helpers import login",
        "from . import _helpers",
    ],
)
def test_every_spelling_of_a_helper_import_is_recognised(source: str) -> None:
    """The guard is only as good as the import spellings it can see."""
    assert "_helpers" in _imported_names(ast.parse(source).body[0])


def test_a_helper_is_a_trigger_for_importing_playwright_not_for_naming_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Transitively, and by imports rather than by the word appearing in the file."""
    (tmp_path / "_real.py").write_text("from playwright.sync_api import Page\n")
    (tmp_path / "_chained.py").write_text("from tests.e2e._real import Page\n")
    (tmp_path / "_quiet.py").write_text('"""Seeding, used by the playwright suite."""\n')
    (tmp_path / "test_ignored.py").write_text("import playwright\n")
    monkeypatch.setattr(sys.modules[__name__], "E2E_DIR", tmp_path)
    _triggers.cache_clear()

    try:
        assert _triggers() == {"playwright", "_real", "_chained"}
    finally:
        _triggers.cache_clear()


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
