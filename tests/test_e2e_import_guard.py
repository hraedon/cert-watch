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
from collections.abc import Iterator
from pathlib import Path

import pytest

E2E_DIR = Path(__file__).resolve().parent / "e2e"


def _is_test_module(path: Path) -> bool:
    """Both of pytest's default ``python_files`` patterns; the repo overrides neither."""
    return path.name.startswith("test_") or path.name.endswith("_test.py")


def _python_files(root: Path) -> Iterator[Path]:
    for path in root.rglob("*.py"):
        if "__pycache__" not in path.parts:
            yield path


def collected_modules(root: Path) -> list[Path]:
    """Every file under ``root`` pytest would import while collecting."""
    return sorted(p for p in _python_files(root) if _is_test_module(p))


def _executed_statements(tree: ast.Module) -> Iterator[ast.stmt]:
    """Statements that run at import time, including conditional ones.

    ``if sys.platform == "linux": import playwright`` executes during
    collection exactly as a plain import does, so descend into anything whose
    body runs immediately — but not into ``def``/``class``, whose bodies run
    when called.
    """
    for node in tree.body:
        yield from _executed_in(node)


def _executed_in(node: ast.stmt) -> Iterator[ast.stmt]:
    yield node
    bodies: list[list[ast.stmt]] = []
    if isinstance(node, ast.If | ast.For | ast.While):
        bodies = [node.body, node.orelse]
    elif isinstance(node, ast.With):
        bodies = [node.body]
    elif isinstance(node, ast.Try):
        bodies = [node.body, node.orelse, node.finalbody, *(h.body for h in node.handlers)]
    for body in bodies:
        for child in body:
            yield from _executed_in(child)


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


def _local_names(node: ast.AST) -> set[str]:
    """The subset of :func:`_imported_names` that can mean a ``tests/e2e`` module.

    Helpers are matched by bare module name, so an unrelated third-party
    ``from vendor import _helpers`` would otherwise inherit the local
    ``_helpers.py``'s Playwright dependency. A local helper can only be reached
    relatively, through a path naming the package, or as a bare module name.
    """
    if isinstance(node, ast.ImportFrom):
        package = node.module or ""
        if node.level or "e2e" in package.split(".") or "." not in package:
            return _imported_names(node)
        return set()
    if isinstance(node, ast.Import):
        return {
            component
            for alias in node.names
            for component in alias.name.split(".")
            if "." not in alias.name or "e2e" in alias.name.split(".")
        }
    return set()


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
            for node in _executed_statements(ast.parse(path.read_text(encoding="utf-8")))
            for name in _imported_names(node)
        }
        for path in _python_files(E2E_DIR)
        if not _is_test_module(path)
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
    """Line number of ``pytest.importorskip("playwright")``, called or assigned."""
    for node in _executed_statements(tree):
        call = node.value if isinstance(node, ast.Expr | ast.Assign | ast.AnnAssign) else None
        if not isinstance(call, ast.Call):
            continue
        func = call.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "importorskip"
            and isinstance(func.value, ast.Name)
            and func.value.id == "pytest"
            and call.args
            and isinstance(call.args[0], ast.Constant)
            and call.args[0].value == "playwright"
        ):
            return node.lineno
    return None


def _first_triggering_import(tree: ast.Module) -> tuple[int, str] | None:
    """Line and name of the earliest import that needs Playwright installed."""
    found: list[tuple[int, str]] = []
    for node in _executed_statements(tree):
        helpers = _local_names(node) & (_triggers() - {"playwright"})
        names = helpers | ({"playwright"} & _imported_names(node))
        found.extend((node.lineno, name) for name in sorted(names))
    return min(found) if found else None


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
    assert "_helpers" in _local_names(ast.parse(source).body[0])


def test_an_unrelated_package_does_not_inherit_a_helper_name() -> None:
    """Helpers are matched by bare name; only local-looking paths may match."""
    assert "_helpers" not in _local_names(ast.parse("from vendor.pkg import _helpers").body[0])


def test_a_conditional_module_level_import_still_counts() -> None:
    """It runs at collection time exactly as an unconditional one does."""
    source = "import sys\nif sys.platform == 'linux':\n    import playwright\n"
    assert _first_triggering_import(ast.parse(source)) == (3, "playwright")

    deferred = "def test_x() -> None:\n    import playwright\n"
    assert _first_triggering_import(ast.parse(deferred)) is None


def test_an_assigned_importorskip_is_a_guard() -> None:
    assert _guard_line(ast.parse('api = pytest.importorskip("playwright")\n')) == 1


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


def test_discovery_matches_what_pytest_would_import(tmp_path: Path) -> None:
    """Both default filename patterns, at any depth — a missed file is a silent hole."""
    (tmp_path / "nested").mkdir()
    for name in ("test_top.py", "login_test.py", "nested/test_nested.py", "nested/x_test.py"):
        (tmp_path / name).write_text("import playwright\n")
    (tmp_path / "_helper.py").write_text("import playwright\n")

    assert {p.relative_to(tmp_path).as_posix() for p in collected_modules(tmp_path)} == {
        "test_top.py", "login_test.py", "nested/test_nested.py", "nested/x_test.py",
    }


@pytest.mark.parametrize(
    "path", collected_modules(E2E_DIR), ids=lambda p: p.relative_to(E2E_DIR).as_posix()
)
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
