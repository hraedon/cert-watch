"""No test may patch a name through the deprecated alerting shims (plan 058).

``cert_watch.alerts``, ``alert_delivery``, ``alert_adapters`` and ``digest``
only re-export names that now live in ``cert_watch.alerting``. Patching one of
those re-exports rebinds the shim's copy and nothing else, so the code under
test keeps calling the real object and the patch silently does nothing. Patch
the module where the name is looked up instead.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

TESTS = Path(__file__).resolve().parent

# Assembled so this file's own source does not match its pattern.
_SHIM_MODULES = tuple("cert_watch." + name for name in (
    "alerts", "alert_delivery", "alert_adapters", "digest",
))
_SHIM_TARGET = re.compile(
    r"^(?:" + "|".join(re.escape(m) for m in _SHIM_MODULES) + r")\.\w"
)
_PATCHERS = {"setattr", "delattr", "patch", "object"}


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _shim_aliases(tree: ast.AST) -> set[str]:
    """Local names bound to a shim module anywhere in the file."""
    aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _SHIM_MODULES and alias.asname:
                    aliases.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.module == "cert_watch":
            for alias in node.names:
                if f"cert_watch.{alias.name}" in _SHIM_MODULES:
                    aliases.add(alias.asname or alias.name)
    return aliases


def _dotted(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    aliases = _shim_aliases(tree)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            # Any string naming an attribute of a shim: patch targets, but also
            # __import__/importlib lookups that feed one.
            if _SHIM_TARGET.match(node.value):
                found.append(f"{path.name}:{node.lineno} string target {node.value!r}")
        elif (
            isinstance(node, ast.Call)
            and _call_name(node.func) in _PATCHERS
            and node.args
        ):
            target = _dotted(node.args[0])
            if target in aliases or target in _SHIM_MODULES:
                found.append(f"{path.name}:{node.lineno} patches through shim {target!r}")
    return found


def test_no_test_patches_through_an_alerting_shim():
    offending = [
        violation
        for path in sorted(TESTS.rglob("*.py"))
        if path.resolve() != Path(__file__).resolve()
        for violation in _violations(path)
    ]
    assert not offending, (
        "Patch the module where the name is looked up under cert_watch.alerting, "
        "not the deprecated shim:\n" + "\n".join(offending)
    )


def test_guard_detects_both_patch_styles(tmp_path: Path):
    """The guard's own detector, on a file that uses both forbidden styles."""
    shim = _SHIM_MODULES[0]
    sample = tmp_path / "test_sample.py"
    sample.write_text(
        f"import {shim} as legacy\n"
        "def test_x(monkeypatch):\n"
        f"    monkeypatch.setattr({shim + '.send_alert'!r}, None)\n"
        "    monkeypatch.setattr(legacy, 'send_alert', None)\n",
        encoding="utf-8",
    )
    assert len(_violations(sample)) == 2


def test_shims_still_resolve_every_reexported_name():
    """Old import paths keep working until the shims are deleted in plan 058 PR 5."""
    import importlib

    for module_name in _SHIM_MODULES:
        module = importlib.import_module(module_name)
        missing = [name for name in module.__all__ if not hasattr(module, name)]
        assert not missing, f"{module_name} lost re-exports: {missing}"
