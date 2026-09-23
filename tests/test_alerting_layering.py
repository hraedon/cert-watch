"""Dependency direction of the alerting package (plan 058 §1).

``cert_watch.alerting`` sits below the scheduler, the scan pipeline, the web
routes and the event stream: those call into it, never the other way round.
``cert_watch.database`` sits below alerting. A static AST scan keeps the
direction from eroding one deferred import at a time -- the cycles plan 058
removed (alerts <-> alert_delivery, alerts <-> alert_adapters) were hidden
exactly that way.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "cert_watch"
ALERTING = SRC / "alerting"
DATABASE = SRC / "database"

# The deprecated re-export shims are alerting under another name: code inside
# the package must not reach back through them, and database/ must not use them.
_SHIMS = (
    "cert_watch.alerts",
    "cert_watch.alert_delivery",
    "cert_watch.alert_adapters",
    "cert_watch.digest",
)


def _imported_modules(path: Path) -> list[tuple[int, str]]:
    """Every absolute module a file imports, including deferred and TYPE_CHECKING ones.

    ``from cert_watch import scan`` is reported as ``cert_watch.scan`` so that
    importing a submodule through its parent package is not a loophole.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path))):
        if isinstance(node, ast.Import):
            found.extend((node.lineno, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, f"{path}:{node.lineno}: use absolute imports"
            module = node.module or ""
            found.append((node.lineno, module))
            found.extend((node.lineno, f"{module}.{alias.name}") for alias in node.names)
    return found


def _is_under(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(prefix + ".")


def _alerting_forbidden(module: str) -> bool:
    if not module.startswith("cert_watch."):
        return False
    top = module.split(".")[1]
    return (
        top.startswith("scheduler")  # scheduler, scheduler_context
        or top.startswith("scan")  # scan, scan_conn, scan_freshness, scan_resolver
        or top in ("routes", "events")
        or any(_is_under(module, shim) for shim in _SHIMS)
    )


def _files(root: Path) -> list[Path]:
    files = sorted(root.rglob("*.py"))
    assert files, f"no Python files under {root}"
    return files


@pytest.mark.parametrize("path", _files(ALERTING), ids=lambda p: str(p.relative_to(SRC)))
def test_alerting_does_not_import_its_callers(path: Path):
    offending = [
        f"{path.relative_to(SRC)}:{line} imports {module}"
        for line, module in _imported_modules(path)
        if _alerting_forbidden(module)
    ]
    assert not offending, (
        "cert_watch.alerting must not import scheduler*, scan*, routes, events or "
        "the deprecated alert shims:\n" + "\n".join(offending)
    )


@pytest.mark.parametrize("path", _files(DATABASE), ids=lambda p: str(p.relative_to(SRC)))
def test_database_does_not_import_alerting(path: Path):
    offending = [
        f"{path.relative_to(SRC)}:{line} imports {module}"
        for line, module in _imported_modules(path)
        if _is_under(module, "cert_watch.alerting")
        or any(_is_under(module, shim) for shim in _SHIMS)
    ]
    assert not offending, "cert_watch.database must not import alerting:\n" + "\n".join(
        offending
    )


def test_the_scan_sees_forbidden_imports():
    """The predicate itself: a scan that matches nothing proves nothing."""
    assert _alerting_forbidden("cert_watch.scheduler_context")
    assert _alerting_forbidden("cert_watch.scan_resolver")
    assert _alerting_forbidden("cert_watch.routes.api.alerts")
    assert _alerting_forbidden("cert_watch.events")
    assert _alerting_forbidden("cert_watch.alerts")
    assert not _alerting_forbidden("cert_watch.alerting.model")
    assert not _alerting_forbidden("cert_watch.database.delivery_evidence")
    assert not _alerting_forbidden("cert_watch.http_client")
