"""Enumerate the app's routes, including those behind included routers."""

from __future__ import annotations

from typing import Any


def _walk(routes: list[Any]) -> list[Any]:
    out: list[Any] = []
    for r in routes:
        if hasattr(r, "effective_candidates"):  # FastAPI >= 0.140 included router
            out.extend(_walk(r.effective_candidates()))
        elif hasattr(r, "routes") and getattr(r, "routes", None):
            # A mounted sub-application (starlette Mount): its routes are real
            # endpoints under the mount prefix and must not escape the inventory.
            # StaticFiles mounts have no routes and fall through to the else.
            out.extend(_walk(r.routes))
        else:
            out.append(r)
    return out


def mutating_routes(app: Any) -> list[tuple[str, str, Any]]:
    """``(method, path, route)`` for every mutating method on every route."""
    result = []
    for r in _walk(app.routes):
        methods = getattr(r, "methods", None) or set()
        for m in sorted(set(methods) - {"GET", "HEAD", "OPTIONS"}):
            result.append((m, r.path, r))
    return result
