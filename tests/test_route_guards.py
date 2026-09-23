"""Every mutating route declares exactly one mutation guard (plan 057 W6).

A mutation guard (:class:`cert_watch.auth.guards.MutationGuard`) always
includes CSRF, so "every write route has one" is "every write route is
CSRF-protected". A read guard (``require_auth`` / ``require_admin`` /
``admin_page_guard``) on a mutating route is a failure: it has no CSRF check.

The allowlist is the pre-session flow, which cannot hold a session-level
guard; each of those routes runs ``check_csrf`` itself.
"""

from __future__ import annotations

from typing import Any

import pytest

from cert_watch.auth.guards import MutationGuard, ReadGuard
from tests._route_inventory import mutating_routes

# (method, path) -> why it carries no guard.
UNGUARDED_ALLOWLIST: dict[tuple[str, str], str] = {
    ("POST", "/login"): "pre-session: authenticates the user; runs check_csrf itself",
    ("POST", "/setup"): "first-run bootstrap before any account exists; runs check_csrf itself",
    ("POST", "/auth/logout"): (
        "public path so an expired session can still log out; runs check_csrf itself"
    ),
}


def _guards(route: Any) -> tuple[list[Any], list[Any]]:
    calls = [d.call for d in route.dependant.dependencies]
    return (
        [c for c in calls if isinstance(c, MutationGuard)],
        [c for c in calls if isinstance(c, ReadGuard)],
    )


@pytest.fixture(scope="module")
def app():
    from cert_watch.app import create_app

    return create_app()


def test_every_mutating_route_has_exactly_one_mutation_guard(app):
    problems = []
    for method, path, route in mutating_routes(app):
        mutation, read = _guards(route)
        if (method, path) in UNGUARDED_ALLOWLIST:
            if mutation or read:
                problems.append(f"{method} {path}: allowlisted but carries a guard")
            continue
        if read:
            problems.append(f"{method} {path}: read guard {read} (no CSRF) on a mutating route")
        if len(mutation) != 1:
            problems.append(f"{method} {path}: {len(mutation)} mutation guards, expected 1")
    assert not problems, "\n".join(problems)


def test_allowlist_names_only_real_routes(app):
    present = {(m, p) for m, p, _ in mutating_routes(app)}
    assert set(UNGUARDED_ALLOWLIST) <= present


def test_the_route_enumeration_sees_the_whole_app(app):
    # A guard test that silently enumerates nothing passes vacuously.
    assert len(mutating_routes(app)) >= 50


def test_mutation_guard_cannot_be_built_without_csrf():
    import inspect

    params = set(inspect.signature(MutationGuard).parameters)
    assert not {p for p in params if "csrf" in p and p != "csrf_failure"}
    with pytest.raises(ValueError):
        MutationGuard("read", form=False)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        MutationGuard("write", form=False, browser_only=True)


def test_inventory_sees_routes_inside_a_mounted_sub_application() -> None:
    from fastapi import FastAPI

    from tests._route_inventory import mutating_routes

    sub = FastAPI()

    @sub.post("/danger")
    def danger() -> dict[str, str]:  # pragma: no cover - never called
        return {}

    outer = FastAPI()
    outer.mount("/sub", sub)

    assert any(method == "POST" for method, _path, _route in mutating_routes(outer))
