"""Every mutating route declares how tag scope is held through its write (#122).

The inventory is deliberately route-complete, while the structural assertions
follow each scoped target route to two concrete functions: the service that
supplies ``ensure_write_scope_on`` and the transaction function that invokes
that guard after ``BEGIN IMMEDIATE`` and before its mutation.  This avoids a
decorator/boolean marker that could drift away from the implementation.

Set-based bulk writes are a separate contract: their effective-tag predicate
is part of the same SQLite UPDATE that mutates the selected rows.  New-resource
routes cannot re-authorize a target that does not exist yet; their services
attach the caller's scope to the new row.  Everything else is explicitly
listed as admin-only or non-estate state.
"""

from __future__ import annotations

import ast
import inspect
import re
import textwrap
from contextlib import nullcontext, suppress
from dataclasses import dataclass
from typing import Any

import pytest

import cert_watch.routes.hosts as html_host_routes
import cert_watch.scan as scan
from cert_watch.app import create_app
from cert_watch.auth.guards import MutationGuard
from cert_watch.database import SqliteHostRepository
from cert_watch.database.alert_store import AlertStore
from cert_watch.database.cert_ops import delete_certificate_cascade
from cert_watch.services import (
    alert_state,
    certificate_management,
    host_edit,
    host_management,
    host_ownership,
    renewal_reports,
    resource_metadata,
)
from tests._route_inventory import mutating_routes


@dataclass(frozen=True)
class _Contract:
    authorizer: Any
    transaction: Any
    mutation: str
    handoffs: tuple[tuple[Any, str], ...] = ()
    advisory_authorizer: str | None = None
    in_transaction_authorizer: str | None = None


def _keys(*paths: str, method: str = "POST") -> set[str]:
    return {f"{method} {path}" for path in paths}


_TARGET_CONTRACTS: dict[str, list[_Contract]] = {}
_ROUTE_SERVICES: dict[str, Any] = {}


def _target(contract: _Contract, *keys: str) -> None:
    for key in keys:
        _TARGET_CONTRACTS.setdefault(key, []).append(contract)


def _route_service(service: Any, *keys: str) -> None:
    for key in keys:
        _ROUTE_SERVICES[key] = service


_target(
    _Contract(
        renewal_reports.create_report,
        renewal_reports.create_report,
        "INSERT INTO renewal_reports",
    ),
    "POST /api/renewal-reports",
)
_route_service(renewal_reports.create_report, "POST /api/renewal-reports")


_target(
    _Contract(
        host_management._add_endpoints_authorized,
        host_management._add_endpoints_authorized,
        "repo.add(",
    ),
    "POST /hosts",
    "POST /api/hosts",
    "POST /hosts/import",
    "POST /api/hosts/import",
)
_target(
    _Contract(
        host_management.create_hosts,
        scan.store_scanned,
        "_stage_replace",
        (
            (host_management.create_hosts, "scope_guard=scope_guard"),
            (host_management._scan_and_store, "guard=scope_guard"),
            (html_host_routes._scan_and_store, "guard=scope_guard"),
            (scan.store_scanned_async, "_guard=guard"),
        ),
    ),
    "POST /hosts",
    "POST /api/hosts",
)
_target(
    _Contract(
        host_management.import_hosts_csv,
        scan.store_scanned,
        "_stage_replace",
        (
            (host_management.import_hosts_csv, "scope_guard=scope_guard"),
            (host_management._scan_and_store, "guard=scope_guard"),
            (html_host_routes._scan_and_store, "guard=scope_guard"),
            (scan.store_scanned_async, "_guard=guard"),
        ),
    ),
    "POST /hosts/import",
    "POST /api/hosts/import",
)
_target(
    _Contract(
        host_management.scan_host_now,
        scan.store_scanned,
        "_stage_replace",
        (
            (host_management.scan_host_now, "scope_guard=scope_guard"),
            (host_management._scan_and_store, "guard=scope_guard"),
            (html_host_routes._scan_and_store, "guard=scope_guard"),
            (scan.store_scanned_async, "_guard=guard"),
        ),
    ),
    "POST /hosts/{host_id}/scan",
    "POST /api/hosts/{host_id}/scan",
)
_target(
    _Contract(
        host_management.scan_all_hosts,
        scan.store_scanned,
        "_stage_replace",
        (
            (host_management.scan_all_hosts, "scope_guard=scope_guard"),
            (host_management._scan_and_store, "guard=scope_guard"),
            (html_host_routes._scan_and_store, "guard=scope_guard"),
            (scan.store_scanned_async, "_guard=guard"),
        ),
    ),
    "POST /hosts/all/scan",
    "POST /api/hosts/scan",
)
_target(
    _Contract(
        host_edit.edit_host,
        host_edit.edit_host,
        '"UPDATE hosts SET owner_name',
        advisory_authorizer="_authorize_tag_transition",
        in_transaction_authorizer="_authorize_tag_transition",
    ),
    "POST /hosts/{resource_id}/edit",
    "PUT /api/hosts/{resource_id}",
)
_target(
    _Contract(
        host_management.update_host_settings,
        host_management.update_host_settings,
        '"UPDATE hosts SET scan_interval_hours',
    ),
    "POST /hosts/{host_id}/settings",
    "PATCH /api/hosts/{host_id}/settings",
)
_target(
    _Contract(host_management.update_expected_issuers,
              host_management.update_expected_issuers,
              '"UPDATE hosts SET expected_issuers'),
    "POST /hosts/{host_id}/expected-issuers", "PUT /api/hosts/{host_id}/issuers",
)
_target(
    _Contract(
        host_management.delete_host,
        host_management.delete_host,
        ".delete(host_id, conn=conn)",
    ),
    "POST /hosts/{host_id}/delete",
    "DELETE /api/hosts/{host_id}",
)
_target(
    _Contract(
        host_ownership.update_host_ownership,
        host_ownership.update_host_ownership,
        "persist_host_ownership(",
    ),
    "POST /hosts/{host_id}/owner",
    "PATCH /api/hosts/{host_id}/owner",
    "POST /certificates/{cert_id}/owner",
)
_target(
    _Contract(resource_metadata.update_host_notes, resource_metadata._transact, "persist(conn)"),
    "POST /hosts/{host_id}/notes",
    "PATCH /api/hosts/{host_id}/notes",
)
_target(
    _Contract(resource_metadata.update_host_tags, resource_metadata._transact, "persist(conn)"),
    "POST /hosts/{host_id}/tags",
    "PUT /api/hosts/{host_id}/tags",
)
_target(
    _Contract(
        resource_metadata.update_certificate_tags, resource_metadata._transact, "persist(conn)"
    ),
    "POST /certificates/{cert_id}/tags",
    "PUT /api/certificates/{cert_id}/tags",
)
_target(
    _Contract(
        certificate_management.delete_certificate,
        delete_certificate_cascade,
        '"DELETE FROM certificates',
    ),
    "POST /certificates/{cert_id}/delete",
    "DELETE /api/certificates/{cert_id}",
)
_target(
    _Contract(alert_state.mark_alert_read, alert_state.mark_alert_read, '"UPDATE alerts SET read'),
    "POST /api/alerts/{alert_id}/read",
)
_target(
    _Contract(AlertStore.operator_retry, AlertStore.operator_retry, "UPDATE alerts SET status"),
    "POST /alerts/{alert_id}/retry",
    "POST /api/alerts/{alert_id}/retry",
)

_route_service(host_management.create_hosts, "POST /hosts", "POST /api/hosts")
_route_service(host_management.import_hosts_csv, "POST /hosts/import", "POST /api/hosts/import")
_route_service(
    host_management.scan_host_now,
    "POST /hosts/{host_id}/scan",
    "POST /api/hosts/{host_id}/scan",
)
_route_service(host_management.scan_all_hosts, "POST /hosts/all/scan", "POST /api/hosts/scan")
_route_service(
    host_edit.edit_host,
    "POST /hosts/{resource_id}/edit",
    "PUT /api/hosts/{resource_id}",
)
_route_service(
    host_management.update_host_settings,
    "POST /hosts/{host_id}/settings",
    "PATCH /api/hosts/{host_id}/settings",
)
_route_service(
    host_management.update_expected_issuers,
    "POST /hosts/{host_id}/expected-issuers",
    "PUT /api/hosts/{host_id}/issuers",
)
_route_service(
    host_management.delete_host,
    "POST /hosts/{host_id}/delete",
    "DELETE /api/hosts/{host_id}",
)
_route_service(
    host_ownership.update_host_ownership,
    "POST /hosts/{host_id}/owner",
    "PATCH /api/hosts/{host_id}/owner",
    "POST /certificates/{cert_id}/owner",
)
_route_service(
    resource_metadata.update_host_notes,
    "POST /hosts/{host_id}/notes",
    "PATCH /api/hosts/{host_id}/notes",
)
_route_service(
    resource_metadata.update_host_tags,
    "POST /hosts/{host_id}/tags",
    "PUT /api/hosts/{host_id}/tags",
)
_route_service(
    resource_metadata.update_certificate_tags,
    "POST /certificates/{cert_id}/tags",
    "PUT /api/certificates/{cert_id}/tags",
)
_route_service(
    certificate_management.delete_certificate,
    "POST /certificates/{cert_id}/delete",
    "DELETE /api/certificates/{cert_id}",
)
_route_service(alert_state.mark_alert_read, "POST /api/alerts/{alert_id}/read")
_route_service(
    AlertStore.operator_retry,
    "POST /alerts/{alert_id}/retry",
    "POST /api/alerts/{alert_id}/retry",
)


_SET_BASED = {
    **dict.fromkeys(
        _keys("/alerts/mark-all-read", "/api/alerts/mark-all-read"),
        "SqliteAlertRepository.mark_all_read: scope predicate is inside UPDATE",
    ),
    "POST /alerts/flush": "AlertStore.claim: scope predicate is inside claiming UPDATE",
}

_NEW_RESOURCE = dict.fromkeys(
    _keys("/upload", "/api/certificates/upload"),
    "uploaded certificate receives the caller's scope tags",
)

_NON_ESTATE = {
    "POST /login": "authentication",
    "POST /auth/logout": "authentication",
    "POST /setup": "first-run setup",
    "POST /api/webhook/test": "test delivery; no estate row",
    "POST /settings/change-password": "caller's own account",
}

_ADMIN_ONLY = {
    *_keys("/trust-anchors", "/api/trust-anchors"),
    "POST /trust-anchors/{anchor_id}/delete",
    "DELETE /api/trust-anchors/{anchor_id}",
    "POST /hosts/{host_id}/expected-issuers",
    "PUT /api/hosts/{host_id}/issuers",
    "POST /api/alert-groups",
    "PATCH /api/alert-groups/{group_id}",
    "DELETE /api/alert-groups/{group_id}",
    "POST /api/alert-groups/{group_id}/certs/{cert_id}",
    "DELETE /api/alert-groups/{group_id}/certs/{cert_id}",
    *_keys(
        "/settings/alert-groups",
        "/settings/alert-groups/{group_id}",
        "/settings/alert-groups/{group_id}/delete",
        "/api/api-keys",
        "/settings/api-keys",
        "/settings/api-keys/{key_id}/revoke",
        "/settings/auth",
        "/settings/ldap-role-map",
        "/settings/test-ldap",
        "/settings/pin-ldap-ca",
        "/settings/smtp",
        "/settings/test-smtp",
        "/settings/alerts",
        "/settings/policy",
        "/settings/events",
        "/settings/roles",
        "/settings/roles/{role_id}",
        "/settings/roles/{role_id}/delete",
        "/settings/users",
        "/settings/users/{user_id}",
        "/settings/users/{user_id}/delete",
    ),
    "DELETE /api/api-keys/{key_id}",
    "PUT /api/policy",
}


def test_every_mutating_route_has_a_transaction_scope_classification() -> None:
    actual = {f"{method} {path}" for method, path, _route in mutating_routes(create_app())}
    classified = (
        set(_TARGET_CONTRACTS)
        | set(_SET_BASED)
        | set(_NEW_RESOURCE)
        | set(_NON_ESTATE)
        | _ADMIN_ONLY
    )
    assert actual == classified, {
        "unclassified": sorted(actual - classified),
        "stale": sorted(classified - actual),
    }


def _source_and_tree(function: Any) -> tuple[str, ast.Module]:
    source = textwrap.dedent(inspect.getsource(function))
    return source, ast.parse(source)


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _call_matches_marker(call: ast.Call, marker: str) -> bool:
    """Match a real call target, keyword handoff, or SQL argument.

    Source substrings are deliberately not considered: a log message that
    merely names an authorization function is not an authorization call.
    """
    keyword = re.fullmatch(r"([A-Za-z_]\w*)=([A-Za-z_]\w*)", marker)
    if keyword:
        name, value = keyword.groups()
        return any(
            item.arg == name and isinstance(item.value, ast.Name) and item.value.id == value
            for item in call.keywords
        )

    normalized = marker.strip("\"'")
    if normalized.startswith(("BEGIN ", "UPDATE ", "DELETE ", "INSERT ")):
        return any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and normalized in node.value
            for arg in call.args
            for node in ast.walk(arg)
        )

    if marker.isidentifier():
        return _call_name(call) == marker or any(
            isinstance(node, ast.Name) and node.id == marker
            for value in (*call.args, *(item.value for item in call.keywords))
            for node in ast.walk(value)
        )

    names = re.findall(r"[A-Za-z_]\w*", marker.partition("(")[0])
    return bool(names) and _call_name(call) == names[-1]


def _is_irrefutable_pattern(pattern: ast.pattern) -> bool:
    if isinstance(pattern, ast.MatchAs):
        return pattern.pattern is None or _is_irrefutable_pattern(pattern.pattern)
    if isinstance(pattern, ast.MatchOr):
        return any(_is_irrefutable_pattern(item) for item in pattern.patterns)
    return False


def _contains_loop_control(statements: list[ast.stmt]) -> bool:
    """Return whether this suite can break/continue an enclosing construct."""

    class Visitor(ast.NodeVisitor):
        found = False

        def visit_Break(self, node: ast.Break) -> None:
            self.found = True

        def visit_Continue(self, node: ast.Continue) -> None:
            self.found = True

        def visit_For(self, node: ast.For) -> None:
            return

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            return

        def visit_While(self, node: ast.While) -> None:
            return

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    visitor = Visitor()
    for statement in statements:
        visitor.visit(statement)
    return visitor.found


def _loop_has_break(loop: ast.While) -> bool:
    class Visitor(ast.NodeVisitor):
        found = False

        def visit_Break(self, node: ast.Break) -> None:
            self.found = True

        def visit_For(self, node: ast.For) -> None:
            return

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            return

        def visit_While(self, node: ast.While) -> None:
            return

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    visitor = Visitor()
    for statement in loop.body:
        visitor.visit(statement)
    return visitor.found


def _suite_always_exits(statements: list[ast.stmt]) -> bool:
    return any(_statement_always_exits(statement) for statement in statements)


def _statement_always_exits(statement: ast.stmt) -> bool:
    if isinstance(statement, (ast.Return, ast.Raise)):
        return True
    if isinstance(statement, ast.If):
        return (
            bool(statement.orelse)
            and _suite_always_exits(statement.body)
            and _suite_always_exits(statement.orelse)
        )
    if isinstance(statement, ast.Match):
        return (
            bool(statement.cases)
            and all(_suite_always_exits(case.body) for case in statement.cases)
            and any(
                case.guard is None and _is_irrefutable_pattern(case.pattern)
                for case in statement.cases
            )
        )
    if isinstance(statement, ast.While):
        return (
            isinstance(statement.test, ast.Constant)
            and statement.test.value is True
            and not _loop_has_break(statement)
        )
    if isinstance(statement, (ast.Try, ast.TryStar)):
        if statement.finalbody and _suite_always_exits(statement.finalbody):
            return True
        if _contains_loop_control(statement.finalbody):
            return False
        if not _suite_always_exits(statement.body):
            return False
        # Any expression in the body may raise (``return f()`` included), so a
        # handler that falls through makes the statements after the try live.
        return all(_suite_always_exits(handler.body) for handler in statement.handlers)
    if isinstance(statement, (ast.With, ast.AsyncWith)):
        # A context manager may swallow an exception raised in its body; treat
        # the known suppressing managers as falling through.
        if any(_is_suppressing_manager(item.context_expr) for item in statement.items):
            return False
        return _suite_always_exits(statement.body)
    return False


def _is_suppressing_manager(expr: ast.expr) -> bool:
    func = expr.func if isinstance(expr, ast.Call) else expr
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
    return name == "suppress"


def _is_reachable(
    tree: ast.Module,
    node: ast.AST,
    *,
    reject_conditionals: bool = False,
    reject_nested_functions: bool = False,
) -> bool:
    """Prove that *node* is reachable from its root function entry.

    Statements after an always-exiting sibling are dead. The exit proof is
    recursive so compound statements cannot hide an unreachable marker.
    """
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    root_function = next(
        node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )
    child: ast.AST = node
    while child in parents:
        parent = parents[child]
        for _field, value in ast.iter_fields(parent):
            if not isinstance(value, list) or child not in value:
                continue
            position = value.index(child)
            preceding = value[:position]
            if all(isinstance(item, ast.stmt) for item in preceding) and any(
                _statement_always_exits(item) for item in preceding
            ):
                return False
        if isinstance(parent, ast.If):
            constant = parent.test.value if isinstance(parent.test, ast.Constant) else None
            if constant is False and child in parent.body:
                return False
            if constant is True and child in parent.orelse:
                return False
        if reject_conditionals and isinstance(
            parent,
            (
                ast.If,
                ast.IfExp,
                ast.For,
                ast.AsyncFor,
                ast.While,
                ast.Match,
                ast.comprehension,
                ast.BoolOp,
            ),
        ):
            return False
        if (
            reject_conditionals
            and isinstance(parent, (ast.Try, ast.TryStar))
            and child not in (*parent.body, *parent.finalbody)
        ):
            return False
        if (
            reject_nested_functions
            and isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            and parent is not root_function
        ):
            return False
        child = parent
    return True


def _call_positions(
    function: Any, marker: str, *, reject_conditionals: bool = False
) -> list[tuple[int, int]]:
    _source, tree = _source_and_tree(function)
    return [
        (node.lineno, node.col_offset)
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _call_matches_marker(node, marker)
        and _is_reachable(
            tree,
            node,
            reject_conditionals=reject_conditionals,
        )
    ]


def _assigned_call_positions(function: Any, target: str) -> list[tuple[int, int]]:
    _source, tree = _source_and_tree(function)
    return [
        (node.value.lineno, node.value.col_offset)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and any(isinstance(name, ast.Name) and name.id == target for name in node.targets)
    ]


def _endpoint_calls_service(endpoint: Any, service: Any) -> bool:
    _source, tree = _source_and_tree(endpoint)
    for call in ast.walk(tree):
        if not isinstance(call, ast.Call) or not _is_reachable(
            tree,
            call,
            reject_conditionals=True,
            reject_nested_functions=True,
        ):
            continue
        target: Any = None
        if isinstance(call.func, ast.Name):
            target = endpoint.__globals__.get(call.func.id)
        elif isinstance(call.func, ast.Attribute):
            owner: Any = None
            if isinstance(call.func.value, ast.Name):
                owner = endpoint.__globals__.get(call.func.value.id)
            elif isinstance(call.func.value, ast.Call) and isinstance(
                call.func.value.func, ast.Name
            ):
                owner = endpoint.__globals__.get(call.func.value.func.id)
            if owner is not None:
                target = getattr(owner, call.func.attr, None)
        if target is service:
            return True
    return False


def _synthetic_delete_bypass(db_path: str, host_id: str) -> None:
    """Negative fixture: the required service exists only in dead code."""
    SqliteHostRepository(db_path).delete(host_id)
    return
    host_management.delete_host(  # pragma: no cover - deliberately unreachable
        db_path,
        host_id,
        auth=None,
        actor="synthetic",
        source_ip=None,
    )


def _synthetic_if_else_bypass(db_path: str, host_id: str) -> None:
    if host_id:
        return
    else:
        return
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_match_bypass(db_path: str, host_id: str) -> None:
    match host_id:
        case "never":
            return
        case _:
            return
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_while_bypass(db_path: str, host_id: str) -> None:
    while True:
        return
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_with_bypass(db_path: str, host_id: str) -> None:
    with nullcontext():
        raise RuntimeError
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_try_bypass(db_path: str, host_id: str) -> None:
    try:
        return
    finally:
        pass
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_mixed_exit_bypass(db_path: str, host_id: str) -> None:
    if host_id:
        return
    else:
        raise RuntimeError
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_finally_service(db_path: str, host_id: str) -> None:
    try:
        return
    finally:
        host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_suppressed_raise_service(db_path: str, host_id: str) -> None:
    with suppress(RuntimeError):
        raise RuntimeError("swallowed")
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_handled_return_service(db_path: str, host_id: str) -> None:
    try:
        return _synthetic_boom()
    except RuntimeError:
        pass
    host_management.delete_host(db_path, host_id, auth=None, actor="synthetic", source_ip=None)


def _synthetic_boom() -> None:
    raise RuntimeError("boom")


def _synthetic_dead_transaction(transaction: Any) -> None:
    return
    transaction.begin_immediate()
    transaction.ensure_write_scope_on()
    transaction.execute("UPDATE hosts SET owner_name = ''")


def _mutation_guards(route: Any) -> list[MutationGuard]:
    found: list[MutationGuard] = []

    def walk(dependant: Any) -> None:
        for dependency in dependant.dependencies:
            if isinstance(dependency.call, MutationGuard):
                found.append(dependency.call)
            walk(dependency)

    walk(route.dependant)
    return found


def test_every_scoped_target_service_authorizes_between_begin_and_mutation() -> None:
    for route, contracts in _TARGET_CONTRACTS.items():
        for contract in contracts:
            assert _call_positions(
                contract.authorizer,
                "ensure_write_scope_on",
                reject_conditionals=(
                    contract.authorizer is not host_management._add_endpoints_authorized
                ),
            ), route
            for function, marker in contract.handoffs:
                assert _call_positions(function, marker), (route, function.__qualname__, marker)

            begin_positions = [
                position
                for marker in ("begin_immediate", "BEGIN IMMEDIATE")
                for position in _call_positions(contract.transaction, marker)
            ]
            guard_positions = [
                position
                for marker in ("ensure_write_scope_on", "guard(conn)", "_guard(conn)")
                for position in _call_positions(
                    contract.transaction,
                    marker,
                    reject_conditionals=(
                        marker == "ensure_write_scope_on"
                        and contract.transaction is not host_management._add_endpoints_authorized
                    ),
                )
            ]
            mutation_positions = _call_positions(contract.transaction, contract.mutation)
            assert begin_positions and guard_positions and mutation_positions, route
            assert min(begin_positions) < min(guard_positions) < min(mutation_positions), route
            if contract.advisory_authorizer is not None:
                authorizer_positions = _call_positions(
                    contract.transaction,
                    contract.advisory_authorizer,
                    reject_conditionals=True,
                )
                assert any(
                    position < min(begin_positions) for position in authorizer_positions
                ), route
            if contract.in_transaction_authorizer is not None:
                authorizer_positions = _call_positions(
                    contract.transaction,
                    contract.in_transaction_authorizer,
                    reject_conditionals=True,
                )
                assert any(
                    min(begin_positions) < position < min(mutation_positions)
                    for position in authorizer_positions
                ), route


def test_each_scoped_route_calls_its_mapped_service() -> None:
    routes = {f"{method} {path}": route for method, path, route in mutating_routes(create_app())}
    assert set(_ROUTE_SERVICES) == set(_TARGET_CONTRACTS)
    for key, service in _ROUTE_SERVICES.items():
        assert _endpoint_calls_service(routes[key].endpoint, service), (
            key,
            service.__qualname__,
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        _synthetic_delete_bypass,
        _synthetic_if_else_bypass,
        _synthetic_match_bypass,
        _synthetic_while_bypass,
        _synthetic_with_bypass,
        _synthetic_try_bypass,
        _synthetic_mixed_exit_bypass,
    ],
)
def test_unreachable_service_call_cannot_satisfy_route_inventory(endpoint: Any) -> None:
    assert not _endpoint_calls_service(
        endpoint,
        host_management.delete_host,
    )


def test_service_call_in_finally_is_reachable() -> None:
    assert _endpoint_calls_service(
        _synthetic_finally_service,
        host_management.delete_host,
    )


@pytest.mark.parametrize(
    "handler",
    [_synthetic_suppressed_raise_service, _synthetic_handled_return_service],
    ids=["with-suppress-raise", "try-return-call-except-pass"],
)
def test_service_call_after_a_swallowed_exit_is_reachable(handler: Any) -> None:
    # Review of #141 round 2: both shapes do reach the service at runtime.
    assert _endpoint_calls_service(handler, host_management.delete_host)


@pytest.mark.parametrize(
    "marker",
    ["begin_immediate", "ensure_write_scope_on", '"UPDATE hosts SET owner_name'],
)
def test_dead_transaction_markers_do_not_count(marker: str) -> None:
    assert not _call_positions(_synthetic_dead_transaction, marker)


def test_route_scope_classes_have_the_expected_guard_tier() -> None:
    routes = {f"{method} {path}": route for method, path, route in mutating_routes(create_app())}
    for key in _ADMIN_ONLY:
        guards = _mutation_guards(routes[key])
        assert guards and all(guard.level == "admin" for guard in guards), key
    scoped = (set(_TARGET_CONTRACTS) - _ADMIN_ONLY) | set(_SET_BASED) | set(_NEW_RESOURCE)
    for key in scoped:
        assert all(guard.level != "admin" for guard in _mutation_guards(routes[key])), key


def test_scan_failure_bookkeeping_authorizes_after_begin() -> None:
    for wrapper in (host_management._scan_and_store, html_host_routes._scan_and_store):
        assert _call_positions(wrapper, "_record_scan_failure"), wrapper.__qualname__
        assert _call_positions(wrapper, "scope_guard=scope_guard"), wrapper.__qualname__
    begin = _call_positions(host_management._record_scan_failure, "begin_immediate")
    guard = _call_positions(host_management._record_scan_failure, "scope_guard(conn)")
    history = _call_positions(host_management._record_scan_failure, "record_scan_history")
    event = _call_positions(host_management._record_scan_failure, "emit_scan_failed")
    assert begin and guard and history and event
    assert min(begin) < min(guard) < min(history) < min(event)


def test_set_based_scope_is_evaluated_by_the_writing_statement() -> None:
    from cert_watch.database.repo import SqliteAlertRepository

    for function, target in (
        (SqliteAlertRepository.mark_all_read, "cur"),
        (AlertStore.claim, "rows"),
    ):
        begin_positions = _call_positions(function, "begin_immediate")
        execution_positions = _assigned_call_positions(function, target)
        assert begin_positions and execution_positions
        assert min(begin_positions) < min(execution_positions)
        source = inspect.getsource(function)
        assert "_add_effective_tag_filter" in source
        assert "UPDATE alerts" in source
