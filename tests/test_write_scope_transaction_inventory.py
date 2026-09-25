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
import textwrap
from dataclasses import dataclass
from typing import Any

import cert_watch.routes.hosts as html_host_routes
import cert_watch.scan as scan
from cert_watch.app import create_app
from cert_watch.auth.guards import MutationGuard
from cert_watch.database.alert_store import AlertStore
from cert_watch.database.cert_ops import delete_certificate_cascade
from cert_watch.services import (
    alert_state,
    certificate_management,
    host_management,
    host_ownership,
    resource_metadata,
)
from tests._route_inventory import mutating_routes


@dataclass(frozen=True)
class _Contract:
    authorizer: Any
    transaction: Any
    mutation: str
    handoffs: tuple[tuple[Any, str], ...] = ()


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
    _Contract(host_management._add_endpoints_authorized, host_management._add_endpoints_authorized,
              "repo.add("),
    "POST /hosts", "POST /api/hosts", "POST /hosts/import", "POST /api/hosts/import",
)
_target(
    _Contract(host_management.create_hosts, scan.store_scanned,
              "_stage_replace", (
                  (host_management.create_hosts, "scope_guard=scope_guard"),
                  (host_management._scan_and_store, "guard=scope_guard"),
                  (html_host_routes._scan_and_store, "guard=scope_guard"),
                  (scan.store_scanned_async, "_guard=guard"),
              )),
    "POST /hosts", "POST /api/hosts",
)
_target(
    _Contract(host_management.import_hosts_csv, scan.store_scanned,
              "_stage_replace", (
                  (host_management.import_hosts_csv, "scope_guard=scope_guard"),
                  (host_management._scan_and_store, "guard=scope_guard"),
                  (html_host_routes._scan_and_store, "guard=scope_guard"),
                  (scan.store_scanned_async, "_guard=guard"),
              )),
    "POST /hosts/import", "POST /api/hosts/import",
)
_target(
    _Contract(host_management.scan_host_now, scan.store_scanned,
              "_stage_replace", (
                  (host_management.scan_host_now, "scope_guard=scope_guard"),
                  (host_management._scan_and_store, "guard=scope_guard"),
                  (html_host_routes._scan_and_store, "guard=scope_guard"),
                  (scan.store_scanned_async, "_guard=guard"),
              )),
    "POST /hosts/{host_id}/scan", "POST /api/hosts/{host_id}/scan",
)
_target(
    _Contract(host_management.scan_all_hosts, scan.store_scanned,
              "_stage_replace", (
                  (host_management.scan_all_hosts, "scope_guard=scope_guard"),
                  (host_management._scan_and_store, "guard=scope_guard"),
                  (html_host_routes._scan_and_store, "guard=scope_guard"),
                  (scan.store_scanned_async, "_guard=guard"),
              )),
    "POST /hosts/all/scan", "POST /api/hosts/scan",
)
_target(
    _Contract(host_management.update_host_settings, host_management.update_host_settings,
              '"UPDATE hosts SET scan_interval_hours'),
    "POST /hosts/{host_id}/settings", "PATCH /api/hosts/{host_id}/settings",
)
_target(
    _Contract(
        host_management.delete_host,
        host_management.delete_host,
        ".delete(host_id, conn=conn)",
    ),
    "POST /hosts/{host_id}/delete", "DELETE /api/hosts/{host_id}",
)
_target(
    _Contract(host_ownership.update_host_ownership, host_ownership.update_host_ownership,
              "persist_host_ownership("),
    "POST /hosts/{host_id}/owner", "PATCH /api/hosts/{host_id}/owner",
    "POST /certificates/{cert_id}/owner",
)
_target(
    _Contract(resource_metadata.update_host_notes, resource_metadata._transact, "persist(conn)"),
    "POST /hosts/{host_id}/notes", "PATCH /api/hosts/{host_id}/notes",
)
_target(
    _Contract(resource_metadata.update_host_tags, resource_metadata._transact, "persist(conn)"),
    "POST /hosts/{host_id}/tags", "PUT /api/hosts/{host_id}/tags",
)
_target(
    _Contract(resource_metadata.update_certificate_tags, resource_metadata._transact,
              "persist(conn)"),
    "POST /certificates/{cert_id}/tags", "PUT /api/certificates/{cert_id}/tags",
)
_target(
    _Contract(certificate_management.delete_certificate, delete_certificate_cascade,
              '"DELETE FROM certificates'),
    "POST /certificates/{cert_id}/delete", "DELETE /api/certificates/{cert_id}",
)
_target(
    _Contract(alert_state.mark_alert_read, alert_state.mark_alert_read,
              '"UPDATE alerts SET read'),
    "POST /api/alerts/{alert_id}/read",
)
_target(
    _Contract(AlertStore.operator_retry, AlertStore.operator_retry,
              "UPDATE alerts SET status"),
    "POST /alerts/{alert_id}/retry", "POST /api/alerts/{alert_id}/retry",
)

_route_service(host_management.create_hosts, "POST /hosts", "POST /api/hosts")
_route_service(
    host_management.import_hosts_csv, "POST /hosts/import", "POST /api/hosts/import"
)
_route_service(
    host_management.scan_host_now,
    "POST /hosts/{host_id}/scan",
    "POST /api/hosts/{host_id}/scan",
)
_route_service(
    host_management.scan_all_hosts, "POST /hosts/all/scan", "POST /api/hosts/scan"
)
_route_service(
    host_management.update_host_settings,
    "POST /hosts/{host_id}/settings",
    "PATCH /api/hosts/{host_id}/settings",
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


def _source_and_calls(function: Any) -> tuple[str, list[ast.Call]]:
    source = textwrap.dedent(inspect.getsource(function))
    tree = ast.parse(source)
    return source, [node for node in ast.walk(tree) if isinstance(node, ast.Call)]


def _call_positions(function: Any, marker: str) -> list[tuple[int, int]]:
    source, calls = _source_and_calls(function)
    return [
        (node.lineno, node.col_offset)
        for node in calls
        if marker in (ast.get_source_segment(source, node) or ast.unparse(node))
    ]


def _assigned_call_positions(function: Any, target: str) -> list[tuple[int, int]]:
    source = textwrap.dedent(inspect.getsource(function))
    tree = ast.parse(source)
    return [
        (node.value.lineno, node.value.col_offset)
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Call)
        and any(isinstance(name, ast.Name) and name.id == target for name in node.targets)
    ]


def _endpoint_calls_service(endpoint: Any, service: Any) -> bool:
    _source, calls = _source_and_calls(endpoint)
    for call in calls:
        if isinstance(call.func, ast.Name):
            if endpoint.__globals__.get(call.func.id) is service:
                return True
        elif isinstance(call.func, ast.Attribute) and call.func.attr == service.__name__:
            return True
    return False


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
            assert _call_positions(contract.authorizer, "ensure_write_scope_on"), route
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
                for position in _call_positions(contract.transaction, marker)
            ]
            mutation_positions = _call_positions(contract.transaction, contract.mutation)
            assert begin_positions and guard_positions and mutation_positions, route
            assert min(begin_positions) < min(guard_positions) < min(mutation_positions), route


def test_each_scoped_route_calls_its_mapped_service() -> None:
    routes = {f"{method} {path}": route for method, path, route in mutating_routes(create_app())}
    assert set(_ROUTE_SERVICES) == set(_TARGET_CONTRACTS)
    for key, service in _ROUTE_SERVICES.items():
        assert _endpoint_calls_service(routes[key].endpoint, service), (
            key,
            service.__qualname__,
        )


def test_route_scope_classes_have_the_expected_guard_tier() -> None:
    routes = {f"{method} {path}": route for method, path, route in mutating_routes(create_app())}
    for key in _ADMIN_ONLY:
        guards = _mutation_guards(routes[key])
        assert guards and all(guard.level == "admin" for guard in guards), key
    for key in set(_TARGET_CONTRACTS) | set(_SET_BASED) | set(_NEW_RESOURCE):
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
