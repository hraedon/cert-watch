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

import inspect
from dataclasses import dataclass
from typing import Any

import cert_watch.scan as scan
from cert_watch.app import create_app
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
    handoff: str = ""


def _keys(*paths: str, method: str = "POST") -> set[str]:
    return {f"{method} {path}" for path in paths}


_TARGET_CONTRACTS: dict[str, list[_Contract]] = {}


def _target(contract: _Contract, *keys: str) -> None:
    for key in keys:
        _TARGET_CONTRACTS.setdefault(key, []).append(contract)


_target(
    _Contract(host_management._add_endpoints_authorized, host_management._add_endpoints_authorized,
              "repo.add("),
    "POST /hosts", "POST /api/hosts", "POST /hosts/import", "POST /api/hosts/import",
)
_target(
    _Contract(host_management.create_hosts, scan.store_scanned,
              '"replace", _stage_replace', "scope_guard=scope_guard"),
    "POST /hosts", "POST /api/hosts",
)
_target(
    _Contract(host_management.import_hosts_csv, scan.store_scanned,
              '"replace", _stage_replace', "scope_guard=scope_guard"),
    "POST /hosts/import", "POST /api/hosts/import",
)
_target(
    _Contract(host_management.scan_host_now, scan.store_scanned,
              '"replace", _stage_replace', "scope_guard=scope_guard"),
    "POST /hosts/{host_id}/scan", "POST /api/hosts/{host_id}/scan",
)
_target(
    _Contract(host_management.scan_all_hosts, scan.store_scanned,
              '"replace", _stage_replace', "scope_guard=scope_guard"),
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
              '"""UPDATE alerts SET status'),
    "POST /alerts/{alert_id}/retry", "POST /api/alerts/{alert_id}/retry",
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


def test_every_scoped_target_service_authorizes_between_begin_and_mutation() -> None:
    for route, contracts in _TARGET_CONTRACTS.items():
        for contract in contracts:
            authorizer = inspect.getsource(contract.authorizer)
            transaction = inspect.getsource(contract.transaction)
            assert "ensure_write_scope_on" in authorizer, route
            if contract.handoff:
                assert contract.handoff in authorizer, route

            begin_positions = [
                pos for marker in ("begin_immediate(", 'execute("BEGIN IMMEDIATE")')
                if (pos := transaction.find(marker)) >= 0
            ]
            guard_positions = [
                pos for marker in ("ensure_write_scope_on(", "guard(conn)", "_guard(conn)")
                if (pos := transaction.find(marker)) >= 0
            ]
            mutation = transaction.find(contract.mutation)
            assert begin_positions and guard_positions and mutation >= 0, route
            assert min(begin_positions) < min(guard_positions) < mutation, route


def test_set_based_scope_is_evaluated_by_the_writing_statement() -> None:
    from cert_watch.database.repo import SqliteAlertRepository

    mark_all = inspect.getsource(SqliteAlertRepository.mark_all_read)
    claim = inspect.getsource(AlertStore.claim)
    for source, execution in ((mark_all, "cur = conn.execute("), (claim, "rows = conn.execute(")):
        assert source.find("begin_immediate(") < source.find(execution)
        assert "_add_effective_tag_filter" in source
        assert "UPDATE alerts" in source
