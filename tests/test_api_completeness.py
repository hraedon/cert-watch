"""The replaceable operational UI has a JSON equivalent for every mutation."""

from __future__ import annotations

from typing import Any

from tests._route_inventory import _walk, mutating_routes

# Explicit by design: adding a server-rendered operational mutation requires a
# reviewed API partner here. Authentication/bootstrap, connection probes, and
# control-plane configuration are a separate browser/session surface; CRUD
# concepts that already have a JSON API are included.
HTML_TO_JSON: dict[tuple[str, str], tuple[str, str]] = {
    ("POST", "/alerts/mark-all-read"): ("POST", "/api/alerts/mark-all-read"),
    ("POST", "/alerts/{alert_id}/retry"): (
        "POST", "/api/alerts/{alert_id}/retry"
    ),
    ("POST", "/hosts"): ("POST", "/api/hosts"),
    ("POST", "/hosts/import"): ("POST", "/api/hosts/import"),
    ("POST", "/hosts/all/scan"): ("POST", "/api/hosts/scan"),
    ("POST", "/hosts/{host_id}/settings"): ("PATCH", "/api/hosts/{host_id}/settings"),
    ("POST", "/hosts/{host_id}/notes"): ("PATCH", "/api/hosts/{host_id}/notes"),
    ("POST", "/hosts/{host_id}/tags"): ("PUT", "/api/hosts/{host_id}/tags"),
    ("POST", "/hosts/{host_id}/expected-issuers"): ("PUT", "/api/hosts/{host_id}/issuers"),
    ("POST", "/hosts/{host_id}/delete"): ("DELETE", "/api/hosts/{host_id}"),
    ("POST", "/hosts/{host_id}/scan"): ("POST", "/api/hosts/{host_id}/scan"),
    ("POST", "/certificates/{cert_id}/delete"): ("DELETE", "/api/certificates/{cert_id}"),
    ("POST", "/certificates/{cert_id}/tags"): ("PUT", "/api/certificates/{cert_id}/tags"),
    ("POST", "/certificates/{cert_id}/owner"): ("PATCH", "/api/hosts/{host_id}/owner"),
    ("POST", "/hosts/{host_id}/owner"): ("PATCH", "/api/hosts/{host_id}/owner"),
    ("POST", "/upload"): ("POST", "/api/certificates/upload"),
    ("POST", "/trust-anchors"): ("POST", "/api/trust-anchors"),
    ("POST", "/trust-anchors/{anchor_id}/delete"): ("DELETE", "/api/trust-anchors/{anchor_id}"),
    ("POST", "/settings/api-keys"): ("POST", "/api/api-keys"),
    ("POST", "/settings/api-keys/{key_id}/revoke"): ("DELETE", "/api/api-keys/{key_id}"),
    ("POST", "/settings/alert-groups"): ("POST", "/api/alert-groups"),
    ("POST", "/settings/alert-groups/{group_id}"): ("PATCH", "/api/alert-groups/{group_id}"),
    ("POST", "/settings/alert-groups/{group_id}/delete"): (
        "DELETE", "/api/alert-groups/{group_id}"
    ),
    ("POST", "/settings/policy"): ("PUT", "/api/policy"),
}


# These are not mutations of the certificate-lifecycle model represented by
# UI-INVENTORY's executable seam. Keep the list explicit so a new route cannot
# disappear from the completeness review.
CONTROL_PLANE_OR_WORKFLOW: set[tuple[str, str]] = {
    ("POST", "/login"),
    ("POST", "/auth/logout"),
    ("POST", "/setup"),
    ("POST", "/alerts/flush"),  # delivery lifecycle is plan 057 W4
    ("POST", "/settings/auth"),
    ("POST", "/settings/ldap-role-map"),
    ("POST", "/settings/test-ldap"),
    ("POST", "/settings/pin-ldap-ca"),
    ("POST", "/settings/smtp"),
    ("POST", "/settings/test-smtp"),
    ("POST", "/settings/alerts"),
    ("POST", "/settings/events"),
    ("POST", "/settings/change-password"),
    ("POST", "/settings/roles"),
    ("POST", "/settings/roles/{role_id}"),
    ("POST", "/settings/roles/{role_id}/delete"),
    ("POST", "/settings/users"),
    ("POST", "/settings/users/{user_id}"),
    ("POST", "/settings/users/{user_id}/delete"),
}


def _routes(app: Any) -> set[tuple[str, str]]:
    return {(method, path) for method, path, _route in mutating_routes(app)}


def test_every_operational_html_mutation_has_a_json_equivalent() -> None:
    from cert_watch.app import create_app

    routes = _routes(create_app())
    html = {route for route in routes if not route[1].startswith("/api/")}
    assert html == set(HTML_TO_JSON) | CONTROL_PLANE_OR_WORKFLOW
    missing = {
        html_route: api_route
        for html_route, api_route in HTML_TO_JSON.items()
        if api_route not in routes
    }
    assert not missing


def test_mapping_does_not_name_nonexistent_html_routes() -> None:
    from cert_watch.app import create_app

    routes = _routes(create_app())
    assert set(HTML_TO_JSON) <= routes


def test_every_api_endpoint_is_owned_by_the_api_package() -> None:
    from cert_watch.app import create_app

    routes = _walk(create_app().routes)
    stray = {
        route.path: route.endpoint.__module__
        for route in routes
        if getattr(route, "path", "").startswith("/api/")
        and not route.endpoint.__module__.startswith("cert_watch.routes.api.")
    }
    assert not stray
