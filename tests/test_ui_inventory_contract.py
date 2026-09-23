"""UI-INVENTORY's service ownership table is executable."""

from __future__ import annotations

import inspect
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests._route_inventory import mutating_routes

INVENTORY = Path(__file__).parents[1] / "UI-INVENTORY.md"
ROW = re.compile(
    r"^\| (?P<concept>[^|]+) \| `(?P<html>[^`]+)` \| `(?P<api>[^`]+)` "
    r"\| `(?P<service>[^`]+)` \|$"
)


def _contracts() -> list[dict[str, str]]:
    return [
        match.groupdict()
        for line in INVENTORY.read_text().splitlines()
        if (match := ROW.match(line))
    ]


def _route_map(app: Any) -> dict[str, Any]:
    return {f"{method} {path}": route.endpoint for method, path, route in mutating_routes(app)}


def _service_calls(endpoint: Any) -> set[str]:
    """Resolve service callables referenced by an adapter's globals.

    This follows the actual monkeypatch seam: route modules bind service
    callables (occasionally under an ``*_service`` alias), so replacing that
    global is exactly how the behavioral tests prove both adapters cross it.
    """
    source = inspect.getsource(endpoint)
    calls: set[str] = set()
    for name, value in endpoint.__globals__.items():
        if not inspect.isfunction(value) or f"{name}(" not in source:
            continue
        module = getattr(value, "__module__", "")
        function_name = getattr(value, "__name__", name)
        if module.startswith("cert_watch.services.") and not function_name.startswith("resolve_"):
            calls.add(f"{module.rsplit('.', 1)[-1]}.{function_name}")
    return calls


def test_inventory_write_contracts_each_have_one_shared_service() -> None:
    from cert_watch.app import create_app

    contracts = _contracts()
    assert len(contracts) >= 17, "inventory parser must see the complete executable table"
    routes = _route_map(create_app())
    failures: list[str] = []
    for contract in contracts:
        html = routes.get(contract["html"])
        api = routes.get(contract["api"])
        if html is None or api is None:
            failures.append(f"{contract['concept']}: missing adapter")
            continue
        expected = {contract["service"]}
        html_calls = _service_calls(html)
        api_calls = _service_calls(api)
        if html_calls != expected or api_calls != expected:
            failures.append(
                f"{contract['concept']}: HTML={sorted(html_calls)}, API={sorted(api_calls)}, "
                f"expected={sorted(expected)}"
            )
    assert not failures, "\n".join(failures)


def _result(service: str, resource_id: str) -> Any:
    if service.endswith(("update_certificate_tags", "update_host_tags")):
        from cert_watch.services.resource_metadata import TagUpdateResult

        return TagUpdateResult(resource_id, "ops", ("ops",), ("ops",))
    if service.endswith("update_host_notes"):
        return "notes"
    if service.endswith("update_host_ownership"):
        from cert_watch.services.host_ownership import HostOwnership

        return HostOwnership(resource_id, "owner", "", "", "pending", "", "", "")
    if service.endswith("create_hosts"):
        from cert_watch.services.host_management import HostCreateResult

        return HostCreateResult((resource_id,), 1)
    if service.endswith("import_hosts_csv"):
        from cert_watch.services.host_management import HostImportResult

        return HostImportResult(1, ())
    if service.endswith("scan_all_hosts"):
        return (1, 0)
    if service.endswith("update_host_settings"):
        return SimpleNamespace(
            id=resource_id,
            scan_interval_hours=None,
            threshold_days=None,
            renewal_status="pending",
        )
    if service.endswith("update_expected_issuers"):
        return ("Example CA",)
    if service.endswith("scan_host_now"):
        from cert_watch.services.host_management import ScanResult

        return ScanResult("success")
    if service.endswith(("upload_certificate_bytes", "add_trust_anchor")):
        from cert_watch.services.certificate_management import UploadResult

        return UploadResult(resource_id, "probe.pem")
    if service.startswith("alert_groups."):
        return SimpleNamespace(
            id=resource_id,
            name="ops",
            recipients=["ops@example.com"],
            match_tags=["ops"],
            webhook_url="",
            created_at=datetime.now(UTC),
            threshold_days=None,
            digest_cadence_days=7,
        )
    if service.endswith("mark_all_alerts_read"):
        return 2
    return True


def _request_pair(concept: str) -> tuple[dict[str, Any], dict[str, Any]]:
    form: dict[str, Any] = {"data": {}}
    api: dict[str, Any] = {"json": {}}
    if concept.endswith("tags"):
        form["data"] = {"tags": "ops"}
        api["json"] = {"tags": ["ops"]}
    elif concept in {"certificate upload", "trust anchor add"}:
        form = {"files": {"file": ("probe.pem", b"probe")}}
        api = dict(form)
    elif concept == "host ownership":
        form["data"] = {"owner_name": "owner"}
        api["json"] = {"owner_name": "owner"}
    elif concept == "host notes":
        form["data"] = {"notes": "notes"}
        api["json"] = {"notes": "notes"}
    elif concept == "host create":
        form["data"] = {"hostname": "example.test", "port": "443"}
        api["json"] = {"hostname": "example.test", "port": 443}
    elif concept == "host import":
        upload = {"file": ("hosts.csv", b"hostname,port\nexample.test,443\n")}
        form = {"files": upload}
        api = {"files": upload}
    elif concept == "host settings":
        form["data"] = {
            "scan_interval_hours": "",
            "threshold_days": "",
            "renewal_status": "pending",
        }
        api["json"] = {
            "scan_interval_hours": None,
            "threshold_days": None,
            "renewal_status": "pending",
        }
    elif concept == "expected issuers":
        form["data"] = {"expected_issuers": "Example CA"}
        api["json"] = {"issuers": ["Example CA"]}
    elif concept.startswith("alert group"):
        form["data"] = {
            "name": "ops",
            "recipients": "ops@example.com",
            "match_tags": "ops",
            "digest_cadence_days": "7",
        }
        api["json"] = {
            "name": "ops",
            "recipients": ["ops@example.com"],
            "match_tags": ["ops"],
            "digest_cadence_days": 7,
        }
    return form, api


@pytest.mark.parametrize("contract", _contracts(), ids=lambda row: row["concept"])
def test_both_adapters_reach_the_inventory_service(
    contract: dict[str, str], reload_app, monkeypatch, tmp_path
) -> None:
    """Behavioral call-graph proof: both adapters hit the monkeypatched owner."""
    from cert_watch.app import create_app
    from cert_watch.database import SqliteHostRepository

    probe_routes = _route_map(create_app())
    endpoints = (probe_routes[contract["html"]], probe_routes[contract["api"]])
    calls: list[str] = []
    target_id = "00000000-0000-4000-8000-000000000001"
    result = _result(contract["service"], target_id)

    async def async_marker(*args, **kwargs):
        calls.append("service")
        return result

    def sync_marker(*args, **kwargs):
        calls.append("service")
        return result

    for endpoint in endpoints:
        for name, value in list(endpoint.__globals__.items()):
            module = getattr(value, "__module__", "")
            symbol = f"{module.rsplit('.', 1)[-1]}.{getattr(value, '__name__', name)}"
            if symbol == contract["service"]:
                marker = async_marker if inspect.iscoroutinefunction(value) else sync_marker
                monkeypatch.setitem(endpoint.__globals__, name, marker)

    with TestClient(reload_app().app) as client:
        host_id = SqliteHostRepository(tmp_path / "cert-watch.sqlite3").add(
            "contract.example.test", 443
        )
        substitutions = {
            "cert_id": host_id,
            "host_id": host_id,
            "anchor_id": target_id,
            "group_id": target_id,
        }

        def concrete(spec: str) -> tuple[str, str]:
            method, path = spec.split(" ", 1)
            for key, value in substitutions.items():
                path = path.replace("{" + key + "}", value)
            return method, path

        form, api = _request_pair(contract["concept"])
        html_method, html_path = concrete(contract["html"])
        api_method, api_path = concrete(contract["api"])
        html_response = client.request(html_method, html_path, follow_redirects=False, **form)
        api_response = client.request(api_method, api_path, follow_redirects=False, **api)

    assert html_response.status_code < 500
    assert api_response.status_code < 500
    assert calls == ["service", "service"]
