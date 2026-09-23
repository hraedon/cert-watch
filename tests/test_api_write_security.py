"""Security regressions for the JSON write presentation seam (PR #90 review)."""

from __future__ import annotations

import importlib
import logging
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient


def _patch_action_services(monkeypatch: pytest.MonkeyPatch, action: str) -> None:
    api_alert_actions = importlib.import_module("cert_watch.routes.api.alert_actions")
    api_certificates = importlib.import_module("cert_watch.routes.api.certificates")
    api_hosts = importlib.import_module("cert_watch.routes.api.hosts")
    import cert_watch.routes.certificates as html_certificates
    import cert_watch.routes.dashboard as html_dashboard
    import cert_watch.routes.hosts as html_hosts
    from cert_watch.services.certificate_management import UploadResult
    from cert_watch.services.host_management import (
        HostCreateResult,
        HostImportResult,
        ScanResult,
    )

    async def create(*_args: Any, **_kwargs: Any) -> HostCreateResult:
        return HostCreateResult(("00000000-0000-4000-8000-000000000001",), 0)

    async def imported(*_args: Any, **_kwargs: Any) -> HostImportResult:
        return HostImportResult(1, ())

    async def scan_all(*_args: Any, **_kwargs: Any) -> tuple[int, int]:
        return (1, 0)

    async def scan_one(*_args: Any, **_kwargs: Any) -> ScanResult:
        return ScanResult("success")

    def settings(*_args: Any, **_kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            id="00000000-0000-4000-8000-000000000001",
            scan_interval_hours=None,
            threshold_days=None,
            renewal_status="pending",
        )

    def upload(*_args: Any, **_kwargs: Any) -> UploadResult:
        return UploadResult("00000000-0000-4000-8000-000000000001", "probe.pem")

    def mark_all(*_args: Any, **_kwargs: Any) -> int:
        return 1

    patches = {
        "add-host": ((html_hosts, "create_hosts"), (api_hosts, "create_hosts"), create),
        "import": (
            (html_hosts, "import_hosts_csv_service"),
            (api_hosts, "import_hosts_csv"),
            imported,
        ),
        "scan-all": (
            (html_hosts, "scan_all_hosts_service"),
            (api_hosts, "scan_all_hosts"),
            scan_all,
        ),
        "scan-host": (
            (html_hosts, "scan_host_now_service"),
            (api_hosts, "scan_host_now_service"),
            scan_one,
        ),
        "settings": (
            (html_hosts, "update_host_settings_service"),
            (api_hosts, "update_host_settings"),
            settings,
        ),
        "upload": (
            (html_certificates, "upload_certificate_bytes"),
            (api_certificates, "upload_certificate_bytes"),
            upload,
        ),
        "mark-all-read": (
            (html_dashboard, "mark_all_alerts_read_service"),
            (api_alert_actions, "mark_all_alerts_read"),
            mark_all,
        ),
    }
    html_patch, api_patch, replacement = patches[action]
    monkeypatch.setattr(*html_patch, replacement)
    monkeypatch.setattr(*api_patch, replacement)


@pytest.mark.parametrize(
    ("action", "limit", "html_request", "api_request"),
    [
        (
            "add-host",
            20,
            ("POST", "/hosts", {"data": {"hostname": "example.test", "port": "443"}}),
            ("POST", "/api/hosts", {"json": {"hostname": "example.test", "port": 443}}),
        ),
        (
            "import",
            5,
            ("POST", "/hosts/import", {"files": {"file": ("h.csv", b"hostname\nexample.test\n")}}),
            (
                "POST",
                "/api/hosts/import",
                {"files": {"file": ("h.csv", b"hostname\nexample.test\n")}},
            ),
        ),
        ("scan-all", 3, ("POST", "/hosts/all/scan", {}), ("POST", "/api/hosts/scan", {})),
        (
            "scan-host",
            10,
            ("POST", "/hosts/{host_id}/scan", {}),
            ("POST", "/api/hosts/{host_id}/scan", {}),
        ),
        (
            "settings",
            30,
            (
                "POST",
                "/hosts/{host_id}/settings",
                {
                    "data": {
                        "scan_interval_hours": "",
                        "threshold_days": "",
                        "renewal_status": "pending",
                    }
                },
            ),
            (
                "PATCH",
                "/api/hosts/{host_id}/settings",
                {
                    "json": {
                        "scan_interval_hours": None,
                        "threshold_days": None,
                        "renewal_status": "pending",
                    }
                },
            ),
        ),
        (
            "upload",
            10,
            ("POST", "/upload", {"files": {"file": ("probe.pem", b"probe")}}),
            (
                "POST",
                "/api/certificates/upload",
                {"files": {"file": ("probe.pem", b"probe")}},
            ),
        ),
        (
            "mark-all-read",
            10,
            ("POST", "/alerts/mark-all-read", {}),
            ("POST", "/api/alerts/mark-all-read", {}),
        ),
    ],
)
def test_html_and_json_share_each_action_rate_limit(
    action: str,
    limit: int,
    html_request: tuple[str, str, dict[str, Any]],
    api_request: tuple[str, str, dict[str, Any]],
    reload_app,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cert_watch.database import SqliteHostRepository

    _patch_action_services(monkeypatch, action)
    app = reload_app().app
    with TestClient(app) as client:
        host_id = SqliteHostRepository(tmp_path / "cert-watch.sqlite3").add(
            "rate-limit.example.test", 443
        )
        html_method, html_path, html_kwargs = html_request
        api_method, api_path, api_kwargs = api_request
        html_path = html_path.replace("{host_id}", host_id)
        api_path = api_path.replace("{host_id}", host_id)

        first = client.request(
            html_method, html_path, follow_redirects=False, **html_kwargs
        )
        assert first.status_code != 429
        for _ in range(limit - 1):
            allowed = client.request(api_method, api_path, **api_kwargs)
            assert allowed.status_code != 429
        blocked = client.request(api_method, api_path, **api_kwargs)

    assert blocked.status_code == 429


@pytest.mark.parametrize(
    "body",
    [
        {"hostname": "example.test", "port": 443.5},
        {"hostname": "example.test", "port": True},
        {"hostname": "example.test", "tags": ["A"]},
        {"hostname": "example.test", "notes": 7},
        {"hostname": "example.test", "starttls_mode": 5},
        {"hostname": "example.test", "threshold_days": 2**70},
        {"hostname": "example.test", "scan_interval_hours": 1.5},
    ],
)
def test_api_create_host_rejects_type_confusion_without_calling_service(
    body: dict[str, Any], reload_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    api_hosts = importlib.import_module("cert_watch.routes.api.hosts")

    async def must_not_run(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("invalid JSON reached the host service")

    monkeypatch.setattr(api_hosts, "create_hosts", must_not_run)
    with TestClient(reload_app().app, raise_server_exceptions=False) as client:
        response = client.post("/api/hosts", json=body)
    assert response.status_code in {400, 422}
    assert "AssertionError" not in response.text
    assert "TypeError" not in response.text


@pytest.mark.parametrize(
    "body",
    [
        {"scan_interval_hours": 1.5, "threshold_days": None, "renewal_status": "pending"},
        {"scan_interval_hours": None, "threshold_days": True, "renewal_status": "pending"},
        {"scan_interval_hours": None, "threshold_days": None, "renewal_status": ["pending"]},
        {"scan_interval_hours": "1", "threshold_days": None, "renewal_status": "pending"},
        {"scan_interval_hours": None, "threshold_days": 2**70, "renewal_status": "pending"},
    ],
)
def test_api_host_settings_rejects_type_confusion_without_calling_service(
    body: dict[str, Any], reload_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    api_hosts = importlib.import_module("cert_watch.routes.api.hosts")

    def must_not_run(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("invalid JSON reached the settings service")

    monkeypatch.setattr(api_hosts, "update_host_settings", must_not_run)
    with TestClient(reload_app().app, raise_server_exceptions=False) as client:
        response = client.patch(
            "/api/hosts/00000000-0000-4000-8000-000000000001/settings", json=body
        )
    assert response.status_code in {400, 422}
    assert "AssertionError" not in response.text
    assert "TypeError" not in response.text


def test_invalid_api_add_host_consumes_action_budget(
    reload_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    api_hosts = importlib.import_module("cert_watch.routes.api.hosts")
    from cert_watch.services.host_management import HostCreateResult

    async def created(*_args: Any, **_kwargs: Any) -> HostCreateResult:
        return HostCreateResult(("00000000-0000-4000-8000-000000000001",), 0)

    monkeypatch.setattr(api_hosts, "create_hosts", created)
    with TestClient(reload_app().app) as client:
        for _ in range(20):
            invalid = client.post("/api/hosts", json={"hostname": "example.test", "port": True})
            assert invalid.status_code in {400, 422}
        blocked = client.post(
            "/api/hosts", json={"hostname": "example.test", "port": True}
        )
        valid_after_flood = client.post(
            "/api/hosts", json={"hostname": "example.test", "port": 443}
        )
    assert blocked.status_code == 429
    assert valid_after_flood.status_code == 429


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [("/upload", 303), ("/api/certificates/upload", 400)],
)
def test_upload_parse_details_are_logged_but_not_returned(
    path: str,
    expected_status: int,
    reload_app,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="cert_watch.services.certificate_management")
    with TestClient(reload_app().app) as client:
        response = client.post(
            path,
            files={"file": ("bad.der", b"not a certificate", "application/pkix-cert")},
            follow_redirects=False,
        )

    assert response.status_code == expected_status
    if path == "/upload":
        assert response.headers["location"] == "/?error=could%20not%20parse%20certificate%20file"
    else:
        assert response.json() == {"error": "could not parse certificate file"}
    assert "ParseError" not in response.text
    assert "ShortData" not in response.text
    assert "failed to parse DER:" in caplog.text


@pytest.mark.parametrize(
    ("path", "expected_status"),
    [("/upload", 303), ("/api/certificates/upload", 422)],
)
def test_non_file_upload_details_are_logged_but_not_returned(
    path: str,
    expected_status: int,
    reload_app,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="cert_watch.routes.upload_validation")
    with TestClient(reload_app().app) as client:
        response = client.post(path, data={"file": "not-a-file"}, follow_redirects=False)

    assert response.status_code == expected_status
    if path == "/upload":
        assert response.headers["location"] == (
            "/?error=upload%20must%20include%20a%20certificate%20file"
        )
    else:
        assert response.json() == {"error": "upload must include a certificate file"}
    assert "UploadFile" not in response.text
    assert "<class 'str'>" not in response.text
    assert "Expected UploadFile" in caplog.text
    assert "not-a-file" not in caplog.text


@pytest.mark.anyio
async def test_scan_all_with_no_hosts_does_not_create_audit_noise(tmp_path) -> None:
    from cert_watch.audit import list_audit
    from cert_watch.auth.rbac import AuthContext
    from cert_watch.config import Settings
    from cert_watch.database import init_schema
    from cert_watch.services.host_management import scan_all_hosts

    db = tmp_path / "cert-watch.sqlite3"
    init_schema(db)
    result = await scan_all_hosts(
        db,
        Settings(db_path=db, data_dir=tmp_path),
        auth=AuthContext.system(),
        actor="scheduler",
        source_ip=None,
    )
    assert result == (0, 0)
    assert list_audit(db) == []
