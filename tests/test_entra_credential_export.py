"""Exercise the shipped PowerShell exporter with an entirely synthetic Graph SDK."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "export-entra-credentials.ps1"
PWSH = shutil.which("pwsh")
TENANT = "00000000-0000-4000-8000-000000000001"
APP = "00000000-0000-4000-8000-000000000002"
KEY = "00000000-0000-4000-8000-000000000003"
SENTINEL = "synthetic-sensitive-value-never-export"

LAUNCHER = r"""
param([string]$ScriptPath, [string]$OutputPath, [string]$FixturePath, [string]$Mode)
$global:Fixture = Get-Content -LiteralPath $FixturePath -Raw | ConvertFrom-Json
$global:Mode = $Mode
function Get-MgContext {
    [CmdletBinding()]
    param()
    if ($global:Mode -eq 'disconnected') { return $null }
    [pscustomobject]@{ TenantId = $global:Fixture.tenant }
}
function Get-MgApplication {
    [CmdletBinding()]
    param([switch]$All, [string[]]$Property)
    if (-not $All -or ($Property -join ',') -ne 'appId,displayName,passwordCredentials') {
        throw 'SDK request did not explicitly select metadata with all-page enumeration'
    }
    foreach ($app in $global:Fixture.applications) { $app }
    if ($global:Mode -eq 'page-failure') { throw 'synthetic-sensitive-value-never-export' }
}
& $ScriptPath -OutputPath $OutputPath
exit $LASTEXITCODE
"""


def _application(*, expiry: str | None = "2027-03-01T02:00:00+02:00") -> dict[str, Any]:
    return {
        "appId": APP,
        "displayName": "Synthetic app",
        "unknown": SENTINEL,
        "passwordCredentials": [{
            "keyId": KEY,
            "displayName": "Scheduled integration",
            "endDateTime": expiry,
            "secretText": SENTINEL,
            "hint": SENTINEL,
            "customKeyIdentifier": SENTINEL,
        }],
    }


def _run(
    tmp_path: Path, applications: list[dict[str, Any]], *, mode: str = "ok"
) -> tuple[subprocess.CompletedProcess[str], Path]:
    assert PWSH is not None
    fixture = tmp_path / "fixture.json"
    fixture.write_text(
        json.dumps({"tenant": TENANT, "applications": applications}), encoding="utf-8"
    )
    launcher = tmp_path / "launcher.ps1"
    launcher.write_text(LAUNCHER, encoding="ascii")
    output = tmp_path / "metadata.json"
    environment = os.environ.copy()
    environment["NO_COLOR"] = "1"
    process = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(launcher),
         "-ScriptPath", str(SCRIPT), "-OutputPath", str(output),
         "-FixturePath", str(fixture), "-Mode", mode],
        capture_output=True, text=True, timeout=30, check=False, env=environment,
    )
    return process, output


def test_exporter_is_ascii() -> None:
    SCRIPT.read_bytes().decode("ascii")


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
def test_export_projects_only_api_metadata_and_normalizes_utc(tmp_path: Path) -> None:
    process, path = _run(tmp_path, [_application()])
    assert process.returncode == 0, process.stderr
    assert json.loads(path.read_text(encoding="utf-8-sig")) == [{
        "application_name": "Synthetic app", "application_id": APP,
        "credential_id": KEY, "credential_name": "Scheduled integration",
        "tenant_id": TENANT, "expires_at": "2027-03-01T00:00:00Z", "owner_email": "",
    }]
    assert SENTINEL not in path.read_text() + process.stdout + process.stderr
    assert "\"exported_credentials\": 1" in process.stdout
    assert not list(tmp_path.glob(".cert-watch-entra-*.tmp"))


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
@pytest.mark.parametrize(
    "applications", [[], [{"appId": APP, "displayName": "Empty", "passwordCredentials": []}]]
)
def test_empty_exports_are_json_arrays(tmp_path: Path, applications: list[dict[str, Any]]) -> None:
    process, path = _run(tmp_path, applications)
    assert process.returncode == 0, process.stderr
    assert json.loads(path.read_text(encoding="utf-8-sig")) == []


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
@pytest.mark.parametrize("expiry", [None, "", "not-a-date", "2027-03-01T00:00:00"])
def test_missing_invalid_or_ambiguous_expiry_is_counted_and_skipped(
    tmp_path: Path, expiry: str | None
) -> None:
    process, path = _run(tmp_path, [_application(expiry=expiry)])
    assert process.returncode == 0, process.stderr
    assert json.loads(path.read_text(encoding="utf-8-sig")) == []
    assert '"skipped_credentials": 1' in process.stdout
    assert "WARNING:" in process.stdout
    assert SENTINEL not in process.stdout + process.stderr + path.read_text()


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
@pytest.mark.parametrize("mode", ["page-failure", "disconnected"])
def test_failed_enumeration_preserves_existing_export_and_redacts_sdk_error(
    tmp_path: Path, mode: str
) -> None:
    path = tmp_path / "metadata.json"
    path.write_bytes(b"previous complete export")
    process, _ = _run(tmp_path, [_application()], mode=mode)
    assert process.returncode == 1
    assert path.read_bytes() == b"previous complete export"
    assert SENTINEL not in process.stdout + process.stderr
    assert not list(tmp_path.glob(".cert-watch-entra-*.tmp"))


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
def test_success_atomically_replaces_existing_export(tmp_path: Path) -> None:
    (tmp_path / "metadata.json").write_bytes(b"previous complete export")
    process, path = _run(tmp_path, [_application()])
    assert process.returncode == 0, process.stderr
    assert len(json.loads(path.read_text(encoding="utf-8-sig"))) == 1


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
def test_failed_file_publication_cleans_temporary_file(tmp_path: Path) -> None:
    directory = tmp_path / "metadata.json"
    directory.mkdir()
    (directory / "keep.txt").write_text("keep", encoding="utf-8")
    process, _ = _run(tmp_path, [_application()])
    assert process.returncode == 1
    assert (directory / "keep.txt").read_text() == "keep"
    assert not list(tmp_path.glob(".cert-watch-entra-*.tmp"))


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
def test_empty_optional_names_use_safe_defaults(tmp_path: Path) -> None:
    application = _application()
    application["displayName"] = None
    application["passwordCredentials"][0]["displayName"] = None
    process, path = _run(tmp_path, [application])
    assert process.returncode == 0, process.stderr
    record = json.loads(path.read_text(encoding="utf-8-sig"))[0]
    assert record["application_name"] == APP
    assert record["credential_name"] == ""


@pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")
@pytest.mark.parametrize(
    "field,value", [("appId", ""), ("displayName", "x" * 257), ("displayName", "bad\nname")]
)
def test_unusable_application_metadata_is_counted_without_echoing_values(
    tmp_path: Path, field: str, value: str
) -> None:
    application = _application()
    application[field] = value
    process, path = _run(tmp_path, [application])
    assert process.returncode == 0, process.stderr
    assert json.loads(path.read_text(encoding="utf-8-sig")) == []
    assert '"skipped_credentials": 1' in process.stdout
