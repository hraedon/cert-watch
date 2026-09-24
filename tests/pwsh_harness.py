# Embedded PowerShell and XML fixtures read better unwrapped.
# ruff: noqa: E501
"""Run pieces of the Windows PowerShell tooling under a real pwsh.

The installer and verifier need an elevated Windows/IIS box to run end to
end, but much of their logic (quoting, redaction, value normalisation, file
writes) is plain PowerShell. This harness parses a script with PowerShell's
own parser, loads only the named top-level functions and variable
assignments, then runs a test body and returns its JSON output. Tests using it
are skipped when pwsh is not installed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

PWSH = shutil.which("pwsh")

requires_pwsh = pytest.mark.skipif(PWSH is None, reason="pwsh is not installed")

_LOADER = r"""
param([string]$ScriptPath, [string]$Functions, [string]$Variables, [string]$BodyPath)
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ('parse errors: ' + ($errors -join '; ')) }
$fnNames = @($Functions -split ',' | Where-Object { $_ })
$varNames = @($Variables -split ',' | Where-Object { $_ })
$defs = New-Object System.Collections.ArrayList
foreach ($stmt in $ast.EndBlock.Statements) {
    if ($stmt -is [System.Management.Automation.Language.AssignmentStatementAst]) {
        $left = $stmt.Left
        if ($left -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $vn = $left.VariablePath.UserPath -replace '^script:', ''
            if ($varNames -contains $vn) { [void]$defs.Add($stmt.Extent.Text) }
        }
    }
}
$found = @{}
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    if ($fnNames -contains $f.Name -and -not $found.ContainsKey($f.Name)) {
        $found[$f.Name] = $true
        [void]$defs.Add($f.Extent.Text)
    }
}
foreach ($n in $fnNames) { if (-not $found.ContainsKey($n)) { throw ('function not found: ' + $n) } }
foreach ($d in $defs) { . ([scriptblock]::Create($d)) }
$result = . $BodyPath
$result | ConvertTo-Json -Depth 8 -Compress
"""


def run_ps(
    script: Path,
    body: str,
    *,
    functions: tuple[str, ...] = (),
    variables: tuple[str, ...] = (),
    forbid_stderr: bool = False,
) -> Any:
    """Load ``functions``/``variables`` from ``script`` then run ``body``.

    ``body`` is PowerShell whose output is converted to JSON and decoded.
    With ``forbid_stderr`` any error-stream output fails the call.
    """
    assert PWSH is not None
    with tempfile.TemporaryDirectory() as tmp:
        loader = Path(tmp) / "loader.ps1"
        loader.write_text(_LOADER, encoding="utf-8")
        body_path = Path(tmp) / "body.ps1"
        body_path.write_text(body, encoding="utf-8")
        proc = subprocess.run(
            [
                PWSH, "-NoProfile", "-NonInteractive", "-File", str(loader),
                "-ScriptPath", str(script),
                "-Functions", ",".join(functions),
                "-Variables", ",".join(variables),
                "-BodyPath", str(body_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    if proc.returncode != 0:
        raise AssertionError(f"pwsh failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}")
    if forbid_stderr and proc.stderr.strip():
        raise AssertionError(f"pwsh wrote to stderr:\n{proc.stderr}")
    out = proc.stdout.strip()
    return json.loads(out) if out else None
