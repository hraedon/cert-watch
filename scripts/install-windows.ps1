<#
.SYNOPSIS
    Bootstrap cert-watch on Windows for hosting behind IIS.

.DESCRIPTION
    Creates the data directory, a virtualenv, installs cert-watch into it, and
    generates persistent signing keys (so sessions survive restarts/recycles).
    It does NOT configure IIS itself — see deploy\iis\README.md for the site,
    binding, and app-pool steps. Re-running is safe: existing secrets are kept.

.PARAMETER InstallDir
    Base directory for data, venv, secrets, and logs.
    Default: C:\ProgramData\cert-watch

.PARAMETER AppPool
    Optional IIS application pool name (e.g. "cert-watch"). When given, the pool
    identity ("IIS AppPool\<name>") is granted modify on the data dir and read
    on the secrets dir.

.PARAMETER WithAuthExtras
    Also install the LDAP + OAuth optional dependencies.

.EXAMPLE
    .\scripts\install-windows.ps1 -AppPool cert-watch -WithAuthExtras
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\cert-watch",
    [string]$AppPool,
    [switch]$WithAuthExtras
)

$ErrorActionPreference = "Stop"

# --- Must be elevated (we write under ProgramData and set ACLs) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

$repoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$venv     = Join-Path $InstallDir "venv"
$secrets  = Join-Path $InstallDir "secrets"
$logs     = Join-Path $InstallDir "logs"

# --- Locate a Python 3.12+ launcher (exe + args kept separate) ---
$launchers = @(
    @{ Exe = "py";     Args = @("-3.12") },
    @{ Exe = "py";     Args = @("-3") },
    @{ Exe = "python"; Args = @() }
)
$python = $null
foreach ($l in $launchers) {
    if (Get-Command $l.Exe -ErrorAction SilentlyContinue) { $python = $l; break }
}
if (-not $python) { throw "Python 3.12+ not found. Install it (winget install Python.Python.3.12) and re-run." }

Write-Host "Creating directories under $InstallDir ..."
foreach ($d in @($InstallDir, $secrets, $logs)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "Creating virtualenv at $venv ..."
$venvArgs = $python.Args + @("-m", "venv", $venv)
& $python.Exe @venvArgs

$venvPy = Join-Path $venv "Scripts\python.exe"
Write-Host "Installing cert-watch ..."
& $venvPy -m pip install --upgrade pip | Out-Null
$pkg = if ($WithAuthExtras) { "$repoRoot[auth-ldap,auth-oauth]" } else { $repoRoot }
& $venvPy -m pip install $pkg

# --- Generate persistent signing keys (idempotent) ---
function New-HexSecret {
    # RNGCryptoServiceProvider works on both Windows PowerShell 5.1 (.NET
    # Framework) and PowerShell 7 (.NET); RandomNumberGenerator.Fill does not.
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    try {
        $bytes = New-Object byte[] 32
        $rng.GetBytes($bytes)
        -join ($bytes | ForEach-Object { $_.ToString("x2") })
    } finally {
        $rng.Dispose()
    }
}
foreach ($name in @("auth_secret", "csrf_secret")) {
    $path = Join-Path $secrets $name
    if (Test-Path $path) {
        Write-Host "Keeping existing $name"
    } else {
        Set-Content -Path $path -Value (New-HexSecret) -NoNewline -Encoding ascii
        Write-Host "Generated $name"
    }
}

# --- Lock down the secrets directory ---
Write-Host "Securing $secrets ..."
icacls $secrets /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" | Out-Null  # Administrators, SYSTEM

if ($AppPool) {
    $identity = "IIS AppPool\$AppPool"
    Write-Host "Granting $identity access (data: modify, secrets: read) ..."
    icacls $InstallDir /grant:r "${identity}:(OI)(CI)M" | Out-Null
    icacls $secrets    /grant   "${identity}:(OI)(CI)R" | Out-Null
}

Write-Host ""
Write-Host "Done. cert-watch installed to $venv"
Write-Host "Data dir: $InstallDir   Secrets: $secrets"
Write-Host ""
Write-Host "Next: configure IIS — see deploy\iis\README.md"
Write-Host "  HttpPlatformHandler: copy deploy\iis\web.config into the site path."
Write-Host "  Reverse proxy:       run as a service + deploy\iis\web.config.reverse-proxy."
