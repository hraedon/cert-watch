<#
STYLE: Never embed single quotes inside double-quoted strings. PowerShell 5.1
reads this file via the system ANSI codepage when the UTF-8 BOM is missing
(e.g. GitHub zip download), and multi-byte UTF-8 sequences corrupt the
parser's quote-tracking state -- every subsequent ' inside "..." becomes a
fatal parse error. Use `" `"` (escaped double quotes) or restructure instead.

Also: this script must run on PowerShell 5.1 (the Windows default). Avoid
PS 7+ syntax: no ?? (null-coalescing), no ternary operator, no pipeline
chain operators (&& / ||). Use if/else and -or/-and instead.

.SYNOPSIS
    Bootstrap cert-watch on Windows for hosting behind IIS.

.DESCRIPTION
    Creates the data directory, a virtualenv, installs cert-watch into it, and
    generates persistent signing keys (so sessions survive restarts/recycles).
    It does NOT configure IIS itself -- see deploy\iis\README.md for the site,
    binding, and app-pool steps. Re-running is safe: existing secrets are kept.

    When the detected Python is user-scoped (the default with the Python Install
    Manager), the script copies it to a shared location under InstallDir so the
    IIS app pool identity can access it without depending on a user profile. See
    deploy\iis\README.md "Why a shared Python install" for the full rationale.

.PARAMETER InstallDir
    Base directory for data, venv, secrets, logs, and the shared Python install.
    Default: C:\ProgramData\cert-watch

.PARAMETER AppPool
    Optional IIS application pool name (e.g. "cert-watch"). When given, the pool
    identity ("IIS AppPool\<name>") is granted modify on the data dir, read on
    the secrets dir, and execute on the shared Python install.

.PARAMETER WithAuthExtras
    Also install the LDAP + OAuth optional dependencies.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -AppPool cert-watch -WithAuthExtras

.NOTES
    This script is not signed. If your execution policy blocks unsigned scripts,
    either bypass it per-invocation (see example above) or sign the script with
    your organisation's code-signing certificate.
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

# --- Locate a Python 3.12+ launcher ---
# The Windows 'py' launcher works interactively but can fail through
# PowerShell's & operator (Windows Store stubs, argument mangling).
# Use cmd /c for probing, then resolve the real python.exe path so all
# subsequent calls go directly to the executable.
function Invoke-PyProbe {
    param([string]$Exe, [string[]]$Arguments)
    $argStr = ($Arguments | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join ' '
    $tmp = Join-Path $env:TEMP "cw-py-probe.txt"
    & cmd /c "`"$Exe`" $argStr > `"$tmp`" 2>&1"
    $exit = $LASTEXITCODE
    $out = ""
    if (Test-Path $tmp) {
        $out = (Get-Content $tmp -Raw)
        Remove-Item $tmp -Force
    }
    @{ ExitCode = $exit; Output = if ($out) { $out.Trim() } else { "" } }
}

$launchers = @(
    @{ Exe = "py";     Args = @("-3.14") },
    @{ Exe = "py";     Args = @("-3.12") },
    @{ Exe = "py";     Args = @("-3") },
    @{ Exe = "python"; Args = @() },
    @{ Exe = "python3"; Args = @() }
)
$python = $null
foreach ($l in $launchers) {
    $label = "$($l.Exe) $($l.Args -join `" `")"
    if (-not (Get-Command $l.Exe -ErrorAction SilentlyContinue)) {
        Write-Host "  [skip] $label -- exe not found on PATH"
        continue
    }
    $probeArgs = $l.Args + @("--version")
    $r = Invoke-PyProbe -Exe $l.Exe -Arguments $probeArgs
    if ($r.ExitCode -ne 0) {
        Write-Host "  [fail] $label -- exit code $($r.ExitCode)"
        continue
    }
    $ver = ($r.Output -split "`n" | Where-Object { $_ -match "^Python\s+\d" } | Select-Object -First 1).Trim()
    if ($ver -match "Python\s+(\d+)\.(\d+)") {
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]
        if ($major -ge 3 -and $minor -ge 12) {
            # Resolve the real python.exe path so we bypass the launcher for
            # all subsequent calls (venv, pip).  Ask Python itself.
            $resolved = ""
            try {
                $selfProbe = Invoke-PyProbe -Exe $l.Exe -Arguments ($l.Args + @("-c", "import sys; print(sys.executable)"))
                if ($selfProbe.ExitCode -eq 0) {
                    $candidate = ($selfProbe.Output -split "`n" | Select-Object -First 1).Trim()
                    if ($candidate -and (Test-Path $candidate -ErrorAction SilentlyContinue)) {
                        $resolved = $candidate
                    }
                }
            } catch { }
            if ($resolved) {
                Write-Host "  [ok]   $label -- $ver (resolved: $resolved)"
                $python = @{ Exe = $resolved; Args = @() }
            } else {
                Write-Host "  [ok]   $label -- $ver (using launcher directly)"
                $python = $l
            }
            break
        }
        Write-Host "  [fail] $label -- version $major.$minor < 3.12"
    } else {
        Write-Host "  [fail] $label -- output not recognised: $ver"
    }
}
if (-not $python) {
    throw "Python 3.12+ not found. Install it (winget install Python.Python.3.14) and re-run."
}

# --- Ensure Python is in a shared (non-user-profile) location ---
# The Python Install Manager installs runtimes per-user only (under
# %LocalAppData%\Python).  The IIS app pool identity cannot access user
# profiles, so we copy the runtime to a shared directory under InstallDir.
# See deploy\iis\README.md "Why a shared Python install" for the rationale.
$sharedPyDir = Join-Path $InstallDir "python"
$sharedPyExe = Join-Path $sharedPyDir "python.exe"
$needsShared = $false
if ($python.Exe -like "*\AppData\*" -or $python.Exe -like "*\WindowsApps\*") {
    $needsShared = $true
}
if ($needsShared) {
    if (Test-Path $sharedPyExe) {
        Write-Host "Using existing shared Python at $sharedPyDir"
    } else {
        Write-Host "Python is user-scoped ($($python.Exe)); copying to shared location ..."
        Write-Host "  Installing to $sharedPyDir via py install --target ..."
        $tag = "$major.$minor"
        $r = Invoke-PyProbe -Exe "py" -Arguments @("install", "--target=$sharedPyDir", $tag)
        if ($r.ExitCode -ne 0) {
            # Fallback: manually copy the installation
            Write-Host "  py install --target failed (exit $($r.ExitCode)); copying manually ..."
            $pySrc = Split-Path $python.Exe
            # Copy the entire Python prefix (not just the exe -- we need stdlib)
            if (Test-Path $pySrc) {
                Copy-Item -Path $pySrc -Destination $sharedPyDir -Recurse -Force
            }
        }
        if (-not (Test-Path $sharedPyExe)) {
            # py install --target may extract to a subdirectory
            $nested = Get-ChildItem -Path $sharedPyDir -Filter "python.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($nested) {
                $sharedPyDir = Split-Path $nested.FullName
                $sharedPyExe = $nested.FullName
            }
        }
        if (-not (Test-Path $sharedPyExe)) {
            throw "Failed to create shared Python at $sharedPyDir. Copy $($python.Exe) manually."
        }
        # Python 3.14+ marks venvlauncher.exe as hidden/system. When we copy the
        # installation to a shared location, those attributes survive. The venv
        # module then cannot copy the launcher into the new venv, producing a
        # degraded wrapper instead of a proper launcher.
        $launcher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvlauncher.exe"
        $wlauncher = Join-Path $sharedPyDir "Lib\venv\scripts\nt\venvwlauncher.exe"
        if (Test-Path $launcher) {
            attrib -H -S $launcher 2>$null | Out-Null
        }
        if (Test-Path $wlauncher) {
            attrib -H -S $wlauncher 2>$null | Out-Null
        }
        Write-Host "  Shared Python ready at $sharedPyExe"
    }
    $python = @{ Exe = $sharedPyExe; Args = @() }
}

Write-Host "Creating directories under $InstallDir ..."
foreach ($d in @($InstallDir, $secrets, $logs)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

Write-Host "Creating virtualenv at $venv ..."
& $python.Exe @($python.Args + @("-m", "venv", $venv))
if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $venv "Scripts\python.exe"))) {
    throw "Failed to create virtualenv at $venv using $($python.Exe)."
}

$venvPy = Join-Path $venv "Scripts\python.exe"
# Verify the venv is functional (not just that the file exists). In Python 3.14
# the venvlauncher copy may silently produce a broken wrapper when the source
# launcher has hidden/system attributes.
$venvProbe = & $venvPy -c "import sys; print(sys.executable)" 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "venv created but python.exe is not functional (exit $LASTEXITCODE): $venvProbe"
}
Write-Host "  venv verified: $venvProbe"
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
    Write-Host "Granting $identity access (data: modify, secrets: read, python: read+execute) ..."
    icacls $InstallDir /grant:r "${identity}:(OI)(CI)M" | Out-Null
    icacls $secrets    /grant   "${identity}:(OI)(CI)R" | Out-Null
    # The shared Python install lives under InstallDir, which already has
    # modify access.  Explicitly set RX on the python subdir to ensure
    # execute is inherited even if the parent's modify ACE is tightened later.
    if (Test-Path $sharedPyDir) {
        icacls $sharedPyDir /grant "${identity}:(OI)(CI)RX" | Out-Null
    }
}

Write-Host ""
Write-Host "Done. cert-watch installed to $venv"
Write-Host "Data dir: $InstallDir   Secrets: $secrets"
Write-Host ""
Write-Host "Next: configure IIS -- see deploy\iis\README.md"
Write-Host "  HttpPlatformHandler: copy deploy\iis\web.config into the site path."
Write-Host "  Reverse proxy:       run as a service + deploy\iis\web.config.reverse-proxy."
Write-Host ""
Write-Host "On first run (behind IIS, TRUST_PROXY=1) cert-watch auto-provisions an"
Write-Host "admin. Get the one-time password from:"
Write-Host "  $InstallDir\initial-admin-password   (or logs\stdout*.log)"
Write-Host "For production, set AUTH_PROVIDER (LDAP/OAuth) in web.config instead."
