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
    When -ConfigureIIS is passed, the script also creates/updates the IIS site,
    app pool, web.config, and TLS binding. Re-running is safe: existing secrets
    are kept and IIS steps are idempotent.

    When the detected Python is user-scoped (the default with the Python Install
    Manager), the script copies it to a shared location under InstallDir so the
    IIS app pool identity can access it without depending on a user profile. See
    deploy\iis\README.md "Why a shared Python install" for the full rationale.

.PARAMETER InstallDir
    Base directory for data, venv, secrets, logs, and the shared Python install.
    Default: C:\ProgramData\cert-watch

.PARAMETER AppPool
    IIS application pool name. Default: cert-watch
    The pool identity ("IIS AppPool\<name>") is granted modify on the data dir,
    read on the secrets dir, and execute on the shared Python install.

.PARAMETER ConfigureIIS
    When passed, the script creates/updates the IIS site, app pool, web.config,
    and TLS binding. Omit to skip IIS setup.

.PARAMETER SitePath
    Physical path for the IIS site (where web.config lives).
    Default: C:\inetpub\cert-watch

.PARAMETER HostName
    Hostname for the HTTPS binding. Default: empty (any hostname).

.PARAMETER TlsCertThumbprint
    Thumbprint of the TLS certificate to bind to the HTTPS endpoint.
    When omitted, the binding is created without a certificate (a warning is
    written).

.PARAMETER WithAuthExtras
    Also install the LDAP + OAuth optional dependencies.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -WithAuthExtras

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -TlsCertThumbprint "ABCDEF123456..."

.NOTES
    This script is not signed. If your execution policy blocks unsigned scripts,
    either bypass it per-invocation (see example above) or sign the script with
    your organisation's code-signing certificate.
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\cert-watch",
    [string]$AppPool = "cert-watch",
    [switch]$ConfigureIIS,
    [string]$SitePath = "C:\inetpub\cert-watch",
    [string]$HostName = "",
    [string]$TlsCertThumbprint = "",
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

# Candidate interpreters, in priority order. Fully-qualified python.exe paths
# come first because they work in non-interactive sessions (SSH / scheduled
# task / service); the bare `py` / `python` / `python3` PATH launchers come
# last and are skipped below when they resolve to a Windows Store
# execution-alias stub under WindowsApps — those 0-byte reparse points fail
# with "cannot be accessed by the system" outside an interactive logon, which
# is exactly what broke a remote (SSH) re-install (WI-050).
$launchers = @()
# 1. The shared interpreter a prior install copied under InstallDir. Present on
#    every re-install/upgrade and guaranteed outside a user profile/WindowsApps.
$sharedCandidate = Join-Path $InstallDir "python\python.exe"
if (Test-Path $sharedCandidate) { $launchers += @{ Exe = $sharedCandidate; Args = @() } }
# 2. Python Install Manager per-user runtimes (full prefixes, real exes — not
#    the Store aliases). Prefer the runtime dir over the bin\ shims so the
#    "ensure shared" copy below has a complete prefix to copy.
$imRoot = Join-Path $env:LOCALAPPDATA "Python"
foreach ($pc in (Get-ChildItem $imRoot -Filter "pythoncore-*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
    $p = Join-Path $pc.FullName "python.exe"
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
# 3. Per-machine Python installs.
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $base) { continue }
    foreach ($d in (Get-ChildItem $base -Filter "Python3*" -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending)) {
        $p = Join-Path $d.FullName "python.exe"
        if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
    }
}
# 4. Install Manager bin shims, then the bare PATH launchers, as a last resort.
foreach ($n in @("python3.exe", "python.exe")) {
    $p = Join-Path (Join-Path $imRoot "bin") $n
    if (Test-Path $p) { $launchers += @{ Exe = $p; Args = @() } }
}
$launchers += @(
    @{ Exe = "py";      Args = @("-3.14") },
    @{ Exe = "py";      Args = @("-3.12") },
    @{ Exe = "py";      Args = @("-3") },
    @{ Exe = "python";  Args = @() },
    @{ Exe = "python3"; Args = @() }
)
$python = $null
foreach ($l in $launchers) {
    $label = "$($l.Exe) $($l.Args -join `" `")"
    $cmd = Get-Command $l.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "  [skip] $label -- exe not found on PATH"
        continue
    }
    # Skip Windows Store execution-alias stubs (WI-050): they resolve on PATH
    # but cannot be executed in a non-interactive session.
    if ($cmd.Source -and $cmd.Source -match "\\WindowsApps\\") {
        Write-Host "  [skip] $label -- Windows Store alias ($($cmd.Source)), unusable non-interactively"
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

# Stop the IIS app pool (if it exists) BEFORE touching the venv so the running
# worker releases the files it holds (venv\Scripts\python.exe and loaded
# .pyd/.exe). On a re-install over a live site, leaving it running locks these
# files and both venv creation and pip install fail. appcmd is always present
# with IIS, so this avoids a hard dependency on the WebAdministration module.
$appcmdExe = "$env:windir\system32\inetsrv\appcmd.exe"
if (Test-Path $appcmdExe) {
    $poolExists = & $appcmdExe list apppool "$AppPool" 2>$null
    if ($poolExists) {
        Write-Host "Stopping app pool `"$AppPool`" to release files before install ..."
        & $appcmdExe stop apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 3
    }
}

# Clear hidden/system attributes on the chosen interpreter's venv launchers
# before creating the venv. Python 3.14 marks venvlauncher.exe hidden+system;
# venv creation then fails with "Unable to copy ... venvlauncher.exe". The
# fresh-copy path above clears these, but when we reuse an existing shared
# Python (the common re-install case) the attributes survive, so clear them
# here unconditionally against whichever interpreter we resolved (WI-050).
$pyPrefix = Split-Path $python.Exe
foreach ($vl in @("Lib\venv\scripts\nt\venvlauncher.exe", "Lib\venv\scripts\nt\venvwlauncher.exe")) {
    $vlPath = Join-Path $pyPrefix $vl
    if (Test-Path $vlPath) { attrib -H -S $vlPath 2>$null | Out-Null }
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

$identity = "IIS AppPool\$AppPool"

function Test-AccountResolves {
    param([string]$Account)
    try {
        $null = (New-Object System.Security.Principal.NTAccount($Account)).Translate(
            [System.Security.Principal.SecurityIdentifier])
        return $true
    } catch {
        return $false
    }
}

function Grant-AppPoolAcls {
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

# App-pool virtual accounts ("IIS AppPool\<name>") only exist once the pool
# does. Grant now if the pool is already there (upgrade-in-place); otherwise
# -ConfigureIIS grants right after creating the pool. A plain venv install
# (CI smoke, dev box) skips the grant — icacls would fail with "No mapping
# between account names and security IDs" and poison the script's exit code.
if (Test-AccountResolves $identity) {
    Grant-AppPoolAcls
} elseif (-not $ConfigureIIS) {
    Write-Host "App pool `"$AppPool`" does not exist; skipping ACL grant (re-run with -ConfigureIIS for IIS hosting)."
}

$script:iisActuallyConfigured = $false

# --- IIS configuration ---
if ($ConfigureIIS) {
    Write-Host ""
    Write-Host "Configuring IIS ..."

    # Check prerequisites
    if (-not (Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)) {
        Write-Host "  [skip] WebAdministration module not available; skipping IIS config."
        Write-Host "  See deploy\iis\README.md for manual IIS setup."
    } else {
        Import-Module WebAdministration

        # 1. Create site directory and web.config
        if (-not (Test-Path $SitePath)) {
            Write-Host "  Creating site directory $SitePath ..."
            New-Item -ItemType Directory -Force -Path $SitePath | Out-Null
        } else {
            Write-Host "  Site directory exists: $SitePath"
        }

        $webConfigSrc = Join-Path $repoRoot "deploy\iis\web.config"
        $webConfigDst = Join-Path $SitePath "web.config"
        # Do NOT clobber an existing web.config. It holds operator-set
        # environmentVariables (AUTH_PROVIDER, LDAP_*, CERT_WATCH_BASE_URL,
        # secret-file paths) that the template does not. Overwriting it on a
        # re-install silently breaks auth (the app still serves /login, so the
        # breakage is invisible until someone tries to log in). Only lay the
        # template down on a fresh install; to reset, delete it and re-run.
        if (Test-Path $webConfigDst) {
            Write-Host "  Keeping existing web.config (preserving operator settings)."
            Write-Host "    To reset it to the template, delete `"$webConfigDst`" and re-run."
        } else {
            Write-Host "  Installing web.config from template ..."
            Copy-Item $webConfigSrc $webConfigDst -Force

            # Update paths in web.config to reflect InstallDir
            $defaultDir = "C:\ProgramData\cert-watch"
            $wcContent = Get-Content $webConfigDst -Raw
            if ($InstallDir -ne $defaultDir) {
                $wcContent = $wcContent.Replace($defaultDir, $InstallDir)
            }
            # Validate the result is well-formed XML before writing
            try {
                $null = [xml]$wcContent
            } catch {
                throw "web.config rewrite produced invalid XML"
            }
            # Write without BOM (Set-Content -Encoding UTF8 emits BOM on PS 5.1)
            [System.IO.File]::WriteAllText($webConfigDst, $wcContent, (New-Object System.Text.UTF8Encoding $false))
            Write-Host "    Wrote template web.config (paths -> $InstallDir)."
            Write-Host "    Edit it to set AUTH_PROVIDER / LDAP_* / secret paths before first login."
        }

        # 2. Unlock handlers section
        Write-Host "  Unlocking system.webServer/handlers ..."
        & "$env:windir\system32\inetsrv\appcmd.exe" unlock config -section:system.webServer/handlers
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to unlock system.webServer/handlers. Run manually: appcmd unlock config -section:system.webServer/handlers"
        }

        # 3. Create app pool
        $poolPath = "IIS:\AppPools\$AppPool"
        $existingPool = Get-Item $poolPath -ErrorAction SilentlyContinue
        if (-not $existingPool) {
            Write-Host "  Creating app pool `"$AppPool`" ..."
            New-Item $poolPath | Out-Null
        } else {
            Write-Host "  App pool `"$AppPool`" already exists."
        }
        Set-ItemProperty $poolPath -Name managedRuntimeVersion -Value ""
        Set-ItemProperty $poolPath -Name startMode -Value "AlwaysRunning"
        Set-ItemProperty $poolPath -Name processModel.idleTimeout -Value "00:00:00"
        Set-ItemProperty $poolPath -Name recycling.periodicRestart.time -Value "00:00:00"
        Write-Host "    App pool configured (No Managed Code, AlwaysRunning, no idle timeout, no periodic restart)."

        # The pool (and its virtual account) now exists — apply the data/
        # secrets/python ACLs that were skipped earlier if it was missing.
        Grant-AppPoolAcls

        # 4. Create IIS site
        $siteName = "cert-watch"
        $sitePathIIS = "IIS:\Sites\$siteName"
        $existingSite = Get-Item $sitePathIIS -ErrorAction SilentlyContinue
        if (-not $existingSite) {
            Write-Host "  Creating IIS site `"$siteName`" ..."
            $bindingInfo = "*:443:$HostName"
            New-Item $sitePathIIS -bindings @{protocol="https"; bindingInformation=$bindingInfo} -physicalPath $SitePath | Out-Null
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
        } else {
            Write-Host "  IIS site `"$siteName`" already exists."
            # Ensure pool and path are up to date
            Set-ItemProperty $sitePathIIS -Name applicationPool -Value $AppPool
            Set-ItemProperty $sitePathIIS -Name physicalPath -Value $SitePath
        }

        # 5. TLS cert binding (idempotent: delete stale bindings, add, verify)
        if ($TlsCertThumbprint) {
            Write-Host "  Binding TLS certificate $TlsCertThumbprint ..."
            $bindPort = "443"
            $appId = "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
            $ipport = "0.0.0.0:$bindPort"
            # Bind the cert to the catch-all ipport. The IIS site binding keeps
            # its host header but stays non-SNI (sslFlags=0), so http.sys serves
            # this cert for the port. We deliberately avoid the SNI hostnameport
            # form: it requires sslFlags=1 on the binding and otherwise fails the
            # netsh add with error 87, deleting the working binding and leaving
            # HTTPS dead (WI-047). cert-watch is the only 443 site on its host,
            # so a catch-all cert is correct. certstorename=MY is explicit
            # (another common error-87 trigger when omitted).
            & netsh http delete sslcert ipport="$ipport" 2>$null | Out-Null
            if ($HostName) {
                & netsh http delete sslcert hostnameport="$HostName`:$bindPort" 2>$null | Out-Null
            }
            $addOut = & netsh http add sslcert ipport="$ipport" certhash="$TlsCertThumbprint" appid="$appId" certstorename=MY 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host ($addOut | Out-String)
                throw "Failed to bind TLS certificate (netsh exit $LASTEXITCODE). HTTPS will not work. Verify the thumbprint exists in LocalMachine\My and has a private key."
            }
            # Verify the binding actually landed (-match is case-insensitive).
            $show = & netsh http show sslcert ipport="$ipport" 2>&1 | Out-String
            if ($show -notmatch [regex]::Escape($TlsCertThumbprint)) {
                throw "TLS certificate binding verification failed for $ipport (cert hash not present after add)."
            }
            Write-Host "    TLS certificate bound to $ipport (store: MY)."
        } else {
            Write-Host "  [warn] No -TlsCertThumbprint provided. HTTPS binding exists but no certificate is assigned."
            Write-Host ('         Assign a certificate via IIS Manager or re-run with -TlsCertThumbprint ' + '.')
        }

        # 6. Grant app pool identity read access to site path
        Write-Host "  Granting $identity read access to $SitePath ..."
        icacls $SitePath /grant "${identity}:(OI)(CI)R" | Out-Null

        # 7. Start the app pool so the freshly installed code is the live code.
        # (It was stopped before pip install on a re-install; a fresh pool may
        # also be stopped depending on IIS state.) Verify it reaches Started so
        # a silent 503 does not slip through.
        Write-Host "  Starting app pool `"$AppPool`" ..."
        & $appcmdExe start apppool /apppool.name:"$AppPool" 2>$null | Out-Null
        Start-Sleep -Seconds 2
        $poolState = (& $appcmdExe list apppool "$AppPool" /text:state) 2>$null
        Write-Host "    App pool state: $poolState"
        if ("$poolState" -ne "Started") {
            Write-Host "    [warn] App pool `"$AppPool`" is not Started; the site will return HTTP 503 until it starts."
        }

        $script:iisActuallyConfigured = $true
    }
}

Write-Host ""
Write-Host "Done. cert-watch installed to $venv"
Write-Host "Data dir: $InstallDir   Secrets: $secrets"
if ($script:iisActuallyConfigured) {
    Write-Host "IIS site: $SitePath   App pool: $AppPool"
    if ($HostName) {
        Write-Host "Browse: https://$HostName/"
    } else {
        Write-Host "Browse: https://<hostname>/"
    }
}
Write-Host ""
Write-Host "On first run (behind IIS, TRUST_PROXY=1) cert-watch auto-provisions an"
Write-Host "admin. Get the one-time password from:"
Write-Host "  $InstallDir\initial-admin-password   (or logs\stdout*.log)"
Write-Host "For production, set AUTH_PROVIDER (LDAP/OAuth) in web.config instead."
