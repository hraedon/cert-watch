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
    Remove a cert-watch Windows/IIS deployment created by install-windows.ps1.

.DESCRIPTION
    Stops and removes the cert-watch IIS site, app pool, and the TLS cert
    binding this deployment owns. Re-running is safe: missing resources are
    skipped, never errored.

    Port-443 sharing is respected. The script inspects the cert-watch site's
    own HTTPS binding to decide which netsh SSL binding it owns:
      - catch-all install (binding *:443: with no hostname, sslFlags=0)
        -> removes ipport=0.0.0.0:443
      - SNI install (binding *:443:<host>, sslFlags=1)
        -> removes hostnameport=<host>:443 ONLY, and leaves the catch-all
           alone (it may belong to a sibling tool such as gpo-lens).
    Use -HostName to target an SNI binding explicitly when the site is already
    gone. The cert-watch installer creates no firewall rule, so none is removed.

    Data is preserved by default. Pass -RemoveData to also delete the data
    directory -- this is destructive: it removes the signing keys (invalidating
    every active session) and the cert-history database.

.PARAMETER InstallDir
    Data directory used by the deployment (data, venv, secrets, logs, shared
    Python). Default: C:\ProgramData\cert-watch

.PARAMETER AppPool
    IIS application pool name. Default: cert-watch

.PARAMETER SiteName
    IIS site name. Default: cert-watch

.PARAMETER SitePath
    Physical path of the IIS site (where web.config lives).
    Default: C:\inetpub\cert-watch

.PARAMETER Port
    HTTPS port the SSL cert binding was created on. Default: 443.
    Set to 0 to skip SSL cert cleanup entirely.

.PARAMETER HostName
    SNI hostname to clean up when the site is already removed (so its binding
    can no longer be inspected). When the site still exists, the hostname is
    discovered from its binding and this is not needed.

.PARAMETER RemoveData
    DESTRUCTIVE. Also remove the data directory: signing keys (active sessions
    are invalidated) and the cert-history database. Without this flag the data
    is preserved so a re-install resumes where it left off.

.PARAMETER Force
    Skip the interactive confirmation that -RemoveData otherwise requires.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1 -RemoveData

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\uninstall-windows.ps1 `
        -HostName "certs.example.com"

.NOTES
    This script is not signed. If your execution policy blocks unsigned scripts,
    bypass it per-invocation (see examples above).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "C:\ProgramData\cert-watch",
    [string]$AppPool = "cert-watch",
    [string]$SiteName = "cert-watch",
    [string]$SitePath = "C:\inetpub\cert-watch",
    [int]$Port = 443,
    [string]$HostName = "",
    [switch]$RemoveData,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# --- Must be elevated (we touch IIS config, netsh, and ProgramData ACLs) ---
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run from an elevated (Administrator) PowerShell."
}

# --- Confirm destructive data removal up front, before changing anything ---
if ($RemoveData -and -not $Force) {
    Write-Warning "-RemoveData will delete $InstallDir, including the signing keys"
    Write-Warning "(every active session is invalidated) and the cert-history database."
    $answer = Read-Host "Type the word remove to proceed, anything else to keep data"
    if ($answer -ne "remove") {
        Write-Host "Keeping data directory. Continuing with IIS/binding cleanup only."
        $RemoveData = $false
    }
}

$haveWebAdmin = [bool](Get-Module -ListAvailable WebAdministration -ErrorAction SilentlyContinue)
if ($haveWebAdmin) { Import-Module WebAdministration -ErrorAction SilentlyContinue }

# --- 1. Inspect the site's HTTPS binding BEFORE removing it, so we know which
#        netsh SSL binding this deployment owns. The discriminator is sslFlags
#        (bit 1 = SNI), NOT the presence of a hostname: a catch-all binding can
#        still carry a host header (*:443:host with sslFlags=0), in which case
#        the cert lives at ipport=0.0.0.0:443, not hostnameport=host:443. ---
$bindingHost = ""         # hostname from the site binding (for the SNI netsh binding)
$isSni = $false           # sslFlags bit 1 -> SNI hostnameport binding
$siteFound = $false
$sitePhysical = ""        # the site's own physicalPath (preferred for removal)
if ($haveWebAdmin) {
    $sitePathIIS = "IIS:\Sites\$SiteName"
    $site = Get-Item $sitePathIIS -ErrorAction SilentlyContinue
    if ($site) {
        $siteFound = $true
        $sitePhysical = "$($site.physicalPath)"
        $bindings = Get-ItemProperty $sitePathIIS -Name bindings -ErrorAction SilentlyContinue
        if ($bindings) {
            foreach ($b in $bindings.Collection) {
                if ($b.protocol -eq "https") {
                    # bindingInformation is ip:port:hostname (e.g. *:443: or *:443:host)
                    $parts = "$($b.bindingInformation)".Split(":")
                    if ($parts.Count -ge 3) { $bindingHost = $parts[2] }
                    # sslFlags is numeric on modern IIS, but older providers may
                    # return a string (Sni/None) -- handle both (cf. installer WI-041).
                    $sf = "$($b.sslFlags)"
                    $sfInt = 0
                    if ([int]::TryParse($sf, [ref]$sfInt)) {
                        $isSni = (($sfInt -band 1) -ne 0)
                    } else {
                        $isSni = ($sf -match "Sni")
                    }
                    break
                }
            }
        }
    }
}
# Caller override when the site is already gone: -HostName targets an SNI
# binding (a catch-all needs no hostname to be cleaned up).
if (-not $siteFound -and $HostName) { $bindingHost = $HostName; $isSni = $true }

# --- 2. Stop and remove the app pool ---
if ($haveWebAdmin) {
    if (Test-Path "IIS:\AppPools\$AppPool") {
        Write-Host "Stopping app pool `"$AppPool`" ..."
        Stop-WebAppPool -Name $AppPool -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Write-Host "Removing app pool `"$AppPool`" ..."
        Remove-WebAppPool -Name $AppPool -ErrorAction SilentlyContinue
    } else {
        Write-Host "App pool `"$AppPool`" not found; skipping."
    }
} else {
    Write-Host "[warn] WebAdministration module not available; skipping IIS app pool/site removal."
}

# --- 3. Remove the IIS site (also drops its IIS-level bindings) ---
if ($haveWebAdmin) {
    if ($siteFound) {
        Write-Host "Removing IIS site `"$SiteName`" ..."
        Remove-Website -Name $SiteName -ErrorAction SilentlyContinue
    } else {
        Write-Host "IIS site `"$SiteName`" not found; skipping."
    }
}

# --- 4. Remove ONLY the netsh SSL cert binding this deployment owns ---
if ($Port -gt 0) {
    if ($isSni -and $bindingHost) {
        # SNI install: remove the per-host binding, leave any catch-all alone
        # (a sibling tool sharing port 443 may own the catch-all).
        $hostnameport = "${bindingHost}:$Port"
        $show = & netsh http show sslcert hostnameport="$hostnameport" 2>&1 | Out-String
        if ($show -match "Certificate Hash") {
            Write-Host "Removing SNI SSL cert binding for $hostnameport ..."
            & netsh http delete sslcert hostnameport="$hostnameport" 2>$null | Out-Null
        } else {
            Write-Host "No SNI SSL cert binding for $hostnameport; skipping."
        }
        Write-Host "[note] Catch-all ipport=0.0.0.0:$Port left untouched (SNI mode -- it may belong to a sibling tool)."
    } else {
        # Catch-all install (or unknown, defaulting to catch-all): remove the
        # 0.0.0.0 binding this deployment created.
        $ipport = "0.0.0.0:$Port"
        $show = & netsh http show sslcert ipport="$ipport" 2>&1 | Out-String
        if ($show -match "Certificate Hash") {
            Write-Host "Removing catch-all SSL cert binding for $ipport ..."
            & netsh http delete sslcert ipport="$ipport" 2>$null | Out-Null
        } else {
            Write-Host "No catch-all SSL cert binding for $ipport; skipping."
        }
    }
}

# --- 5. Remove the physical site directory. Prefer the site's OWN physicalPath
#        (captured before removal) so a non-default -SiteName can never delete a
#        different site's directory; fall back to -SitePath only when the site
#        was already gone. ---
$dirToRemove = $SitePath
if ($siteFound -and $sitePhysical) { $dirToRemove = $sitePhysical }
if ($dirToRemove -and (Test-Path $dirToRemove)) {
    Write-Host "Removing site directory $dirToRemove ..."
    Remove-Item $dirToRemove -Recurse -Force -ErrorAction SilentlyContinue
}

# --- 6. Optionally remove the data directory (destructive) ---
if ($RemoveData) {
    if (Test-Path $InstallDir) {
        Write-Host "Removing data directory $InstallDir (signing keys + database) ..."
        Remove-Item $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "Data directory $InstallDir not found; skipping."
    }
} else {
    Write-Host "Data directory $InstallDir preserved (pass -RemoveData to delete it)."
}

Write-Host ""
Write-Host "Done. cert-watch removed."
if (-not $RemoveData) {
    Write-Host "Data dir $InstallDir was preserved; re-run install-windows.ps1 to redeploy."
}
