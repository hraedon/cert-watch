<#
STYLE (same constraints as install-windows.ps1): Never embed single quotes
inside double-quoted strings. PowerShell 5.1 reads this file via the system
ANSI codepage when the UTF-8 BOM is missing (e.g. GitHub zip download), and
multi-byte UTF-8 sequences corrupt the parser quote-tracking state -- every
subsequent quote inside a double-quoted string becomes a fatal parse error.
Keep this file ASCII-only and prefer single-quoted literals.

Also: this script must run on PowerShell 5.1 (the Windows default). Avoid
PS 7+ syntax: no null-coalescing, no ternary operator, no pipeline chain
operators. Use if/else and -or/-and instead.

.SYNOPSIS
    Verify a cert-watch Windows/IIS install and emit an agent-friendly report.

.DESCRIPTION
    Runs a battery of acceptance checks against an installed cert-watch
    deployment (prerequisites, secrets/keys, ACLs, IIS site + app pool, and
    live HTTP health) and gathers a self-contained diagnostics bundle. The
    result is written as a single structured JSON document so an agent or a
    human can diagnose a failed deploy WITHOUT shelling into the box, plus a
    readable console summary.

    Exit code is 0 when no check fails (warnings are allowed) and 1 otherwise,
    so CI and change-control gates can branch on it.

    This script is read-only: it inspects state and never modifies the install.

.PARAMETER InstallDir
    Base install directory. Default: C:\ProgramData\cert-watch

.PARAMETER BaseUrl
    URL to probe for health (e.g. https://certs.example.com). When omitted, the
    script tries https://localhost/ then http://localhost/, and the loopback
    port if -Port is given.

.PARAMETER Port
    Loopback port for the reverse-proxy / Windows-service model (uvicorn on
    127.0.0.1). Used to build a fallback probe URL.

.PARAMETER SiteName
    IIS site name to inspect. Default: cert-watch

.PARAMETER AppPool
    IIS application pool name. When given, ACL and pool-config checks run.

.PARAMETER OutputPath
    Where to write the JSON report. Default: <InstallDir>\logs\verify-report.json

.PARAMETER Json
    Also write the JSON document to stdout (for piping into an agent).

.PARAMETER Markdown
    Also write a human/agent-readable Markdown report next to the JSON.

.PARAMETER SkipCertCheck
    Accept self-signed / internal-CA TLS certs when probing HTTPS.

.PARAMETER FullDiagnostics
    Always gather the full diagnostics bundle, even when every check passes
    (default: the heavy bundle is gathered only when something fails or warns).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\Verify-Install.ps1 -AppPool cert-watch -BaseUrl https://certs.example.com -SkipCertCheck -Json
#>
[CmdletBinding()]
param(
    [string]$InstallDir = 'C:\ProgramData\cert-watch',
    [string]$BaseUrl = '',
    [int]$Port = 0,
    [string]$SiteName = 'cert-watch',
    [string]$AppPool = '',
    [string]$OutputPath = '',
    [switch]$Json,
    [switch]$Markdown,
    [switch]$SkipCertCheck,
    [switch]$FullDiagnostics
)

$ToolVersion   = '0.1.0'
$SchemaVersion = '1.0'

# Per-check error handling is explicit (try/catch); do not abort the whole run.
$ErrorActionPreference = 'Continue'

# --- TLS / cert handling for HTTP probes (PS 5.1 defaults can be too old) ---
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Older frameworks may not expose Tls12; the probe still attempts the default.
}
if ($SkipCertCheck) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Build a check-result body. Status is one of: pass warn fail skip.
function New-Body {
    param([string]$Status, [string]$Detail, [string]$Evidence = '')
    return [ordered]@{ Status = $Status; Detail = $Detail; Evidence = $Evidence }
}

# Truncate long text so the JSON stays ingestible; keep the TAIL (most recent /
# most relevant lines usually live at the end of logs and command output).
function Limit-Text {
    param([string]$Text, [int]$MaxChars = 4000)
    if ($null -eq $Text) { return '' }
    if ($Text.Length -le $MaxChars) { return $Text }
    $kept = $Text.Substring($Text.Length - $MaxChars)
    return ('...[truncated ' + ($Text.Length - $MaxChars) + ' chars]...' + "`n" + $kept)
}

$script:Checks = New-Object System.Collections.ArrayList

# Run one check. $Test is a scriptblock returning a New-Body hashtable.
function Add-Check {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Category,
        [string]$Severity,
        [scriptblock]$Test,
        [string]$Remediation = ''
    )
    $status = 'fail'
    $detail = ''
    $evidence = ''
    try {
        $r = & $Test
        if ($null -eq $r) {
            $status = 'fail'
            $detail = 'check produced no result'
        } else {
            $status = [string]$r.Status
            $detail = [string]$r.Detail
            if ($r.Contains('Evidence')) { $evidence = [string]$r.Evidence }
        }
    } catch {
        $status = 'fail'
        $detail = 'check raised an error: ' + $_.Exception.Message
        $evidence = ($_ | Out-String)
    }
    $row = [ordered]@{
        id          = $Id
        title       = $Title
        category    = $Category
        severity    = $Severity
        status      = $status
        detail      = $detail
        evidence    = (Limit-Text $evidence 3000)
        remediation = $Remediation
    }
    [void]$script:Checks.Add($row)
}

# HTTP GET that never throws; returns a small result hashtable.
function Invoke-Http {
    param([string]$Url, [int]$TimeoutSec = 10)
    $out = [ordered]@{ Url = $Url; Ok = $false; Code = 0; Body = ''; Error = '' }
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec $TimeoutSec
        $out.Ok = $true
        $out.Code = [int]$resp.StatusCode
        $out.Body = [string]$resp.Content
    } catch {
        $we = $_.Exception
        if ($we.Response -ne $null) {
            try { $out.Code = [int]$we.Response.StatusCode } catch { }
        }
        $out.Error = $we.Message
    }
    return $out
}

function Get-AppcmdPath {
    if ([string]::IsNullOrEmpty($env:windir)) { return '' }
    return (Join-Path $env:windir 'system32\inetsrv\appcmd.exe')
}

function Test-IisAvailable {
    $appcmd = Get-AppcmdPath
    if ($appcmd -ne '' -and (Test-Path $appcmd)) { return $true }
    if (Get-Module -ListAvailable -Name WebAdministration) { return $true }
    return $false
}

# Resolve the real interpreter the venv points at (venv python is a symlink).
function Get-VenvRealPython {
    param([string]$VenvPython)
    if (-not (Test-Path $VenvPython)) { return '' }
    try {
        $item = Get-Item $VenvPython
        if ($item.Target) { return [string]$item.Target }
    } catch { }
    return $VenvPython
}

# ---------------------------------------------------------------------------
# Derived paths / probe targets
# ---------------------------------------------------------------------------
$venvPython = Join-Path $InstallDir 'venv\Scripts\python.exe'
$certWatchExe = Join-Path $InstallDir 'venv\Scripts\cert-watch.exe'
$secretsDir = Join-Path $InstallDir 'secrets'
$logDir     = Join-Path $InstallDir 'logs'
$authSecret = Join-Path $secretsDir 'auth_secret'
$csrfSecret = Join-Path $secretsDir 'csrf_secret'

$probeUrls = New-Object System.Collections.ArrayList
if ($BaseUrl -ne '') {
    [void]$probeUrls.Add(($BaseUrl.TrimEnd('/')))
} else {
    [void]$probeUrls.Add('https://localhost')
    [void]$probeUrls.Add('http://localhost')
}
if ($Port -gt 0) { [void]$probeUrls.Add('http://127.0.0.1:' + $Port) }

# ---------------------------------------------------------------------------
# Checks: environment + prerequisites
# ---------------------------------------------------------------------------

Add-Check -Id 'ENV-001' -Title 'Running on a supported PowerShell' -Category 'environment' -Severity 'low' -Test {
    $v = $PSVersionTable.PSVersion
    if ($v.Major -ge 5) {
        return (New-Body 'pass' ('PowerShell ' + $v.ToString()))
    }
    return (New-Body 'warn' ('PowerShell ' + $v.ToString() + ' is older than 5.1'))
}

Add-Check -Id 'ENV-002' -Title 'Process is elevated (Administrator)' -Category 'environment' -Severity 'medium' -Remediation 'Re-run from an elevated PowerShell so ACL and IIS state can be read.' -Test {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            return (New-Body 'pass' 'elevated')
        }
        return (New-Body 'warn' 'not elevated; some ACL / IIS checks may be incomplete')
    } catch {
        return (New-Body 'skip' 'elevation state not determinable on this platform')
    }
}

Add-Check -Id 'ENV-003' -Title 'Install directory exists' -Category 'environment' -Severity 'high' -Remediation 'Run install-windows.ps1 first, or pass the correct -InstallDir.' -Test {
    if (Test-Path $InstallDir) { return (New-Body 'pass' $InstallDir) }
    return (New-Body 'fail' ('not found: ' + $InstallDir))
}

# ---------------------------------------------------------------------------
# Checks: Python / venv / app install
# ---------------------------------------------------------------------------

Add-Check -Id 'PY-001' -Title 'Virtualenv interpreter present' -Category 'runtime' -Severity 'high' -Remediation 'Re-run install-windows.ps1; the venv at <InstallDir>\venv was not created.' -Test {
    if (Test-Path $venvPython) { return (New-Body 'pass' $venvPython) }
    return (New-Body 'fail' ('missing: ' + $venvPython))
}

Add-Check -Id 'PY-002' -Title 'Interpreter runs and is Python 3.12+' -Category 'runtime' -Severity 'high' -Remediation 'The shared Python install may be missing or unreadable; see deploy/iis/README.md "Why a shared Python install".' -Test {
    if (-not (Test-Path $venvPython)) { return (New-Body 'skip' 'no venv interpreter') }
    $out = & $venvPython '--version' 2>&1 | Out-String
    $out = $out.Trim()
    if ($out -match 'Python\s+(\d+)\.(\d+)') {
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]
        if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 12)) {
            return (New-Body 'pass' $out -Evidence $out)
        }
        return (New-Body 'fail' ('too old: ' + $out) -Evidence $out)
    }
    return (New-Body 'fail' 'interpreter did not report a version' -Evidence $out)
}

Add-Check -Id 'PY-003' -Title 'Real interpreter is outside a user profile' -Category 'runtime' -Severity 'medium' -Remediation 'A per-user Python (Install Manager default) is not reachable by the app-pool identity. install-windows.ps1 should have copied it to <InstallDir>\python. See deploy/iis/README.md.' -Test {
    if (-not (Test-Path $venvPython)) { return (New-Body 'skip' 'no venv interpreter') }
    $real = Get-VenvRealPython $venvPython
    if ($real -eq '') { return (New-Body 'warn' 'could not resolve the real interpreter path') }
    if ($real -match '(?i)\\Users\\' -or $real -match '(?i)LocalAppData') {
        return (New-Body 'warn' ('interpreter lives under a user profile: ' + $real) -Evidence $real)
    }
    return (New-Body 'pass' $real -Evidence $real)
}

Add-Check -Id 'PY-004' -Title 'cert-watch is installed in the venv' -Category 'runtime' -Severity 'high' -Remediation 'Re-run install-windows.ps1; pip install of cert-watch did not complete.' -Test {
    if (Test-Path $certWatchExe) { return (New-Body 'pass' $certWatchExe) }
    if (Test-Path $venvPython) {
        $out = & $venvPython '-m' 'cert_watch' '--version' 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) { return (New-Body 'pass' ($out.Trim()) -Evidence $out) }
        return (New-Body 'fail' 'cert_watch module did not run' -Evidence $out)
    }
    return (New-Body 'fail' 'no console script and no interpreter to probe')
}

# ---------------------------------------------------------------------------
# Checks: secrets / signing keys
# ---------------------------------------------------------------------------

Add-Check -Id 'SEC-001' -Title 'Persistent signing keys exist and are non-empty' -Category 'secrets' -Severity 'high' -Remediation 'Without persisted AUTH/CSRF secrets every recycle logs all users out. Re-run install-windows.ps1 to generate them.' -Test {
    $missing = New-Object System.Collections.ArrayList
    foreach ($f in @($authSecret, $csrfSecret)) {
        if (-not (Test-Path $f)) { [void]$missing.Add($f); continue }
        $len = (Get-Item $f).Length
        if ($len -le 0) { [void]$missing.Add($f + ' (empty)') }
    }
    if ($missing.Count -eq 0) { return (New-Body 'pass' 'auth_secret and csrf_secret present') }
    return (New-Body 'fail' ('problem with: ' + ($missing -join ', ')))
}

# ---------------------------------------------------------------------------
# Checks: ACLs (only meaningful when -AppPool is supplied)
# ---------------------------------------------------------------------------

Add-Check -Id 'ACL-001' -Title 'App-pool identity has Modify on the data dir' -Category 'acl' -Severity 'high' -Remediation 'Re-run install-windows.ps1 -AppPool <name>, or grant icacls Modify (see deploy/iis/README.md Step 2a.5).' -Test {
    if ($AppPool -eq '') { return (New-Body 'skip' 'no -AppPool supplied') }
    $identity = 'IIS AppPool\' + $AppPool
    $out = & icacls $InstallDir 2>&1 | Out-String
    if ($out -match [Regex]::Escape($identity)) {
        return (New-Body 'pass' ('grant present for ' + $identity) -Evidence $out)
    }
    return (New-Body 'fail' ('no ACL entry for ' + $identity) -Evidence $out)
}

Add-Check -Id 'ACL-002' -Title 'App-pool identity can read the Python install' -Category 'acl' -Severity 'high' -Remediation 'Without RX on the interpreter dir, HttpPlatformHandler logs "Access is denied" and IIS hangs. See deploy/iis/README.md Step 2a.5.' -Test {
    if ($AppPool -eq '') { return (New-Body 'skip' 'no -AppPool supplied') }
    $real = Get-VenvRealPython $venvPython
    if ($real -eq '' -or -not (Test-Path $real)) { return (New-Body 'skip' 'real interpreter path not resolved') }
    $pyDir = Split-Path $real
    $identity = 'IIS AppPool\' + $AppPool
    $out = & icacls $pyDir 2>&1 | Out-String
    if ($out -match [Regex]::Escape($identity)) {
        return (New-Body 'pass' ('grant present on ' + $pyDir) -Evidence $out)
    }
    return (New-Body 'fail' ('no ACL entry for ' + $identity + ' on ' + $pyDir) -Evidence $out)
}

# ---------------------------------------------------------------------------
# Checks: IIS site + app pool
# ---------------------------------------------------------------------------

Add-Check -Id 'IIS-001' -Title 'handlers config section is unlocked' -Category 'iis' -Severity 'high' -Remediation 'Run: appcmd unlock config -section:system.webServer/handlers (fixes 0x80070021). See deploy/iis/README.md Prerequisites.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $appcmd = Get-AppcmdPath
    $out = & $appcmd list config -section:system.webServer/handlers 2>&1 | Out-String
    if ($out -match '0x80070021' -or $out -match 'locked') {
        return (New-Body 'fail' 'handlers section appears locked at a parent level' -Evidence $out)
    }
    return (New-Body 'pass' 'handlers section readable (not parent-locked)' -Evidence (Limit-Text $out 800))
}

Add-Check -Id 'IIS-002' -Title 'Application pool exists and is configured for always-on' -Category 'iis' -Severity 'high' -Remediation 'Apply the Step 2a.4 settings: idleTimeout 0, startMode AlwaysRunning, periodicRestart 0 -- otherwise the scan scheduler stops when the pool idles.' -Test {
    if ($AppPool -eq '') { return (New-Body 'skip' 'no -AppPool supplied') }
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $appcmd = Get-AppcmdPath
    $out = & $appcmd list apppool $AppPool '/text:*' 2>&1 | Out-String
    if ($out -eq '' -or $out -match 'ERROR') {
        return (New-Body 'fail' ('app pool not found: ' + $AppPool) -Evidence $out)
    }
    $warnings = New-Object System.Collections.ArrayList
    if ($out -notmatch '(?i)startMode:"AlwaysRunning"') { [void]$warnings.Add('startMode is not AlwaysRunning') }
    if ($out -notmatch '(?i)idleTimeout:"00:00:00"') { [void]$warnings.Add('idleTimeout is not 0') }
    if ($warnings.Count -gt 0) {
        return (New-Body 'warn' ($warnings -join '; ') -Evidence (Limit-Text $out 1200))
    }
    return (New-Body 'pass' 'pool exists; always-on settings look correct' -Evidence (Limit-Text $out 1200))
}

Add-Check -Id 'IIS-003' -Title 'IIS site exists and has a binding' -Category 'iis' -Severity 'medium' -Remediation 'Create the site and binding per deploy/iis/README.md Step 2a.3.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $appcmd = Get-AppcmdPath
    $out = & $appcmd list site $SiteName '/text:*' 2>&1 | Out-String
    if ($out -eq '' -or $out -match 'ERROR') {
        return (New-Body 'warn' ('site not found: ' + $SiteName + ' (expected for the service / reverse-proxy model)') -Evidence $out)
    }
    return (New-Body 'pass' ('site present: ' + $SiteName) -Evidence (Limit-Text $out 1200))
}

# ---------------------------------------------------------------------------
# Checks: live HTTP health
# ---------------------------------------------------------------------------

$script:HealthBaseUsed = ''

Add-Check -Id 'HTTP-001' -Title 'Health endpoint returns 200' -Category 'http' -Severity 'critical' -Remediation 'Check logs\stdout*.log. Common causes: wrong processPath, missing venv, or app-pool identity lacking data/secrets/python access (502.5).' -Test {
    $last = ''
    foreach ($base in $probeUrls) {
        $r = Invoke-Http ($base + '/healthz')
        $last = ($r.Url + ' -> code ' + $r.Code + ' ' + $r.Error)
        if ($r.Ok -and $r.Code -eq 200) {
            $script:HealthBaseUsed = $base
            return (New-Body 'pass' ($base + '/healthz returned 200') -Evidence $r.Body)
        }
    }
    return (New-Body 'fail' ('no probe URL returned 200; last: ' + $last) -Evidence $last)
}

Add-Check -Id 'HTTP-002' -Title 'Readiness endpoint returns 200' -Category 'http' -Severity 'high' -Remediation 'readyz failing while healthz passes usually means the DB / data dir is not writable by the app-pool identity.' -Test {
    if ($script:HealthBaseUsed -eq '') { return (New-Body 'skip' 'no reachable base URL from HTTP-001') }
    $r = Invoke-Http ($script:HealthBaseUsed + '/readyz')
    if ($r.Ok -and $r.Code -eq 200) { return (New-Body 'pass' 'readyz 200' -Evidence $r.Body) }
    return (New-Body 'fail' ('readyz code ' + $r.Code + ' ' + $r.Error) -Evidence ($r.Body + $r.Error))
}

Add-Check -Id 'HTTP-003' -Title 'Login page renders (app is serving HTML)' -Category 'http' -Severity 'medium' -Remediation 'If healthz passes but /login does not, a template or static-asset path is broken; see logs\stdout*.log.' -Test {
    if ($script:HealthBaseUsed -eq '') { return (New-Body 'skip' 'no reachable base URL') }
    $r = Invoke-Http ($script:HealthBaseUsed + '/login')
    if ($r.Ok -and $r.Code -eq 200) { return (New-Body 'pass' 'login page served') }
    return (New-Body 'warn' ('login code ' + $r.Code + ' ' + $r.Error))
}

# ---------------------------------------------------------------------------
# Decide overall + gather diagnostics
# ---------------------------------------------------------------------------
$passed  = (@($script:Checks | Where-Object { $_.status -eq 'pass' })).Count
$failed  = (@($script:Checks | Where-Object { $_.status -eq 'fail' })).Count
$warned  = (@($script:Checks | Where-Object { $_.status -eq 'warn' })).Count
$skipped = (@($script:Checks | Where-Object { $_.status -eq 'skip' })).Count
$total   = $script:Checks.Count

if ($failed -gt 0) { $overall = 'fail' }
elseif ($warned -gt 0) { $overall = 'warn' }
else { $overall = 'pass' }

$nextActions = New-Object System.Collections.ArrayList
foreach ($c in $script:Checks) {
    if ($c.status -eq 'fail' -and $c.remediation -ne '') {
        [void]$nextActions.Add(($c.id + ': ' + $c.remediation))
    }
}

function Get-Diagnostics {
    $d = [ordered]@{}

    # Newest stdout log tail.
    try {
        $logFile = Get-ChildItem -Path $logDir -Filter 'stdout*.log' -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($logFile) {
            $tail = (Get-Content -Path $logFile.FullName -Tail 120 -ErrorAction Stop) -join "`n"
            $d['stdout_log_tail'] = Limit-Text $tail 6000
        } else {
            $d['stdout_log_tail'] = 'no stdout*.log found in ' + $logDir
        }
    } catch { $d['stdout_log_tail'] = 'error reading logs: ' + $_.Exception.Message }

    # Relevant Application event-log entries (Windows only).
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 40 -ErrorAction Stop |
            Where-Object { $_.ProviderName -match '(?i)HttpPlatform|IIS|W3SVC|WAS|Application Error' }
        if ($events) {
            $d['application_events'] = Limit-Text (($events | ForEach-Object { $_.TimeCreated.ToString('s') + ' [' + $_.ProviderName + '] ' + ($_.Message -replace "`r?`n", ' ') }) -join "`n") 5000
        } else {
            $d['application_events'] = 'no matching Application events in the last 2h'
        }
    } catch { $d['application_events'] = 'event log unavailable: ' + $_.Exception.Message }

    # IIS config dumps.
    if (Test-IisAvailable) {
        $appcmd = Get-AppcmdPath
        try { $d['iis_apppool_config'] = Limit-Text ((& $appcmd list apppool $AppPool '/text:*' 2>&1 | Out-String)) 4000 } catch { $d['iis_apppool_config'] = 'n/a' }
        try { $d['iis_site_config'] = Limit-Text ((& $appcmd list site $SiteName '/text:*' 2>&1 | Out-String)) 4000 } catch { $d['iis_site_config'] = 'n/a' }
        try { $d['iis_worker_processes'] = Limit-Text ((& $appcmd list wp 2>&1 | Out-String)) 2000 } catch { $d['iis_worker_processes'] = 'n/a' }
    } else {
        $d['iis'] = 'IIS not detected (service / reverse-proxy model or app not IIS-hosted)'
    }

    # ACL dumps.
    try { $d['acl_data_dir'] = Limit-Text ((& icacls $InstallDir 2>&1 | Out-String)) 2500 } catch { $d['acl_data_dir'] = 'n/a' }
    try {
        $real = Get-VenvRealPython $venvPython
        if ($real -ne '' -and (Test-Path $real)) {
            $d['acl_python_dir'] = Limit-Text ((& icacls (Split-Path $real) 2>&1 | Out-String)) 2500
        }
    } catch { $d['acl_python_dir'] = 'n/a' }

    # web.config (env vars, processPath).
    try {
        if (Test-IisAvailable) {
            $appcmd = Get-AppcmdPath
            $siteOut = & $appcmd list site $SiteName '/text:physicalPath' 2>&1 | Out-String
            $phys = $siteOut.Trim()
            if ($phys -ne '' -and (Test-Path (Join-Path $phys 'web.config'))) {
                $d['web_config'] = Limit-Text ((Get-Content -Path (Join-Path $phys 'web.config') -Raw)) 4000
            }
        }
    } catch { $d['web_config'] = 'n/a' }

    # Relevant processes.
    try {
        $procs = Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -match '(?i)python|w3wp|cert-watch|uvicorn' } |
            Select-Object Id, ProcessName, @{ N = 'WS_MB'; E = { [Math]::Round($_.WorkingSet64 / 1MB, 1) } }
        if ($procs) { $d['processes'] = Limit-Text (($procs | Format-Table -AutoSize | Out-String)) 2000 }
        else { $d['processes'] = 'no python / w3wp / cert-watch processes found' }
    } catch { $d['processes'] = 'process list unavailable: ' + $_.Exception.Message }

    # TLS binding.
    try { $d['sslcert_bindings'] = Limit-Text ((& netsh http show sslcert 2>&1 | Out-String)) 3000 } catch { $d['sslcert_bindings'] = 'n/a' }

    return $d
}

$diagnostics = [ordered]@{}
if ($FullDiagnostics -or $overall -ne 'pass') {
    $diagnostics = Get-Diagnostics
} else {
    $diagnostics['note'] = 'all checks passed; run with -FullDiagnostics to force a full bundle'
}

# ---------------------------------------------------------------------------
# Host facts
# ---------------------------------------------------------------------------
$hostName = $env:COMPUTERNAME
$osDesc = ''
try { $osDesc = [string]([System.Environment]::OSVersion.VersionString) } catch { }
$isElevated = $null
try {
    $idc = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pc = New-Object Security.Principal.WindowsPrincipal($idc)
    $isElevated = [bool]$pc.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { $isElevated = $null }

$report = [ordered]@{
    schemaVersion  = $SchemaVersion
    tool           = 'cert-watch Verify-Install'
    toolVersion    = $ToolVersion
    generatedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    host           = [ordered]@{
        name       = $hostName
        os         = $osDesc
        psVersion  = $PSVersionTable.PSVersion.ToString()
        isElevated = $isElevated
    }
    target = [ordered]@{
        installDir = $InstallDir
        baseUrl    = $(if ($script:HealthBaseUsed -ne '') { $script:HealthBaseUsed } else { ($probeUrls -join ', ') })
        siteName   = $SiteName
        appPool    = $AppPool
    }
    summary = [ordered]@{
        total   = $total
        passed  = $passed
        failed  = $failed
        warned  = $warned
        skipped = $skipped
        overall = $overall
    }
    checks      = @($script:Checks)
    nextActions = @($nextActions)
    diagnostics = $diagnostics
}

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
if ($OutputPath -eq '') {
    if (-not (Test-Path $logDir)) {
        try { New-Item -ItemType Directory -Force -Path $logDir | Out-Null } catch { }
    }
    if (Test-Path $logDir) { $OutputPath = Join-Path $logDir 'verify-report.json' }
    else { $OutputPath = Join-Path (Get-Location) 'verify-report.json' }
}

$jsonText = $report | ConvertTo-Json -Depth 10
try {
    Set-Content -Path $OutputPath -Value $jsonText -Encoding UTF8
    $wrote = $OutputPath
} catch {
    $wrote = '(failed to write ' + $OutputPath + ': ' + $_.Exception.Message + ')'
}

if ($Markdown) {
    $mdPath = [System.IO.Path]::ChangeExtension($OutputPath, '.md')
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# cert-watch install verification')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('- Host: ' + $hostName)
    [void]$sb.AppendLine('- Generated (UTC): ' + $report.generatedAtUtc)
    [void]$sb.AppendLine('- Overall: ' + $overall.ToUpper() + ' (' + $passed + ' pass / ' + $failed + ' fail / ' + $warned + ' warn / ' + $skipped + ' skip)')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Status | ID | Check | Detail |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($c in $script:Checks) {
        [void]$sb.AppendLine('| ' + $c.status.ToUpper() + ' | ' + $c.id + ' | ' + $c.title + ' | ' + ($c.detail -replace '\|', '/') + ' |')
    }
    if ($nextActions.Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## Next actions')
        foreach ($a in $nextActions) { [void]$sb.AppendLine('- ' + $a) }
    }
    try { Set-Content -Path $mdPath -Value ($sb.ToString()) -Encoding UTF8 } catch { }
}

# Console summary (human-facing; ASCII status tags).
Write-Host ''
Write-Host ('cert-watch verify  ::  overall=' + $overall.ToUpper() + '  (' + $passed + ' pass / ' + $failed + ' fail / ' + $warned + ' warn / ' + $skipped + ' skip)')
Write-Host ('report: ' + $wrote)
Write-Host ''
foreach ($c in $script:Checks) {
    $tag = '[' + $c.status.ToUpper() + ']'
    $tag = $tag.PadRight(7)
    Write-Host ($tag + $c.id + '  ' + $c.title)
    if ($c.status -eq 'fail' -or $c.status -eq 'warn') {
        Write-Host ('         ' + $c.detail)
    }
}
if ($nextActions.Count -gt 0) {
    Write-Host ''
    Write-Host 'Next actions:'
    foreach ($a in $nextActions) { Write-Host ('  - ' + $a) }
}

if ($Json) {
    Write-Output $jsonText
}

if ($overall -eq 'fail') { exit 1 } else { exit 0 }
