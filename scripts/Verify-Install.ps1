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
    Always gather the diagnostics bundle, even when every check passes
    (default: it is gathered only when something fails or warns). The bundle
    never contains log or event-log CONTENT: it lists the stdout log files
    (path, size, time) and recent IIS/HttpPlatform event ids, sources, levels
    and times, so you can review and attach the logs yourself.

.NOTES
    Threat model. The report is meant to be shareable (tickets, chat, agent
    sessions). Configured VALUES are withheld unless the setting is on an
    allowlist and the value passes a strict format check (bool, integer,
    fixed enum, a path under the install or site directory, a URL reduced to
    scheme://host:port). What IS included: the NAMES of settings, response
    headers, log files and event sources, file-system paths, and the URL path
    you pass in -BaseUrl (its userinfo, query string and fragment are
    dropped). Log contents and event-log messages are never included; review
    the logs yourself before attaching them. -Verbose prints full error
    messages to the console only, never to the report.

    The report is built so that it can be shared: free text (log lines, event
    messages, exception messages, HTTP bodies, raw config) never enters it,
    URLs are reduced to scheme://host:port/path, and config values are shown
    only for allowlisted settings whose value matches a strict grammar. Error
    details in checks are reduced to the exception type; run with -Verbose to
    see the full messages on the console (they are NOT sanitized there and
    never reach the report files). Review the report before sharing anyway.

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
# -SkipCertCheck: PowerShell 7+ has Invoke-WebRequest -SkipCertificateCheck,
# which Invoke-Http passes there. Windows PowerShell 5.1 has no such switch.
# Setting ServicePointManager.ServerCertificateValidationCallback would trust
# every certificate PROCESS-WIDE for as long as it is set, and a scriptblock
# callback fails anyway ("There is no Runspace available to run scripts in this
# thread"). So on 5.1 the probe goes through a small compiled helper that sets
# the PER-REQUEST HttpWebRequest.ServerCertificateValidationCallback (.NET 4.5+)
# on its own request only. ServicePointManager's callback is never touched.
$script:UseSkipCertificateCheckSwitch = $false
$script:UsePerRequestTrustAll = $false
if ($SkipCertCheck) {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        $script:UseSkipCertificateCheckSwitch = $true
    } else {
        # Guard against re-adding the type when the script runs twice in one
        # session (Add-Type of an existing type name throws).
        if (-not ('CertWatchVerify.InsecureProbe' -as [type])) {
            Add-Type -TypeDefinition @'
namespace CertWatchVerify
{
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    public class ProbeResult
    {
        public bool Ok;
        public int Code;
        public string Body = "";
        public string Error = "";
    }

    public static class InsecureProbe
    {
        private static bool AcceptAny(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
        {
            return true;
        }

        private static string ReadBody(WebResponse response)
        {
            using (Stream s = response.GetResponseStream())
            using (StreamReader r = new StreamReader(s))
            {
                return r.ReadToEnd();
            }
        }

        // GET with certificate validation disabled for THIS request only. The
        // request uses its own connection group and no keep-alive, so its
        // unvalidated connection is never shared or reused.
        public static ProbeResult Get(string url, int timeoutMs)
        {
            ProbeResult result = new ProbeResult();
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.KeepAlive = false;
            req.ConnectionGroupName = "cert-watch-verify-" + Guid.NewGuid().ToString("N");
            req.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(AcceptAny);
            try
            {
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    result.Ok = true;
                    result.Code = (int)resp.StatusCode;
                    result.Body = ReadBody(resp);
                }
            }
            catch (WebException ex)
            {
                result.Error = "WebException: " + ex.Status.ToString();
                HttpWebResponse resp = ex.Response as HttpWebResponse;
                if (resp != null)
                {
                    result.Code = (int)resp.StatusCode;
                    try { result.Body = ReadBody(resp); } catch (Exception) { }
                    resp.Close();
                }
            }
            return result;
        }
    }
}
'@
        }
        $script:UsePerRequestTrustAll = $true
    }
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
    # Sanitize BEFORE truncating: a cut through "password=..." or a URL's
    # userinfo would otherwise leave a value the final pass cannot recognise.
    $Text = ConvertTo-SafeText $Text
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
        $detail = 'check raised ' + (Format-ErrorSummary $_) + '; re-run with -Verbose to see the message'
        $evidence = ''
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
    $out = [ordered]@{ Url = (Format-SafeUrl $Url); Ok = $false; Code = 0; Body = ''; Error = '' }
    if ($script:UsePerRequestTrustAll) {
        try {
            $r = [CertWatchVerify.InsecureProbe]::Get($Url, $TimeoutSec * 1000)
            $out.Ok = [bool]$r.Ok
            $out.Code = [int]$r.Code
            $out.Body = [string]$r.Body
            $out.Error = [string]$r.Error
        } catch {
            $out.Error = Format-ErrorSummary $_
        }
        return $out
    }
    $iwr = @{ Uri = $Url; UseBasicParsing = $true; TimeoutSec = $TimeoutSec }
    if ($script:UseSkipCertificateCheckSwitch) { $iwr['SkipCertificateCheck'] = $true }
    try {
        $resp = Invoke-WebRequest @iwr
        $out.Ok = $true
        $out.Code = [int]$resp.StatusCode
        $out.Body = [string]$resp.Content
    } catch {
        $we = $_.Exception
        if ($we.Response -ne $null) {
            try { $out.Code = [int]$we.Response.StatusCode } catch { }
        }
        $out.Error = Format-ErrorSummary $_
    }
    return $out
}

# A shareable summary of an error: the exception type (plus the WebException
# status, an enum) -- never the message, which can carry URLs, paths or
# credentials. The full message goes to the verbose stream only.
function Format-ErrorSummary {
    param($ErrorRecord)
    $ex = $ErrorRecord
    if ($ErrorRecord -is [System.Management.Automation.ErrorRecord]) { $ex = $ErrorRecord.Exception }
    if ($null -eq $ex) { return 'an unknown error' }
    Write-Verbose ('error detail (not in the report): ' + $ex.Message)
    $summary = $ex.GetType().Name
    if ($ex -is [System.Net.WebException]) { $summary = $summary + ': ' + $ex.Status.ToString() }
    return $summary
}

# Structural URL sanitizing: scheme://host[:port]/path only. Userinfo, the
# whole query string and the fragment are dropped; anything that does not
# parse as an absolute URL is not echoed at all.
function Format-SafeUrl {
    param([string]$Url, [switch]$NoPath)
    $u = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$u)) { return '[unparseable URL]' }
    if ($u.Scheme -notmatch '^(https?|ldaps?)$' -or [string]::IsNullOrEmpty($u.Host)) { return '[unparseable URL]' }
    $out = $u.Scheme + '://' + $u.Host
    if (-not $u.IsDefaultPort) { $out = $out + ':' + $u.Port }
    if (-not $NoPath) { $out = $out + $u.AbsolutePath }
    return $out
}

# The HTTP body is free text; only a /healthz-style {"status": "<word>"} is
# reported.
function Format-SafeBody {
    param([string]$Body)
    try {
        $j = $Body | ConvertFrom-Json -ErrorAction Stop
        if ($j -and $j.status -and ([string]$j.status -match '^\w{1,32}$')) { return ('status=' + $j.status) }
    } catch { Write-Verbose 'response body is not the expected JSON' }
    return ''
}

# icacls output reduced to its ACE lines ("<principal>:(rights)"): the
# "Successfully processed ..." chatter and anything else is dropped.
function Select-AceLine {
    param([string]$Text)
    $aces = @(($Text -split "`r?`n") | Where-Object { $_ -match ':(\((?:[A-Z]{1,4}|[A-Z,]+)\))+\s*$' } | ForEach-Object { $_.Trim() })
    return ($aces -join "`n")
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

function Get-AppInitState {
    # warmup.dll alone is not proof that IIS has the role service enabled: IIS
    # can have the file present while the native module remains unregistered.
    $warmupDll = Join-Path $env:windir 'System32\inetsrv\warmup.dll'
    $appHostConfig = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    $featureKnown = $false
    $featureEnabled = $false
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsFeature Web-AppInit -ErrorAction SilentlyContinue
        if ($feature) {
            $featureKnown = $true
            $featureEnabled = [bool]$feature.Installed
        }
    } elseif (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName IIS-ApplicationInit -ErrorAction SilentlyContinue
        if ($feature) {
            $featureKnown = $true
            $featureEnabled = $feature.State -in @('Enabled', 'EnablePending')
        }
    }
    if (-not $featureKnown) {
        # Last-resort compatibility signal for older Windows images.
        $featureEnabled = Test-Path $warmupDll
    }
    $moduleRegistered = $false
    $cfg = Read-TextFileSafely $appHostConfig
    if ($cfg.Ok) { $moduleRegistered = $cfg.Text.Contains('name="ApplicationInitializationModule"') }
    return [PSCustomObject]@{
        FeatureEnabled = $featureEnabled
        ModuleRegistered = $moduleRegistered
        WarmupDll = (Test-Path $warmupDll)
    }
}

# Read an external text file without ever writing a provider error to the
# console: a missing path, a DIRECTORY with the file's name, or an unreadable
# file all come back as Ok=$false with a sanitized error summary.
function Read-TextFileSafely {
    param([string]$Path)
    $r = [PSCustomObject]@{ Ok = $false; Text = ''; Error = '' }
    if ([string]::IsNullOrEmpty($Path)) { $r.Error = 'no path'; return $r }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf -ErrorAction SilentlyContinue)) {
        if (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue) { $r.Error = 'not a file' } else { $r.Error = 'not found' }
        return $r
    }
    try {
        $r.Text = [string](Get-Content -LiteralPath $Path -Raw -ErrorAction Stop)
        $r.Ok = $true
    } catch { $r.Error = 'not readable (' + (Format-ErrorSummary $_) + ')' }
    return $r
}

# Resolve the real interpreter the venv points at (venv python is a symlink).
function Get-VenvRealPython {
    param([string]$VenvPython)
    if (-not (Test-Path $VenvPython)) { return '' }
    try {
        $item = Get-Item -LiteralPath $VenvPython -ErrorAction Stop
        if ($item.Target) { return [string]$item.Target }
    } catch { Write-Verbose ('could not inspect the venv interpreter: ' + (Format-ErrorSummary $_)) }
    return $VenvPython
}

# Normalise an IIS configuration value to a bool. Get-ItemProperty on the IIS:
# drive returns a Microsoft.IIs.PowerShell.Framework.ConfigurationAttribute for
# a leaf attribute (the real value is in .Value), some provider versions return
# the bare value, and Get-WebConfigurationProperty returns either shape too.
# Returns $null when no boolean could be extracted.
function ConvertTo-IisBool {
    param($Value, [string]$LegacyName = '')
    for ($i = 0; $i -lt 4; $i++) {
        if ($null -eq $Value) { return $null }
        if ($Value -is [bool]) { return $Value }
        if ($Value -is [string]) {
            if ([string]::Equals($Value, 'true', [StringComparison]::OrdinalIgnoreCase)) { return $true }
            if ([string]::Equals($Value, 'false', [StringComparison]::OrdinalIgnoreCase)) { return $false }
            return $null
        }
        $names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
        if ($names -contains 'Value') {
            $Value = $Value.Value
        } elseif ($LegacyName -ne '' -and ($names -contains $LegacyName)) {
            $Value = $Value.$LegacyName
        } else {
            return $null
        }
    }
    return $null
}

# Describe an IIS config value for evidence: its type and unwrapped value.
function Format-IisValue {
    param($Value)
    if ($null -eq $Value) { return '<null>' }
    $typeName = $Value.GetType().FullName
    $inner = $Value
    $names = @($Value.PSObject.Properties | ForEach-Object { $_.Name })
    if ($names -contains 'Value') { $inner = $Value.Value }
    return ($typeName + ' value=' + [string]$inner)
}

# The app pool actually serving the site (so IIS-006 works without -AppPool).
function Get-SiteAppPool {
    if ($AppPool -ne '') { return $AppPool }
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
        if ($site -and $site.applicationPool) { return [string]$site.applicationPool }
    } catch { Write-Verbose ('site lookup failed: ' + $_.Exception.Message) }
    return ''
}

# IIS worker-process ids serving an app pool, from appcmd list wp.
function Get-PoolWorkerProcessId {
    param([string]$Pool)
    $appcmd = Get-AppcmdPath
    $pids = New-Object System.Collections.ArrayList
    if ($appcmd -eq '' -or -not (Test-Path $appcmd)) { return $null }
    $out = & $appcmd list wp ('/apppool.name:' + $Pool) 2>&1 | Out-String
    foreach ($line in ($out -split "`r?`n")) {
        if ($line -match '^WP "(\d+)"') { [void]$pids.Add([int]$Matches[1]) }
    }
    return ,$pids
}

# Child processes of the given worker pids, via CIM (Get-Process has no parent
# id on 5.1). CommandLine/ExecutablePath let IIS-006 correlate with web.config.
# A bounded timeout: a wedged WMI provider must not hang the verifier.
function Get-ChildProcessRow {
    param([int[]]$ParentIds, [int]$TimeoutSec = 15)
    if ($ParentIds.Count -eq 0) { return @() }
    $filter = ($ParentIds | ForEach-Object { 'ParentProcessId=' + $_ }) -join ' OR '
    return @(Get-CimInstance -ClassName Win32_Process -Filter $filter -OperationTimeoutSec $TimeoutSec -ErrorAction Stop |
        Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
}

# Physical path of the IIS site (provider first, appcmd fallback). appcmd can
# emit 'ERROR ( message:... )' instead of a path (WI-049), so guard that.
function Get-SitePhysicalPath {
    $phys = ''
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
        if ($site) { $phys = [string]$site.physicalPath }
    } catch { $phys = '' }
    if ($phys -eq '') {
        $appcmd = Get-AppcmdPath
        if ($appcmd -ne '' -and (Test-Path $appcmd)) {
            $siteOut = (& $appcmd list site $SiteName '/text:physicalPath' 2>&1 | Out-String).Trim()
            if ($siteOut -ne '' -and $siteOut -notmatch 'ERROR') { $phys = $siteOut }
        }
    }
    if ($phys -ne '') { $phys = [Environment]::ExpandEnvironmentVariables($phys) }
    return $phys
}

# The HttpPlatformHandler launch spec (processPath + arguments) from a
# web.config's text. Returns $null when it cannot be read.
function Get-BackendLaunchSpec {
    param([string]$WebConfigText)
    try {
        $xml = [xml]$WebConfigText
        $node = $xml.SelectSingleNode('/configuration/system.webServer/httpPlatform')
        if (-not $node -or -not $node.processPath) { return $null }
        return [PSCustomObject]@{
            ProcessPath = [Environment]::ExpandEnvironmentVariables([string]$node.processPath)
            Arguments   = [string]$node.arguments
        }
    } catch { return $null }
}

# The part of the configured arguments that is fixed at launch: everything
# before the first %VAR% placeholder (HttpPlatformHandler substitutes
# %HTTP_PLATFORM_PORT% per start), whitespace-normalised.
function Get-FixedArgumentPrefix {
    param([string]$Arguments)
    if ($null -eq $Arguments) { return '' }
    $idx = $Arguments.IndexOf('%')
    $prefix = $Arguments
    if ($idx -ge 0) { $prefix = $Arguments.Substring(0, $idx) }
    return (($prefix -replace '\s+', ' ').Trim())
}

# Classify worker child rows. A row is CONFIRMED as the cert-watch backend only
# when the site web.config launch spec is known and the row's ExecutablePath or
# CommandLine shows the configured processPath and its command line carries the
# fixed part of the configured arguments. A python.exe that cannot be
# correlated that way (no launch spec, or CIM hid the process details) is
# UNCONFIRMED: it may be the backend, but the check must not claim so.
function Select-BackendProcess {
    param($Rows, $Spec)
    $confirmed = New-Object System.Collections.ArrayList
    $unconfirmed = New-Object System.Collections.ArrayList
    $wantExe = ''
    $wantLeaf = 'python.exe'
    $fixed = ''
    if ($Spec) {
        $wantExe = [string]$Spec.ProcessPath
        if ($wantExe -ne '') { $wantLeaf = (@($wantExe -split '[\\/]')[-1]).ToLower() }
        $fixed = Get-FixedArgumentPrefix $Spec.Arguments
    }
    foreach ($r in @($Rows)) {
        if ($null -eq $r) { continue }
        $name = ([string]$r.Name).ToLower()
        $cmd = (([string]$r.CommandLine) -replace '\s+', ' ')
        $exe = [string]$r.ExecutablePath
        if ($wantExe -ne '') {
            $exeOk = [string]::Equals($exe, $wantExe, [StringComparison]::OrdinalIgnoreCase) -or
                ($cmd.IndexOf($wantExe, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            $argsOk = ($fixed -eq '') -or ($cmd.IndexOf($fixed, [StringComparison]::OrdinalIgnoreCase) -ge 0)
            if ($exeOk -and $argsOk -and ($cmd -ne '' -or $fixed -eq '')) {
                [void]$confirmed.Add($r)
                continue
            }
            if ($exe -eq '' -and $cmd -eq '' -and $name -eq $wantLeaf) { [void]$unconfirmed.Add($r) }
        } elseif ($name -eq 'python.exe') {
            [void]$unconfirmed.Add($r)
        }
    }
    return [PSCustomObject]@{ Confirmed = $confirmed; Unconfirmed = $unconfirmed }
}

# --- What may enter the report ---
# The report (JSON file, -Json stdout, Markdown, console) is meant to be pasted
# into tickets and agent sessions. The guarantee that it carries no secrets
# comes from what is COLLECTED, not from scrubbing:
#   * no free text: log lines, event-log messages, exception messages, HTTP
#     bodies and raw config are never copied in;
#   * URLs are rebuilt structurally (Format-SafeUrl);
#   * config is summarised from an allowlist of settings, each value checked
#     against a strict grammar (ConvertTo-WebConfigSummary, Select-AppcmdField).
# ConvertTo-SafeText / Protect-ReportValue run over the finished report as
# defence in depth only.
$script:Redacted = '[REDACTED]'
$script:SanitizationNote = 'Built for sharing: no log, event or exception text, URLs reduced to scheme://host:port/path, config values only for allowlisted settings with strictly-formed values. Review it before sharing anyway.'

# web.config environment variables whose VALUE may be shown, with the grammar
# the value must match. Names not listed (and values that do not match) show
# as [REDACTED]. Kinds: bool, int, enum:a|b|c, path (rooted, under the install
# or site directory), url (scheme://host:port only).
$script:EnvValueGrammar = @{
    'AUTH_PROVIDER'                  = 'enum:none|ldap|oauth|entra|azure|oidc'
    'CERT_WATCH_LOG_FORMAT'          = 'enum:text|json'
    'CERT_WATCH_TRUST_PROXY'         = 'bool'
    'CERT_WATCH_ALLOW_PRIVATE_IPS'   = 'bool'
    'CERT_WATCH_ALLOW_UNAUTH'        = 'bool'
    'CERT_WATCH_COOKIE_SECURE'       = 'bool'
    'CERT_WATCH_EVENTLOG'            = 'bool'
    'CERT_WATCH_TLS_VERIFY'          = 'bool'
    'CERT_WATCH_LDAP_ALLOW_INSECURE' = 'bool'
    'LDAP_START_TLS'                 = 'bool'
    'LDAP_CONNECT_TIMEOUT'           = 'int'
    'CERT_WATCH_DATA_DIR'            = 'path'
    'CERT_WATCH_AUTH_SECRET_FILE'    = 'path'
    'CERT_WATCH_CSRF_SECRET_FILE'    = 'path'
    'LDAP_BIND_PASSWORD_FILE'        = 'path'
    'CERT_WATCH_BASE_URL'            = 'url'
    'LDAP_SERVER'                    = 'url'
}

# A path is shown only when it is rooted, made of plain path characters, and
# (after normalisation) inside one of the given roots.
function Test-SafePath {
    param([string]$Value, [string[]]$Roots)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value -notmatch '^[A-Za-z0-9 _.\-\\/:()]{1,260}$') { return $false }
    if (-not [System.IO.Path]::IsPathRooted($Value)) { return $false }
    try { $full = [System.IO.Path]::GetFullPath($Value) } catch { return $false }
    foreach ($root in @($Roots | Where-Object { $_ })) {
        try { $r = ([System.IO.Path]::GetFullPath($root)).TrimEnd('\', '/') } catch { continue }
        if ($r -eq '') { continue }
        if ([string]::Equals($full, $r, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        foreach ($sep in @('\', '/')) {
            if ($full.StartsWith($r + $sep, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        }
    }
    return $false
}

# Return $Value when it matches the grammar kind, else [REDACTED].
function Format-GrammarValue {
    param([string]$Value, [string]$Kind, [string[]]$Roots)
    if ($null -eq $Value) { return $script:Redacted }
    if ($Kind -eq 'bool') {
        if ($Value -match '^(?i:0|1|true|false|yes|no|on|off)$') { return $Value }
    } elseif ($Kind -eq 'int') {
        if ($Value -match '^\d{1,6}$') { return $Value }
    } elseif ($Kind -eq 'timespan') {
        if ($Value -match '^\d{1,2}:\d{2}:\d{2}$') { return $Value }
    } elseif ($Kind -like 'enum:*') {
        $allowed = $Kind.Substring(5) -split '\|'
        if ($allowed -contains $Value.ToLower()) { return $Value }
    } elseif ($Kind -eq 'path') {
        if (Test-SafePath $Value $Roots) { return $Value }
    } elseif ($Kind -eq 'url') {
        $u = Format-SafeUrl $Value -NoPath
        if ($u -ne '[unparseable URL]') { return $u }
    } elseif ($Kind -eq 'python') {
        if ((Test-SafePath $Value $Roots) -and ($Value -match '(?i)[\\/]python\.exe$')) { return $Value }
    } elseif ($Kind -like 're:*') {
        if ($Value -match ('^' + $Kind.Substring(3) + '$')) { return $Value }
    }
    return $script:Redacted
}

# httpPlatform arguments are shown only when every token is part of the known
# launch grammar (-m cert_watch --host <addr> --port <port|%VAR%> ...);
# anything else (a literal --token SECRET) withholds the whole string.
function Test-SafeBackendArgument {
    param([string]$Arguments)
    if ($null -eq $Arguments) { return $true }
    $tokens = @($Arguments.Trim() -split '\s+' | Where-Object { $_ -ne '' })
    $expectValue = ''
    foreach ($t in $tokens) {
        if ($expectValue -eq 'module') {
            if ($t -notmatch '^[A-Za-z_][\w.]*$') { return $false }
            $expectValue = ''
        } elseif ($expectValue -eq 'addr') {
            if ($t -notmatch '^(\d{1,3}(\.\d{1,3}){3}|\[?[0-9A-Fa-f:]+\]?|localhost|%\w+%)$') { return $false }
            $expectValue = ''
        } elseif ($expectValue -eq 'port') {
            if ($t -notmatch '^(\d{1,5}|%\w+%)$') { return $false }
            $expectValue = ''
        } elseif ($t -eq '-m') {
            $expectValue = 'module'
        } elseif ($t -eq '--host') {
            $expectValue = 'addr'
        } elseif ($t -eq '--port') {
            $expectValue = 'port'
        } elseif ($t -notmatch '^--(no-)?(proxy-headers|access-log|reload)$') {
            return $false
        }
    }
    return ($expectValue -eq '')
}

function Format-BackendArgument {
    param([string]$Arguments)
    if (Test-SafeBackendArgument $Arguments) { return $Arguments }
    return ($script:Redacted + ' (arguments contain tokens outside the known launch grammar)')
}

# Summarise a web.config for the report. Only settings reached by their FULL
# path from the root, with no namespace, are read (a prefixed or
# default-namespaced element is ignored, as IIS ignores it); every value is
# checked against its grammar. Environment variables are listed by name, with
# a value only for allowlisted names; response headers by name only.
# Unparseable XML yields no summary at all.
function ConvertTo-WebConfigSummary {
    param([string]$Text, [string[]]$Roots)
    $out = [ordered]@{}
    try { $xml = [xml]$Text } catch { return [ordered]@{ note = 'web.config is not well-formed XML; not summarised' } }
    $plat = $xml.SelectSingleNode('/configuration/system.webServer/httpPlatform')
    if ($plat) {
        $hp = [ordered]@{}
        $spec = @(
            @('processPath', 'python'), @('stdoutLogEnabled', 'bool'), @('stdoutLogFile', 'path'),
            @('startupTimeLimit', 'int'), @('startupRetryCount', 'int'), @('rapidFailsPerMinute', 'int'),
            @('processesPerApplication', 'int'), @('requestTimeout', 'timespan')
        )
        foreach ($pair in $spec) {
            if ($plat.HasAttribute($pair[0])) { $hp[$pair[0]] = Format-GrammarValue -Value $plat.GetAttribute($pair[0]) -Kind $pair[1] -Roots $Roots }
        }
        if ($plat.HasAttribute('arguments')) { $hp['arguments'] = Format-BackendArgument $plat.GetAttribute('arguments') }
        $envs = New-Object System.Collections.ArrayList
        foreach ($ev in @($xml.SelectNodes('/configuration/system.webServer/httpPlatform/environmentVariables/add | /configuration/system.webServer/httpPlatform/environmentVariables/environmentVariable'))) {
            $n = [string]$ev.GetAttribute('name')
            if ($n -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$') { [void]$envs.Add([ordered]@{ name = $script:Redacted; value = $script:Redacted }); continue }
            $kind = $script:EnvValueGrammar[$n.ToUpper()]
            $v = $script:Redacted
            if ($kind) { $v = Format-GrammarValue -Value ([string]$ev.GetAttribute('value')) -Kind $kind -Roots $Roots }
            [void]$envs.Add([ordered]@{ name = $n; value = $v })
        }
        $hp['environmentVariables'] = $envs
        $out['httpPlatform'] = $hp
    }
    $handlers = New-Object System.Collections.ArrayList
    foreach ($h in @($xml.SelectNodes('/configuration/system.webServer/handlers/add'))) {
        [void]$handlers.Add([ordered]@{
            name         = Format-GrammarValue -Value $h.GetAttribute('name') -Kind 're:[\w.\-]{1,64}' -Roots $Roots
            path         = Format-GrammarValue -Value $h.GetAttribute('path') -Kind 're:[\w.*\-/]{1,64}' -Roots $Roots
            verb         = Format-GrammarValue -Value $h.GetAttribute('verb') -Kind 're:[\w*, ]{1,64}' -Roots $Roots
            modules      = Format-GrammarValue -Value $h.GetAttribute('modules') -Kind 're:[\w, ]{1,128}' -Roots $Roots
            resourceType = Format-GrammarValue -Value $h.GetAttribute('resourceType') -Kind 're:\w{1,32}' -Roots $Roots
        })
    }
    $out['handlers'] = $handlers
    $headers = New-Object System.Collections.ArrayList
    foreach ($h in @($xml.SelectNodes('/configuration/system.webServer/httpProtocol/customHeaders/add'))) {
        [void]$headers.Add((Format-GrammarValue -Value $h.GetAttribute('name') -Kind 're:[A-Za-z0-9\-]{1,64}' -Roots $Roots))
    }
    $out['responseHeaderNames'] = $headers
    $out['note'] = 'Only allowlisted settings are shown; values outside their expected format are [REDACTED] and everything else in web.config is omitted.'
    return $out
}

# appcmd /text:* fields (apppool + site) whose values are safe to show. Any
# other name:"value" line is dropped (password, adPassword, *Params, and any
# field a future IIS adds).
$script:SafeAppcmdFields = @(
    'APPPOOL.NAME', 'PipelineMode', 'RuntimeVersion', 'state', 'name', 'queueLength', 'autoStart',
    'enable32BitAppOnWin64', 'enableEmulationOnWinArm64', 'managedRuntimeVersion', 'managedRuntimeLoader',
    'enableConfigurationOverride', 'managedPipelineMode', 'CLRConfigFile', 'passAnonymousToken', 'startMode',
    'identityType', 'userName', 'loadUserProfile', 'setProfileEnvironment', 'logonType', 'manualGroupMembership',
    'idleTimeout', 'idleTimeoutAction', 'maxProcesses', 'shutdownTimeLimit', 'startupTimeLimit', 'pingingEnabled',
    'pingInterval', 'pingResponseTime', 'logEventOnProcessModel', 'disallowOverlappingRotation',
    'disallowRotationOnConfigChange', 'logEventOnRecycle', 'memory', 'privateMemory', 'requests', 'time',
    'loadBalancerCapabilities', 'orphanWorkerProcess', 'rapidFailProtection', 'rapidFailProtectionInterval',
    'rapidFailProtectionMaxCrashes', 'limit', 'action', 'resetInterval', 'smpAffinitized', 'processorGroup',
    'numaNodeAssignment', 'numaNodeAffinityMode',
    'SITE.NAME', 'SITE.ID', 'bindings', 'id', 'serverAutoStart', 'protocol', 'bindingInformation', 'sslFlags',
    'maxBandwidth', 'maxConnections', 'connectionTimeout', 'maxUrlSegments', 'logExtFileFlags', 'logFormat',
    'logTargetW3C', 'directory', 'period', 'truncateSize', 'localTimeRollover', 'enabled', 'logSiteId',
    'flushByEntryCountW3CLog', 'maxLogLineLength', 'maxCustomFieldLength', 'maxLogFiles', 'maxLogFileSizeKB',
    'customActionsEnabled', 'max-age', 'includeSubDomains', 'preload', 'redirectHttpToHttps', 'path',
    'applicationPool', 'enabledProtocols', 'serviceAutoStartEnabled', 'preloadEnabled', 'physicalPath',
    'logonMethod', 'allowSubDirConfig'
)

# Keep only allowlisted name:"value" fields of appcmd /text:* output (plus
# [section] headers); every other line is dropped.
function Select-AppcmdField {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $kept = New-Object System.Collections.ArrayList
    $dropped = 0
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*\[[\w.]+\]\s*$') { [void]$kept.Add($line.TrimEnd()); continue }
        if ($line -match '^(\s*)([^:"\s]+):"([^"]*)"\s*$' -and ($script:SafeAppcmdFields -contains $Matches[2]) -and ($Matches[3] -match '^[\w .:\-*\[\]\\/,@%()]{0,256}$')) {
            [void]$kept.Add($line.TrimEnd())
            continue
        }
        if ($line.Trim() -ne '') { $dropped++ }
    }
    if ($dropped -gt 0) { [void]$kept.Add('(' + $dropped + ' other lines omitted)') }
    return ($kept -join "`n")
}

# Final sanitizer for any free text (exception messages, URLs, log lines).
$script:SecretWord = '(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|key|signature|credential|auth)'
# A name that looks secret: contains one of the words, or is exactly sig.
$script:SecretName = '(?:[\w.\-]*' + $script:SecretWord + '[\w.\-]*|sig)'
function ConvertTo-SafeText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $r = $script:Redacted
    $t = $Text
    # URL userinfo (user and password before the host) -> scheme://[REDACTED]@host
    $t = [regex]::Replace($t, '(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s@?#]+@', ('$1' + $r + '@'))
    # Authorization header values, and bare Bearer/Basic/... credentials.
    $t = [regex]::Replace($t, '(?i)\b((?:proxy-)?authorization\s*[:=]\s*)(?:"[^"]*"|(?:bearer|basic|digest|negotiate|ntlm|token)\s+\S+|\S+)', ('$1' + $r))
    $t = [regex]::Replace($t, '(?i)\b(bearer|basic|negotiate|ntlm)\s+(?!\[REDACTED\])[A-Za-z0-9._~+/=\-]{6,}', ('$1 ' + $r))
    # --secret-flag value / --secret-flag=value
    $t = [regex]::Replace($t, ('(?i)(?<![\w\-])(--?[\w\-]*' + $script:SecretWord + '[\w\-]*)(\s*=\s*|\s+)(?!"?\[REDACTED\])("[^"]*"|' + [char]39 + '[^' + [char]39 + ']*' + [char]39 + '|\S+)'), ('$1$2' + $r))
    # name=value, name: value, name:"value", query parameters (?sig=... &token=...)
    $t = [regex]::Replace($t, ('(?i)(?<![\w.\-])(' + $script:SecretName + ')(\s*[:=]\s*)(?!"?\[REDACTED\])("[^"]*"|' + [char]39 + '[^' + [char]39 + ']*' + [char]39 + '|[^\s&;,"' + [char]39 + '<>]+)'), ('$1$2' + $r))
    return $t
}

# Return a sanitized copy of a report object tree (dictionaries, lists,
# PSCustomObjects): every string value AND every key / property name passes
# through ConvertTo-SafeText.
function Protect-ReportValue {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (ConvertTo-SafeText $Value) }
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($k in @($Value.Keys)) {
            $nk = ConvertTo-SafeText ([string]$k)
            while ($copy.Contains($nk)) { $nk = $nk + '_' }
            $copy[$nk] = Protect-ReportValue $Value[$k]
        }
        return $copy
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $copy = [ordered]@{}
        foreach ($p in @($Value.PSObject.Properties)) {
            $nk = ConvertTo-SafeText ([string]$p.Name)
            while ($copy.Contains($nk)) { $nk = $nk + '_' }
            $copy[$nk] = Protect-ReportValue $p.Value
        }
        return [PSCustomObject]$copy
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $Value) { [void]$list.Add((Protect-ReportValue $item)) }
        return ,$list
    }
    if ($Value -is [ValueType]) { return $Value }
    return (ConvertTo-SafeText ([string]$Value))
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
    if ($out -match 'Python\s+(\d+)\.(\d+)(\.\d+)?') {
        $ver = 'Python ' + $Matches[1] + '.' + $Matches[2] + $Matches[3]
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]
        if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 12)) {
            return (New-Body 'pass' $ver)
        }
        return (New-Body 'fail' ('too old: ' + $ver))
    }
    return (New-Body 'fail' 'interpreter did not report a version (run it by hand to see its output)')
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
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            if ($out -match '(\d+\.\d+(\.\d+)?)') { return (New-Body 'pass' ('cert_watch module runs, version ' + $Matches[1])) }
            return (New-Body 'pass' 'cert_watch module runs')
        }
        return (New-Body 'fail' ('cert_watch module did not run (exit ' + $code + '); run it by hand to see its output'))
    }
    return (New-Body 'fail' 'no console script and no interpreter to probe')
}

# ---------------------------------------------------------------------------
# Checks: secrets / signing keys
# ---------------------------------------------------------------------------

Add-Check -Id 'SEC-001' -Title 'Persistent signing keys exist and are non-empty' -Category 'secrets' -Severity 'high' -Remediation 'Without persisted AUTH/CSRF secrets every recycle logs all users out. Re-run install-windows.ps1 to generate them.' -Test {
    $missing = New-Object System.Collections.ArrayList
    foreach ($f in @($authSecret, $csrfSecret)) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf -ErrorAction SilentlyContinue)) { [void]$missing.Add($f); continue }
        try { $len = (Get-Item -LiteralPath $f -ErrorAction Stop).Length } catch {
            [void]$missing.Add($f + ' (not readable: ' + (Format-ErrorSummary $_) + ')')
            continue
        }
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
        return (New-Body 'pass' ('grant present for ' + $identity) -Evidence (Select-AceLine $out))
    }
    return (New-Body 'fail' ('no ACL entry for ' + $identity) -Evidence (Select-AceLine $out))
}

Add-Check -Id 'ACL-002' -Title 'App-pool identity can read the Python install' -Category 'acl' -Severity 'high' -Remediation 'Without RX on the interpreter dir, HttpPlatformHandler logs "Access is denied" and IIS hangs. See deploy/iis/README.md Step 2a.5.' -Test {
    if ($AppPool -eq '') { return (New-Body 'skip' 'no -AppPool supplied') }
    $real = Get-VenvRealPython $venvPython
    if ($real -eq '' -or -not (Test-Path $real)) { return (New-Body 'skip' 'real interpreter path not resolved') }
    $pyDir = Split-Path $real
    $identity = 'IIS AppPool\' + $AppPool
    $out = & icacls $pyDir 2>&1 | Out-String
    if ($out -match [Regex]::Escape($identity)) {
        return (New-Body 'pass' ('grant present on ' + $pyDir) -Evidence (Select-AceLine $out))
    }
    return (New-Body 'fail' ('no ACL entry for ' + $identity + ' on ' + $pyDir) -Evidence (Select-AceLine $out))
}

# ---------------------------------------------------------------------------
# Checks: IIS site + app pool
# ---------------------------------------------------------------------------

Add-Check -Id 'IIS-001' -Title 'handlers config section is unlocked' -Category 'iis' -Severity 'high' -Remediation 'Run: appcmd unlock config -section:system.webServer/handlers (fixes 0x80070021). See deploy/iis/README.md Prerequisites.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $appcmd = Get-AppcmdPath
    $out = & $appcmd list config -section:system.webServer/handlers 2>&1 | Out-String
    if ($out -match '0x80070021' -or $out -match 'locked') {
        return (New-Body 'fail' 'handlers section appears locked at a parent level (appcmd reported 0x80070021 / locked)')
    }
    return (New-Body 'pass' 'handlers section readable (not parent-locked)')
}

Add-Check -Id 'IIS-002' -Title 'Application pool exists and is configured for always-on' -Category 'iis' -Severity 'high' -Remediation 'Apply the Step 2a.4 settings: idleTimeout 0, startMode AlwaysRunning, periodicRestart 0 -- otherwise the scan scheduler stops when the pool idles.' -Test {
    if ($AppPool -eq '') { return (New-Body 'skip' 'no -AppPool supplied') }
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $appcmd = Get-AppcmdPath
    $raw = & $appcmd list apppool $AppPool '/text:*' 2>&1 | Out-String
    if ($raw.Trim() -eq '' -or $raw -match 'ERROR') {
        return (New-Body 'fail' ('app pool not found: ' + $AppPool))
    }
    $out = Select-AppcmdField $raw
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
    # Use the WebAdministration provider as the source of truth. appcmd list
    # site can emit 'ERROR ( message:... )' for a site that actually exists,
    # which previously produced a false 'site not found' warn (WI-049).
    $site = $null
    try {
        Import-Module WebAdministration -ErrorAction SilentlyContinue
        $site = Get-Website -Name $SiteName -ErrorAction SilentlyContinue
    } catch { $site = $null }
    if ($site) {
        $bindings = (@($site.bindings.Collection) | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation }) -join '; '
        return (New-Body 'pass' ('site present: ' + $SiteName + ' [' + $bindings + ']'))
    }
    # Fall back to appcmd if the provider was unavailable.
    $appcmd = Get-AppcmdPath
    $raw = & $appcmd list site $SiteName '/text:*' 2>&1 | Out-String
    if ($raw.Trim() -eq '' -or $raw -match 'ERROR') {
        return (New-Body 'warn' ('site not found: ' + $SiteName + ' (expected for the service / reverse-proxy model)'))
    }
    $out = Select-AppcmdField $raw
    return (New-Body 'pass' ('site present: ' + $SiteName) -Evidence (Limit-Text $out 1200))
}

Add-Check -Id 'IIS-004' -Title 'Application Initialization is installed and registered' -Category 'iis' -Severity 'high' -Remediation 'Install the IIS Application Initialization role service (Web-AppInit / IIS-ApplicationInit) and ensure ApplicationInitializationModule plus warmup.dll are present. preloadEnabled is inert without them.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    $state = Get-AppInitState
    $missing = New-Object System.Collections.ArrayList
    if (-not $state.FeatureEnabled) { [void]$missing.Add('Application Initialization feature disabled') }
    if (-not $state.ModuleRegistered) { [void]$missing.Add('ApplicationInitializationModule not registered') }
    if (-not $state.WarmupDll) { [void]$missing.Add('warmup.dll missing') }
    $evidence = 'featureEnabled=' + $state.FeatureEnabled + '; moduleRegistered=' + $state.ModuleRegistered + '; warmupDll=' + $state.WarmupDll
    if ($missing.Count -gt 0) {
        return (New-Body 'fail' ($missing -join '; ') -Evidence $evidence)
    }
    return (New-Body 'pass' 'Application Initialization feature, module, and binary are present' -Evidence $evidence)
}

Add-Check -Id 'IIS-005' -Title 'IIS application preload is enabled' -Category 'iis' -Severity 'high' -Remediation 'Set applicationDefaults.preloadEnabled=true for the cert-watch IIS site. AlwaysRunning alone does not start HttpPlatformHandler until the first request.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    $sitePath = 'IIS:\Sites\' + $SiteName
    $site = Get-Item $sitePath -ErrorAction SilentlyContinue
    if (-not $site) { return (New-Body 'skip' ('site not found: ' + $SiteName)) }
    # Get-ItemProperty returns a ConfigurationAttribute whose .Value holds the
    # bool (reading a property named 'applicationDefaults.preloadEnabled' off
    # it yields nothing, which made this check fail on a correctly configured
    # site). ConvertTo-IisBool handles that shape, a bare bool, and the legacy
    # PSCustomObject-with-dotted-name shape.
    $legacyName = 'applicationDefaults.preloadEnabled'
    $readErr = ''
    $raw = $null
    try {
        $raw = Get-ItemProperty $sitePath -Name $legacyName -ErrorAction Stop
    } catch { $readErr = Format-ErrorSummary $_ }
    $enabled = ConvertTo-IisBool $raw $legacyName
    $evidence = 'Get-ItemProperty: ' + (Format-IisValue $raw)
    if ($null -eq $enabled) {
        # Second source of truth: the configuration API directly.
        try {
            $filter = 'system.applicationHost/sites/site[@name=''' + $SiteName + ''']/applicationDefaults'
            $raw2 = Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $filter -Name 'preloadEnabled' -ErrorAction Stop
            $enabled = ConvertTo-IisBool $raw2
            $evidence = $evidence + '; Get-WebConfigurationProperty: ' + (Format-IisValue $raw2)
        } catch { $readErr = $readErr + ' ' + (Format-ErrorSummary $_) }
    }
    if ($null -eq $enabled) {
        return (New-Body 'fail' 'could not read applicationDefaults.preloadEnabled' -Evidence ($evidence + '; ' + $readErr))
    }
    if ($enabled) {
        return (New-Body 'pass' 'applicationDefaults.preloadEnabled is true' -Evidence ('preloadEnabled=True (' + $evidence + ')'))
    }
    return (New-Body 'fail' 'applicationDefaults.preloadEnabled is not true' -Evidence ('preloadEnabled=False (' + $evidence + ')'))
}

Add-Check -Id 'IIS-006' -Title 'Backend process is running under the app pool worker' -Category 'iis' -Severity 'medium' -Remediation 'Recycle the app pool (appcmd recycle apppool /apppool.name:<pool>) so preload respawns the backend. Saving web.config stops python.exe and IIS does not restart it until a request arrives, so the scheduler stalls.' -Test {
    if (-not (Test-IisAvailable)) { return (New-Body 'skip' 'IIS not detected on this host') }
    Import-Module WebAdministration -ErrorAction SilentlyContinue
    if (-not (Get-Item ('IIS:\Sites\' + $SiteName) -ErrorAction SilentlyContinue)) {
        return (New-Body 'skip' ('site not found: ' + $SiteName))
    }
    $pool = Get-SiteAppPool
    if ($pool -eq '') { return (New-Body 'warn' 'could not determine the app pool serving the site; backend state unknown') }
    $recycle = 'appcmd recycle apppool /apppool.name:' + $pool
    $pids = Get-PoolWorkerProcessId $pool
    if ($null -eq $pids) { return (New-Body 'warn' 'appcmd not available; backend state unknown') }
    if ($pids.Count -eq 0) {
        return (New-Body 'warn' ('no IIS worker process (w3wp) is running for app pool ' + $pool + '; the backend is down. Start or recycle the pool: ' + $recycle))
    }
    $spec = $null
    $specNote = ''
    $phys = Get-SitePhysicalPath
    if ($phys -ne '') {
        $wc = Read-TextFileSafely (Join-Path $phys 'web.config')
        if ($wc.Ok) { $spec = Get-BackendLaunchSpec $wc.Text } else { $specNote = 'web.config ' + $wc.Error }
    }
    try { $rows = Get-ChildProcessRow -ParentIds ([int[]]@($pids)) } catch {
        return (New-Body 'warn' ('could not list worker child processes (CIM query failed or timed out); backend state unknown: ' + (Format-ErrorSummary $_)))
    }
    $sel = Select-BackendProcess $rows $spec
    $evidence = 'pool=' + $pool + '; w3wp pids=' + ($pids -join ',')
    if ($spec) {
        $evidence = $evidence + '; processPath=' + (Format-GrammarValue -Value $spec.ProcessPath -Kind 'python' -Roots @($InstallDir)) + '; arguments=' + (Format-BackendArgument $spec.Arguments)
    } else {
        $evidence = $evidence + '; web.config launch spec unreadable'
        if ($specNote -ne '') { $evidence = $evidence + ' (' + $specNote + ')' }
    }
    $describe = { param($list) ($list | ForEach-Object { [string]$_.Name + ' pid ' + $_.ProcessId + ' (parent ' + $_.ParentProcessId + ')' }) -join '; ' }
    if ($sel.Confirmed.Count -gt 0) {
        return (New-Body 'pass' ('backend running: ' + (& $describe $sel.Confirmed)) -Evidence $evidence)
    }
    if ($sel.Unconfirmed.Count -gt 0) {
        return (New-Body 'warn' ('a ' + ($sel.Unconfirmed[0].Name) + ' process is running under the worker, but it could not be confirmed as the cert-watch backend (launch spec unreadable or process details unavailable): ' + (& $describe $sel.Unconfirmed)) -Evidence $evidence)
    }
    $others = @($rows | ForEach-Object { [string]$_.Name + ' pid ' + $_.ProcessId }) -join '; '
    if ($others -ne '') { $evidence = $evidence + '; other worker children: ' + $others }
    return (New-Body 'warn' ('IIS worker is up but the configured backend is not running under it, so the scheduler is not scanning (typical after saving web.config). The HTTP checks below may start it on demand; recycle the pool to restore preload: ' + $recycle) -Evidence $evidence)
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
            return (New-Body 'pass' ($r.Url + ' returned 200') -Evidence (Format-SafeBody $r.Body))
        }
    }
    return (New-Body 'fail' ('no probe URL returned 200; last: ' + $last))
}

Add-Check -Id 'HTTP-002' -Title 'Readiness endpoint returns 200' -Category 'http' -Severity 'high' -Remediation 'readyz failing while healthz passes usually means the DB / data dir is not writable by the app-pool identity.' -Test {
    if ($script:HealthBaseUsed -eq '') { return (New-Body 'skip' 'no reachable base URL from HTTP-001') }
    $r = Invoke-Http ($script:HealthBaseUsed + '/readyz')
    if ($r.Ok -and $r.Code -eq 200) { return (New-Body 'pass' 'readyz 200' -Evidence (Format-SafeBody $r.Body)) }
    return (New-Body 'fail' ('readyz code ' + $r.Code + ' ' + $r.Error) -Evidence (Format-SafeBody $r.Body))
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
    $d['note'] = 'No log, event-log or exception TEXT is included. Review the listed log files and events yourself and attach them if needed.'

    # Log files: path, size and time only -- never their content.
    try {
        $files = @(Get-ChildItem -Path $logDir -Filter 'stdout*.log' -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending | Select-Object -First 10)
        $d['stdout_logs'] = @($files | ForEach-Object {
            [ordered]@{ path = $_.FullName; sizeBytes = [int64]$_.Length; lastWriteUtc = $_.LastWriteTimeUtc.ToString('o') }
        })
    } catch { $d['stdout_logs'] = 'log directory not readable (' + (Format-ErrorSummary $_) + ')' }

    # Application events: id, source, level and time only -- never the message.
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = (Get-Date).AddHours(-2) } -MaxEvents 40 -ErrorAction Stop |
            Where-Object { $_.ProviderName -match '(?i)HttpPlatform|IIS|W3SVC|WAS|Application Error' }
        $d['application_events'] = @($events | ForEach-Object {
            [ordered]@{ timeUtc = $_.TimeCreated.ToUniversalTime().ToString('o'); source = [string]$_.ProviderName; id = [int]$_.Id; level = [string]$_.LevelDisplayName }
        })
    } catch { $d['application_events'] = 'event log unavailable (' + (Format-ErrorSummary $_) + ')' }

    if (Test-IisAvailable) {
        $appcmd = Get-AppcmdPath
        try { $d['iis_apppool_config'] = Select-AppcmdField (& $appcmd list apppool $AppPool '/text:*' 2>&1 | Out-String) } catch { $d['iis_apppool_config'] = 'n/a' }
        try { $d['iis_site_config'] = Select-AppcmdField (& $appcmd list site $SiteName '/text:*' 2>&1 | Out-String) } catch { $d['iis_site_config'] = 'n/a' }
        try {
            $wpOut = & $appcmd list wp 2>&1 | Out-String
            $d['iis_worker_processes'] = @([regex]::Matches($wpOut, 'WP "(\d+)" \(applicationPool:([\w .\-]{1,64})\)') | ForEach-Object {
                [ordered]@{ pid = [int]$_.Groups[1].Value; appPool = $_.Groups[2].Value }
            })
        } catch { $d['iis_worker_processes'] = 'n/a' }
        try {
            $phys = Get-SitePhysicalPath
            if ($phys -ne '') {
                $wc = Read-TextFileSafely (Join-Path $phys 'web.config')
                if ($wc.Ok) { $d['web_config'] = ConvertTo-WebConfigSummary $wc.Text @($InstallDir, $phys) }
                else { $d['web_config'] = 'web.config ' + $wc.Error }
            }
        } catch { $d['web_config'] = 'n/a (' + (Format-ErrorSummary $_) + ')' }
    } else {
        $d['iis'] = 'IIS not detected (service / reverse-proxy model or app not IIS-hosted)'
    }

    try { $d['acl_data_dir'] = Select-AceLine (& icacls $InstallDir 2>&1 | Out-String) } catch { $d['acl_data_dir'] = 'n/a' }
    try {
        $real = Get-VenvRealPython $venvPython
        if ($real -ne '' -and (Test-Path $real)) {
            $d['acl_python_dir'] = Select-AceLine (& icacls (Split-Path $real) 2>&1 | Out-String)
        }
    } catch { $d['acl_python_dir'] = 'n/a' }

    try {
        $d['processes'] = @(Get-Process -ErrorAction Stop | Where-Object { $_.ProcessName -match '(?i)^(python\d*|w3wp|cert-watch|uvicorn)$' } | ForEach-Object {
            [ordered]@{ pid = [int]$_.Id; name = [string]$_.ProcessName; workingSetMB = [Math]::Round($_.WorkingSet64 / 1MB, 1) }
        })
    } catch { $d['processes'] = 'process list unavailable (' + (Format-ErrorSummary $_) + ')' }

    # http.sys TLS bindings: only the binding, certificate hash, app id and
    # store fields.
    try {
        $ssl = & netsh http show sslcert 2>&1 | Out-String
        $bindings = New-Object System.Collections.ArrayList
        $cur = $null
        foreach ($line in ($ssl -split "`r?`n")) {
            if ($line -match '^\s*(IP:port|Hostname:port|Central Certificate Store)\s*:\s*([\w.:\[\]\-*]{1,128})\s*$') {
                $cur = [ordered]@{ binding = $Matches[1] + ' ' + $Matches[2] }
                [void]$bindings.Add($cur)
            } elseif ($cur -and $line -match '^\s*(Certificate Hash|Application ID|Certificate Store Name)\s*:\s*([\w{}\-()]{1,80})\s*$') {
                $cur[$Matches[1]] = $Matches[2]
            }
        }
        $d['sslcert_bindings'] = $bindings
    } catch { $d['sslcert_bindings'] = 'n/a' }

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
    sanitization   = $script:SanitizationNote
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
        baseUrl    = $(if ($script:HealthBaseUsed -ne '') { Format-SafeUrl $script:HealthBaseUsed } else { (@($probeUrls | ForEach-Object { Format-SafeUrl $_ }) -join ', ') })
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

# Defence in depth: every key and string in the report passes through
# ConvertTo-SafeText. From here on, EVERYTHING that is written or printed --
# the JSON file, -Json stdout, the Markdown and the console summary -- is
# rendered from this one sanitized object.
$report = Protect-ReportValue $report

# ---------------------------------------------------------------------------
# Emit
# ---------------------------------------------------------------------------
if ($OutputPath -eq '') {
    if (-not (Test-Path $logDir)) {
        try { New-Item -ItemType Directory -Force -Path $logDir -ErrorAction Stop | Out-Null } catch { Write-Verbose 'could not create the log directory' }
    }
    if (Test-Path $logDir) { $OutputPath = Join-Path $logDir 'verify-report.json' }
    else { $OutputPath = Join-Path (Get-Location) 'verify-report.json' }
}
$safeOutputPath = ConvertTo-SafeText $OutputPath

$jsonText = $report | ConvertTo-Json -Depth 12
$writeNote = ''
try {
    Set-Content -Path $OutputPath -Value $jsonText -Encoding UTF8 -ErrorAction Stop
    $wrote = $safeOutputPath
} catch {
    $wrote = '(not written)'
    $writeNote = 'could not write the report to ' + $safeOutputPath + ' (' + (Format-ErrorSummary $_) + ')'
}

if ($Markdown) {
    $mdPath = [System.IO.Path]::ChangeExtension($OutputPath, '.md')
    $sum = $report.summary
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# cert-watch install verification')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('- Host: ' + $report.host.name)
    [void]$sb.AppendLine('- Generated (UTC): ' + $report.generatedAtUtc)
    [void]$sb.AppendLine('- Overall: ' + ([string]$sum.overall).ToUpper() + ' (' + $sum.passed + ' pass / ' + $sum.failed + ' fail / ' + $sum.warned + ' warn / ' + $sum.skipped + ' skip)')
    [void]$sb.AppendLine('- ' + $report.sanitization)
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('| Status | ID | Check | Detail |')
    [void]$sb.AppendLine('|---|---|---|---|')
    foreach ($c in $report.checks) {
        [void]$sb.AppendLine('| ' + ([string]$c.status).ToUpper() + ' | ' + $c.id + ' | ' + $c.title + ' | ' + ([string]$c.detail -replace '\|', '/') + ' |')
    }
    if (@($report.nextActions).Count -gt 0) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('## Next actions')
        foreach ($a in $report.nextActions) { [void]$sb.AppendLine('- ' + $a) }
    }
    try { Set-Content -Path $mdPath -Value ($sb.ToString()) -Encoding UTF8 -ErrorAction Stop } catch {
        $mdNote = 'could not write the Markdown report to ' + (ConvertTo-SafeText $mdPath) + ' (' + (Format-ErrorSummary $_) + ')'
        if ($writeNote -eq '') { $writeNote = $mdNote } else { $writeNote = $writeNote + '; ' + $mdNote }
    }
}

# Console summary (human-facing; ASCII status tags), from the sanitized report.
$sum = $report.summary
Write-Host ''
Write-Host ('cert-watch verify  ::  overall=' + ([string]$sum.overall).ToUpper() + '  (' + $sum.passed + ' pass / ' + $sum.failed + ' fail / ' + $sum.warned + ' warn / ' + $sum.skipped + ' skip)')
Write-Host ('report: ' + $wrote)
if ($writeNote -ne '') { Write-Host ('warning: ' + (ConvertTo-SafeText $writeNote)) }
Write-Host ('note: ' + $report.sanitization)
Write-Host ''
foreach ($c in $report.checks) {
    $tag = '[' + ([string]$c.status).ToUpper() + ']'
    $tag = $tag.PadRight(7)
    Write-Host ($tag + $c.id + '  ' + $c.title)
    if ($c.status -eq 'fail' -or $c.status -eq 'warn') {
        Write-Host ('         ' + $c.detail)
    }
}
if (@($report.nextActions).Count -gt 0) {
    Write-Host ''
    Write-Host 'Next actions:'
    foreach ($a in $report.nextActions) { Write-Host ('  - ' + $a) }
}

if ($Json) {
    Write-Output $jsonText
}

if ($overall -eq 'fail') { exit 1 } else { exit 0 }
