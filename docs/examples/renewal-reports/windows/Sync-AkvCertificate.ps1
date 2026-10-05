<#
.SYNOPSIS
    Keep a Windows machine certificate in step with an Azure Key Vault
    certificate, using the Azure Arc machine identity, and report renewals to
    cert-watch.

.DESCRIPTION
    TEMPLATE. The deployment step (Invoke-CertificateUpdate) is deliberately
    left for you to define: importing the PFX and rebinding IIS, RDP, SQL
    Server, an agent or a service differs on every host.

    Each run:

      1. Takes a token for https://vault.azure.net from the Azure Arc
         (Connected Machine agent) managed identity endpoint.
      2. Reads the current version of the Key Vault certificate (public part
         only) and checks that it is enabled and inside its validity window.
      3. Finds the certificate that is installed now: first the thumbprint
         saved by the previous run, then a store search by identity (subject
         CN plus the exact set of DNS SANs).
      4. Compares the two by SHA-256. When they differ and the vault
         certificate is newer, it reports "started" to cert-watch, calls
         Invoke-CertificateUpdate, checks that the new certificate is in the
         store with a private key, and reports "succeeded" with the new leaf
         fingerprint (or "failed" with the error).
      5. Saves the identity, the installed thumbprint and the outcome in a
         JSON state file for the next run.

    An unchanged certificate sends nothing to cert-watch. cert-watch reports
    describe renewal attempts, not heartbeats: a bare "succeeded" with nothing
    deployed would raise "Renewal not deployed". cert-watch's own scans show
    that the endpoint is healthy.

    Reporting is best effort. A cert-watch outage or rejection is logged and
    never changes the outcome or the exit code of a renewal.

    Exit codes:
      0  Up to date, or updated successfully (also: -WhatIf run)
      1  Update attempted and failed (reported as "failed")
      2  Check failed: identity token, Key Vault, or unusable vault certificate
      3  Configuration error
      4  Refused by policy: vault certificate is not newer than the installed
         one, or its CN/SANs differ from the tracked identity
      5  Another run for the same certificate holds the lock
    PowerShell itself exits 1 when it rejects a parameter (for example an
    invalid -VaultName) before the script starts; the error text says so.

.PARAMETER VaultName
    Key Vault name (the first label of https://<name>.vault.azure.net).

.PARAMETER CertificateName
    Key Vault certificate name. The current (latest) version is used.

.PARAMETER CertWatchUrl
    cert-watch base URL, for example https://cert-watch.example.com.

.PARAMETER CertWatchHost
    Monitored endpoint host name for reports (recommended). Without it,
    reports target the SHA-256 fingerprint of the installed certificate, which
    cert-watch answers with 409 when several endpoints serve it.

.PARAMETER CertWatchPort
    Monitored endpoint port. Default 443.

.PARAMETER CertWatchKeySecretName
    Name of a Key Vault secret (in the same vault) that holds the cert-watch
    renewal-report key. Preferred: nothing secret is stored on the machine.

.PARAMETER CertWatchKeyFile
    Alternative to CertWatchKeySecretName: a file that holds exactly the
    cwk_ token, optionally followed by one LF. CRLF, a byte-order mark and any
    ACL entry granting read access to Everyone, Authenticated Users or Users
    are rejected.

.PARAMETER MatchSubjectCN
    Override the tracked identity CN. Normally the identity is learned from
    the vault certificate on the first run and kept in the state file.

.PARAMETER MatchDnsName
    Override the tracked identity DNS SAN set (exact set match).

.PARAMETER AcceptIdentityChange
    Deploy a vault certificate whose CN or DNS SANs differ from the tracked
    identity, and track the new identity afterwards. Without this switch such
    a certificate is refused (exit 4).

.PARAMETER AllowOlderCertificate
    Deploy a vault certificate that does not expire later than the installed
    one. Without this switch it is refused (exit 4).

.PARAMETER ReportCheckFailures
    Also report "failed" to cert-watch when the check itself fails (token,
    Key Vault, policy refusal). Requires CertWatchHost. Off by default: a
    "Renewal failed" condition stays open until a new certificate is observed
    or an operator clears it, so a transient Key Vault outage would leave a
    sticky alert.

.EXAMPLE
    # Dry run: shows the decision without deploying, reporting or saving state.
    .\Sync-AkvCertificate.ps1 -VaultName kv-example -CertificateName www-example-com `
        -CertWatchUrl https://cert-watch.example.com `
        -CertWatchHost www.example.com -CertWatchKeySecretName cert-watch-report-key -WhatIf

.EXAMPLE
    # Daily scheduled task as SYSTEM (SYSTEM can read the Arc challenge files).
    $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' +
        '"C:\Program Files\CertWatch\Sync-AkvCertificate.ps1" -VaultName kv-example ' +
        '-CertificateName www-example-com -CertWatchUrl https://cert-watch.example.com ' +
        '-CertWatchHost www.example.com -CertWatchKeySecretName cert-watch-report-key'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Daily -At 3am -RandomDelay (New-TimeSpan -Hours 1)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName 'CertWatch AKV sync (www-example-com)' `
        -Action $action -Trigger $trigger -Principal $principal

.NOTES
    Requirements
      - Windows PowerShell 5.1 or PowerShell 7. No Az modules are needed.
      - Azure Arc Connected Machine agent with its system-assigned identity.
        The account running the script must be in the local Administrators or
        "Hybrid agent extension applications" group to answer the token
        challenge.
      - Key Vault data-plane access for the machine identity. With Azure RBAC:
        "Key Vault Certificate User" on the certificate (or vault) to read the
        certificate and its private key. "Key Vault Secrets User" on the
        CertWatchKeySecretName secret if you use it. Check the role
        definitions against current Azure documentation before assigning.
      - Network: https to <vault>.vault.azure.net (system proxy is honoured)
        and to cert-watch. The Arc endpoint is local and never proxied.
      - A cert-watch API key with the renewal-report scope, bound to a host
        tag that covers CertWatchHost.

    Files (default StateDirectory %ProgramData%\CertWatch\AkvSync, created with
    an ACL for SYSTEM and Administrators only):
      <vault>_<certificate>.json   identity, installed thumbprint, last outcome
      <vault>_<certificate>.log    one line per event, rotated at 1 MiB

    Only certificates with a private key are considered installed. Only DNS
    SANs take part in identity matching; IP SANs are ignored.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9-]{3,24}$')]
    [string]$VaultName,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9-]{1,127}$')]
    [string]$CertificateName,

    [Parameter(Mandatory = $true)]
    [string]$CertWatchUrl,

    [string]$CertWatchHost,

    [ValidateRange(1, 65535)]
    [int]$CertWatchPort = 443,

    [ValidatePattern('^[A-Za-z0-9-]{1,127}$')]
    [string]$CertWatchKeySecretName,

    [string]$CertWatchKeyFile,

    [string]$MatchSubjectCN,

    [string[]]$MatchDnsName,

    [switch]$AcceptIdentityChange,

    [switch]$AllowOlderCertificate,

    [switch]$ReportCheckFailures,

    [ValidateSet('LocalMachine', 'CurrentUser')]
    [string]$StoreLocation = 'LocalMachine',

    [string]$StoreName = 'My',

    [string]$StateDirectory = (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CertWatch\AkvSync'),

    [string]$VaultDnsSuffix = 'vault.azure.net',

    [string]$KeyVaultApiVersion = '7.4',

    [ValidatePattern('^[A-Za-z0-9._+-]{1,64}$')]
    [string]$ToolName = 'akv-arc-sync'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Deployment step: DEFINE THIS
# ---------------------------------------------------------------------------

function Invoke-CertificateUpdate {
    <#
        Install $Context.Vault into the store and move every consumer from
        the old certificate to the new one. Return the thumbprint of the
        installed certificate. Throw on any failure; the caller reports
        "failed" with the exception message, so keep secrets out of it.

        $Context fields:
          Vault         Key Vault certificate (see Get-AkvCertificate):
                        .Certificate (public X509Certificate2), .Thumbprint,
                        .Sha256, .Version, .SecretId, .NotAfter
          Installed     Currently installed X509Certificate2, or $null on a
                        first deployment
          StoreLocation / StoreName
          Token         Key Vault access token
          KeyVaultApiVersion

        A typical implementation:

          $bytes = Get-AkvCertificatePfx -SecretId $Context.Vault.SecretId `
              -Token $Context.Token -ApiVersion $Context.KeyVaultApiVersion
          try {
              $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]'MachineKeySet, PersistKeySet'
              $collection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
              $collection.Import($bytes, $null, $flags)
              $leaf = $collection | Where-Object { $_.Thumbprint -eq $Context.Vault.Thumbprint }
              # Add $leaf (and intermediates, to CA) with X509Store.Add.
              # Grant the service account read access to the private key if needed.
          } finally {
              [Array]::Clear($bytes, 0, $bytes.Length)
          }
          # Rebind consumers, for example:
          #   IIS:  (Get-WebBinding -Name 'Site' -Protocol https).AddSslCertificate($thumb, 'My')
          #   RDP:  Set-CimInstance on Win32_TSGeneralSetting SSLCertificateSHA1Hash
          #   service: update its config, then Restart-Service
          # Optionally remove or archive $Context.Installed afterwards.
          return $Context.Vault.Thumbprint

        Leaving the PFX key exportable or writing the PFX to disk are choices
        to make deliberately; this template does neither.
    #>
    param([Parameter(Mandatory = $true)] $Context)

    throw [System.NotImplementedException]::new(
        'Invoke-CertificateUpdate is a template stub: define the import and rebind steps for this host.')
}

# ---------------------------------------------------------------------------
# Logging and small helpers
# ---------------------------------------------------------------------------

$script:LogFile = $null

function Write-SyncLog {
    param(
        [Parameter(Mandatory = $true)] [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')] [string]$Level = 'INFO'
    )
    $line = '{0} {1} {2}' -f (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'), $Level, $Message
    switch ($Level) {
        'WARN' { Write-Warning $Message }
        default { Write-Host $line }
    }
    if ($script:LogFile) {
        try {
            if ((Test-Path -LiteralPath $script:LogFile) -and
                (Get-Item -LiteralPath $script:LogFile).Length -gt 1MB) {
                Move-Item -LiteralPath $script:LogFile -Destination ($script:LogFile + '.1') -Force -WhatIf:$false
            }
            Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 -WhatIf:$false
        } catch {
            Write-Warning ('cannot write log file: {0}' -f $_.Exception.Message)
        }
    }
}

function New-RandomHex {
    param([int]$Bytes = 16)
    $buffer = New-Object byte[] $Bytes
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($buffer) } finally { $rng.Dispose() }
    return -join ($buffer | ForEach-Object { $_.ToString('x2') })
}

function Get-CertificateSha256 {
    param([Parameter(Mandatory = $true)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Certificate.RawData) } finally { $sha.Dispose() }
    return -join ($hash | ForEach-Object { $_.ToString('x2') })
}

function ConvertTo-ReportText {
    # cert-watch rejects control characters other than tab and newline, C1
    # controls and bidi overrides, and caps messages at 2000 code points.
    param([AllowEmptyString()] [string]$Text)
    if ($null -eq $Text) { return '' }
    $clean = [regex]::Replace($Text, '[\x00-\x08\x0B-\x1F\x7F-\x9F\u202A-\u202E\u2066-\u2069]', ' ')
    if ($clean.Length -gt 1900) { $clean = $clean.Substring(0, 1900) + '...' }
    return $clean
}

# ---------------------------------------------------------------------------
# HTTP (System.Net.Http works the same on 5.1 and 7 and never throws on status)
# ---------------------------------------------------------------------------

$script:HttpClients = @{}

function Get-HttpClient {
    param([bool]$UseProxy = $true)
    $key = [string]$UseProxy
    if (-not $script:HttpClients.ContainsKey($key)) {
        Add-Type -AssemblyName System.Net.Http
        if ($PSVersionTable.PSEdition -ne 'Core') {
            # .NET Framework: make sure TLS 1.2 is offered regardless of the
            # machine's SchUseStrongCrypto setting.
            [Net.ServicePointManager]::SecurityProtocol =
                [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        }
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.UseProxy = $UseProxy
        $handler.AllowAutoRedirect = $false
        $client = New-Object System.Net.Http.HttpClient -ArgumentList $handler
        $client.Timeout = [TimeSpan]::FromSeconds(30)
        $script:HttpClients[$key] = $client
    }
    return $script:HttpClients[$key]
}

function Invoke-Http {
    param(
        [Parameter(Mandatory = $true)] [string]$Method,
        [Parameter(Mandatory = $true)] [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$JsonBody,
        [bool]$UseProxy = $true
    )
    # Create the client first: on Windows PowerShell it loads System.Net.Http.
    $client = Get-HttpClient -UseProxy $UseProxy
    $request = New-Object System.Net.Http.HttpRequestMessage -ArgumentList ([System.Net.Http.HttpMethod]::new($Method)), $Uri
    foreach ($name in $Headers.Keys) {
        [void]$request.Headers.TryAddWithoutValidation($name, [string]$Headers[$name])
    }
    if ($PSBoundParameters.ContainsKey('JsonBody')) {
        $request.Content = New-Object System.Net.Http.StringContent -ArgumentList $JsonBody, ([Text.UTF8Encoding]::new($false)), 'application/json'
    }
    try {
        try {
            $response = $client.SendAsync($request).GetAwaiter().GetResult()
        } catch {
            # Surface the root cause (DNS, refused, TLS, timeout) instead of
            # the wrapper text; the URI carries no secrets.
            $e = $_.Exception
            $messages = New-Object System.Collections.Generic.List[string]
            while ($e) {
                if ($e -isnot [System.Management.Automation.MethodInvocationException] -and -not $messages.Contains($e.Message)) { $messages.Add($e.Message) }
                $e = $e.InnerException
            }
            if ($_.Exception -is [System.Threading.Tasks.TaskCanceledException]) { $messages.Add('timed out') }
            throw ('{0} {1}://{2}{3} failed: {4}' -f $Method, ([Uri]$Uri).Scheme, ([Uri]$Uri).Authority, ([Uri]$Uri).AbsolutePath, ($messages -join ' -> '))
        }
        $responseHeaders = @{}
        foreach ($pair in $response.Headers) {
            $responseHeaders[$pair.Key.ToLowerInvariant()] = ($pair.Value -join ', ')
        }
        return [pscustomobject]@{
            StatusCode = [int]$response.StatusCode
            Headers    = $responseHeaders
            Body       = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
    } finally {
        $request.Dispose()
    }
}

function Get-ErrorDetail {
    # Key Vault and cert-watch return JSON errors; keep just the useful text.
    param($Response)
    try {
        $json = $Response.Body | ConvertFrom-Json
        if ($json.PSObject.Properties['error']) {
            if ($json.error -is [string]) { return $json.error }
            return ('{0}: {1}' -f $json.error.code, $json.error.message)
        }
    } catch { }  # not JSON: fall through to the raw body
    $body = [string]$Response.Body
    if ($body.Length -gt 300) { $body = $body.Substring(0, 300) }
    return $body
}

function Get-JsonProperty {
    # Optional JSON fields: StrictMode forbids reading a missing property.
    param($Object, [Parameter(Mandatory = $true)] [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

# ---------------------------------------------------------------------------
# Azure Arc managed identity
# ---------------------------------------------------------------------------

function Get-ArcTokenEndpoint {
    $endpoint = $env:IDENTITY_ENDPOINT
    if (-not $endpoint) {
        # A task or service started before the agent was installed has a stale
        # environment block; the machine scope is authoritative.
        $endpoint = [Environment]::GetEnvironmentVariable('IDENTITY_ENDPOINT', 'Machine')
    }
    if (-not $endpoint) {
        throw 'IDENTITY_ENDPOINT is not set: this machine is not Azure Arc-enabled, or the Connected Machine agent is not running.'
    }
    $uri = [Uri]$endpoint
    # The challenge answer is a local secret; never send it off the machine.
    if ($uri.Scheme -ne 'http' -or -not $uri.IsLoopback) {
        throw ('IDENTITY_ENDPOINT {0} is not a loopback http endpoint; refusing to use it.' -f $endpoint)
    }
    return $endpoint
}

function Test-ArcChallengePath {
    # The same checks the Azure SDKs apply: the file must be a .key file of at
    # most 4096 bytes directly inside %ProgramData%\AzureConnectedMachineAgent\Tokens.
    param([Parameter(Mandatory = $true)] [string]$Path)
    $expected = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AzureConnectedMachineAgent\Tokens'
    $full = [IO.Path]::GetFullPath($Path)
    $parent = [IO.Path]::GetDirectoryName($full)
    if (-not [string]::Equals($parent.TrimEnd('\'), $expected.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Arc challenge file {0} is not in {1}.' -f $full, $expected)
    }
    if (-not [string]::Equals([IO.Path]::GetExtension($full), '.key', [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Arc challenge file {0} does not have a .key extension.' -f $full)
    }
    $item = Get-Item -LiteralPath $full -ErrorAction Stop
    if ($item.Length -gt 4096) {
        throw ('Arc challenge file {0} is larger than 4096 bytes.' -f $full)
    }
    return $full
}

function Get-ArcManagedIdentityToken {
    param([string]$Resource = 'https://vault.azure.net')
    $endpoint = Get-ArcTokenEndpoint
    $uri = '{0}?api-version=2020-06-01&resource={1}' -f $endpoint, [Uri]::EscapeDataString($Resource)

    $challenge = Invoke-Http -Method GET -Uri $uri -Headers @{ Metadata = 'true' } -UseProxy $false
    if ($challenge.StatusCode -ne 401 -or -not $challenge.Headers.ContainsKey('www-authenticate')) {
        throw ('Arc identity endpoint answered {0} without a challenge: {1}' -f $challenge.StatusCode, (Get-ErrorDetail $challenge))
    }
    $match = [regex]::Match($challenge.Headers['www-authenticate'], 'Basic realm=(.+)$')
    if (-not $match.Success) {
        throw 'Arc identity endpoint sent an unexpected WWW-Authenticate challenge.'
    }
    $keyPath = Test-ArcChallengePath -Path $match.Groups[1].Value.Trim()
    try {
        $secret = [IO.File]::ReadAllText($keyPath).Trim()
    } catch [UnauthorizedAccessException] {
        throw 'Cannot read the Arc challenge file: run as SYSTEM, an administrator, or a member of "Hybrid agent extension applications".'
    }

    $response = Invoke-Http -Method GET -Uri $uri -Headers @{ Metadata = 'true'; Authorization = ('Basic ' + $secret) } -UseProxy $false
    $secret = $null
    if ($response.StatusCode -ne 200) {
        throw ('Arc identity endpoint returned {0}: {1}' -f $response.StatusCode, (Get-ErrorDetail $response))
    }
    $token = Get-JsonProperty ($response.Body | ConvertFrom-Json) 'access_token'
    if (-not $token) { throw 'Arc identity endpoint returned no access_token.' }
    return $token
}

# ---------------------------------------------------------------------------
# Key Vault
# ---------------------------------------------------------------------------

function ConvertFrom-UnixTime {
    param($Seconds)
    if ($null -eq $Seconds) { return $null }
    return [DateTimeOffset]::FromUnixTimeSeconds([long]$Seconds).UtcDateTime
}

function Get-AkvCertificate {
    param(
        [Parameter(Mandatory = $true)] [string]$VaultBaseUri,
        [Parameter(Mandatory = $true)] [string]$Name,
        [Parameter(Mandatory = $true)] [string]$Token,
        [Parameter(Mandatory = $true)] [string]$ApiVersion
    )
    $uri = '{0}/certificates/{1}?api-version={2}' -f $VaultBaseUri, $Name, $ApiVersion
    $response = Invoke-Http -Method GET -Uri $uri -Headers @{ Authorization = ('Bearer ' + $Token) }
    if ($response.StatusCode -ne 200) {
        $hint = ''
        if ($response.StatusCode -eq 403) { $hint = ' (does the machine identity have Key Vault Certificate User?)' }
        throw ('Key Vault returned {0} for certificate {1}{2}: {3}' -f $response.StatusCode, $Name, $hint, (Get-ErrorDetail $response))
    }
    $bundle = $response.Body | ConvertFrom-Json
    $cer = Get-JsonProperty $bundle 'cer'
    if (-not $cer) { throw ('Key Vault certificate {0} has no issued version yet.' -f $Name) }

    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, [Convert]::FromBase64String($cer))
    $id = [string](Get-JsonProperty $bundle 'id')
    return [pscustomobject]@{
        Id          = $id
        Version     = ($id -split '/')[-1]
        SecretId    = Get-JsonProperty $bundle 'sid'
        ContentType = Get-JsonProperty (Get-JsonProperty (Get-JsonProperty $bundle 'policy') 'secret_props') 'contentType'
        Enabled     = [bool](Get-JsonProperty (Get-JsonProperty $bundle 'attributes') 'enabled')
        Certificate = $certificate
        Thumbprint  = $certificate.Thumbprint
        Sha256      = Get-CertificateSha256 $certificate
        NotBefore   = $certificate.NotBefore.ToUniversalTime()
        NotAfter    = $certificate.NotAfter.ToUniversalTime()
    }
}

function Get-AkvSecretValue {
    param(
        [Parameter(Mandatory = $true)] [string]$SecretUri,
        [Parameter(Mandatory = $true)] [string]$Token,
        [Parameter(Mandatory = $true)] [string]$ApiVersion
    )
    $uri = '{0}?api-version={1}' -f $SecretUri, $ApiVersion
    $response = Invoke-Http -Method GET -Uri $uri -Headers @{ Authorization = ('Bearer ' + $Token) }
    if ($response.StatusCode -ne 200) {
        throw ('Key Vault returned {0} for secret {1}: {2}' -f $response.StatusCode, ($SecretUri -split '/secrets/')[-1], (Get-ErrorDetail $response))
    }
    $secret = $response.Body | ConvertFrom-Json
    return [pscustomobject]@{ Value = Get-JsonProperty $secret 'value'; ContentType = Get-JsonProperty $secret 'contentType' }
}

function Get-AkvCertificatePfx {
    # The private key of a Key Vault certificate is served as its backing
    # secret: base64 PKCS#12 for application/x-pkcs12. PEM-format vault
    # certificates are not handled here; switch the policy to PKCS#12.
    param(
        [Parameter(Mandatory = $true)] [string]$SecretId,
        [Parameter(Mandatory = $true)] [string]$Token,
        [Parameter(Mandatory = $true)] [string]$ApiVersion
    )
    $secret = Get-AkvSecretValue -SecretUri $SecretId -Token $Token -ApiVersion $ApiVersion
    if ($secret.ContentType -ne 'application/x-pkcs12') {
        throw ('Key Vault certificate secret has content type {0}; only application/x-pkcs12 is supported.' -f $secret.ContentType)
    }
    return , [Convert]::FromBase64String($secret.Value)
}

# ---------------------------------------------------------------------------
# Certificate identity (CN + DNS SANs) and store lookup
# ---------------------------------------------------------------------------

function Read-DerLength {
    param([byte[]]$Data, [ref]$Offset)
    $first = $Data[$Offset.Value]; $Offset.Value++
    if ($first -lt 0x80) { return [int]$first }
    $count = $first -band 0x7F
    if ($count -lt 1 -or $count -gt 3) { throw 'unsupported DER length' }
    $length = 0
    for ($i = 0; $i -lt $count; $i++) {
        $length = ($length -shl 8) -bor $Data[$Offset.Value]; $Offset.Value++
    }
    return $length
}

function Get-CertificateDnsNames {
    # Parse the SAN extension (2.5.29.17) directly: X509Extension.Format()
    # output is localized, and .NET Framework has no SAN API. dNSName is the
    # context-specific primitive tag [2] (0x82).
    param([Parameter(Mandatory = $true)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if (-not $extension) { return @() }
    $data = $extension.RawData
    $offset = 0
    if ($data[$offset] -ne 0x30) { throw 'SAN extension is not a DER SEQUENCE' }
    $offset++
    $end = (Read-DerLength -Data $data -Offset ([ref]$offset)) + $offset
    if ($end -gt $data.Length) { throw 'SAN extension length is out of range' }
    $names = New-Object System.Collections.Generic.List[string]
    while ($offset -lt $end) {
        $tag = $data[$offset]; $offset++
        $length = Read-DerLength -Data $data -Offset ([ref]$offset)
        if ($offset + $length -gt $end) { throw 'SAN entry length is out of range' }
        if ($tag -eq 0x82) {
            $names.Add([Text.Encoding]::ASCII.GetString($data, $offset, $length).ToLowerInvariant())
        }
        $offset += $length
    }
    return $names.ToArray()
}

function Get-CertificateCommonName {
    param([Parameter(Mandatory = $true)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    # Decode with one RDN per line so a comma inside a value cannot split it.
    $flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]'UseNewLines, DoNotUsePlusSign'
    foreach ($rdn in ($Certificate.SubjectName.Decode($flags) -split "`r?`n")) {
        if ($rdn -match '^\s*CN=(.*)$') { return $Matches[1].Trim().Trim('"').ToLowerInvariant() }
    }
    return ''
}

function Get-CertificateIdentity {
    param([Parameter(Mandatory = $true)] [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return [pscustomobject]@{
        CommonName = Get-CertificateCommonName $Certificate
        DnsNames   = @(Get-CertificateDnsNames $Certificate | Sort-Object -Unique)
    }
}

function New-Identity {
    param([string]$CommonName, [string[]]$DnsNames)
    $names = @()
    if ($DnsNames) { $names = @($DnsNames | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique) }
    $cn = ''
    if ($CommonName) { $cn = $CommonName.Trim().ToLowerInvariant() }
    return [pscustomobject]@{ CommonName = $cn; DnsNames = $names }
}

function Test-IdentityMatch {
    # Exact match: same CN and the same set of DNS SANs. A partial overlap is
    # not the same certificate role and must not be replaced silently.
    param([Parameter(Mandatory = $true)] $Identity, [Parameter(Mandatory = $true)] $Candidate)
    if ($Identity.CommonName -ne $Candidate.CommonName) { return $false }
    $left = @($Identity.DnsNames) -join "`n"
    $right = @($Candidate.DnsNames) -join "`n"
    return $left -eq $right
}

function Format-Identity {
    param($Identity)
    return ('CN={0}; DNS=[{1}]' -f $Identity.CommonName, (@($Identity.DnsNames) -join ', '))
}

function Get-StoreCertificates {
    param([string]$Location, [string]$Name)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $Name, $Location
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]'ReadOnly, OpenExistingOnly')
    try { return , @($store.Certificates) } finally { $store.Close() }
}

function Find-InstalledCertificate {
    # Returns @{ Certificate; Method } or $null. The thumbprint saved by the
    # last run wins, so a renewal that leaves the old certificate in the store
    # cannot confuse the next run. Otherwise: exact identity match with a
    # private key, latest expiry first.
    param(
        [Parameter(Mandatory = $true)] [AllowEmptyCollection()] [object[]]$Certificates,
        [Parameter(Mandatory = $true)] $Identity,
        [string]$PreferredThumbprint
    )
    $now = (Get-Date).ToUniversalTime()
    if ($PreferredThumbprint) {
        $saved = $Certificates | Where-Object { $_.Thumbprint -eq $PreferredThumbprint -and $_.HasPrivateKey } | Select-Object -First 1
        if ($saved) { return [pscustomobject]@{ Certificate = $saved; Method = 'state thumbprint' } }
        Write-SyncLog -Level WARN ('Saved thumbprint {0} is no longer in the store with a private key; searching by identity.' -f $PreferredThumbprint)
    }
    $matched = @($Certificates | Where-Object {
            $_.HasPrivateKey -and -not $_.Archived -and (Test-IdentityMatch -Identity $Identity -Candidate (Get-CertificateIdentity $_))
        } | Sort-Object -Property @{ Expression = { $_.NotAfter }; Descending = $true }, @{ Expression = { $_.NotBefore }; Descending = $true })
    if ($matched.Count -eq 0) { return $null }
    if ($matched.Count -gt 1) {
        Write-SyncLog -Level WARN ('{0} certificates match {1}; using the latest expiry {2}. Others: {3}' -f
            $matched.Count, (Format-Identity $Identity), $matched[0].Thumbprint, (($matched | Select-Object -Skip 1 | ForEach-Object { $_.Thumbprint }) -join ', '))
    }
    if ($matched[0].NotAfter.ToUniversalTime() -lt $now) {
        Write-SyncLog -Level WARN ('The installed certificate {0} expired at {1:u}.' -f $matched[0].Thumbprint, $matched[0].NotAfter.ToUniversalTime())
    }
    return [pscustomobject]@{ Certificate = $matched[0]; Method = 'identity match' }
}

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

function Initialize-StateDirectory {
    param([Parameter(Mandatory = $true)] [string]$Path)
    if (Test-Path -LiteralPath $Path) { return }
    $null = New-Item -ItemType Directory -Path $Path -Force -WhatIf:$false
    # SYSTEM and Administrators only, not inherited from ProgramData (where
    # Users can create files).
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    foreach ($sid in 'S-1-5-18', 'S-1-5-32-544') {
        $identity = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sid
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $identity, 'FullControl', $inherit, 'None', 'Allow'
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -WhatIf:$false
}

function Read-SyncState {
    param([Parameter(Mandatory = $true)] [string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        $state = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($state.schema -ne 1) { throw ('unsupported schema {0}' -f $state.schema) }
        return $state
    } catch {
        # State only speeds up lookup and pins the identity; a damaged file
        # falls back to the identity of the vault certificate.
        Write-SyncLog -Level WARN ('Ignoring unreadable state file {0}: {1}' -f $Path, $_.Exception.Message)
        return $null
    }
}

function Save-SyncState {
    param([Parameter(Mandatory = $true)] [string]$Path, [Parameter(Mandatory = $true)] $State)
    $temp = $Path + '.tmp'
    $State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $Path -Force
}

# ---------------------------------------------------------------------------
# cert-watch reporting (best effort: never throws)
# ---------------------------------------------------------------------------

function Test-SecretFileAcl {
    param([Parameter(Mandatory = $true)] [string]$Path)
    $broad = @('S-1-1-0', 'S-1-5-11', 'S-1-5-32-545')  # Everyone, Authenticated Users, Users
    # ReadData, GENERIC_ALL, GENERIC_READ (generic bits appear on inherited ACEs)
    $readMask = [int64]1 -bor [int64]268435456 -bor [int64]2147483648
    foreach ($rule in (Get-Acl -LiteralPath $Path).Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
        if ($broad -contains $sid -and (([int64]$rule.FileSystemRights) -band $readMask)) {
            throw ('{0} is readable by {1}; restrict it to SYSTEM and Administrators.' -f $Path, $rule.IdentityReference)
        }
    }
}

function Assert-CertWatchKey {
    param([AllowEmptyString()] [string]$Key)
    if ($Key -notmatch '^cwk_[A-Za-z0-9_-]+$') {
        throw 'invalid renewal-report key (expected cwk_ followed by A-Z a-z 0-9 _ -)'
    }
}

function Read-CertWatchKeyFile {
    # Same contract as cw-report.sh: exactly the token, optionally one LF.
    # Write it with: [IO.File]::WriteAllText($path, $token)
    param([Parameter(Mandatory = $true)] [string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw ('key file {0} does not exist' -f $Path) }
    Test-SecretFileAcl -Path $Path
    $bytes = [IO.File]::ReadAllBytes($Path)
    $length = $bytes.Length
    if ($length -gt 0 -and $bytes[$length - 1] -eq 0x0A) { $length-- }
    for ($i = 0; $i -lt $length; $i++) {
        if ($bytes[$i] -lt 0x21 -or $bytes[$i] -gt 0x7E) {
            throw 'key file holds a byte-order mark, CR, NUL or other non-token byte (write it with [IO.File]::WriteAllText)'
        }
    }
    $key = [Text.Encoding]::ASCII.GetString($bytes, 0, $length)
    Assert-CertWatchKey $key
    return $key
}

function Get-CertWatchKey {
    param([Parameter(Mandatory = $true)] $Reporter)
    if ($Reporter.KeyFile) { return Read-CertWatchKeyFile -Path $Reporter.KeyFile }
    if (-not $Reporter.Session.Token) { throw 'no Key Vault token to read the cert-watch key secret' }
    $secret = Get-AkvSecretValue -SecretUri $Reporter.KeySecretUri -Token $Reporter.Session.Token -ApiVersion $Reporter.ApiVersion
    $value = [string]$secret.Value
    Assert-CertWatchKey $value
    return $value
}

function Send-CertWatchReport {
    param(
        [Parameter(Mandatory = $true)] $Reporter,
        [Parameter(Mandatory = $true)] [ValidateSet('started', 'succeeded', 'failed')] [string]$Outcome,
        [string]$NewFingerprint,
        [string]$Message
    )
    try {
        $body = [ordered]@{ outcome = $Outcome }
        if ($Reporter.Host) {
            $body.hostname = $Reporter.Host
            $body.port = [int]$Reporter.Port
        } elseif ($Reporter.TargetFingerprint) {
            $body.cert_fingerprint = $Reporter.TargetFingerprint
        } else {
            Write-SyncLog -Level WARN ('cert-watch {0} report skipped: no -CertWatchHost and no installed certificate to target by fingerprint.' -f $Outcome)
            return $false
        }
        if ($NewFingerprint) { $body.new_fingerprint = $NewFingerprint }
        if ($Message) { $body.message = ConvertTo-ReportText $Message }
        $body.tool = $Reporter.Tool
        $body.correlation_id = $Reporter.Correlation
        $body.occurred_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'+00:00'")
        $json = $body | ConvertTo-Json -Compress

        $key = Get-CertWatchKey -Reporter $Reporter
        $headers = @{ Authorization = ('Bearer ' + $key); 'Idempotency-Key' = (New-RandomHex 16) }
        $key = $null
        $uri = $Reporter.BaseUrl.TrimEnd('/') + '/api/renewal-reports'

        # Retry 429, 5xx and transport errors with the same idempotency key and
        # body, as the API asks. The per-endpoint limit is 5 reports a minute.
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            $response = $null
            try {
                $response = Invoke-Http -Method POST -Uri $uri -Headers $headers -JsonBody $json
            } catch {
                Write-SyncLog -Level WARN ('cert-watch {0} report attempt {1} failed: {2}' -f $Outcome, $attempt, $_.Exception.Message)
            }
            if ($response) {
                if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                    Write-SyncLog ('cert-watch accepted {0} report: {1}' -f $Outcome, $response.Body)
                    return $true
                }
                $detail = Get-ErrorDetail $response
                if ($response.StatusCode -ne 429 -and $response.StatusCode -lt 500) {
                    Write-SyncLog -Level WARN ('cert-watch rejected {0} report with HTTP {1}: {2}' -f $Outcome, $response.StatusCode, $detail)
                    return $false
                }
                Write-SyncLog -Level WARN ('cert-watch returned HTTP {0} for {1} report (attempt {2}): {3}' -f $response.StatusCode, $Outcome, $attempt, $detail)
            }
            if ($attempt -lt 3) {
                $delay = 15
                if ($response -and $response.Headers.ContainsKey('retry-after')) {
                    $parsed = 0
                    if ([int]::TryParse($response.Headers['retry-after'], [ref]$parsed)) { $delay = [Math]::Min([Math]::Max($parsed, 1), 60) }
                }
                Start-Sleep -Seconds $delay
            }
        }
        Write-SyncLog -Level WARN ('cert-watch {0} report not delivered; the renewal outcome is unaffected.' -f $Outcome)
        return $false
    } catch {
        Write-SyncLog -Level WARN ('cert-watch {0} report not sent: {1}' -f $Outcome, $_.Exception.Message)
        return $false
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

function Invoke-AkvCertificateSync {
    param([Parameter(Mandatory = $true)] $Config)

    $statePath = Join-Path $Config.StateDirectory ('{0}_{1}.json' -f $Config.VaultName, $Config.CertificateName)
    $state = Read-SyncState -Path $statePath
    $vaultBaseUri = 'https://{0}.{1}' -f $Config.VaultName, $Config.VaultDnsSuffix
    $session = [pscustomobject]@{ Token = $null }

    $reporter = [pscustomobject]@{
        BaseUrl           = $Config.CertWatchUrl
        Host              = $Config.CertWatchHost
        Port              = $Config.CertWatchPort
        TargetFingerprint = $null
        Tool              = $Config.ToolName
        Correlation       = New-RandomHex 16
        KeyFile           = $Config.CertWatchKeyFile
        KeySecretUri      = '{0}/secrets/{1}' -f $vaultBaseUri, $Config.CertWatchKeySecretName
        ApiVersion        = $Config.KeyVaultApiVersion
        Session           = $session
    }

    # $record and $checkFailed are plain script blocks invoked with & from this
    # function, so they read $Config, $state and $reporter through dynamic scope.

    $record = {
        param([string]$Result, [string]$Detail, $Identity, $Installed, [string]$VaultVersion)
        if ($Config.WhatIf) { return }
        $previousInstalled = $null
        if ($state -and $state.PSObject.Properties['installed']) { $previousInstalled = $state.installed }
        $installedRecord = $previousInstalled
        if ($Installed) {
            $installedRecord = [ordered]@{
                thumbprint   = $Installed.Thumbprint
                sha256       = Get-CertificateSha256 $Installed
                notAfter     = $Installed.NotAfter.ToUniversalTime().ToString('o')
                vaultVersion = $VaultVersion
            }
        }
        $identityRecord = $null
        if ($Identity) { $identityRecord = [ordered]@{ commonName = $Identity.CommonName; dnsNames = @($Identity.DnsNames) } }
        elseif ($state -and $state.PSObject.Properties['identity']) { $identityRecord = $state.identity }
        $newState = [ordered]@{
            schema          = 1
            vault           = $Config.VaultName
            certificateName = $Config.CertificateName
            identity        = $identityRecord
            installed       = $installedRecord
            lastCheck       = [ordered]@{ at = (Get-Date).ToUniversalTime().ToString('o'); result = $Result; detail = $Detail }
        }
        try { Save-SyncState -Path $statePath -State $newState } catch { Write-SyncLog -Level WARN ('cannot save state: {0}' -f $_.Exception.Message) }
    }

    $checkFailed = {
        param([int]$Code, [string]$Result, [string]$Detail, $Identity)
        Write-SyncLog -Level ERROR $Detail
        & $record $Result $Detail $Identity $null $null
        if ($Config.ReportCheckFailures -and -not $Config.WhatIf) {
            [void](Send-CertWatchReport -Reporter $reporter -Outcome failed -Message ('Key Vault sync check failed: ' + $Detail))
        }
        return $Code
    }

    # 1-2. Token and vault certificate.
    try {
        $session.Token = Get-ArcManagedIdentityToken -Resource 'https://vault.azure.net'
        $vault = Get-AkvCertificate -VaultBaseUri $vaultBaseUri -Name $Config.CertificateName -Token $session.Token -ApiVersion $Config.KeyVaultApiVersion
    } catch {
        return (& $checkFailed 2 'check-failed' $_.Exception.Message $null)
    }
    $now = (Get-Date).ToUniversalTime()
    Write-SyncLog ('Vault {0}/{1} version {2}: {3} SHA-256 {4}, valid {5:u} to {6:u}' -f $Config.VaultName, $Config.CertificateName,
        $vault.Version, $vault.Thumbprint, $vault.Sha256, $vault.NotBefore, $vault.NotAfter)
    if (-not $vault.Enabled -or $vault.NotBefore -gt $now -or $vault.NotAfter -le $now) {
        return (& $checkFailed 2 'check-failed' ('Vault certificate version {0} is disabled, not yet valid or expired; nothing deployed.' -f $vault.Version) $null)
    }

    # 3. Identity: explicit override, then state, then the vault certificate.
    $vaultIdentity = Get-CertificateIdentity $vault.Certificate
    if ($Config.MatchSubjectCN -or $Config.MatchDnsName) {
        $identity = New-Identity -CommonName $Config.MatchSubjectCN -DnsNames $Config.MatchDnsName
        $identitySource = 'parameters'
    } elseif ($state -and $state.PSObject.Properties['identity'] -and $state.identity) {
        $identity = New-Identity -CommonName $state.identity.commonName -DnsNames @($state.identity.dnsNames)
        $identitySource = 'state file'
    } else {
        $identity = $vaultIdentity
        $identitySource = 'vault certificate (first run)'
    }
    Write-SyncLog ('Tracking {0} from {1}' -f (Format-Identity $identity), $identitySource)

    $preferred = $null
    if ($state -and $state.PSObject.Properties['installed'] -and $state.installed) { $preferred = $state.installed.thumbprint }
    try {
        $storeCertificates = Get-StoreCertificates -Location $Config.StoreLocation -Name $Config.StoreName
        $found = Find-InstalledCertificate -Certificates $storeCertificates -Identity $identity -PreferredThumbprint $preferred
    } catch {
        return (& $checkFailed 2 'check-failed' ('Cannot read certificate store {0}\{1}: {2}' -f $Config.StoreLocation, $Config.StoreName, $_.Exception.Message) $identity)
    }
    $installed = $null
    if ($found) {
        $installed = $found.Certificate
        $reporter.TargetFingerprint = Get-CertificateSha256 $installed
        Write-SyncLog ('Installed: {0} expires {1:u} (found by {2})' -f $installed.Thumbprint, $installed.NotAfter.ToUniversalTime(), $found.Method)
    } else {
        Write-SyncLog -Level WARN ('No installed certificate matches {0}; treating this as a first deployment.' -f (Format-Identity $identity))
    }

    # 4. Compare.
    if ($installed -and $reporter.TargetFingerprint -eq $vault.Sha256) {
        Write-SyncLog 'Up to date.'
        & $record 'up-to-date' '' $identity $installed $vault.Version
        return 0
    }
    if (-not (Test-IdentityMatch -Identity $identity -Candidate $vaultIdentity)) {
        if (-not $Config.AcceptIdentityChange) {
            return (& $checkFailed 4 'refused' ('Vault certificate names {0} differ from the tracked {1}; rerun with -AcceptIdentityChange if intended.' -f
                    (Format-Identity $vaultIdentity), (Format-Identity $identity)) $identity)
        }
        Write-SyncLog -Level WARN ('Accepting identity change to {0}' -f (Format-Identity $vaultIdentity))
    }
    if ($installed -and $vault.NotAfter -le $installed.NotAfter.ToUniversalTime() -and -not $Config.AllowOlderCertificate) {
        return (& $checkFailed 4 'refused' ('Vault certificate expires {0:u}, not later than the installed {1} ({2:u}); rerun with -AllowOlderCertificate if intended.' -f
                $vault.NotAfter, $installed.Thumbprint, $installed.NotAfter.ToUniversalTime()) $identity)
    }

    $from = 'nothing installed'
    if ($installed) { $from = $installed.Thumbprint }
    $action = 'Replace {0} with Key Vault {1}/{2} version {3} ({4})' -f $from, $Config.VaultName, $Config.CertificateName, $vault.Version, $vault.Thumbprint
    if (-not $Config.Cmdlet.ShouldProcess($action)) {
        Write-SyncLog ('WhatIf: would {0}' -f $action)
        return 0
    }

    # 5. Deploy and report.
    Write-SyncLog $action
    [void](Send-CertWatchReport -Reporter $reporter -Outcome started -Message $action)
    $context = [pscustomobject]@{
        Vault              = $vault
        Installed          = $installed
        StoreLocation      = $Config.StoreLocation
        StoreName          = $Config.StoreName
        Token              = $session.Token
        KeyVaultApiVersion = $Config.KeyVaultApiVersion
    }
    try {
        $newThumbprint = Invoke-CertificateUpdate -Context $context
        if ($newThumbprint -ne $vault.Thumbprint) {
            throw ('Invoke-CertificateUpdate returned thumbprint {0}, expected {1}.' -f $newThumbprint, $vault.Thumbprint)
        }
        $afterUpdate = Get-StoreCertificates -Location $Config.StoreLocation -Name $Config.StoreName
        $deployed = $afterUpdate | Where-Object { $_.Thumbprint -eq $vault.Thumbprint -and $_.HasPrivateKey } | Select-Object -First 1
        if (-not $deployed) {
            throw ('Certificate {0} is not in {1}\{2} with a private key after the update.' -f $vault.Thumbprint, $Config.StoreLocation, $Config.StoreName)
        }
    } catch {
        $detail = 'Update failed: ' + $_.Exception.Message
        Write-SyncLog -Level ERROR $detail
        [void](Send-CertWatchReport -Reporter $reporter -Outcome failed -NewFingerprint $vault.Sha256 -Message $detail)
        & $record 'failed' $detail $identity $null $null
        return 1
    }

    Write-SyncLog ('Deployed {0}.' -f $vault.Thumbprint)
    [void](Send-CertWatchReport -Reporter $reporter -Outcome succeeded -NewFingerprint $vault.Sha256 -Message ('Deployed Key Vault version {0}' -f $vault.Version))
    $newIdentity = $identity
    if ($identitySource -ne 'parameters') { $newIdentity = $vaultIdentity }
    & $record 'updated' $action $newIdentity $deployed $vault.Version
    return 0
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if ([bool]$CertWatchKeySecretName -eq [bool]$CertWatchKeyFile) {
    Write-Error 'Specify exactly one of -CertWatchKeySecretName and -CertWatchKeyFile.' -ErrorAction Continue
    exit 3
}
if ($ReportCheckFailures -and -not $CertWatchHost) {
    Write-Error '-ReportCheckFailures requires -CertWatchHost.' -ErrorAction Continue
    exit 3
}
$parsedUrl = $null
if (-not [Uri]::TryCreate($CertWatchUrl, [UriKind]::Absolute, [ref]$parsedUrl) -or $parsedUrl.Scheme -notin @('https', 'http')) {
    Write-Error '-CertWatchUrl must be an absolute http(s) URL.' -ErrorAction Continue
    exit 3
}
if ($parsedUrl.Scheme -eq 'http' -and -not $parsedUrl.IsLoopback) {
    Write-Warning 'cert-watch URL is plain http: the renewal-report key will cross the network unencrypted.'
}
if ($CertWatchHost) {
    # cert-watch matches hostnames in canonical form: lower case, no trailing dot.
    $CertWatchHost = $CertWatchHost.Trim().TrimEnd('.').ToLowerInvariant()
}

try {
    Initialize-StateDirectory -Path $StateDirectory
} catch {
    Write-Error ('Cannot create state directory {0}: {1}' -f $StateDirectory, $_.Exception.Message) -ErrorAction Continue
    exit 3
}
$script:LogFile = Join-Path $StateDirectory ('{0}_{1}.log' -f $VaultName, $CertificateName)

$mutex = New-Object System.Threading.Mutex -ArgumentList $false, ('Global\CertWatchAkvSync_{0}_{1}' -f $VaultName, $CertificateName)
$haveLock = $false
try {
    try { $haveLock = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $haveLock = $true }
    if (-not $haveLock) {
        Write-SyncLog -Level WARN 'Another run for this certificate is in progress; exiting.'
        exit 5
    }
    $config = [pscustomobject]@{
        VaultName              = $VaultName
        CertificateName        = $CertificateName
        VaultDnsSuffix         = $VaultDnsSuffix
        KeyVaultApiVersion     = $KeyVaultApiVersion
        CertWatchUrl           = $CertWatchUrl
        CertWatchHost          = $CertWatchHost
        CertWatchPort          = $CertWatchPort
        CertWatchKeySecretName = $CertWatchKeySecretName
        CertWatchKeyFile       = $CertWatchKeyFile
        MatchSubjectCN         = $MatchSubjectCN
        MatchDnsName           = $MatchDnsName
        AcceptIdentityChange   = [bool]$AcceptIdentityChange
        AllowOlderCertificate  = [bool]$AllowOlderCertificate
        ReportCheckFailures    = [bool]$ReportCheckFailures
        StoreLocation          = $StoreLocation
        StoreName              = $StoreName
        StateDirectory         = $StateDirectory
        ToolName               = $ToolName
        WhatIf                 = [bool]$WhatIfPreference
        Cmdlet                 = $PSCmdlet
    }
    $exitCode = Invoke-AkvCertificateSync -Config $config
} catch {
    Write-SyncLog -Level ERROR ('Unexpected error: {0}' -f $_.Exception.Message)
    $exitCode = 2
} finally {
    if ($haveLock) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
exit $exitCode
