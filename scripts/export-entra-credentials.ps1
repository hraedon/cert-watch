<#
.SYNOPSIS
Export application password-credential expiry metadata using an existing Graph session.
.DESCRIPTION
Reads every application page through Get-MgApplication -All. Only explicitly
projected metadata is retained. Nothing is posted to Entra or cert-watch.
The output directory must already exist and should be restricted to the operator.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Get-ExportProperty {
    param([object]$InputObject, [string]$Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function ConvertTo-ExportText {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    if ($Value -isnot [string] -and $Value -isnot [guid]) { return $null }
    $text = $Value.ToString().Trim()
    if ($text.Length -gt 256 -or $text -match '[\x00-\x1F\x7F]') { return $null }
    return $text
}

function ConvertTo-ExportExpiry {
    param([object]$Value)
    if ($Value -is [datetimeoffset]) {
        return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return $null }
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    if ($Value -isnot [string] -or $Value -notmatch '(Z|[+-]\d{2}:\d{2})$') {
        return $null
    }
    $expiry = [datetimeoffset]::MinValue
    $parsed = [datetimeoffset]::TryParse(
        $Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None, [ref]$expiry
    )
    if (-not $parsed) { return $null }
    return $expiry.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

$temporaryPath = $null
try {
    $destination = [IO.Path]::GetFullPath($OutputPath)
    $directory = [IO.Path]::GetDirectoryName($destination)
    if (-not [IO.Directory]::Exists($directory)) { throw 'output directory unavailable' }
    $context = Get-MgContext -ErrorAction Stop -WarningAction SilentlyContinue `
        -InformationAction SilentlyContinue -Verbose:$false -Debug:$false
    $tenant = ConvertTo-ExportText (Get-ExportProperty $context 'TenantId')
    if (-not $tenant) { throw 'a connected tenant is required' }

    # Buffer all pages before touching the destination. A later page failure
    # must not turn a partial inventory into a successful-looking export.
    $applications = @(Get-MgApplication -All `
        -Property @('appId', 'displayName', 'passwordCredentials') `
        -ErrorAction Stop -WarningAction SilentlyContinue `
        -InformationAction SilentlyContinue -Verbose:$false -Debug:$false)
    $records = New-Object 'System.Collections.Generic.List[object]'
    $skipped = 0
    foreach ($application in $applications) {
        $appId = ConvertTo-ExportText (Get-ExportProperty $application 'AppId')
        $appName = ConvertTo-ExportText (Get-ExportProperty $application 'DisplayName')
        if ($appName -eq '') { $appName = $appId }
        foreach ($credential in @(Get-ExportProperty $application 'PasswordCredentials')) {
            if ($null -eq $credential) { continue }
            $keyId = ConvertTo-ExportText (Get-ExportProperty $credential 'KeyId')
            $keyName = ConvertTo-ExportText (Get-ExportProperty $credential 'DisplayName')
            $expiry = ConvertTo-ExportExpiry (Get-ExportProperty $credential 'EndDateTime')
            if (-not $appId -or -not $appName -or -not $keyId -or
                $null -eq $keyName -or -not $expiry) {
                $skipped += 1
                continue
            }
            # Do not serialize the Graph application or credential object.
            # Optional fields are explicit so this matches cert-watch API input.
            $records.Add([ordered]@{
                application_name = $appName
                application_id = $appId
                credential_id = $keyId
                credential_name = $keyName
                tenant_id = $tenant
                expires_at = $expiry
                owner_email = ''
            })
        }
    }
    $json = ConvertTo-Json -InputObject @($records.ToArray()) -Depth 4
    $temporaryPath = [IO.Path]::Combine(
        $directory, ('.cert-watch-entra-' + [guid]::NewGuid().ToString('N') + '.tmp')
    )
    $stream = New-Object IO.FileStream(
        $temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    if ([IO.File]::Exists($destination)) {
        [IO.File]::Replace($temporaryPath, $destination, [NullString]::Value)
    }
    else { [IO.File]::Move($temporaryPath, $destination) }
    $temporaryPath = $null
    if ($skipped -gt 0) {
        Write-Warning ('Skipped credentials with unusable metadata: ' + $skipped)
    }
    [ordered]@{
        applications = $applications.Count
        exported_credentials = $records.Count
        skipped_credentials = $skipped
    } | ConvertTo-Json
    exit 0
}
catch {
    # SDK errors can carry response bodies or diagnostic values. Never echo them.
    Write-Error 'Entra metadata export failed; check the Graph session and output directory.' `
        -ErrorAction Continue
    exit 1
}
finally {
    if ($temporaryPath -and [IO.File]::Exists($temporaryPath)) {
        [IO.File]::Delete($temporaryPath)
    }
}
