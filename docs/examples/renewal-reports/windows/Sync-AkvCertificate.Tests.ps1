# Pester 5 tests for Sync-AkvCertificate.ps1. Run on Windows PowerShell 5.1
# and PowerShell 7:  Invoke-Pester .\Sync-AkvCertificate.Tests.ps1
# Azure Arc, Key Vault and the certificate store are mocked; certificates are
# created in memory and nothing is written outside TestDrive.

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Sync-AkvCertificate.ps1'
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw ('parse errors: ' + ($errors -join '; ')) }
    # Load only the function definitions, not the entry point.
    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
        . ([scriptblock]::Create($fn.Extent.Text))
    }
    Set-StrictMode -Version 2.0
    $script:LogFile = $null
    $script:HttpClients = @{}

    function New-TestCert {
        param([string]$CN, [string[]]$Dns = @(), [int]$StartDays = -1, [int]$Days = 90, [string[]]$Ips = @())
        $rsa = [System.Security.Cryptography.RSA]::Create(2048)
        $subject = 'O=Example'
        if ($CN) { $subject = 'CN=' + $CN + ', O=Example' }
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            $subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        if ($Dns.Count -or $Ips.Count) {
            $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            foreach ($d in $Dns) { $san.AddDnsName($d) }
            foreach ($ip in $Ips) { $san.AddIpAddress([Net.IPAddress]::Parse($ip)) }
            $req.CertificateExtensions.Add($san.Build())
        }
        $now = [DateTimeOffset]::UtcNow
        return $req.CreateSelfSigned($now.AddDays($StartDays), $now.AddDays($StartDays + $Days))
    }

    function New-VaultObject {
        param($Cert, [string]$Version = 'v2', [bool]$Enabled = $true)
        $public = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $Cert.RawData)
        return [pscustomobject]@{
            Id          = 'https://kv-test.vault.azure.net/certificates/www/' + $Version
            Version     = $Version
            SecretId    = 'https://kv-test.vault.azure.net/secrets/www/' + $Version
            ContentType = 'application/x-pkcs12'
            Enabled     = $Enabled
            Certificate = $public
            Thumbprint  = $public.Thumbprint
            Sha256      = Get-CertificateSha256 $public
            NotBefore   = $public.NotBefore.ToUniversalTime()
            NotAfter    = $public.NotAfter.ToUniversalTime()
        }
    }

    function New-TestConfig {
        param([hashtable]$Overrides = @{}, [bool]$Proceed = $true)
        $cmdlet = New-Object psobject
        $cmdlet | Add-Member -MemberType NoteProperty -Name Proceed -Value $Proceed
        $cmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param($action) $this.Proceed }
        $config = [ordered]@{
            VaultName = 'kv-test'; CertificateName = 'www'; VaultDnsSuffix = 'vault.azure.net'
            KeyVaultApiVersion = '7.4'; CertWatchUrl = 'https://cw.example.test'
            CertWatchHost = 'www.example.test'; CertWatchPort = 443
            CertWatchKeySecretName = 'cw-key'; CertWatchKeyFile = $null
            MatchSubjectCN = $null; MatchDnsName = $null
            AcceptIdentityChange = $false; AllowOlderCertificate = $false; ReportCheckFailures = $false
            StoreLocation = 'LocalMachine'; StoreName = 'My'; StateDirectory = (Join-Path $TestDrive 'state')
            ToolName = 'akv-arc-sync'; WhatIf = $false; Cmdlet = $cmdlet
        }
        foreach ($k in $Overrides.Keys) { $config[$k] = $Overrides[$k] }
        if (-not (Test-Path $config.StateDirectory)) { $null = New-Item -ItemType Directory -Path $config.StateDirectory }
        return [pscustomobject]$config
    }

    function Get-StatePath { param($Config) Join-Path $Config.StateDirectory 'kv-test_www.json' }
}

Describe 'Certificate identity' {
    It 'reads DNS SANs only, lower-cased, from DER' {
        $c = New-TestCert -CN 'WWW.Example.test' -Dns 'WWW.example.test', 'api.example.test' -Ips '192.0.2.1'
        @(Get-CertificateDnsNames $c) | Should -Be @('www.example.test', 'api.example.test')
    }
    It 'returns nothing when there is no SAN extension' {
        @(Get-CertificateDnsNames (New-TestCert -CN 'a.example.test')).Count | Should -Be 0
    }
    It 'reads the CN, lower-cased' {
        Get-CertificateCommonName (New-TestCert -CN 'WWW.Example.test') | Should -Be 'www.example.test'
        Get-CertificateCommonName (New-TestCert -CN $null -Dns 'x.example.test') | Should -Be ''
    }
    It 'matches exact CN and SAN set regardless of order and case' {
        $a = Get-CertificateIdentity (New-TestCert -CN 'www.example.test' -Dns 'www.example.test', 'api.example.test')
        $b = New-Identity -CommonName 'WWW.example.test' -DnsNames 'API.example.test', 'www.example.test'
        Test-IdentityMatch -Identity $a -Candidate $b | Should -BeTrue
    }
    It 'does not match a SAN subset or superset' {
        $a = Get-CertificateIdentity (New-TestCert -CN 'www.example.test' -Dns 'www.example.test', 'api.example.test')
        Test-IdentityMatch -Identity $a -Candidate (New-Identity -CommonName 'www.example.test' -DnsNames 'www.example.test') | Should -BeFalse
        Test-IdentityMatch -Identity $a -Candidate (New-Identity -CommonName 'other.example.test' -DnsNames 'www.example.test', 'api.example.test') | Should -BeFalse
    }
}

Describe 'Find-InstalledCertificate' {
    BeforeAll {
        $identity = New-Identity -CommonName 'www.example.test' -DnsNames 'www.example.test'
        $older = New-TestCert -CN 'www.example.test' -Dns 'www.example.test' -StartDays -60 -Days 90
        $newer = New-TestCert -CN 'www.example.test' -Dns 'www.example.test' -StartDays -1 -Days 90
        $other = New-TestCert -CN 'other.example.test' -Dns 'other.example.test' -Days 400
        $publicOnly = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, (New-TestCert -CN 'www.example.test' -Dns 'www.example.test' -Days 800).RawData)
    }
    It 'picks the latest-expiring identity match with a private key' {
        $r = Find-InstalledCertificate -Certificates @($older, $other, $newer, $publicOnly) -Identity $identity
        $r.Certificate.Thumbprint | Should -Be $newer.Thumbprint
        $r.Method | Should -Be 'identity match'
    }
    It 'prefers the thumbprint saved by the previous run' {
        $r = Find-InstalledCertificate -Certificates @($older, $newer) -Identity $identity -PreferredThumbprint $older.Thumbprint
        $r.Certificate.Thumbprint | Should -Be $older.Thumbprint
        $r.Method | Should -Be 'state thumbprint'
    }
    It 'falls back to identity when the saved thumbprint is gone' {
        $r = Find-InstalledCertificate -Certificates @($newer) -Identity $identity -PreferredThumbprint 'ABCDEF'
        $r.Certificate.Thumbprint | Should -Be $newer.Thumbprint
    }
    It 'returns null when nothing matches' {
        Find-InstalledCertificate -Certificates @($other, $publicOnly) -Identity $identity | Should -BeNullOrEmpty
        Find-InstalledCertificate -Certificates @() -Identity $identity | Should -BeNullOrEmpty
    }
}

Describe 'Read-CertWatchKeyFile' {
    BeforeEach { Mock Test-SecretFileAcl { } }
    It 'accepts the token with and without one LF' {
        $p = Join-Path $TestDrive 'k1'
        [IO.File]::WriteAllText($p, 'cwk_abc-DEF_123')
        Read-CertWatchKeyFile $p | Should -Be 'cwk_abc-DEF_123'
        [IO.File]::WriteAllText($p, "cwk_abc-DEF_123`n")
        Read-CertWatchKeyFile $p | Should -Be 'cwk_abc-DEF_123'
    }
    It 'rejects CRLF, a BOM, two newlines and a wrong prefix' {
        $p = Join-Path $TestDrive 'k2'
        [IO.File]::WriteAllText($p, "cwk_abc`r`n"); { Read-CertWatchKeyFile $p } | Should -Throw '*non-token byte*'
        [IO.File]::WriteAllText($p, 'cwk_abc', [Text.UTF8Encoding]::new($true)); { Read-CertWatchKeyFile $p } | Should -Throw '*non-token byte*'
        [IO.File]::WriteAllText($p, "cwk_abc`n`n"); { Read-CertWatchKeyFile $p } | Should -Throw '*non-token byte*'
        [IO.File]::WriteAllText($p, 'abc'); { Read-CertWatchKeyFile $p } | Should -Throw '*invalid renewal-report key*'
        [IO.File]::WriteAllText($p, ''); { Read-CertWatchKeyFile $p } | Should -Throw '*invalid renewal-report key*'
    }
}

Describe 'Test-SecretFileAcl' {
    It 'rejects a file readable by Users and accepts one that is not' {
        $p = Join-Path $TestDrive 'acl'
        [IO.File]::WriteAllText($p, 'cwk_x')
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $me, 'FullControl', 'Allow'))
        Set-Acl -LiteralPath $p -AclObject $acl
        { Test-SecretFileAcl $p } | Should -Not -Throw
        $users = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-545'
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList $users, 'Read', 'Allow'))
        Set-Acl -LiteralPath $p -AclObject $acl
        { Test-SecretFileAcl $p } | Should -Throw '*readable by*'
    }
}

Describe 'Arc managed identity' {
    It 'refuses a non-loopback IDENTITY_ENDPOINT' {
        $saved = $env:IDENTITY_ENDPOINT
        try {
            $env:IDENTITY_ENDPOINT = 'http://169.254.1.1:40342/metadata/identity/oauth2/token'
            { Get-ArcTokenEndpoint } | Should -Throw '*not a loopback*'
            $env:IDENTITY_ENDPOINT = 'https://localhost:40342/metadata/identity/oauth2/token'
            { Get-ArcTokenEndpoint } | Should -Throw '*not a loopback*'
        } finally { $env:IDENTITY_ENDPOINT = $saved }
    }
    It 'rejects challenge files outside the Tokens directory or without .key' {
        { Test-ArcChallengePath 'C:\Windows\Temp\x.key' } | Should -Throw '*is not in*'
        $tokens = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'AzureConnectedMachineAgent\Tokens'
        { Test-ArcChallengePath (Join-Path $tokens 'x.txt') } | Should -Throw '*.key extension*'
        { Test-ArcChallengePath (Join-Path $tokens '..\Certs\x.key') } | Should -Throw '*is not in*'
    }
    It 'answers the challenge with the key file content, locally and unproxied' {
        $keyFile = Join-Path $TestDrive 'c.key'
        [IO.File]::WriteAllText($keyFile, 'challenge-secret')
        Mock Get-ArcTokenEndpoint { 'http://localhost:40342/metadata/identity/oauth2/token' }
        Mock Test-ArcChallengePath { $keyFile }
        $script:calls = @()
        Mock Invoke-Http {
            $script:calls += , @{ Uri = $Uri; Headers = $Headers; UseProxy = $UseProxy }
            if (-not $Headers.ContainsKey('Authorization')) {
                return [pscustomobject]@{ StatusCode = 401; Headers = @{ 'www-authenticate' = 'Basic realm=' + $keyFile }; Body = '' }
            }
            return [pscustomobject]@{ StatusCode = 200; Headers = @{}; Body = '{"access_token":"tok123","expires_in":"3599"}' }
        }
        Get-ArcManagedIdentityToken | Should -Be 'tok123'
        $script:calls.Count | Should -Be 2
        $script:calls[0].Uri | Should -Be 'http://localhost:40342/metadata/identity/oauth2/token?api-version=2020-06-01&resource=https%3A%2F%2Fvault.azure.net'
        $script:calls[1].Headers.Authorization | Should -Be 'Basic challenge-secret'
        $script:calls[1].Headers.Metadata | Should -Be 'true'
        @($script:calls | Where-Object { $_.UseProxy }).Count | Should -Be 0
    }
    It 'fails clearly when the endpoint does not challenge' {
        Mock Get-ArcTokenEndpoint { 'http://localhost:40342/metadata/identity/oauth2/token' }
        Mock Invoke-Http { [pscustomobject]@{ StatusCode = 500; Headers = @{}; Body = '{"error":"boom"}' } }
        { Get-ArcManagedIdentityToken } | Should -Throw '*answered 500 without a challenge*'
    }
}

Describe 'Get-AkvCertificate' {
    It 'parses the certificate bundle' {
        $c = New-TestCert -CN 'www.example.test' -Dns 'www.example.test'
        $bundle = @{
            id = 'https://kv-test.vault.azure.net/certificates/www/abc123'; sid = 'https://kv-test.vault.azure.net/secrets/www/abc123'
            cer = [Convert]::ToBase64String($c.RawData); attributes = @{ enabled = $true }
            policy = @{ secret_props = @{ contentType = 'application/x-pkcs12' } }
        } | ConvertTo-Json -Depth 4
        Mock Invoke-Http { [pscustomobject]@{ StatusCode = 200; Headers = @{}; Body = $bundle } } -ParameterFilter {
            $Uri -eq 'https://kv-test.vault.azure.net/certificates/www?api-version=7.4' -and $Headers.Authorization -eq 'Bearer t'
        }
        $v = Get-AkvCertificate -VaultBaseUri 'https://kv-test.vault.azure.net' -Name 'www' -Token 't' -ApiVersion '7.4'
        $v.Version | Should -Be 'abc123'
        $v.Thumbprint | Should -Be $c.Thumbprint
        $v.Sha256 | Should -Match '^[0-9a-f]{64}$'
        $v.Enabled | Should -BeTrue
        $v.ContentType | Should -Be 'application/x-pkcs12'
    }
    It 'tolerates a bundle without policy and reports 403 with a hint' {
        $c = New-TestCert -CN 'www.example.test'
        $bundle = @{ id = 'https://kv/certificates/www/v1'; sid = 's'; cer = [Convert]::ToBase64String($c.RawData); attributes = @{ enabled = $false } } | ConvertTo-Json
        Mock Invoke-Http { [pscustomobject]@{ StatusCode = 200; Headers = @{}; Body = $bundle } }
        (Get-AkvCertificate -VaultBaseUri 'https://kv' -Name 'www' -Token 't' -ApiVersion '7.4').ContentType | Should -BeNullOrEmpty
        Mock Invoke-Http { [pscustomobject]@{ StatusCode = 403; Headers = @{}; Body = '{"error":{"code":"Forbidden","message":"denied"}}' } }
        { Get-AkvCertificate -VaultBaseUri 'https://kv' -Name 'www' -Token 't' -ApiVersion '7.4' } | Should -Throw '*403*Certificate User*Forbidden: denied*'
    }
    It 'returns PFX bytes intact and refuses PEM secrets' {
        $pfx = [byte[]](1, 2, 3, 0, 255)
        Mock Get-AkvSecretValue { [pscustomobject]@{ Value = [Convert]::ToBase64String($pfx); ContentType = 'application/x-pkcs12' } }
        $bytes = Get-AkvCertificatePfx -SecretId 's' -Token 't' -ApiVersion '7.4'
        $bytes.GetType().Name | Should -Be 'Byte[]'
        $bytes | Should -Be $pfx
        Mock Get-AkvSecretValue { [pscustomobject]@{ Value = 'x'; ContentType = 'application/x-pem-file' } }
        { Get-AkvCertificatePfx -SecretId 's' -Token 't' -ApiVersion '7.4' } | Should -Throw '*only application/x-pkcs12*'
    }
}

Describe 'Send-CertWatchReport' {
    BeforeAll {
        $reporter = [pscustomobject]@{
            BaseUrl = 'https://cw.example.test/'; Host = 'www.example.test'; Port = 8443; TargetFingerprint = ('ab' * 32)
            Tool = 'akv-arc-sync'; Correlation = 'corr1'; KeyFile = $null; KeySecretUri = 's'; ApiVersion = '7.4'
            Session = [pscustomobject]@{ Token = 't' }
        }
    }
    BeforeEach {
        Mock Get-CertWatchKey { 'cwk_test' }
        Mock Start-Sleep { }
        $script:posts = @()
    }
    It 'sends a schema-shaped body to the hostname target' {
        Mock Invoke-Http { $script:posts += , @{ Uri = $Uri; Headers = $Headers; Body = $JsonBody }; [pscustomobject]@{ StatusCode = 202; Headers = @{}; Body = '{}' } }
        Send-CertWatchReport -Reporter $reporter -Outcome succeeded -NewFingerprint ('cd' * 32) -Message ("line1`nbad" + [char]0x202E + 'x') | Should -BeTrue
        $script:posts.Count | Should -Be 1
        $script:posts[0].Uri | Should -Be 'https://cw.example.test/api/renewal-reports'
        $script:posts[0].Headers.Authorization | Should -Be 'Bearer cwk_test'
        $script:posts[0].Headers['Idempotency-Key'] | Should -Match '^[0-9a-f]{32}$'
        $b = $script:posts[0].Body | ConvertFrom-Json
        @($b.PSObject.Properties.Name) | Should -Be @('outcome', 'hostname', 'port', 'new_fingerprint', 'message', 'tool', 'correlation_id', 'occurred_at')
        $script:posts[0].Body | Should -Match '"port":8443[,}]'
        $b.message | Should -Be "line1`nbad x"
        $script:posts[0].Body | Should -Match '"occurred_at":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00"'
    }
    It 'targets the installed fingerprint when no host is configured' {
        Mock Invoke-Http { $script:posts += , @{ Body = $JsonBody }; [pscustomobject]@{ StatusCode = 202; Headers = @{}; Body = '{}' } }
        $r2 = $reporter.PSObject.Copy(); $r2.Host = $null
        Send-CertWatchReport -Reporter $r2 -Outcome started | Should -BeTrue
        $b = $script:posts[0].Body | ConvertFrom-Json
        $b.cert_fingerprint | Should -Be ('ab' * 32)
        $b.PSObject.Properties.Name | Should -Not -Contain 'hostname'
    }
    It 'retries 429 with the same idempotency key and body' {
        Mock Invoke-Http {
            $script:posts += , @{ Headers = $Headers; Body = $JsonBody }
            if ($script:posts.Count -eq 1) { return [pscustomobject]@{ StatusCode = 429; Headers = @{ 'retry-after' = '7' }; Body = '{"error":"slow down"}' } }
            [pscustomobject]@{ StatusCode = 202; Headers = @{}; Body = '{}' }
        }
        Send-CertWatchReport -Reporter $reporter -Outcome started | Should -BeTrue
        $script:posts.Count | Should -Be 2
        $script:posts[1].Headers['Idempotency-Key'] | Should -Be $script:posts[0].Headers['Idempotency-Key']
        $script:posts[1].Body | Should -Be $script:posts[0].Body
        Should -Invoke Start-Sleep -Times 1 -ParameterFilter { $Seconds -eq 7 }
    }
    It 'does not retry a 4xx rejection and never throws' {
        Mock Invoke-Http { $script:posts += , 1; [pscustomobject]@{ StatusCode = 422; Headers = @{}; Body = '{"error":"tool: bad"}' } }
        Send-CertWatchReport -Reporter $reporter -Outcome started | Should -BeFalse
        $script:posts.Count | Should -Be 1
        Mock Get-CertWatchKey { throw 'no key' }
        Send-CertWatchReport -Reporter $reporter -Outcome started | Should -BeFalse
    }
    It 'gives up after three transport failures' {
        Mock Invoke-Http { $script:posts += , 1; throw 'connection refused' }
        Send-CertWatchReport -Reporter $reporter -Outcome failed | Should -BeFalse
        $script:posts.Count | Should -Be 3
    }
}

Describe 'Template stub' {
    It 'throws NotImplementedException until the deployment step is defined' {
        { Invoke-CertificateUpdate -Context ([pscustomobject]@{}) } | Should -Throw -ExceptionType ([System.NotImplementedException])
    }
}

Describe 'Invoke-AkvCertificateSync' {
    BeforeAll {
        $oldCert = New-TestCert -CN 'www.example.test' -Dns 'www.example.test', 'example.test' -StartDays -80 -Days 90
        $newCert = New-TestCert -CN 'www.example.test' -Dns 'example.test', 'www.example.test' -StartDays -1 -Days 90
    }
    BeforeEach {
        Remove-Item (Join-Path $TestDrive 'state') -Recurse -Force -ErrorAction SilentlyContinue
        $script:reports = @()
        $script:store = @($oldCert)
        Mock Get-ArcManagedIdentityToken { 'tok' }
        Mock Get-AkvCertificate { New-VaultObject $newCert }
        Mock Get-StoreCertificates { , $script:store }
        Mock Send-CertWatchReport { $script:reports += , @{ Outcome = $Outcome; New = $NewFingerprint; Message = $Message }; $true }
        Mock Invoke-CertificateUpdate { $script:store = @($oldCert, $newCert); $newCert.Thumbprint }
    }

    It 'deploys a newer vault certificate and reports started then succeeded' {
        $cfg = New-TestConfig
        $result = Invoke-AkvCertificateSync -Config $cfg
        $result | Should -Be 0
        @($result).Count | Should -Be 1
        @($script:reports.Outcome) | Should -Be @('started', 'succeeded')
        $script:reports[1].New | Should -Be (Get-CertificateSha256 $newCert)
        Should -Invoke Invoke-CertificateUpdate -Times 1 -ParameterFilter {
            $Context.Installed.Thumbprint -eq $oldCert.Thumbprint -and $Context.Token -eq 'tok' -and $Context.Vault.Thumbprint -eq $newCert.Thumbprint
        }
        $state = Get-Content (Get-StatePath $cfg) -Raw | ConvertFrom-Json
        $state.installed.thumbprint | Should -Be $newCert.Thumbprint
        $state.installed.vaultVersion | Should -Be 'v2'
        $state.lastCheck.result | Should -Be 'updated'
        @($state.identity.dnsNames) | Should -Be @('example.test', 'www.example.test')
    }

    It 'is quiet when up to date, and uses the saved thumbprint next run even with the old cert still present' {
        $cfg = New-TestConfig
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 0
        $script:reports = @()
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 0
        $script:reports.Count | Should -Be 0
        Should -Invoke Invoke-CertificateUpdate -Times 1 -Exactly
        (Get-Content (Get-StatePath $cfg) -Raw | ConvertFrom-Json).lastCheck.result | Should -Be 'up-to-date'
    }

    It 'reports failed and exits 1 when the update throws (as the template stub does)' {
        Mock Invoke-CertificateUpdate { throw [System.NotImplementedException]::new('template stub') }
        $cfg = New-TestConfig
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 1
        @($script:reports.Outcome) | Should -Be @('started', 'failed')
        $script:reports[1].Message | Should -BeLike 'Update failed: *template stub*'
        $state = Get-Content (Get-StatePath $cfg) -Raw | ConvertFrom-Json
        $state.lastCheck.result | Should -Be 'failed'
        $state.installed | Should -BeNullOrEmpty
    }

    It 'treats an update returning the wrong thumbprint as failed' {
        Mock Invoke-CertificateUpdate { $oldCert.Thumbprint }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 1
        $script:reports[1].Message | Should -BeLike '*returned thumbprint*expected*'
    }

    It 'treats an update that leaves no private-key certificate as failed' {
        Mock Invoke-CertificateUpdate { $newCert.Thumbprint }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 1
        $script:reports[1].Message | Should -BeLike '*not in LocalMachine\My with a private key*'
    }

    It 'refuses a vault certificate that is not newer (exit 4, no report)' {
        $script:store = @($newCert)
        Mock Get-AkvCertificate { New-VaultObject $oldCert }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 4
        $script:reports.Count | Should -Be 0
        Should -Invoke Invoke-CertificateUpdate -Times 0
        Mock Invoke-CertificateUpdate { $script:store = @($newCert, $oldCert); $oldCert.Thumbprint }
        Invoke-AkvCertificateSync -Config (New-TestConfig -Overrides @{ AllowOlderCertificate = $true }) | Should -Be 0
    }

    It 'refuses a changed identity unless accepted, then tracks the new identity' {
        $cfg = New-TestConfig
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 0
        $renamed = New-TestCert -CN 'www.example.test' -Dns 'www.example.test', 'example.test', 'extra.example.test' -Days 120
        Mock Get-AkvCertificate { New-VaultObject $renamed 'v3' }
        Mock Invoke-CertificateUpdate { $script:store = @($script:store + $renamed); $renamed.Thumbprint }
        $script:reports = @()
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 4
        $script:reports.Count | Should -Be 0
        $accept = New-TestConfig -Overrides @{ AcceptIdentityChange = $true }
        Invoke-AkvCertificateSync -Config $accept | Should -Be 0
        @((Get-Content (Get-StatePath $cfg) -Raw | ConvertFrom-Json).identity.dnsNames) | Should -Contain 'extra.example.test'
    }

    It 'treats a missing installed certificate as a first deployment' {
        $script:store = @()
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 0
        @($script:reports.Outcome) | Should -Be @('started', 'succeeded')
    }

    It 'exits 2 on a token failure and reports only with -ReportCheckFailures' {
        Mock Get-ArcManagedIdentityToken { throw 'IDENTITY_ENDPOINT is not set' }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 2
        $script:reports.Count | Should -Be 0
        Invoke-AkvCertificateSync -Config (New-TestConfig -Overrides @{ ReportCheckFailures = $true }) | Should -Be 2
        $script:reports[0].Outcome | Should -Be 'failed'
        $script:reports[0].Message | Should -BeLike '*IDENTITY_ENDPOINT*'
    }

    It 'exits 2 for a disabled or expired vault certificate' {
        Mock Get-AkvCertificate { New-VaultObject $newCert 'v2' $false }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 2
        $expired = New-TestCert -CN 'www.example.test' -Dns 'www.example.test' -StartDays -30 -Days 10
        Mock Get-AkvCertificate { New-VaultObject $expired }
        Invoke-AkvCertificateSync -Config (New-TestConfig) | Should -Be 2
        Should -Invoke Invoke-CertificateUpdate -Times 0
    }

    It 'changes nothing under -WhatIf' {
        $cfg = New-TestConfig -Overrides @{ WhatIf = $true } -Proceed $false
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 0
        $script:reports.Count | Should -Be 0
        Should -Invoke Invoke-CertificateUpdate -Times 0
        Test-Path (Get-StatePath $cfg) | Should -BeFalse
    }

    It 'honours an explicit identity override' {
        $cfg = New-TestConfig -Overrides @{ MatchSubjectCN = 'www.example.test'; MatchDnsName = @('www.example.test') }
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 4
        $script:reports.Count | Should -Be 0
    }

    It 'ignores a corrupt state file' {
        $cfg = New-TestConfig
        Set-Content -Path (Get-StatePath $cfg) -Value '{not json'
        Invoke-AkvCertificateSync -Config $cfg | Should -Be 0
        (Get-Content (Get-StatePath $cfg) -Raw | ConvertFrom-Json).schema | Should -Be 1
    }
}
