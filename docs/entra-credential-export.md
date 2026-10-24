# Export Entra application credential expiry

The standalone [PowerShell exporter](../scripts/export-entra-credentials.ps1)
reads application password-credential metadata through an already connected
Microsoft Graph PowerShell session. It writes a JSON array for operator review
and subsequent import into cert-watch. It does not create or rotate credentials,
write to Entra, or submit anything to cert-watch.

Use the Microsoft.Graph.Authentication and Microsoft.Graph.Applications modules
with Windows PowerShell 5.1 or PowerShell 7. Establish the session yourself using
your normal tenant-approved authentication flow. The least privileged delegated
permission for listing applications is `Application.Read.All`, which requires
appropriate tenant consent. See Microsoft's
[Get-MgApplication reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.applications/get-mgapplication?view=graph-powershell-1.0).

For example, after the modules have been installed:

```powershell
Connect-MgGraph -TenantId '<tenant-id>' -Scopes 'Application.Read.All' -ContextScope Process
.\scripts\export-entra-credentials.ps1 -OutputPath 'C:\restricted\application-expiry.json'
```

The destination directory must already exist. Restrict its permissions to the
operator: application names, IDs and tenant IDs describe your inventory even
though the file contains no secret values. Keep the file outside the repository.
The exporter takes no token or password arguments and does not initiate a login.
Avoid Graph debug tracing or transcripts containing authentication diagnostics
in the surrounding session.

The exporter requests only `appId`, `displayName` and `passwordCredentials` using
`Get-MgApplication -All`; the SDK enumerates all pages. Before serialization it
projects each credential to exactly these cert-watch metadata input fields:

| JSON field | Source |
| --- | --- |
| `application_name` | Application display name, falling back to application ID when empty |
| `application_id` | Application/client `appId`, rather than the directory object ID |
| `credential_id` | Password credential `keyId` |
| `credential_name` | Password credential display name, or an empty string |
| `tenant_id` | The connected Graph context's tenant ID |
| `expires_at` | Credential `endDateTime`, normalized to UTC |
| `owner_email` | Empty; assign an operational owner in cert-watch |

Graph's [passwordCredential resource](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0)
also has fields such as `hint` and `secretText`. The exporter does not serialize
those fields, additional properties, raw Graph responses, or exception details.
It handles password credentials on application registrations only; service
principal credentials, certificate credentials and federated identity
credentials are outside this export.

The output is always an array, including `[]` for an empty inventory. A successful
run prints counts of applications, exported credentials and skipped credentials.
A missing, invalid or timezone-free expiry is skipped rather than assigned an
invented expiration. Missing identifiers and text that cert-watch cannot accept
(more than 256 characters or control characters) are also skipped. The warning
reports only the skipped count. Investigate skips in the tenant; they are not
evidence that the omitted credentials are current.

All pages are collected before a temporary file is created beside the
destination. The complete UTF-8 JSON is flushed and published with an atomic
same-directory move or replacement. A Graph failure, including a later-page
failure, leaves an existing export unchanged. Errors print a fixed diagnostic
and exit `1`; success exits `0`. A successful run with skips is intentionally
partial, so inspect `skipped_credentials` before treating it as complete. Local
filesystem replacement semantics still apply; use a local filesystem that
supports atomic replacement and keep the destination under operator control.

## Add the reviewed records to cert-watch

The JSON API accepts one object at a time at `POST /api/application-secrets`.
Use an administrator API key created in cert-watch, supplied through the process
environment by your normal secret-injection mechanism. Do not paste its value
into the command, script or a transcript. This example is a separate, intentional
write to cert-watch after reviewing the export; the exporter never runs it:

```powershell
if (-not $env:CERT_WATCH_API_KEY) { throw 'An administrator API key is required.' }
$endpoint = [uri]'https://cert-watch.invalid/api/application-secrets'
$headers = @{ Authorization = 'Bearer ' + $env:CERT_WATCH_API_KEY }
$records = @(Get-Content -LiteralPath 'C:\restricted\application-expiry.json' -Raw `
    -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
$imported = 0
try {
    foreach ($record in $records) {
        $body = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Depth 4))
        $null = Invoke-RestMethod -Method Post -Uri $endpoint -Headers $headers `
            -ContentType 'application/json; charset=utf-8' -Body $body `
            -MaximumRedirection 0 -ErrorAction Stop
        $imported += 1
    }
}
catch {
    throw ('Import stopped after ' + $imported + ' records; inspect the inventory before retrying.')
}
finally { $headers.Clear() }
Write-Output ('Imported credentials: ' + $imported)
```

Replace the example HTTPS endpoint with your cert-watch endpoint. The request
uses the [API-key authentication](access-control.md#api-keys) path and refuses
redirects. Do not enable request tracing or print `$headers`. A browser-session
alternative must carry its normal CSRF token.

This is a create-only loop, not a synchronized or transactional import. An
active duplicate `(tenant_id, application_id, credential_id)` returns `422` and
stops the loop; earlier records remain created. Re-running the same export
therefore requires checking the existing inventory first. The helper does not
retire records that disappear from Graph, update existing entries, or assign
owner email addresses. Use the administrator UI for those decisions, including
manual entry when Graph access is unavailable.

This helper has synthetic tests under a real PowerShell process with mocked
Graph commands, including partial-page failure and sensitive-field canaries.
It has not been exercised against a live tenant or under Windows PowerShell 5.1.
