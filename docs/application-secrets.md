# Application credential expiry

Administrators can open **Credentials** to track application secret metadata.
Add the application name and client ID, the credential's key ID, its expiry in
UTC, and optionally its label, tenant ID and owner email. Enter one record for
each active credential, including overlapping credentials during a rotation.
Never enter the secret value. cert-watch has no field for it.

The inventory distinguishes current, expires within 30 days, expires within
7 days, expired and retired. A record whose stored expiry cannot be read (after
a hand edit or a restore) shows as expiry unreadable and gets no reminders;
the scheduler logs an error for it on every alert cycle, and the API returns
its `expires_at` as `null` with the field named in `unreadable`. Retire it and
add the credential again. Expiry is an exact instant: a secret expiring
tomorrow is still valid today. UTC avoids a browser's timezone silently moving
the deadline.

The scheduler raises one reminder at the most urgent crossed stage: 30, 14,
7, 3 or 1 days, then a separate expired alert at the expiry instant. A stage
is recorded once per record, with a durable stage marker independent of alert
history retention. If a credential is first added with two days
remaining, only the 3-day reminder is queued. Later stages cancel older
unsent reminders, including abandoned delivery leases. Delivery uses the
existing retry queue and append-only
delivery evidence. The next alert evaluation occurs with the normal scheduler
cycle; this is not an exact-time alarm.

Credential reminders are individual alerts even when certificate digest mode
is enabled. They use the global SMTP/webhook channels and the optional owner
email. They do not match certificate tag groups. The inventory and all its
mutations require administrator access. Global unscoped alert readers and
configured notification recipients can see application/credential metadata;
tag-scoped alert readers and scoped manual flushes cannot see or send them.

After rotating a credential in its provider and deploying the replacement,
add the replacement's metadata and **Retire credential** on the old record.
Retirement is an operator assertion, not evidence that Entra removed a key or
that a workload switched credentials. It cancels pending reminders, retains
the inventory/audit history, and attempts to resolve supported webhook incidents.
A send already in flight finishes its trigger before the dispatcher requests
resolution. Resolution requests are best effort and can be repeated.
cert-watch neither reads secret values nor creates, rotates or deletes keys.
To correct an incorrect entry, retire it and add the corrected metadata.

## JSON API

The admin-only JSON surface mirrors the page:

- `GET /api/application-secrets` lists metadata and status, including retired records.
- `POST /api/application-secrets` creates a record and returns `201 {"id": "..."}`.
- `POST /api/application-secrets/{id}/retire` retires an active record, returning
  `200 {"retired": true}`. An absent or already retired record returns 404.

Creation accepts these fields only:

```json
{
  "application_name": "Example application",
  "application_id": "example-client-id",
  "credential_id": "example-key-id",
  "credential_name": "Deployment key",
  "tenant_id": "example-tenant-id",
  "expires_at": "2027-01-01T00:00:00Z",
  "owner_email": "owner@example.invalid"
}
```

The first three fields and expiry are required. Other fields default to empty
strings. Values must be text of at most 256 characters without control
characters; the owner is a single email address. Expiry must include a
timezone. Unknown fields, including `secretText`, are rejected without
reflecting their values. The API request is limited to 16 KiB. An active
tenant/application/key identity cannot be added twice; retire it explicitly
before replacing an incorrect record. Browser writes require a CSRF token;
JSON writes follow the existing authenticated JSON/CSRF contract.

## Microsoft Entra

Entra exposes `passwordCredentials` metadata on application registrations.
Its `keyId`, `displayName` and `endDateTime` map to credential ID, label and
expiry. The secret value is only returned when creating the credential; it
cannot be retrieved later and is unnecessary for expiry monitoring.
See Microsoft's [passwordCredential reference](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0).

A separate read-only exporter can collect this metadata using an operator's
Graph session; see [exporting Entra metadata](entra-credential-export.md).
This feature does not store Graph credentials or schedule tenant polling.
