# API reference

## Renewal reports

Renewal automation uses a dedicated `renewal-report` API key. Send it as
`Authorization: Bearer cwk_…`. These keys can call only the two routes below;
ordinary read, write and admin API keys cannot call them. The normal per-IP
API limit still applies, plus 30 requests per minute per report key and five
per minute per key and endpoint.

### `POST /api/renewal-reports`

The body is a strict JSON object, limited to 16 KiB, and the request must send
`Content-Type: application/json` (a `charset` parameter is allowed). Other
media types return 415. Unknown fields, duplicate JSON keys, non-finite
numbers and type coercion are rejected. Select exactly one target:

- `hostname` and `port` (recommended); or
- `cert_fingerprint`, a 64-character SHA-256 hexadecimal fingerprint.

Fingerprint lookup considers only scanned leaves on endpoints in the key's
current host-tag binding. It matches the currently served leaf or a leaf
recorded as replaced on that endpoint in the last seven days. Recent-
predecessor lookup depends on the predecessor still being available in
retained certificate history when migration 0046 backfills older lineage.
No match returns 404. More than one in-binding match returns 409 without naming
the endpoints. Uploaded certificates cannot be targeted.

`outcome` is required and is `started`, `failed` or `succeeded`. A successful
report moves an open, failed or newly created attempt to `verifying`, ends any
stall-suppression lease, and queues an immediate normal scan of the monitored
endpoint. The request never scans inline. If already-stored scan evidence
matches `new_fingerprint`, the response can be `verified` immediately. A
success claim never closes an existing `renewal_not_deployed` condition; a
later stored scan must do that. An endpoint with no scanned leaf returns
`409 {"error":"endpoint has not been scanned yet; report again after its first scan"}`
for `succeeded` unless `new_fingerprint` is supplied. A supplied fingerprint
equal to the attempt baseline is retained in report history with `no_change`,
but is not applied as evidence. Optional fields are:

| Field | Contract |
|---|---|
| `message` | At most 2,000 Unicode code points after NFC normalization. C0/C1 controls other than tab/newline and bidi overrides are rejected. |
| `tool` | 1–64 characters matching `[A-Za-z0-9._+-]`. |
| `correlation_id` | 1–128 printable, non-space ASCII characters (`0x21`–`0x7e`). It identifies one renewal attempt; reusing it for later work is recorded as late and ignored unless that report itself opens a replacement attempt. It is not an idempotency key. |
| `new_fingerprint` | A 64-character SHA-256 hexadecimal fingerprint. |
| `occurred_at` | ISO 8601 with a UTC offset. Stored for history, never used to order or reduce reports. |

The optional `Idempotency-Key` header is 1–128 printable ASCII characters and
is scoped to the reporting key and resolved endpoint. Duplicate header lines
return 400. Repeating the same key, endpoint and canonical body returns the
saved response. Reusing it with another body or an endpoint that resolves to a
different `host_id` returns 409 while the original endpoint remains in the
caller's live binding. If that endpoint is gone or out of binding, its row is
replaced and the request is processed fresh. A different report key may reuse
the same value. Target existence and the live binding are checked before every
replay lookup.

Accepted reports return status 202:

```json
{"report_id": "7f3a1b9c4d2e4870a6c5e8d1f2b3a490", "attempt_id": "…", "state": "open", "effect": "applied"}
```

Send `new_fingerprint` whenever the automation knows the certificate it meant
to deploy. That is the exact verification target. For a bare `succeeded`
report, cert-watch can recognize a successor that was scanned before the
report only when its replacement lineage was observed in the preceding 24
hours, the endpoint has not flapped back to that leaf, and no earlier attempt
has already verified or used that leaf as its baseline. Otherwise the served
leaf becomes the new attempt's baseline and a later scan must observe a change.
An explicit `cert_fingerprint` target naming the replaced certificate retains
the seven-day target-lookup behavior described above.

A first report whose `new_fingerprint` equals the baseline is stored with
`"effect":"no_change"` and returns `"state":null`, because no attempt exists.

`report_id` is an opaque random identifier and carries no ordering information.
History is ordered newest-first by an internal sequence that is never exposed.
A repeated `started` is retained but never extends the original lease. The default lease is 24
hours (`CERT_WATCH_RENEWAL_REPORT_LEASE_HOURS`, range 1–168). A lapsed lease
becomes `abandoned` without raising an alert. A partial unique index marks at
most one attempt as current for an endpoint. Repeated
`failed` reports are retained without changing the state. Correlation
ownership moves when its report opens a new attempt, so an identical retry
resolves to that current attempt. Until retention removes the ownership row, a
late report stays attached to its finished attempt and cannot reopen work.
Only the first attempt for an endpoint and baseline leaf can suppress a stalled signal,
including across intervening baselines and cancelled attempts.

Each reporting key may create at most 1,000 correlation IDs per endpoint in a
rolling 24-hour period. Further new correlations return the same
`429 {"error":"rate limited"}` response as the request-rate limits.

### `GET /api/renewal-reports?hostname=…&port=…`

Returns newest-first history. `page` defaults to 1 (maximum 10,000) and
`limit` defaults to 50 (maximum 100). A report key receives only reports created by that same key,
and only while the endpoint remains in its live host-tag binding. Unknown and
out-of-binding endpoints both return `404 {"error":"endpoint not found"}`.
GET also maps a malformed hostname to that same 404; POST treats a malformed
hostname as body validation and returns 422.

A signed-in user who can read the endpoint sees outcome, timestamps, effect
and the state of that report's actual attempt. `message`, `tool`, `source` and
`correlation_id` are included only for an administrator or a caller with
HOST-tag write access to the endpoint. A report key can see those fields on
its own reports. Report text is never
copied to logs, events, alerts or notification delivery. Audit detail
deliberately retains `tool` and `correlation_id` for administrators, but stores
only the message length and hash rather than its text.

Each endpoint retains at least its newest 50 reports plus every report newer
than `history_retention_days`. Non-current attempts and correlation ownership
also expire after that interval. Maintenance preserves the newest granted
stall lease for every endpoint/baseline pair so retention cannot grant a
second suppression lease. A retry that reuses a correlation older than the
retention interval is treated as new and can appear as in progress, but it
never receives another stall-suppression lease for the same endpoint and
baseline. Idempotency records expire after seven days.
Deleting an endpoint deletes its reports, attempt and correlation history, and
idempotency records, so re-adding the same address does not inherit private
history.

The legacy host `renewal_status` field is optional on JSON `PUT` and `PATCH`
requests. Omitting it leaves renewal state unchanged. Supplying it is explicit
intent: `in_progress` creates a `started` report when there is no live lease,
and `pending` cancels a current attempt only while its lease is live. HTML
forms also submit the value rendered to the operator; changing the select acts
on the lease-aware state at commit, while leaving it unchanged never alters a
lease even if automation reported progress or a lease lapsed while the form
was open. Responses return `in_progress` exactly when the current attempt is
open and its lease is live, without consulting the stored compatibility
column.
