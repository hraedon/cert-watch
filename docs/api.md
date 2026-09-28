# API reference

## Renewal reports

Renewal automation uses a dedicated `renewal-report` API key. Send it as
`Authorization: Bearer cwk_…`. These keys can call only the two routes below;
ordinary read, write and admin API keys cannot call them. The normal per-IP
API limit still applies, plus 30 requests per minute per report key and five
per minute per key and endpoint.

### `POST /api/renewal-reports`

The body is a strict JSON object, limited to 16 KiB. Unknown fields, duplicate
JSON keys, non-finite numbers and type coercion are rejected. Select exactly
one target:

- `hostname` and `port` (recommended); or
- `cert_fingerprint`, a 64-character SHA-256 hexadecimal fingerprint.

Fingerprint lookup considers only scanned leaves on endpoints in the key's
current host-tag binding. It matches the currently served leaf or a leaf
recorded as replaced on that endpoint in the last seven days. No match returns
404. More than one in-binding match returns 409 without naming the endpoints.
Uploaded certificates cannot be targeted.

`outcome` is required and is `started`, `failed` or `succeeded`. S2 accepts
`started` and `failed`; until deployment verification ships, `succeeded`
returns `503 {"error":"renewal verification is not available yet"}` and
stores nothing. Optional fields are:

| Field | Contract |
|---|---|
| `message` | At most 2,000 Unicode code points after NFC normalization. C0/C1 controls other than tab/newline and bidi overrides are rejected. |
| `tool` | 1–64 characters matching `[A-Za-z0-9._+-]`. |
| `correlation_id` | At most 128 code points; informational, not an idempotency key. |
| `new_fingerprint` | A 64-character SHA-256 hexadecimal fingerprint. |
| `occurred_at` | ISO 8601 with a UTC offset. Stored for history, never used to order or reduce reports. |

The optional `Idempotency-Key` header is 1–128 printable ASCII characters and
is scoped to the reporting key. Repeating the same key and canonical body
returns the saved response. Reusing it with another body returns 409. A
different report key may reuse the same value. Target existence and the live
binding are checked before every replay lookup.

Accepted reports return status 202:

```json
{"report_id": 42, "attempt_id": "…", "state": "open", "effect": "applied"}
```

Reports are ordered only by the monotonic `report_id`. A repeated `started`
is retained but never extends the original lease. The default lease is 24
hours (`CERT_WATCH_RENEWAL_REPORT_LEASE_HOURS`, range 1–168). A lapsed lease
becomes `abandoned` without raising an alert. Repeated `failed` reports are
retained without changing the state; late reports do not reopen a terminal
attempt.

### `GET /api/renewal-reports?hostname=…&port=…`

Returns newest-first history. `page` defaults to 1 and `limit` defaults to 50
(maximum 100). A report key receives only reports created by that same key,
and only while the endpoint remains in its live host-tag binding. Unknown and
out-of-binding endpoints both return `404 {"error":"endpoint not found"}`.

A signed-in user who can read the endpoint sees outcome, timestamps, effect
and attempt state. `message`, `tool` and `source` are included only for an
administrator or a caller with effective write access to the endpoint. A
report key can see those fields on its own reports. Report text is never
copied to logs, events, alerts or notification delivery.

Each endpoint retains at least its newest 50 reports plus every report newer
than `history_retention_days`. Idempotency records expire after seven days.
Deleting an endpoint deletes its reports, current attempt and idempotency
records, so re-adding the same address does not inherit private history.
