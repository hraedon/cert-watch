# Reporting renewals from automation

A renewal report is a claim from your automation. A cert-watch scan is the
evidence that decides which certificate the endpoint actually serves. Reports
can pause a **Renewal stalled** notice while work is active and can create
renewal-specific alerts, but they never suppress an expiry warning or an
expired alert.

This guide covers the reporting API and ready-to-adapt hooks for plain shell,
Certbot, and acme.sh. The examples are in
[`docs/examples/renewal-reports/`](examples/renewal-reports/).

## Create a reporting key

In **Settings → API keys**, create a key with the `renewal-report` scope. Copy
the token when it is shown; only its hash is stored.

Every reporting key needs an explicit binding:

- **Selected host tags** is the normal choice. A request can target an
  endpoint when at least one of its host tags matches the key. Certificate-only
  tags do not count, because a report changes endpoint-level state.
- **All endpoints** is an explicit trust decision for automation that really
  manages the whole fleet. It is never selected implicitly.

Bindings are checked on every request and cannot be edited. Revoke and replace
the key when its scope changes. An endpoint that does not exist and one outside
the key's binding both return the same `404`.

The credential can reach only `GET /api/renewal-reports` and
`POST /api/renewal-reports`. It cannot read certificates, health, metrics,
settings, HTML, or static files. Ordinary read, write, and admin keys cannot
call the reporting routes.

Put the token in a root- or service-readable file, not in a script:

```sh
install -m 600 /dev/null /etc/cert-watch/renewal-report.key
# Write the token to that file using your secret-management process.
export CW_RENEWAL_REPORT_KEY_FILE=/etc/cert-watch/renewal-report.key
export CW_BASE_URL=https://cert-watch.example.com
```

`cw-report.sh` also accepts the token through `CW_RENEWAL_REPORT_KEY`. It never
accepts a token argument, and it keeps the token out of curl's process
arguments.

## Send a report

`POST /api/renewal-reports` requires `Content-Type: application/json` and a
strict JSON object no larger than 16 KiB. Unknown fields, duplicate JSON keys,
non-finite numbers, and type coercion are rejected.

Target exactly one endpoint in one of these ways:

- `hostname` plus `port` is recommended and remains unambiguous when several
  endpoints serve the same wildcard or SAN certificate.
- `cert_fingerprint` is a 64-character SHA-256 hexadecimal fingerprint. It
  matches an in-binding scanned leaf that is current or was replaced on that
  endpoint in the last seven days. No match is `404`; more than one in-binding
  match is `409`. Uploaded certificates cannot be targeted.

The fields are:

| Field | Required | Limit and meaning |
|---|:---:|---|
| `outcome` | yes | `started`, `succeeded`, or `failed` |
| `hostname` and `port` | one target | Canonical DNS name or IP plus an integer from 1 through 65535 |
| `cert_fingerprint` | one target | 64 hexadecimal SHA-256 characters |
| `new_fingerprint` | no | 64 hexadecimal SHA-256 characters for the certificate automation intended to deploy |
| `message` | no | At most 2,000 Unicode code points after NFC normalization; bidi overrides and control characters other than tab/newline are rejected |
| `tool` | no | 1–64 characters from `A-Z`, `a-z`, `0-9`, `.`, `_`, `+`, or `-` |
| `correlation_id` | no | 1–128 printable, non-space ASCII characters (`!` through `~`) identifying the renewal run |
| `occurred_at` | no | ISO 8601 timestamp with a UTC offset; retained for history, not ordering |

Send an `Idempotency-Key` header containing 1–128 printable ASCII characters
when a delivery might be retried. It is scoped to the reporting key and the
resolved endpoint. Repeating the same key and canonical request body returns
the saved response; changing the body returns `409`. `correlation_id` groups
the reports in a renewal run, but is not an idempotency key.

For example:

```sh
docs/examples/renewal-reports/cw-report.sh started \
  --host www.example.com --port 443 \
  --tool deploy-job --correlation renewal-needed-event-id

docs/examples/renewal-reports/cw-report.sh succeeded \
  --host www.example.com --port 443 \
  --tool deploy-job --correlation renewal-needed-event-id \
  --new-pem /etc/tls/www.example.com/cert.pem
```

The helper calculates a PEM leaf's SHA-256 fingerprint with OpenSSL, generates
an idempotency key, safely JSON-encodes text, and exits non-zero for a non-2xx
response. Set `CW_IDEMPOTENCY_KEY` yourself when retrying one logical delivery.

### Responses

An accepted report returns `202` with an opaque report id and the affected
attempt:

```json
{"report_id":"7f3a1b9c4d2e4870a6c5e8d1f2b3a490","attempt_id":"…","state":"open","effect":"applied"}
```

`effect` is `applied`, `duplicate`, `no_change`, or `ignored_late`. The other
responses an integration should handle are:

| Status | Meaning |
|---:|---|
| `400` | More than one `Idempotency-Key` header was sent. |
| `404` | The endpoint is unknown, outside the key's live host-tag binding, or not addressable by the supplied fingerprint. These cases deliberately look identical. |
| `409` | A fingerprint matches several in-binding endpoints; an `Idempotency-Key` was reused with another body or endpoint; or a bare `succeeded` report targets an endpoint that has never completed a scan. |
| `413` | The request body exceeds 16 KiB. |
| `415` | The media type is not `application/json`. A charset parameter is allowed. |
| `422` | JSON, field, target, timestamp, fingerprint, tool, or correlation validation failed. |
| `429` | A request or correlation limit was reached. Honor backoff and retry with the same idempotency key and body. |

## What each outcome does

### `started`

`started` opens a lease (24 hours by default). The first lease for an endpoint
and served certificate mutes only **Renewal stalled** and the automation-facing
`renewal_needed` webhook. It does not mute expiry alerts. Repeating `started`
stores the report but never extends or re-grants the lease. When the lease
lapses, stalled evaluation resumes; no separate lease-expired alert is raised.

### `succeeded`

`succeeded` is a claim that deployment finished. cert-watch queues an immediate
normal scan; the request itself does no network I/O. Only a stored scan can
verify the attempt and clear **Renewal not deployed** or a carried
**Renewal failed** condition.

An unchanged successful scan counts toward **Renewal not deployed** only after
the configured grace period (5 minutes by default, 5–15). Checks and alert
deadlines depend on how long the previous certificate has left:

| Previous certificate has left | Check cadence | Deployment alert |
|---|---|---|
| 14 days or more | Standard scan or 24 hours, whichever comes first | First unchanged check at or after 24 hours |
| 3–14 days | Every 6 hours or the standard scan, whichever comes first | First unchanged check at or after 12 hours |
| Less than 3 days, or unknown | At the grace boundary, then hourly | First qualifying unchanged check |
| Expired | At the grace boundary, then every 15 minutes | First qualifying unchanged check |

A failed scan is not evidence and leaves verification pending.

Always send `new_fingerprint` when the tool knows it. It makes verification
exact: the endpoint must serve that leaf, and serving another new leaf becomes
**Deployment not confirmed**. Without it, any safe successor can verify the
claim. cert-watch may recognize a deployment that happened just before the
report by using the current leaf's predecessor as the baseline, but only when
the replacement was observed within 24 hours, the endpoint has not flapped
back to that current leaf, and no earlier attempt already used it. That narrow
24-hour rule necessarily leaves an ambiguity after an unrelated recent
replacement; `new_fingerprint` removes it.

### `failed`

`failed` wakes the alert rules and raises **Renewal failed** for a scanned
endpoint. Repeats and later attempts carry one continuous failure condition,
so provider incident keys remain stable. Report text is visible only in
authorized history; alerts use fixed server wording.

The failure clears when a post-failure stored scan verifies the renewal, when
a stored successor matches the newest reported fingerprint (or any successor
when no fingerprint was reported and no unserved claim blocks it), when the
endpoint is deleted, or when an authorized operator uses **Clear failure** on
endpoint detail. Its JSON peer is
`POST /api/hosts/{id}/renewal-failure/clear`. A start, lease expiry, bare
success claim, or compatibility `renewal_status=pending` write does not clear
it.

## Limits and history

The POST limits are 30 requests per minute per reporting key and five per
minute for each key-and-endpoint pair. A key may also create at most 1,000 new
correlation ids per endpoint in a rolling 24 hours. Independently, the normal
API middleware allows 60 requests per minute per source IP. Keys behind one
NAT address share that 60-request allowance even though their per-key limits
are separate.

`GET /api/renewal-reports?hostname=www.example.com&port=443` returns
newest-first history. `page` defaults to 1 (maximum 10,000) and `limit` to 50
(maximum 100). A report key sees only reports made by that key and only while
the endpoint remains in its binding. A signed-in reader sees outcome, time,
effect, and attempt state for visible endpoints. Message, tool, source, and
correlation are shown only to administrators and users with host-tag write
access. Report text never enters logs, events, digests, alerts, or outbound
notifications.

## Connect the renewal webhook

The `renewal_needed` webhook includes an `event_id`, a stable 32-character
hexadecimal id across delivery retries. Echo it as `correlation_id` on
`started`, `succeeded`, and `failed` reports from that run. It links the
request and outcome for operators without making repeated HTTP deliveries
idempotent; continue to use a separate `Idempotency-Key` header for those.

## Certbot

Certbot's `--pre-hook` and `--post-hook` run around an actual renewal attempt.
`--deploy-hook` runs once per successfully issued certificate and exports
`RENEWED_LINEAGE` (the live certificate directory) and `RENEWED_DOMAINS` (a
space-delimited domain list). A deploy hook therefore reports success, but it
cannot report failure. `certbot-renew.sh` wraps one named certificate so it can
report the command's failing exit status, while the pre and deploy hooks report
started and succeeded:

```sh
export CW_REPORT_SCRIPT=/opt/cert-watch-hooks/cw-report.sh
export CW_HOST=www.example.com CW_PORT=443
export CERTBOT_CERT_NAME=www.example.com
/opt/cert-watch-hooks/certbot-renew.sh --quiet
```

The wrapper supplies its hook paths to `certbot renew`; no renewal report is
sent when the certificate is not due because Certbot does not run the hooks.
The deploy hook uses `$RENEWED_LINEAGE/cert.pem` for the exact leaf fingerprint
and defaults the host to the first `RENEWED_DOMAINS` entry when `CW_HOST` is not
set. Set `CW_HOST` explicitly for a load balancer or another endpoint name.

Behavior was checked against the official
[Certbot renewal hook documentation](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates).

## acme.sh

acme.sh accepts `--pre-hook`, `--post-hook`, and `--renew-hook` on the initial
`--issue` command, saves them, and applies them to later `--renew` and `--cron`
runs. The renew hook runs only after success. `--reloadcmd` runs after a
successfully installed certificate; keep your existing server reload there
rather than replacing it with reporting.

Install the reporting hooks when issuing the certificate, alongside the
challenge options your deployment already uses:

```sh
acme.sh --issue -d www.example.com \
  --pre-hook /opt/cert-watch-hooks/acme-pre-hook.sh \
  --renew-hook /opt/cert-watch-hooks/acme-renew-hook.sh
```

Run one certificate through the failure-aware wrapper:

```sh
export CW_REPORT_SCRIPT=/opt/cert-watch-hooks/cw-report.sh
export ACME_DOMAIN=www.example.com
export CW_HOST=www.example.com CW_PORT=443
export ACME_SH_BIN=/root/.acme.sh/acme.sh
/opt/cert-watch-hooks/acme-renew.sh
```

The pre-hook uses acme.sh's exported `Le_Domain`. The success hook uses its
exported `CERT_PATH` to calculate the intended leaf fingerprint. acme.sh's
post-hook runs after both successful and failed issuance and does not expose a
portable success flag, so it is not used to infer an outcome. The wrapper
reports other non-zero exits as failures and treats acme.sh status 2 as
“not due,” not a failure.

Behavior and flags were checked against the official
[acme.sh hook wiki](https://github.com/acmesh-official/acme.sh/wiki/Using-pre-hook-post-hook-renew-hook-reloadcmd),
and the exported hook variables and status 2 behavior against the maintained
[`acme.sh` source](https://github.com/acmesh-official/acme.sh/blob/master/acme.sh).

## Troubleshooting

### My renewal shows “Deployment not confirmed”

Open the endpoint and compare the reported fingerprint with the currently
served fingerprint. Confirm that the deployment updated the actual monitored
hostname and port, including every load-balancer/backend path. Then run **Scan
now**. A report cannot clear this state; only a successful scan serving the
expected certificate can. If the report omitted `new_fingerprint`, check
whether another certificate replacement happened in the preceding 24 hours
and send fingerprints on future runs to remove that ambiguity.

### The failure will not clear

A successful report alone is not evidence, and the old certificate continuing
to be served cannot clear a failure. If a fingerprint was reported, cert-watch
waits for that certificate rather than accepting an unrelated replacement.
Check the latest stored scan and the intended fingerprint, fix deployment or
scanning, and scan again. If the automation report was wrong or the incident
was handled outside the observed endpoint, a host-tag writer or administrator
can use **Clear failure** on endpoint detail; the action is audited.
