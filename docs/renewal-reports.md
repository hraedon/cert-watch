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
install -d -m 755 /etc/cert-watch
install -m 600 /dev/null /etc/cert-watch/renewal-report.key
# Write the token to that file using your secret-management process.
export CW_RENEWAL_REPORT_KEY_FILE=/etc/cert-watch/renewal-report.key
export CW_BASE_URL=https://cert-watch.example.com
```

`cw-report.sh` also accepts the token through `CW_RENEWAL_REPORT_KEY`, but the
0600 file is preferred: an environment value is inherited by every child hook
and reload command. The helper unsets that variable as soon as it reads it. It
never accepts a token argument, and it keeps the token out of curl's process
arguments.

The file must hold exactly the token, optionally followed by one Unix newline.
A Windows (CRLF) line ending, a NUL byte, or any character outside the token
alphabet is rejected rather than stripped. When called directly, `cw-report.sh`
exits 3 for such key problems and non-zero when cert-watch rejects or cannot
receive the report; the hook examples below never let that affect a renewal.

## Send a report

`POST /api/renewal-reports` requires `Content-Type: application/json` and a
strict JSON object no larger than 16 KiB. Unknown fields, duplicate JSON keys,
non-finite numbers, and type coercion are rejected.

Target exactly one endpoint in one of these ways:

- `hostname` plus `port` is recommended and remains unambiguous when several
  endpoints serve the same wildcard or SAN certificate.
- `cert_fingerprint` is a 64-character SHA-256 hexadecimal fingerprint. It
  matches an in-binding scanned leaf that is current, or the current leaf's
  immediate predecessor when that replacement was observed in the last seven
  days. No match is `404`; more than one in-binding match is `409`. Uploaded
  certificates cannot be targeted.

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
when a delivery might be retried. It is scoped to the reporting key. Repeating
the same key and canonical request body returns the saved response; reusing it
with another body or endpoint returns `409`. `correlation_id` groups the
reports in a renewal run, but is not an idempotency key.

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
response. It checks the HTTP status manually, so it also works with curl
versions older than 7.76. Set `CW_REPORT_TIMEOUT_SECONDS` to change its
10-second request timeout, and set `CW_IDEMPOTENCY_KEY` yourself when retrying
one logical delivery.

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
| `401` | No API key was supplied, or the supplied key is invalid. |
| `403` | The caller is authenticated (a key of another kind, or a signed-in browser session) but is not a `renewal-report` key. |
| `404` | The endpoint is unknown, outside the key's live host-tag binding, or not addressable by the supplied fingerprint. These cases deliberately look identical. |
| `409` | A fingerprint matches several in-binding endpoints; an `Idempotency-Key` was reused with another body or endpoint; or a bare `succeeded` report targets an endpoint that has never completed a scan. |
| `413` | The request body exceeds 16 KiB. |
| `415` | The media type is not `application/json`. Media-type parameters are ignored. |
| `422` | JSON, field, target, timestamp, fingerprint, tool, correlation, or `Idempotency-Key` validation failed. |
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
the configured grace period (5 minutes by default, 5–15 minutes). Checks and alert
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
the endpoint remains in its binding. A signed-in reader sees `report_id`,
`attempt_id`, outcome, `new_fingerprint`, `occurred_at`, `received_at`, effect,
and attempt state for visible endpoints. Message, tool, source, and correlation
are shown only to administrators and users with host-tag write access. Report
text never enters logs, events, digests, alerts, or outbound notifications.

## Connect the renewal webhook

The `renewal_needed` webhook includes an `event_id`, a stable 32-character
hexadecimal id across delivery retries. Echo it as `correlation_id` on
`started`, `succeeded`, and `failed` reports from that run. It links the
request and outcome for operators without making repeated HTTP deliveries
idempotent; continue to use a separate `Idempotency-Key` header for those.

## Install the hook examples

Copy all files in `docs/examples/renewal-reports/` together and create a state
directory owned by the account that runs renewals:

```sh
install -d -m 700 /var/lib/cert-watch-renewal-hooks
export CW_RENEWAL_STATE_DIR=/var/lib/cert-watch-renewal-hooks
```

The pre-hook creates a random correlation id in a per-tool, per-endpoint state
file with mode 0600. The success hook or a failure-aware wrapper reads it and
removes it after the terminal report. A terminal hook with no state file
generates a fresh random id; it never uses a fixed fallback. An explicitly
supplied `CW_CORRELATION_ID`, such as a `renewal_needed` event id, takes
precedence.

Each reporting key can send five reports per endpoint per minute and 30 per
minute in total. Above that, cert-watch answers `429`. The hooks do not retry,
so a renewal re-run within the same minute can lose a report; the hook logs the
`429` to standard error.

Reporting is strictly best effort. Every hook logs a reporting error to
standard error and exits zero when cert-watch is unavailable, times out, or
rejects a request. If the state directory cannot be used safely, the hooks
still report, each with a fresh correlation id, and say so on standard error. The wrappers preserve the renewal command's own exit status;
whether cert-watch accepted a report never changes a renewal from succeeded to
failed or from failed to succeeded.

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

Certbot saves hooks passed to `renew` in that certificate's renewal
configuration. After the first wrapper run, the normal Certbot timer will also
run those saved hooks, without the wrapper's shell environment. Choose one
deployment explicitly:

- Schedule `certbot-renew.sh` once per certificate and disable the stock
  Certbot timer. This is the failure-aware option; put the `CW_*` settings in
  the scheduled service or its 0600 environment file.
- Keep the stock timer and rely on the saved hooks for `started` and
  `succeeded`. Put `CW_REPORT_SCRIPT`, `CW_BASE_URL`,
  `CW_RENEWAL_REPORT_KEY_FILE`, `CW_RENEWAL_STATE_DIR`, `CW_HOST`, and `CW_PORT`
  in the timer service's environment. A global `CW_HOST` makes this option
  suitable for a single certificate only: Certbot runs an identical pre-hook
  once per invocation, even when several certificates are due. For multiple
  certificates, use separate timer instances that each pass `--cert-name` and
  set the matching endpoint. This path cannot report Certbot's own failing
  exit.

Do not leave both schedules enabled. The per-run state makes saved hooks safe
when they run without the wrapper, but two schedulers would still perform two
renewal checks.

To try the wiring before a certificate is due, add
`--force-renewal --no-random-sleep-on-renew` to the wrapper command; it passes
extra arguments to `certbot renew`. This issues a real certificate. Without a
terminal, Certbot otherwise waits a random delay of up to eight minutes before
it renews.

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

acme.sh also runs the pre-hook for this first `--issue`, but it runs the renew
hook only on later renewals. If `CW_REPORT_SCRIPT` is set, the issue therefore
reports `started` and never sends a matching `succeeded`. The attempt is still
verified once a scan finds a certificate other than the one served when it
started; until then, its lease mutes **Renewal stalled**. To send no report at
all, run `--issue` with `CW_REPORT_SCRIPT` unset. The pre-hook then logs that
reporting is unset and exits zero, and acme.sh still saves both hooks.

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
reports other non-zero exits as failures and treats acme.sh status 2 as “not
due,” not a failure. Because status 2 can also mean the requested domain is not
an issued certificate, the wrapper warns about the exact `ACME_DOMAIN` spelling
when neither its standard RSA nor ECC config directory exists. For wildcard
certificates, set `CW_HOST` to the actual monitored endpoint; a wildcard
`Le_Domain` is not a valid report target.

Choose how acme.sh is scheduled:

- Keep acme.sh's installed cron entry and rely on the saved hooks. Add the
  non-secret helper path, URL, key-file path, and private state directory to
  that cron environment. The hooks default to `Le_Domain` on port 443; use a
  per-certificate launcher or the wrapper for wildcard certificates and custom
  endpoints. Each cron-driven pre-hook creates a new correlation even though
  no wrapper supplied one. This reports starts and successful deploys, but
  acme.sh's own failure exit is unavailable to the hooks.
- Replace the installed acme.sh cron entry with one scheduled
  `acme-renew.sh` invocation per certificate. The wrapper inherits the saved
  hooks, supplies one random correlation to them, and reports acme.sh failures.

Do not keep the installed cron entry when scheduling the wrapper, or the same
certificate will be checked by both jobs.

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

### A hook logs “cert-watch returned HTTP 400” and “invalid Host header”

The instance runs with sign-in disabled (`CERT_WATCH_ALLOW_UNAUTH=1`). In that
mode cert-watch accepts only `localhost`, a loopback address, or the host
named in `CERT_WATCH_BASE_URL`. Set `CERT_WATCH_BASE_URL` to the address in
`CW_BASE_URL`, or point `CW_BASE_URL` at that host.

### The failure will not clear

A successful report alone is not evidence, and the old certificate continuing
to be served cannot clear a failure. If a fingerprint was reported, cert-watch
waits for that certificate rather than accepting an unrelated replacement.
Check the latest stored scan and the intended fingerprint, fix deployment or
scanning, and scan again. If the automation report was wrong or the incident
was handled outside the observed endpoint, a host-tag writer or administrator
can use **Clear failure** on endpoint detail; the action is audited.
