# Operating cert-watch

What to watch, what to back up, and what to do when something looks wrong.

## How it runs

cert-watch is a single process. Alongside the web server it runs a scheduler
thread that:

- scans every host once a day at `CERT_WATCH_SCHED_HOUR:CERT_WATCH_SCHED_MIN`
  (UTC), or on a host's own cadence if one is set;
- retries a failed host after an hour;
- evaluates alert rules and delivers pending alerts;
- sends the digests;
- purges old records according to the retention settings.

Everything is stored in one SQLite database, `cert-watch.sqlite3`, in the data
directory (`CERT_WATCH_DATA_DIR`). The same directory holds the generated
secrets and the pre-upgrade backups.

Because the database has a single writer, run exactly one cert-watch process
against a data directory. Two copies started at once, for example during an
overlapping restart, serialise their startup, but the application doesn't
support two live writers.

## Monitoring

**Health endpoints.** Both work without authentication. Their status codes
are the probe contract; the bodies reveal nothing beyond the status to
anyone who is not an administrator.

| Endpoint | Returns | Use it for |
|----------|---------|------------|
| `/healthz` | `200 {"status": "ok"}` while the process is serving | Liveness probes |
| `/readyz` | `200` when ready; `503` if the database can't be read or written, or the scheduler isn't running or is repeatedly failing | Readiness probes and uptime checks |

With authentication enabled, `/readyz` answers `{"status": "ok"}` or
`{"status": "degraded"}` and nothing more, unless the caller is an
administrator (browser session or `admin` API key) or presents the metrics
bearer token (`CERT_WATCH_METRICS_TOKEN`); those get the detailed `checks`
(database, last scan, certificate and alert counts, scheduler state), which
describe the whole estate. `/api/health`, which feeds the dashboard's health
strip, requires a session and gives the same detail to administrators only;
every other signed-in user gets `{"overall": "ok" | "warning" | "critical"}`.
A monitor that scrapes the detail should therefore use `/readyz` with the
metrics token, not a personal account. With authentication disabled both
endpoints return the full body to everyone.

**Metrics.** `/metrics` exposes Prometheus gauges. With authentication
enabled, it answers only the dedicated bearer token (`CERT_WATCH_METRICS_TOKEN`,
not an API key) or an administrator's browser session, so set the token for
your scraper. With authentication disabled it is open, unless a metrics token is set, in which
case the token is still required.
The labels include host names and certificate subjects, so also restrict it to
your monitoring network at the ingress or firewall.

| Metric | Labels | Meaning |
|--------|--------|---------|
| `cert_watch_cert_expiry_days` | `host`, `subject`, `fingerprint` | Days until expiry (negative once expired) |
| `cert_watch_certificates_tracked` | | Leaf certificates tracked |
| `cert_watch_certificates_expired` | | Leaf certificates already expired |
| `cert_watch_certificates_by_urgency` | `urgency` | Count per urgency bucket, as on the dashboard |
| `cert_watch_certificates_by_posture` | `grade` | Count per posture grade |
| `cert_watch_hosts_tracked` | | Hosts tracked |
| `cert_watch_scan_errors` | `host`, `reason` | Recorded scan failures (until retention removes them) |
| `cert_watch_last_scan_timestamp_seconds` | | When the most recent scan finished |
| `cert_watch_alerts` | `status` | Alerts by lifecycle state (pending, sending, failed, …) |
| `cert_watch_alerts_failed_recent` | | Alerts that gave up in the last 24 hours, counted from when they gave up; the `CertWatchAlertDeliveryFailed` rule uses it |

`deploy/k8s/prometheus-rules.yaml` contains ready-made rules. The one to keep
even if you use no others is **`CertWatchScanStalled`**: no scan for 36 hours.
A cert-watch that has stopped scanning looks healthy from the outside, and it
is the failure that matters most. It has happened in practice, on IIS hosts
that weren't configured to start the process without an incoming request.

**The health strip** at the top of every page polls `/api/health` (any
signed-in user). It turns amber when any of these is non-zero or the last scan
failed, and red when the scheduler or the database is down:

| Field | Counts |
|-------|--------|
| `failed_alerts_24h` | Alerts not delivered whose delivery failed in the last 24 hours: gave up in that time (counted from when they gave up, attempt or not), or still retrying after a refused or failed attempt (an HTTP 500 from the webhook, say) |
| `undelivered_alerts` | Alerts still pending a day after creation, or stuck in a sending lease; only when SMTP or a webhook is configured |
| `endpoints_without_successful_scan` | Endpoints in your scope that have never been scanned successfully (Home's "without a successful scan" chip) |

Its timestamps are UTC, like the rest of the UI.

### What the numbers mean

Every page counts the estate with the same definitions.

- **Endpoint** — a registered `host:port`. It is *scanned* once a scan has
  stored its certificate, and *pending* until then. A later failed scan
  doesn't make it pending again: it keeps the certificate it last saw.
- **Certificate** — a stored leaf certificate: the current one for each
  scanned endpoint (a rescan replaces it) and one per uploaded file. Chain
  certificates aren't counted.
- **Tracked** — one row per endpoint, scanned or pending, plus one per
  uploaded file. Home, Inventory and the issuer, owner and renewal-method views
  show the same total and the same status counts; the group views split those
  same rows. Grouping Inventory by certificate shares one row between
  endpoints but doesn't change the counts.
- **Effective days** — whole days until the soonest expiry among the leaf
  and the chain certificates stored with it, negative once one has expired.
  An expired intermediate makes a leaf with 99 days left −3.
- **Condition** — certificate expiry only: `expired` below zero effective
  days, `le7` at 0–7 days, `8to30` at 8–30 days, and `ok` above 30 days.
  Chain trust is a separate `chain_trust_problem` flag and `chain_status`; an
  incomplete, invalid, unknown, self-signed or not-yet-verified chain never
  changes the expiry bucket. Pending endpoints have no condition.
- **Monitoring** — `current` means the existing scan-freshness rule has a
  successful observation inside the endpoint's configured cadence and no
  later incomplete attempt. `failing` covers a later failed/partial attempt,
  overdue evidence or unreadable timing; `since` is the first consecutive
  failed attempt (or the cadence deadline when evidence simply became
  overdue). Its `cause` is the plain-language scan guidance and `raw_error`
  preserves the scanner text. `never_scanned` means no attempt and no
  successful observation are recorded. A failing or never-scanned endpoint
  is never labelled Healthy or OK overall, even when its last certificate's
  condition is `ok`. Uploaded files use `not_monitored`: they have no endpoint
  scan lifecycle and are excluded from monitoring counts and filters.
- **Renewal** — precedence is `in_progress` when an operator reported that
  host state; then `stalled` when the current leaf is inside the configured
  renewal window with no successor; then `automation_configured` for an ACME
  or cert-manager method; then `manual` for a manual method. If the method is
  unset, renewal analytics may supply `automation_configured` from
  `likely-automated` or `manual` from its manual classification; otherwise the
  state is `unknown`. The model records which source made the decision.
- **Delivery** — per-certificate recipients and matched groups come from the
  same `alerting.routing` resolver that snapshots a queued alert. SMTP lists
  the global plus routed recipients and is deliverable only when its relay,
  sender and at least one recipient exist. The global webhook is deliverable
  when configured. Each channel includes its latest append-only delivery
  outcome. `unrouted` means no route at all: no certificate-specific or group
  route and no global recipient or webhook fallback. A route that exists only
  globally is therefore `ok` when its channel can deliver; a later slice may
  expose that distinction separately. `failing` means a route has no usable
  channel or its latest configured-channel outcome was not fully accepted;
  otherwise it is `ok`. Read-level API users see only delivery state, channel
  types and anonymous counts; recipient identities and group names are admin-only.
- **Filters** — Browse and the host/certificate JSON lists accept the same
  combinable URL parameters: `condition=expired|le7|8to30|ok`,
  `monitoring=current|failing|never_scanned`,
  `renewal=automation_configured|manual|stalled|in_progress|unknown`, and
  `delivery=ok|failing|unrouted`. They are applied in SQL after the caller's
  effective tag scope. Grouped Browse paginates the matching fingerprint
  groups in SQL before it builds display rows. A grouped filter or search
  selects a group when any member matches, then shows every in-scope member of
  that selected group; the group is the result unit.
- **Home links** — Home's summary numbers use those same condition, monitoring
  and delivery filters. Its owner/group gap, chain rows, and twelve-week bars
  add exact routing, issuer, and seven-day expiry filters. All open flat Browse,
  so the destination row count is the number shown on Home.
- **Days** — whole days until the leaf certificate expires, negative once it
  has expired ("expired 41 days ago"). A group view's *Earliest expiry* is the
  smallest effective days in the group, so it agrees with the group's status.
- **Home triage** — Certificate risk ranks expired, ≤7-day and 8–30-day rows
  by effective days, while chain-trust problems are grouped once per issuer.
  Monitoring gaps exclude uploaded files and show bounded failing and
  never-scanned rows with their cause and start time. Delivery/routing reports
  certificates whose configured routes cannot deliver, routing gaps, and the
  latest failed webhook channel/time without exposing recipient or group
  identities to non-admins. Row building remains bounded; expanding a
  Browse group loads it 100 rows at a time.
- **Graded** — a certificate with a posture grade: its latest scan's grade, or,
  for an uploaded file, the grade of the file itself. The Posture fleet grade
  and the compliance report's grade distribution cover the same certificates.
- **Compliance report** — *Certificates* are the certificates in scope and
  *Endpoints* the scanned endpoints among them. Its expiry sections place each
  certificate by its effective days, with the legacy display-status boundaries
  (under 7 days, then under 30 days), and list
  the expiry date and days that put it
  there: for a certificate whose intermediate expires first, the
  intermediate's. Each entry also carries monitoring, renewal and delivery;
  condition remains a separate expiry fact.
- **Posture trends** count each endpoint once per month, by its latest scan
  that month.
- **Scan history** groups scans that ran within five minutes of each other.
  *Endpoints* counts each endpoint once, judged by its latest attempt in the
  batch: successful only when that scan fully succeeded. A partial scan is
  shown as incomplete, not as a success, and makes the batch partial.
  *Attempts* counts every attempt, retries included. What started a scan
  (the schedule, Scan now, the API) isn't recorded, so it isn't shown.

**Logs** go to standard output. Set `CERT_WATCH_LOG_FORMAT=json` for structured
output. Each scan, alert delivery attempt and scheduler cycle is logged, and
failures are logged at WARNING or above.

## Backups

The database is the only state. Everything else can be recreated from
configuration.

```bash
cert-watch backup /backups/cert-watch-$(date +%F).sqlite3
```

This writes a consistent copy with SQLite's `VACUUM INTO`, so it's safe while
cert-watch is running. It refuses to overwrite an existing file, so give each
backup a new name.
Don't copy the database file directly while the process is up: with
write-ahead logging, a plain copy can miss committed data. Keep the generated
`.auth_secret` file from the data directory with your backups, or set
`CERT_WATCH_AUTH_SECRET` explicitly. Without the auth secret, stored SMTP, LDAP and webhook
credentials can't be decrypted.

cert-watch also writes a backup automatically before applying database
migrations on upgrade: `cert-watch-pre-migration-<timestamp>-<id>.sqlite3` in
the data directory. Delete old ones once you're satisfied with an upgrade.

### Restoring

1. Stop cert-watch.
2. Remove `cert-watch.sqlite3`, and `cert-watch.sqlite3-wal` and
   `cert-watch.sqlite3-shm` if present.
3. Copy the backup to `cert-watch.sqlite3`.
4. Start cert-watch. If the backup is from an older version, it is migrated
   forward on startup.

## Retention

Old records are purged at startup and daily. `0` keeps a record type forever.

| Setting | Default | Covers |
|---------|---------|--------|
| `CERT_WATCH_HISTORY_RETENTION_DAYS` | 365 | Per-scan certificate snapshots and trend data |
| `CERT_WATCH_ALERT_RETENTION_DAYS` | 90 | Delivered and cancelled alerts. Undelivered ones are kept four times as long, so the record of an outage outlives it. |
| `CERT_WATCH_AUDIT_RETENTION_DAYS` | 90 | Audit log |
| `CERT_WATCH_EVENT_RETENTION_DAYS` | 30 | Lifecycle event log |

If you forward the audit log to a SIEM (see
[configuration.md](configuration.md#siem-export)), the SIEM is the long-term
record and cert-watch's copy can stay short.

## Upgrading

Stop the process, install the new version, start it. Migrations run on startup
after an automatic backup; each migration either applies completely or not at
all. [UPGRADING.md](../UPGRADING.md) lists what changed between versions and
anything you need to do. Downgrading means restoring the pre-migration backup
the upgrade wrote.

## Rotating secrets

- **`CERT_WATCH_AUTH_SECRET`** signs sessions and encrypts stored credentials.
  After changing it, run `cert-watch re-encrypt <old-secret>` so stored
  credentials stay readable. Everyone is signed out, and signed compliance
  reports issued under the old secret no longer verify.
- **`CERT_WATCH_CSRF_SECRET`** is optional; when unset it is derived from the
  auth secret. Changing it only invalidates forms that are already open.
- **API keys**: create the replacement, move the client over, revoke the old
  key under **Settings → API keys**.
- **The break-glass password**: generate a new hash with
  `cert-watch hash-password` and set `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH`, or,
  if the hash isn't set in the environment, change it under **Settings →
  Authentication** while signed in as the break-glass admin.

## Command line

| Command | Does |
|---------|------|
| `cert-watch` | Starts the server |
| `cert-watch backup <path>` | Writes an online backup of the database |
| `cert-watch hash-password` | Prompts for a password and prints its hash for `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` |
| `cert-watch re-encrypt <old-secret>` | Re-encrypts stored credentials after an auth-secret change |
| `cert-watch verify-report <report.json>` | Checks the signature on an exported compliance report |
| `cert-watch routing-report <backup.sqlite3>` | Shows who alerts would be routed to, from a backup, without sending anything (see [alerting.md](alerting.md#checking-routing)) |

## Troubleshooting

**Nothing has been scanned for a day or more.** Check `/readyz` and the log
for scheduler errors. On IIS, check that the Application Initialization
feature is installed and the application has `preloadEnabled`; without both,
the process doesn't start until someone visits the site.
`scripts/Verify-Install.ps1` checks this.

**A host can't be scanned: "blocked" or "not allowed".** The address falls
outside the scanning policy. Private addresses need to be inside
`CERT_WATCH_ALLOWED_SUBNETS` when that is set. Loopback, link-local and cloud
metadata addresses are always refused.

**Alerts aren't arriving.** **Activity → Alerts** shows each alert's delivery
attempts: channel, outcome, and the reason for any failure. **Settings →
Channels → Send test email** tests SMTP. `POST /api/webhook/test` tests the
webhook. [alerting.md](alerting.md) explains how alerts are created, routed and
retried.

**Everyone was signed out after an upgrade.** Upgrading to 1.0 does this once,
by design. After that, it means the auth secret changed; see
[Rotating secrets](#rotating-secrets).

**"database is locked" in the log.** Occasional instances are retried
automatically and are harmless. Persistent ones mean a second process, or
another tool, is holding the database open.
