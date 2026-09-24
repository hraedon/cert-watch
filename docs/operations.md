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
| `cert_watch_alerts_failed_recent` | | Alerts that gave up in the last 24 hours; the `CertWatchAlertDeliveryFailed` rule uses it |

`deploy/k8s/prometheus-rules.yaml` contains ready-made rules. The one to keep
even if you use no others is **`CertWatchScanStalled`**: no scan for 36 hours.
A cert-watch that has stopped scanning looks healthy from the outside, and it
is the failure that matters most. It has happened in practice, on IIS hosts
that weren't configured to start the process without an incoming request.

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
