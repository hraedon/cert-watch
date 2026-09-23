# Upgrading cert-watch

## How upgrades work

Install the new version over the same data directory and start it. On
startup, cert-watch:

1. takes a lock so a second process starting at the same time waits;
2. writes a backup of the database next to it
   (`cert-watch-pre-migration-<timestamp>-<id>.sqlite3`);
3. applies each pending schema migration in its own transaction, recorded in
   `schema_version`.

A migration that fails leaves the database exactly as it was, and startup
stops with the error. There is no separate migrate command.

Upgrades only go forward. To roll back, stop cert-watch, restore the
pre-migration backup (see [operations.md](docs/operations.md#restoring)), and
start the previous version.

**Supported upgrade path: 0.9.x to 1.0.** A test replays a real 0.9.0
database through the upgrade and checks that nothing is lost. For an older
release, upgrade to 0.9.x first. Or start a fresh 1.0 and re-add your hosts
with the CSV import; history is not carried over that way.

## Upgrading from 0.9 to 1.0

1.0 is the release where cert-watch's defaults became strict. Most
installations need to do nothing, but go through this list first: several
items can lock someone out or change who gets alerted.

### Before you upgrade

- [ ] **Back up the database and its secrets.** On a command-line install, run
      `cert-watch backup /backups/cert-watch-pre-1.0.sqlite3` and keep the data
      directory's `.auth_secret` if cert-watch generated it. A Windows/IIS
      install instead uses `secrets\auth_secret` and `secrets\csrf_secret`
      through the `*_FILE` settings in `web.config`. Its CLI is inside the
      data directory and does not inherit the environment variables from
      `web.config`; for a default install, use an elevated PowerShell:

      ```powershell
      $dataDir = "C:\ProgramData\cert-watch"
      $env:CERT_WATCH_DATA_DIR = $dataDir
      & "$dataDir\venv\Scripts\cert-watch.exe" backup "C:\backups\cert-watch-pre-1.0.sqlite3"
      Copy-Item "$dataDir\secrets\auth_secret", "$dataDir\secrets\csrf_secret" "C:\backups"
      ```

      Set `$dataDir` and `CERT_WATCH_DATA_DIR` to the actual data directory if
      `-InstallDir` was used.
- [ ] **LDAP over plain `ldap://` is refused.** A simple bind now needs
      `ldaps://` or `LDAP_START_TLS=1`. If you can't change that yet, set
      `CERT_WATCH_LDAP_ALLOW_INSECURE=1`, knowing it sends directory
      passwords in cleartext.
- [ ] **If you use `CERT_WATCH_ADMINS` or `CERT_WATCH_WRITE_USERS` without a
      role mapping,** they are now enforced. Make sure every administrator is
      in `CERT_WATCH_ADMINS`. With only `CERT_WATCH_WRITE_USERS` set,
      administration is limited to those users too.
- [ ] **If you have saved a role mapping under Settings → Roles,** it now
      takes effect. It had been saved but never used. Directory users who
      match no mapping become read-only, so map your administrators first.
      Once a mapping has been saved there, clearing it leaves directory users
      read-only rather than restoring full access. See
      [access-control.md](docs/access-control.md#1-role-mapping-recommended).
- [ ] **Review three saved settings** that earlier releases saved but
      ignored, because they now apply: the OAuth scope, the LDAP user filter,
      and the alert webhook kind. Where an environment variable and a saved
      value both set `SMTP_PORT`, `LDAP_CONNECT_TIMEOUT` or
      `ALERT_DIGEST_ONLY`, the environment variable now wins.
- [ ] **Prometheus:** set `CERT_WATCH_METRICS_TOKEN` and scrape with it.
      Without a token, `/metrics` answers only an administrator's browser
      session.
- [ ] **API clients:** JSON writes must send `Content-Type:
      application/json` and a JSON object. Creating and revoking API keys now
      needs an administrator's browser session; an API key can't manage keys.
- [ ] **Anything that imports cert-watch in Python:** `cert_watch.alerts`,
      `cert_watch.alert_delivery`, `cert_watch.alert_adapters` and
      `cert_watch.digest` are gone. Import from `cert_watch.alerting`.
- [ ] **Alert-webhook consumers that match the renewal digest's subject:** it
      now shows the digest window, e.g. `Renewal Digest (14d)`, instead of a
      fixed `(7d)`.
- [ ] **If you scan carrier-grade NAT addresses (`100.64.0.0/10`)**, they now
      count as private: allow private addresses, and include the range in
      `CERT_WATCH_ALLOWED_SUBNETS` if you use it.
- [ ] **If you run with authentication disabled and reach it by a name other
      than `localhost`**, set `CERT_WATCH_BASE_URL` to that name. Requests
      for other host names are refused.

### Upgrade

- **Container / Compose:** pull `ghcr.io/hraedon/cert-watch:v1.0.0`, verify it
  ([install.md](docs/install.md#verifying-an-image)), and restart on the same
  volume.
- **Kubernetes:** update the image and apply. The `Recreate` strategy ensures
  the old pod has stopped before the new one migrates.
- **Linux:** re-run `scripts/install-linux.sh`, or install the new version into
  the existing virtual environment and restart the service. The script
  rewrites the unit file, so keep local settings in a drop-in
  (`systemctl edit cert-watch`), not in the unit itself.
- **Windows / IIS:** download and extract the `vX.Y.Z` source archive from the
  repository's GitHub **Tags** page (or a release page's generated **Source
  code** link), then run `scripts\install-windows.ps1` from that extracted
  tree with your original arguments. The release workflow publishes container
  images; it does not attach a Windows installer asset.

  If the original command was not recorded, recover the important IIS values
  before re-running it:

  ```powershell
  $dataDir = "C:\ProgramData\cert-watch" # change if -InstallDir was used
  & "$dataDir\venv\Scripts\python.exe" -m pip show ldap3 authlib
  Import-Module WebAdministration
  Get-WebBinding -Name cert-watch -Protocol https |
      Select-Object bindingInformation, sslFlags
  netsh http show sslcert ipport=0.0.0.0:443
  # For an SNI binding, use the host from bindingInformation instead:
  netsh http show sslcert hostnameport=certs.example.com:443
  ```

  If both Python packages are present, retain `-WithAuthExtras`. An IIS binding
  such as `*:443:certs.example.com` supplies `-HostName certs.example.com`;
  `sslFlags=1` supplies `-SharePort443`. The matching `netsh` entry reports the
  certificate hash to pass as `-TlsCertThumbprint`. Also retain any non-default
  `-InstallDir`, `-AppPool`, or `-SitePath`. **Do not re-run `-ConfigureIIS`
  with the default binding arguments: with no `-HostName` or `-SharePort443`,
  the installer rewrites the HTTPS binding to `*:443:` (and switches out of
  SNI mode).** (`-SharePort443` by itself is rejected.)

  The installer stops the application pool, which releases the database,
  updates the code, and starts the pool again. It does not replace the database,
  signing keys, or an existing `web.config`; the restarted application applies
  the pending database migrations. For any *manual* file operation, such as
  restoring a backup, stop the pool first; Windows won't let you replace an
  open database.

  The script installs cert-watch from the extracted source tree, but resolves
  and upgrades its dependencies from PyPI at install time; it does not install
  from `uv.lock`. Dependency versions can therefore differ between installer
  runs unless your environment supplies a constrained package mirror.

Then watch the log for `backed up …` and `applying migration …` lines, and open
the web interface. Those lines are visible from 1.0.1 onward. Independently of
the application version, confirm that a new
`cert-watch-pre-migration-*.sqlite3` file appeared beside the database and
inspect the database's `schema_version` table: every migration through the
target release's head must have a row. For 1.0, that final row is `0037`.

### What to expect afterwards

**Everyone signs in again once,** including the break-glass administrator,
because the session format changed. API keys keep working. On Windows/IIS, a
form left open across the upgrade fails once, because the CSRF secret file is
now honoured; reload the page.

**A v0.9.5 database runs nine migrations, 0029–0037:**

- **0029** adds the durable digest-delivery claim ledger.
- **0030** adds per-tag permission tiers to roles.
- **0031** merges certificate notes into host notes and drops the old column.
- **0032** adds append-only alert-delivery evidence.
- **0033** adds the clock used to bound alert-evidence deferral.
- **0034** records the certificate that triggered each alert.
- **0035** reconciles the schema of databases that had drifted from a fresh
  install: it adds `hosts.notes` and four indexes, and drops a duplicate column.
- **0036** gives alerts a delivery lifecycle.
- **0037** gives each alert a dedupe key and a saved routing snapshot.

Earlier 0.9.x databases can run additional migrations according to the highest
ID already present in `schema_version`; for example, the supported v0.9.0
fixture ends at `0023`, so it runs `0024`–`0037`.

**Alerting behaves better, and slightly differently.** See
[alerting.md](docs/alerting.md) for the whole picture.

- Failed deliveries back off and retry (1 h, 4 h, 12 h), and give up after 12
  attempts. A given-up alert stays **failed** until someone selects **Retry**.
  `cert_watch_alerts_failed_recent` lets you alert on that.
- Alerts that were already failed before the upgrade stay failed. The one
  exception: a failed alert for a certificate that is still current, at its
  current threshold, is retried once on the next evaluation, which is what
  0.9 would have done.
- A renewal-stalled alert fires once per certificate and endpoint, and policy
  alerts fire once while the violation persists. Neither repeats every scan.
- Policy and drift alerts now go to matching alert groups, host owners and
  roles, not only to the global recipients, so some people start receiving
  them.
- A certificate served on several endpoints alerts each endpoint's owner.
- Recipients are fixed when an alert is raised. A group change affects new
  alerts, not ones already queued.
- Alerts made obsolete by a replaced or deleted certificate are kept as
  **cancelled** instead of deleted.
- Digests are claimed per recipient and period: never sent twice, and a
  partial failure retries only who missed it. The orphan notice goes out once
  a week.

**Access control is tighter.**

- Accounts created under Settings → Users can finally sign in. Each one gets
  its role's permissions; no role means read-only.
- A tag-scoped user can no longer add or import hosts with another team's
  tags.
- CSRF is enforced even with authentication disabled.
- Login throttling counts per user and address (10 per 5 minutes), with a
  higher ceiling per address (50).
- Request bodies over 12 MiB are refused.

**New and moved:**

- Every change you can make in the UI now has a JSON API equivalent (see the
  [changelog](CHANGELOG.md) for the list). No existing API path moved.
- The ownership form posts to `/hosts/{id}/owner`; the old path still works.
- The landing page is **Home**, and the inventory is at **/browse**. Old links
  redirect.
- The audit log is administrator-only.

The [changelog](CHANGELOG.md) has every change in detail, with the issue each
one fixes.
