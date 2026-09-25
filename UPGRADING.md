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

## Upgrading from 1.0.3 (unreleased)

The manual `renewed` host status has been removed. Operators can still mark a
renewal `in_progress`, which suppresses renewal-stalled notices only; expiry
warnings and expired alerts always remain active until a scan observes a
successor certificate.

Migration **0041** changes every stored `renewed` status to `pending` and
writes one audit-log row for each host changed. Scripts that send
`renewal_status: "renewed"` to either host write API must be updated: the
request now receives a `400` or `422` validation error instead of being
accepted. Use `in_progress` only while work is underway, or omit the field/use
`pending` when it is not.

Three schema migrations are applied on startup; nothing else to reconfigure.

- **0039** adds a cached chain status to each certificate row
  (`chain_status`, `chain_status_basis`). The cache is filled on the first
  page load after the upgrade, one chain verification per certificate. Until
  a certificate's entry is filled -- and whenever its chain, the trust
  anchors or the system CA bundle change, until it is re-verified -- it
  counts as *unverified* (Warning), never Healthy.
- **0040** adds `alerts.failed_at`, the time an alert gave up, which
  `/api/health` `failed_alerts_24h` and `cert_watch_alerts_failed_recent`
  now count by. Existing failed alerts are dated by their last delivery
  attempt; one that failed without any attempt is dated to the upgrade, so
  it shows as a recent failure for the first 24 hours rather than possibly
  being missed.

Behaviour to be aware of: Home's *Needs attention* panel lists the 50 most
urgent items and says how many there are, and expanding a group in the
issuer, owner or renewal-method views loads 100 rows at a time. Tag scopes
now match tags stored with spaces (`staging, edge` is in scope `edge`)
everywhere, as grouped Browse already did.

One more behaviour change affects access control:

- **Certificate tags are now durable grants.** A scan no longer wipes the
  tags set on a certificate itself, and a renewal carries them to the new
  certificate. In 1.0.3 and earlier the next scan cleared them, so removing
  a team's tag from the *host* was enough to revoke that team's access within
  a scan cycle. Now a team keeps access through a tag set on the certificate
  until that tag is removed too. Before relying on a host tag change to revoke
  access, check the certificate's own tags on its detail page. (Tags that
  earlier releases already wiped are not restored.)

## Upgrading from 1.0.2 to 1.0.3

One schema migration, **0038**, rewrites every stored host name to one
canonical spelling (lower-case IDNA A-labels without a trailing dot; the
compressed form for IP literals) across `hosts`, `certificates`,
`scan_history`, `cert_history`, `scan_posture`, `alerts`, event payloads and
alert dedupe keys. Read [CHANGELOG.md](CHANGELOG.md) for why. Three things to
know:

- **It can take a while on a large database.** Each table is rewritten in a
  single pass, so a few thousand hosts with tens of thousands of events take
  seconds, not minutes, but the pre-migration backup copies the whole
  database file first. The application does not open its port until
  migrations finish. On Kubernetes, `deploy/k8s/deployment.yaml` now has a
  `startupProbe` (15 minutes) for that reason; if you use your own manifest
  with only a liveness probe, add one or raise the liveness
  `failureThreshold` before upgrading, or a long migration is killed and
  retried indefinitely. On IIS the startup limit is 60 s
  (`deploy/iis/web.config`). If the database is large, migrate before
  starting the site: stop the site, run `cert-watch` from a console with the
  same `CERT_WATCH_*` environment the site uses (at least the database
  path), wait for the `migration 0038 applied` log line, stop it with
  Ctrl+C, then start the site.
- **Two rows that spell one endpoint are collapsed.** If both rows carry the
  same tags, they are merged. If they carry different tags, the migration
  fails closed: the surviving row keeps only the tags both had (none, if
  disjoint, which makes the endpoint visible to administrators only); every
  other field (owner, notes, threshold, scan interval, expected issuers,
  STARTTLS mode, renewal status and method, runbook) is kept only where both
  agreed and otherwise reset to its default; the certificates under that
  endpoint lose their per-certificate tags and any alert-group assignment
  not shared by both; and alerts still queued for them are sent to the
  global recipients only, not to the recipients they were queued with.
  Nothing is deleted from the history. Every such collapse is a
  `WARNING` line in the startup log and an audit entry with action
  `host.merge_alias` that holds the removed row and every dropped value in
  full. **After upgrading, an administrator should open the audit log,
  filter for `host.merge_alias`, and re-tag or re-own the affected endpoints
  deliberately.**
- **`/readyz` and `/api/health` return a shallow body to non-administrators.**
  Status codes are unchanged, so Kubernetes probes, the Docker health check
  and `Verify-Install` are unaffected. A script that reads the detailed body
  with a non-administrator account or a `read`/`write` API key now gets only
  `{"status": ...}` / `{"overall": ...}`; use `/readyz` with the metrics
  token, or an `admin` API key.
- Host names typed as legacy numeric IPv4 forms (`010.010.010.010`,
  `8.8.2056`, `0x08080808`) are rejected from now on; write the dotted quad.
  Stored ones are folded into the dotted-quad row by the migration.

## Upgrading from 1.0.1 to 1.0.2

Nothing to migrate or reconfigure. Two behaviour changes to be aware of:

- JSON API request bodies are limited to 256 KiB and 64 levels of nesting;
  larger or deeper bodies get `400`. Every JSON endpoint takes small bodies
  (the largest real one is a host note, capped at 10,000 characters), so
  this only affects a client that sends far more than the API uses.
- The container image runs Python 3.14 and no longer contains `pip`. If you
  extend the image or run `pip` inside the container, install it in your own
  layer.

## Upgrading from 1.0.0 to 1.0.1

Nothing to migrate and nothing to reconfigure: install the new version and
restart. On Windows/IIS, re-run the installer from the 1.0.1 source with your
original arguments. The IIS steps under [Upgrade](#upgrade) below show how
to recover them from the live site; from 1.0.1 on, the installer records
them in `install-args.json`.

If you ran `scripts\Verify-Install.ps1` on an earlier version, delete any
`verify-report.json` / `verify-report.md` it wrote (by default in
`<InstallDir>\logs\`, or the directory you ran it from when that folder
didn't exist) and any copies you shared: they can contain your
`web.config` verbatim, including secrets set inline rather than through a
`*_FILE` variable. See the 1.0.1 entry in [CHANGELOG.md](CHANGELOG.md).

## Upgrading from 0.9 to 1.0

1.0 is the release where cert-watch's defaults became strict. Most
installations need to do nothing, but go through this list first: several
items can lock someone out or change who gets alerted.

### Before you upgrade

- [ ] **Back up the database and its secrets.** On a command-line install, run
      `cert-watch backup /backups/cert-watch-pre-1.0.sqlite3` and keep the data
      directory's `.auth_secret` if cert-watch generated it.

      For Docker Compose, first write the WAL-safe backup inside the persistent
      `/var/lib/cert-watch` mount, then copy it out of the volume:

      ```bash
      docker compose exec cert-watch cert-watch backup \
        /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3
      docker compose cp \
        cert-watch:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3 \
        ./cert-watch-pre-1.0.sqlite3
      # If the app generated its signing key in the data directory, copy it too.
      docker compose cp cert-watch:/var/lib/cert-watch/.auth_secret ./.auth_secret
      ```

      With plain Docker, the equivalent commands are `docker exec cert-watch
      cert-watch backup /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3` and
      `docker cp cert-watch:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3 .`;
      copy `.auth_secret` too if it exists. If the signing key is supplied by
      container configuration instead, preserve it in that secret store.

      On Kubernetes, target the pod, write the backup inside the PVC mount, and
      copy it out:

      ```bash
      pod=$(kubectl get pod -n cert-watch \
        -l app.kubernetes.io/name=cert-watch \
        -o jsonpath='{.items[0].metadata.name}')
      kubectl exec -n cert-watch "$pod" -- cert-watch backup \
        /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3
      kubectl cp -n cert-watch \
        "${pod}:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3" \
        ./cert-watch-pre-1.0.sqlite3
      ```

      The supplied Kubernetes deployment reads its signing keys from the
      `cert-watch-secrets` Kubernetes Secret, not from the data directory. Keep
      that Secret in your secret-management system, or export it separately
      and protect the exported file; never commit it:

      ```bash
      kubectl get secret -n cert-watch cert-watch-secrets -o yaml \
        > cert-watch-secrets.yaml
      ```

      A Windows/IIS install instead uses `secrets\auth_secret` and
      `secrets\csrf_secret` through the `*_FILE` settings in `web.config`. Its
      CLI is inside the install directory and does not inherit the environment
      variables from `web.config`; for a default install, use an elevated
      PowerShell:

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

  Recover the values the live IIS site actually uses before re-running the
  installer. The following also shows child applications, because one can
  override the root site's pool or physical path:

  ```powershell
  Import-Module WebAdministration
  $site = Get-Website -Name "cert-watch"
  $site | Select-Object Name, physicalPath, applicationPool
  Get-WebApplication -Site "cert-watch" |
      Select-Object Path, physicalPath, applicationPool
  $pool = [string]$site.applicationPool
  Get-Item "IIS:\AppPools\$pool" | Select-Object Name, State

  $sitePath = [Environment]::ExpandEnvironmentVariables([string]$site.physicalPath)
  [xml]$webConfig = Get-Content (Join-Path $sitePath "web.config")
  $httpPlatform = $webConfig.configuration.'system.webServer'.httpPlatform
  $python = [Environment]::ExpandEnvironmentVariables([string]$httpPlatform.processPath)
  $installDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $python))
  $dataSetting = $httpPlatform.environmentVariables.environmentVariable |
      Where-Object name -eq "CERT_WATCH_DATA_DIR"
  $dataDir = [Environment]::ExpandEnvironmentVariables([string]$dataSetting.value)
  [pscustomobject]@{ InstallDir = $installDir; DataDir = $dataDir; AppPool = $pool; SitePath = $sitePath }

  $argsRecord = Join-Path $installDir "install-args.json"
  if (Test-Path $argsRecord) { Get-Content $argsRecord }

  & $python -m pip show ldap3 authlib
  Get-WebBinding -Name cert-watch -Protocol https |
      Select-Object bindingInformation, sslFlags
  netsh http show sslcert ipport=0.0.0.0:443
  # For an SNI binding, use the host from bindingInformation instead:
  netsh http show sslcert hostnameport=certs.example.com:443
  ```

  The Python path identifies `-InstallDir`; the root site's `physicalPath` is
  `-SitePath`; and its `applicationPool` is `-AppPool`. If the cert-watch
  application is a child application, use the corresponding
  `Get-WebApplication` row instead. If both Python packages are present,
  retain `-WithAuthExtras`. An IIS binding such as
  `*:443:certs.example.com` supplies `-HostName certs.example.com`;
  `sslFlags=1` supplies `-SharePort443`. The matching `netsh` entry reports the
  certificate hash to pass as `-TlsCertThumbprint`.

  Installers from 1.0.1 on also write the supplied, non-secret installer
  arguments and a reusable command to `<InstallDir>\install-args.json`; use
  that record on later upgrades when it is present. Older installs have no
  record, so use the live IIS values above.

  The script stops only the pool supplied as `-AppPool`. With `-ConfigureIIS`,
  it then assigns the existing `cert-watch` site to the supplied pool and sets
  its physical path to `-SitePath`. **Omitting custom values can therefore
  leave the real pool running during the install and repoint the site to the
  default pool or path.** Also keep the existing binding arguments: with no
  `-HostName` or `-SharePort443`, the installer rewrites the HTTPS binding to
  `*:443:` and switches out of SNI mode. (`-SharePort443` by itself is
  rejected.)

  The installer stops the application pool, which releases the database,
  updates the code, and starts the pool again. It does not replace the database,
  signing keys, or an existing `web.config`; the restarted application applies
  the pending database migrations. For any *manual* file operation, such as
  restoring a backup, stop the pool first; Windows won't let you replace an
  open database.

  The script upgrades pip, then runs `pip install --upgrade` for the cert-watch
  project in the extracted source tree; it does not install from `uv.lock`.
  With pip's default `only-if-needed` upgrade strategy, already-installed
  dependencies remain in place unless they no longer satisfy cert-watch's
  declared ranges. Any dependency resolution uses pip's configured package
  index, which is not necessarily PyPI.

Then watch the log for `backed up …` and `applying migration …` lines, and open
the web interface. Those lines are visible from 1.0.1 onward. Independently of
the application version, confirm that a new
`cert-watch-pre-migration-*.sqlite3` file appeared beside the database and
inspect the database's `schema_version` table. Windows does not include a
`sqlite3` executable, so use the installation's Python. Reuse `$python` and
`$dataDir` from the live IIS inspection above (the default `$python` is
`C:\ProgramData\cert-watch\venv\Scripts\python.exe`):

```powershell
& $python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('select max(id), count(*) from schema_version').fetchone())" (Join-Path $dataDir "cert-watch.sqlite3")
```

The default bare-metal Linux install uses `/opt/cert-watch/venv`; run:

```bash
sudo /opt/cert-watch/venv/bin/python -c \
  'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute("select max(id), count(*) from schema_version").fetchone())' \
  /var/lib/cert-watch/cert-watch.sqlite3
```

Inside a Compose container, the equivalent check is:

```bash
docker compose exec cert-watch python -c \
  'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute("select max(id), count(*) from schema_version").fetchone())' \
  /var/lib/cert-watch/cert-watch.sqlite3
```

Every migration registered by the target release must have a row. For 1.0,
an unmodified ledger prints `('0037', 37)`.

### What to expect afterwards

**Everyone signs in again once,** including the break-glass administrator,
because the session format changed. API keys keep working. On Windows/IIS, a
form left open across the upgrade fails once, because the CSRF secret file is
now honoured; reload the page.

**A v0.9.5 database runs nine migrations, 0029–0037:**

- **0029** adds the durable digest-delivery claim ledger.
- **0030** adds per-tag permission tiers to roles.
- **0031** merges certificate notes into matching host notes. If any note has
  no matching host, it remains in the deprecated `certificates.notes` column;
  that column is dropped only when no unmatched notes remain.
- **0032** adds append-only alert-delivery evidence.
- **0033** adds the clock used to bound alert-evidence deferral.
- **0034** records the certificate that triggered each alert.
- **0035** reconciles the schema of databases that had drifted from a fresh
  install: it adds `hosts.notes` and four indexes, and drops a duplicate column.
- **0036** gives alerts a delivery lifecycle.
- **0037** gives each alert a dedupe key and a saved routing snapshot.

The runner applies every registered migration whose ID is absent from
`schema_version`, in registry order; it does not assume that every ID at or
below the highest recorded ID is present. For the unchanged schemas in the
0.9.x release tags, the pending ranges are:

- **v0.9.0:** 0024–0037.
- **v0.9.1 and v0.9.2:** 0026–0037.
- **v0.9.3:** 0027–0037.
- **v0.9.4 and v0.9.5:** 0029–0037.

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
