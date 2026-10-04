# Taking over a cert-watch installation

Start here if you've inherited a running cert-watch and the person who set it
up isn't around to ask. This page is a map plus a short list of rules. The
detail lives in the other docs, and this page links to the right section
instead of repeating it.

## 1. Fill in the site sheet first

Every installation differs in hostnames, accounts, and how it was installed.
Keep these facts in your own records, **not in this repository**, which is
public. Copy the table below into your team's documentation and fill it in
with the previous owner before they leave.

| Fact | Where to find it | Value |
|------|------------------|-------|
| Version running | shown next to the cert-watch wordmark on every page | |
| Server and hosting model | IIS with HttpPlatformHandler, IIS reverse proxy + Windows service, Docker, or k8s ([install](install.md)) | |
| Install directory (`<InstallDir>`) | IIS site physical path; `install-args.json` lives here on 1.0.1+ | |
| Data directory (`CERT_WATCH_DATA_DIR`) | holds `cert-watch.sqlite3`, the `secrets` folder, and pre-migration backups | |
| IIS site name, app pool, and TLS binding | IIS Manager | |
| App-pool / service identity | IIS Manager → Application Pools → Advanced Settings | |
| Where the auth secret is kept | `<data dir>\secrets` or `CERT_WATCH_AUTH_SECRET` | |
| Break-glass admin: who holds it | [access control](access-control.md) | |
| Directory sign-in (LDAP/AD or OIDC) and its service account | Settings → Identity provider | |
| Alert delivery (SMTP relay, webhook) and recipients | Settings → Email (SMTP), Webhook & behavior, Alert groups | |
| Where backups go and how often | your backup job | |
| Who gets told when it breaks | | |

## 2. Rules that are easy to break

These rules come from real failures. Everything else in the docs is
recoverable.

1. **Back up with the CLI, never by copying the file.**
   `cert-watch backup <new-file>.sqlite3` is safe while the app runs. A plain
   copy of the database can miss committed data. See
   [operations: backups](operations.md#backups).
2. **Keep the auth secret with the backups.** Without it, stored SMTP, LDAP,
   and webhook credentials can't be decrypted after a restore. If you ever
   change it, run `cert-watch re-encrypt <old-secret>`
   ([operations: rotating secrets](operations.md#rotating-secrets)).
3. **Exactly one cert-watch process per data directory.** The SQLite database
   has a single writer ([operations: how it runs](operations.md#how-it-runs)).
4. **On IIS, the app pool must never idle out.** If it does, scanning silently
   stops while the site still looks healthy. Set `startMode=AlwaysRunning`,
   `idleTimeout=0`, *and* application preload, which needs the
   `IIS-ApplicationInit` feature. See
   [deploy/iis](../deploy/iis/README.md). Watch for a stalled scan (next
   section).
5. **On an IIS upgrade, give the installer the live site's real values.**
   It stops only the pool named by `-AppPool`. With `-ConfigureIIS` it
   repoints the site to `-SitePath`, so accepting the defaults on a customised
   install can point the live site at the wrong place. Installs from 1.0.1 on
   record their arguments in `<InstallDir>\install-args.json`. Read
   [UPGRADING.md](../UPGRADING.md) before every upgrade.

## 3. Routine

| How often | What | How |
|-----------|------|-----|
| When you look at it | The health strip at the top of every page is green | Amber means failed or undelivered alerts, or endpoints never scanned. Red means the scheduler or database is down. |
| Daily (automate it) | The last scan is under 36 hours old | Uptime-check `/readyz` with the metrics token, or alert on `cert_watch_last_scan_timestamp_seconds`. This is the failure that matters most ([monitoring](operations.md#monitoring)). |
| Weekly | Work through what's expiring or failing | **Home** (status counts, what needs attention) and **Activity**. Each alert is a certificate someone has to act on ([renewal reports](renewal-reports.md)). |
| Monthly | Make a backup and **test-restore it** somewhere that isn't production | [operations: restoring](operations.md#restoring) |
| Monthly | Check for a new release | The project's GitHub Releases page. Read the release's entry in [UPGRADING.md](../UPGRADING.md) and [CHANGELOG.md](../CHANGELOG.md) before deciding. |
| When someone joins or leaves | Grant or revoke their access | Settings → Roles (directory group mapping), Local users, API keys ([access control](access-control.md)) |
| Yearly | Rotate the break-glass password and any API keys | [operations: rotating secrets](operations.md#rotating-secrets) |

## 4. Upgrading

1. Read the section of [UPGRADING.md](../UPGRADING.md) for every version
   between yours and the target. Skipping versions is fine; skipping the
   notes isn't.
2. Take a CLI backup and copy the `secrets` folder.
3. Upgrade using the procedure for your hosting model
   ([deploy/iis](../deploy/iis/README.md#upgrading), or [install](install.md)).
4. Migrations run on startup and write their own pre-migration backup to the
   data directory first.
5. Confirm `/readyz` returns 200, then trigger a scan of one host and check it
   completes.

**To roll back**, stop the app, restore the CLI backup you took in step 2
([operations: restoring](operations.md#restoring)), and reinstall the
previous version.

## 5. Where updates come from

cert-watch is MIT-licensed open source. Releases (source tag, release notes,
and a container image) are published on the project's GitHub Releases page.
If upstream ever stops publishing, the license lets your organisation fork the
repository and keep building it. The test suite and CI configuration come with
it.

Report a security issue as described in [SECURITY.md](../SECURITY.md).

## 6. Where everything else is

| Question | Document |
|----------|----------|
| What does it do, and what doesn't it? | [README](../README.md), [positioning](positioning.md) |
| How is it put together? | [architecture](architecture.md), [threat model](threat-model.md) |
| Every setting | [configuration](configuration.md) |
| Who can do what | [access control](access-control.md) |
| Alert rules and delivery | [alerting](alerting.md) |
| Renewal reports | [renewal reports](renewal-reports.md) |
| The API | [api](api.md) |
| Running, monitoring, backups, the CLI | [operations](operations.md) |
| Something's wrong | [operations: troubleshooting](operations.md#troubleshooting), [deploy/iis: troubleshooting](../deploy/iis/README.md#troubleshooting) |
