# Changelog

All notable changes to cert-watch are documented in this file.

## [Unreleased]

### Fixed

- Settings → Tags no longer fails with a server error once any alert group
  exists (#113).
- A signed-in user who is not an administrator and opens a Settings page is
  sent to Home with "Settings are available to administrators only." It
  previously redirected to `/settings` forever (#113).
- Certificate links keep working after a rescan. A rescan that sees the same
  certificate keeps its id, so detail pages, bookmarks, API ids and renewal
  webhook links no longer break on the next scan. A link to a certificate
  that has since been renewed, or to an endpoint's host id, now opens the
  endpoint's current certificate with a short note, instead of "certificate
  not found". For a certificate replaced before this release, the link
  resolves only while its successor, its lifecycle event or an alert still
  records the endpoint. Scope still applies: a link never reveals a
  certificate the viewer can't see (#113).

## [1.0.2] - 2026-09-23

A patch release. No schema migrations and no configuration changes. The main
fix is OAuth/OIDC sign-in; see [UPGRADING.md](UPGRADING.md) for two small
behaviour changes (a JSON body size limit, and no `pip` in the container).

### Changed

- The container image runs Python 3.14 (was 3.13); CI also runs the unit
  suite on 3.14.
- The container image no longer includes the base image's system `pip`, which
  the app never used; its vendored libraries failed the release image scan.

### Fixed

- Signing in through OAuth/OIDC no longer lands on `/login` the first time.
  The callback set the `SameSite=Strict` session cookie on a redirect that
  continued the IdP's cross-site navigation, and browsers withheld the cookie
  from the redirected request: Firefox and WebKit always, Chromium whenever
  the IdP showed a sign-in page. The callback now answers with a short page
  that moves on to the app itself, so the cookie stays Strict and is sent
  (#98).
- JSON API bodies are refused with `400` when they nest deeper than 64 levels
  or exceed 256 KiB. The previous depth guard relied on `RecursionError`, which
  CPython 3.14.7 no longer raises for such bodies, so on that interpreter a
  hostile deeply nested body was accepted.
- `Verify-Install.ps1` run with no arguments no longer fails on a healthy
  host-name-bound IIS site. Without `-BaseUrl` it now probes the URLs from the
  site's own bindings (https first) before the `localhost` fallbacks, and
  without `-AppPool` it checks the site's application pool, so IIS-002,
  ACL-001 and ACL-002 run instead of skipping. Explicit arguments still win
  (#105).

## [1.0.1] - 2026-09-23

A patch release. No schema migrations and no configuration changes. Windows
operators should read the Security note below.

### Security

- `scripts/Verify-Install.ps1` no longer copies `web.config` into its
  diagnostics. Earlier versions wrote the raw file, including any secret set
  directly as an environment variable there (for example
  `LDAP_BIND_PASSWORD`), to `logs\verify-report.json` and `.md` whenever a
  check failed or warned, and the IIS-005 preload check always failed. If you
  ran the verifier and set secrets inline rather than through `*_FILE`, delete
  old `verify-report.*` files and any copies you attached to tickets, and
  consider rotating those secrets. Reports are now built from allowlisted,
  format-checked facts only; log contents and error messages are never
  included (see the script's help for what a report contains).
- `Verify-Install.ps1 -SkipCertCheck` no longer changes the process-wide
  certificate validation callback; the bypass applies to its own requests only.

### Fixed

- `Verify-Install.ps1`: the IIS-005 preload check no longer fails on every
  install; `-SkipCertCheck` works on Windows PowerShell 5.1; a new IIS-006
  check warns when IIS is up but the cert-watch backend process isn't (for
  example after `web.config` is saved).
- `install-windows.ps1` recognises an upgrade and no longer prints first-run
  admin guidance over an existing database, and records its non-secret
  arguments in `<InstallDir>\install-args.json` so the next upgrade can reuse
  them.
- `cert-watch verify-report` prints a clean `FAIL` and exits 1 when the report
  file is missing, unreadable, not UTF-8, or nested too deeply to parse,
  instead of a Python traceback (#66).
- Configure application logging before startup schema migration so the
  pre-migration backup path and each applied migration reach the configured
  handler.

- `cert-watch verify-report` reads the report as UTF-8 regardless of the
  system locale, so a report containing non-ASCII text no longer fails as
  tampered on Windows.
- Digest delivery leases are evaluated on the digest engine's clock, and
  SQL date arithmetic (dashboard buckets, pivot day counts, the `/readyz`
  expired count) uses a reference time bound from the application instead of
  SQLite's own clock.

### Documentation

- Correct the 0.9-to-1.0 migration behavior and ranges, including preservation
  of unmatched certificate notes. Expand the upgrade procedure with
  Docker/Compose, Kubernetes, Linux, and IIS backup and verification commands;
  live IIS path, pool, binding, and installer-argument recovery; the 1.0.1
  installer argument record; warnings about defaults repointing an IIS site;
  pip's actual dependency/index behavior; and the required recycle after a
  `web.config` edit.

## [1.0.0] - 2026-09-23

cert-watch 1.0 is a maintenance release in the literal sense: it rebuilds the
parts that were costly to change, and makes the defaults strict. Read
[UPGRADING.md](UPGRADING.md) before upgrading. Several changes can lock
someone out or change who gets alerted.

Highlights:

- **Alerting has a persisted lifecycle.** Alerts are claimed under a lease,
  retried with backoff, and given up visibly. Each alert type has one dedupe
  key per endpoint, routing is stored with the alert, and a single claimed
  engine sends every digest. Duplicate pages and silently lost alerts are both
  designed out.
- **Access control is enforced in one place.** One guard family, with CSRF on
  every write. Services check scope inside the write lock. Local accounts'
  roles are authoritative. A golden authorization matrix covers every
  mutating route.
- **Configuration has one source of truth.** Settings are declared once and
  resolved by one rule; `_FILE` secrets fail closed, and the reference is
  generated from the code.
- **The JSON API is complete.** Every UI action has an API equivalent over the
  same service, and a test proves it.
- **The schema is defined once.** Migrations are atomic, fresh and upgraded
  databases are identical, and concurrent startups serialise.
- **The scheduler is an object** that restarts itself with backoff and
  reports honestly when it can't.
- **Security hardening** from a threat-model refresh: `/metrics`
  authentication, content-type and Host checks, request-body caps,
  cleartext-LDAP refusal and cloud-metadata blocking.
- **Documentation rewritten**, with install, configuration, access-control,
  alerting, operations and architecture guides. The planning history moved out
  of the tree; see [docs/history.md](docs/history.md).

This section also covers changes shipped in 0.9.4 and 0.9.5, which were tagged
without changelog sections of their own.

### Security

- **Pre-1.0 request and outbound hardening.** `/metrics` now requires either
  its configured bearer token or an administrator browser session; API keys
  cannot authorize the admin-session path. API-key creation, listing, and
  revocation likewise require an administrator browser session. JSON-body
  writes require `application/json` and reject malformed or non-object bodies
  without a server error. In auth-disabled mode, requests accept only a
  loopback `Host` or the host configured by `CERT_WATCH_BASE_URL`. An ASGI
  request-body limit rejects declared and streamed bodies above 12 MiB before
  multipart parsing. Login throttling now uses a normalized username plus
  client IP, with a separate looser per-IP ceiling. The per-IP ceiling is
  deliberately 50 attempts per five minutes (up from 10): the tight
  10-attempt account-and-IP bucket still limits focused guessing, while the
  looser aggregate ceiling avoids locking out many users behind one NAT or
  untrusted proxy.
- **Plain LDAP simple binds are refused by default.** Use `ldaps://` or
  `LDAP_START_TLS=1`. A legacy deployment can explicitly retain plaintext
  binds with `CERT_WATCH_LDAP_ALLOW_INSECURE=1`; login and the Settings test
  action report a clear refusal when the transport is unsafe.
- **Outbound address classification covers cloud and carrier ranges.** The AWS
  IPv6 service range `fd00:ec2::/32` is always blocked for scans and webhook
  HTTP, including the `.253` DNS resolver and `.254` metadata endpoint. The
  local-use NAT64 prefix `64:ff9b:1::/48` is unwrapped before address-policy
  checks, matching the well-known NAT64 prefix. `100.64.0.0/10` is treated as private and follows
  `CERT_WATCH_ALLOW_PRIVATE_IPS` / `CERT_WATCH_ALLOWED_SUBNETS` policy.
- **JSON write routes now enforce the same per-action budgets and scope as the
  HTML forms.** HTML and JSON calls share one client budget for host creation,
  import, scans, endpoint settings, certificate upload, and mark-all-read.
  Host JSON bodies are strictly typed and bounded before service execution.
  Application services now reject a missing acting principal; trusted
  request-less work uses an explicit system principal instead of `None`.
- **Scoped host creation and CSV import reject tags outside the caller's
  scope.** Earlier versions could accept a scoped user's extra tag and persist
  the union (for example `B,A` for an `A`-scoped user). The caller's scope tag
  is still attached automatically, but every additionally submitted tag must
  be within that scope.
- **Sensitive settings uniformly support secret files.** Every environment-backed
  sensitive setting accepts a `<NAME>_FILE` source (including CSRF and metrics
  tokens), with the direct environment variable taking precedence. An explicitly
  configured secret file that is missing, unreadable, a directory, or empty now
  stops startup with a configuration error naming the variable; its contents are
  never logged. Empty `_FILE` variables remain unset.
- **`CERT_WATCH_ADMINS` is enforced without a role map.** With no role map,
  every directory user was admin regardless of `CERT_WATCH_ADMINS`, so a
  read-only user (outside `CERT_WATCH_WRITE_USERS`) could mint a write-scoped
  API key. Admin now requires membership when the list is set, and admin
  implies write: with only `CERT_WATCH_WRITE_USERS` set, admin requires
  membership in it. With neither legacy list set, the full-access default is
  unchanged. See UPGRADING.md.
- **Local accounts are authorized by their assigned role, not the role map.**
  With #59 fixed, accounts created in Settings → Users would have received
  full access whenever no `CERT_WATCH_ROLE_MAP` was set. A users-table
  session now resolves from its own role on every request (no role, or a
  deleted role, means read-only) and ignores the legacy write/admin user
  lists; the break-glass admin is always admin. How a session was minted
  travels as a reserved claim an IdP cannot supply, so a directory user who
  shares a local username gets neither its role nor break-glass status.
- **The Settings → Roles IdP mapping takes effect.** It was stored but never
  read, so directory users kept full access while the UI showed them mapped.
  It is now merged into the role map (env `CERT_WATCH_ROLE_MAP` wins per role)
  at startup and when saved. See UPGRADING.md before saving a first mapping.
- **A role mapping cannot outlive its role.** Settings → Roles mappings are
  now stored by role id: renaming a role keeps its mapping, deleting a role
  deletes it, and an entry that names no existing role grants nothing. (Keyed
  by name, a deleted or renamed role called `admin` left a mapping that fell
  back to the built-in admin tier.) Legacy name-keyed entries are honoured
  while a role of that name exists and rewritten by id on the next save.
- **Oversized sessions fail closed.** Trimming a session to fit the cookie
  limit could drop its roles, and with them the local-account marker, turning
  a read-only local account into full access. Roles are never trimmed now
  (groups, then email, are); a local login whose session cannot carry its
  marker is refused. Local usernames are capped at 128 characters and emails
  at 254.
- **Sessions from earlier releases are rejected (everyone signs in once).**
  They carry no local-account marker, so an unmarked session would have been
  authorized as a directory user (full access with no role map), and a
  directory session holding the literal claim `cw:break-glass` would have
  read as break-glass. The session format version is now bound into the
  signature; older tokens fail verification.
- **A renamed account's cookie cannot attach to a new account.** Renaming a
  local user revokes sessions for the old and new names, and creating a user
  revokes any residual session for that name; previously an old `alice`
  cookie resolved to a later account created as `alice`. The revocation happens
  before the new or renamed account becomes visible (and again after), so
  there is no window in which an old cookie matches it.
- **A role-map read error no longer grants full access.** A database error
  while reading the Settings → Roles mapping (e.g. `database is locked`
  during a settings rebuild) used to produce an empty role map, which means
  "full access" for directory users. The error now propagates and the last
  good settings stay in force; if settings cannot be loaded at startup,
  directory users are read-only until they load cleanly.
- **Removing the last IdP mapping no longer restores full access.** Once a
  Settings → Roles mapping has been saved (or one exists from an earlier
  release), an empty mapping leaves directory users read-only instead of
  reverting to the never-configured "full access" default. The Roles page
  warns before the last mapped role is deleted. A stored mapping that is not a
  readable JSON object is treated the same way (and logged), rather than as
  "never configured".
- **Legacy name-keyed mappings are normalised once.** Entries stored by role
  name are rewritten to role ids on load (dropped if no role has that name)
  and name keys are then ignored, so a role created later with a reused name
  never inherits an old mapping.
- **OAuth state and session tokens are signed in separate domains.** A
  session token (including a pre-1.0 one) no longer verifies as an OAuth
  state token, or vice versa. An OAuth sign-in in progress during the
  upgrade must be restarted.
- **A local account cannot shadow the break-glass admin.** Settings → Users
  rejects the break-glass username (case-insensitive) on create and rename,
  and sign-in tries the break-glass password even if a same-named account
  already exists.
- **Trust-anchor upload and delete are admin-only (#65).** `POST /trust-anchors`
  and `POST /trust-anchors/{id}/delete` required only write access on some tag,
  so a tag-scoped operator could install or remove a fleet-wide trust anchor.
  They now require an administrator (with CSRF), matching the settings page.
- **Scan history is scope-filtered.** `/scan-history` showed every host's
  name, port and scan error to tag-scoped users; it now lists only scans of
  hosts inside the user's scope.
- **Cryptography security floor.** `cryptography` now requires 50.0.0, which
  fixes CVE-2026-69247 / PYSEC-2026-3552. cert-watch does not use the affected
  PKCS#7 decryption APIs, but the update keeps the locked closure and strict
  advisory gate clean.
- **Trusted-proxy peer enforcement.** Forwarded client-IP headers are accepted
  only when the immediate TCP peer is in `CERT_WATCH_TRUSTED_PROXIES`; malformed
  forwarding chains fail closed to the peer address.
- **SMTP DNS-rebinding closure.** SMTP delivery and the admin test route now
  resolve and validate the relay once, connect to that pinned address on both
  STARTTLS and implicit-TLS paths, preserve the configured hostname for
  certificate verification, and fail closed when resolution fails.
- **Removed `CERT_WATCH_CSRF_DISABLED` env var (WI-097).** CSRF protection can
  no longer be disabled at runtime via environment variable. The deprecated env
  var (which globally disabled CSRF on all routes) has been removed from
  `middleware.check_csrf` and the startup lifespan. Deployments that set
  `CERT_WATCH_CSRF_DISABLED=1` must remove it — CSRF is now always enforced.
  The unit test suite uses an internal test-only flag (not env-var settable) to
  bypass CSRF for form-POST convenience; `csrf_strict` fixture re-enables real
  validation for tests that assert CSRF enforcement.
- **Tag-scope enforcement for bulk operations (WI-078).** The three bulk routes
  — scan-all-hosts, flush-alert-queue, and mark-all-alerts-read — now honour the
  caller's tag scope. Previously a scoped user could scan every host, flush the
  entire alert queue, or mark all alerts read regardless of their team scope;
  these operations now act only on in-scope resources, while admins / unscoped
  users are unchanged. The scoped SQL lives in repository methods
  (`SqliteHostRepository.list_scoped`, `SqliteAlertRepository.list_pending_scoped`
  / `mark_all_read`) and a `ScopedAlertRepository` decorator, with route-level
  regression tests that drive real scoped sessions end-to-end.

### Added

- **Endpoint-keyed alert lifecycle and persisted routing.** Migration 0037
  adds alert dedupe keys, condition closure timestamps, versioned routing
  snapshots, an open-queue uniqueness guard, and a `rule_firings` ledger for
  recurring event-only rules. Policy and drift alerts now receive the same
  alert-group, owner, and role-member routes as expiry alerts.
- **Durable alert dispatch claims and operator retry.** Migration 0036 adds
  atomic claims, expiring leases, attempt counters and scheduled retry times.
  Activity shows the new `sending` state and offers an audited **Retry failed**
  action (HTML and JSON API) that resets a terminal alert's attempt budget.
- **The JSON API is now the operational presentation seam.** Every inventory
  mutation has a JSON counterpart over the same application service as its
  server-rendered form. New endpoints are:

  | Action | JSON endpoint |
  |---|---|
  | Create or import hosts | `POST /api/hosts`, `POST /api/hosts/import` |
  | Scan all or one host | `POST /api/hosts/scan`, `POST /api/hosts/{id}/scan` |
  | Edit host settings | `PATCH /api/hosts/{id}/settings` |
  | Delete a host | `DELETE /api/hosts/{id}` |
  | Upload or delete a certificate | `POST /api/certificates/upload`, `DELETE /api/certificates/{id}` |
  | Add or delete a trust anchor | `POST /api/trust-anchors`, `DELETE /api/trust-anchors/{id}` |
  | Mark all visible alerts read | `POST /api/alerts/mark-all-read` |

  Existing `/api/health`, `/api/audit`, certificate-posture, host-export, and
  alert-read URLs are unchanged but their route definitions now live under
  `routes/api/`. No endpoint path moved or redirects were added.
- **Host ownership has a coherent UI write path.** The detail form now posts to
  `POST /hosts/{id}/owner` instead of the certificate-namespaced path. The old
  `POST /certificates/{id}/owner` path remains callable for compatibility and
  uses the same service; API clients continue to use
  `PATCH /api/hosts/{id}/owner`.
- **Published container images are signed and attested, and verified before
  deploy.** The release workflow signs the pushed digest with keyless cosign,
  attaches an SPDX SBOM and max-detail SLSA provenance, then re-verifies the
  signature (exact workflow-and-ref identity) and the attestations (they must
  name the released commit) before the deployment pointer may move
  (`scripts/verify_release_attestations.py`). The pointer itself now pins the
  verified digest, so Argo CD pulls what was verified rather than whatever a
  mutable tag resolves to at sync time. Verification commands and caveats are
  in `docs/runbook.md`; Dependabot watches the pinned actions and base images,
  with the release-pipeline actions split into their own review PR group.
- **Scan freshness and coverage.** Home counts current observations across the
  visible monitored fleet; Browse and endpoint details distinguish overdue,
  incomplete and unobserved scans. Daily/custom cadence shares the scheduler's
  policy, and retry attempts cannot refresh the last successful observation.
- **Endpoint settings.** Edit cadence, alert threshold and operator-reported
  renewal status on the detail page, with explicit suppression/reset guidance.
- **Per-alert delivery evidence.** Record transport attempts and sanitized
  routing/outcome observations for administrator inspection in Activity.
  Historical alerts remain explicitly without delivery evidence.
- **Offline alert-routing inspection.** `cert-watch routing-report <snapshot>`
  lists group coverage, specific recipients, orphans and multiple matches from a
  completed database backup. It reuses delivery's routing resolver, does not send
  alerts or load credentials, and refuses incomplete or incompatible snapshots.
- **Alert delivery receipt tests.** Local TLS/AUTH SMTP and HTTP receivers verify
  recipient unions, negative destinations, fallback and durable retry behavior.
  The receipt suite runs explicitly in CI, including TLS certificate and hostname
  refusal checks, rather than being silently excluded by integration markers.
- **Renewal webhook (automation seam).** When the daily scan cycle detects a
  **renewal-overdue** certificate (inside its renewal window with no successor
  yet), cert-watch can POST a structured, machine-readable payload to an
  external renewal tool — certbot, acme.sh, Certify the Web, an Ansible play, a
  custom script — carrying hostname, port, SANs, issuer, expiry, and an
  `automation_hint` so the receiver can act without calling back. Distinct from
  the human-facing alert webhook. Enabled with `CERT_WATCH_RENEWAL_WEBHOOK_URL`
  (optional `CERT_WATCH_RENEWAL_WEBHOOK_HEADERS`, `CERT_WATCH_BASE_URL` for a
  deep-link); routed through the same SSRF-guarded opener as the alert webhook,
  **retried** with exponential backoff (3 attempts) on transient failure, and
  best-effort (a failing endpoint is logged, never blocks the scan cycle).
  cert-watch does not renew certificates itself — this is the integration seam
  for closing the loop on a stalled job. Documented in the README; the wiring
  (detect → emit → deliver, plus 24h dedup and retry) is covered by
  `tests/test_scheduler_renewal_webhook.py`.
- **Windows uninstaller (`scripts/uninstall-windows.ps1`).** Tears down a
  Windows/IIS deployment created by `install-windows.ps1`: stops/removes the
  app pool and site, removes the physical site directory, and deletes **only
  the TLS cert binding this deployment owns**. Port-443 sharing is respected —
  the script reads the site's own HTTPS binding to decide ownership: a catch-all
  install removes `ipport=0.0.0.0:443`; an SNI install (`-SharePort443`) removes
  `hostnameport=<host>:443` only and leaves the catch-all alone (a sibling tool
  such as gpo-lens may own it). The catch-all/SNI decision keys on `sslFlags`
  (bit 1), not hostname presence, since a catch-all binding can carry a host
  header. The site directory removed is the site's own `physicalPath` (not a
  fixed path), so a non-default `-SiteName` cannot delete another site's
  directory. Data is preserved by default; `-RemoveData` (gated behind a typed
  confirmation or `-Force`) also deletes the signing keys and cert-history DB.
  Validated end-to-end on a real IIS host with disposable sibling sites; covered
  by `tests/test_uninstall_windows_ps1.py` and documented in
  `deploy/iis/README.md`.

### Changed

- **Alert rules no longer manufacture repeat notifications for a persistent
  condition.** Renewal-stalled alerts fire once per endpoint and certificate
  fingerprint;
  policy violations remain quiet until the rule clears and later reappears;
  expiry thresholds are endpoint/fingerprint-keyed and remain once-only.
  Shared wildcard/SAN certificates retain one alert and immutable route per
  endpoint; uploaded certificates use their row identity. Cancelled alerts that
  never reached a recipient no longer suppress a recreated lifetime condition.
  Renewal-overdue cadence now uses `rule_firings` after the event is persisted,
  instead of reparsing event JSON every cycle.
  Routes are fixed when an alert is queued (destination credentials and URLs
  still resolve when it is sent). Certificate replacement/deletion cancels and
  retains stale pending alerts instead of deleting them. A live leased row is
  marked closed and settles as sent or cancelled; an expired stale lease is
  cancelled rather than reclaimed. Failed drift edges can be retried. Cancelled
  rows use the normal delivered retention horizon.
- **Alert delivery failures back off before giving up.** A failed delivery
  round returns to `pending` for 1 hour, then 4 hours, then 12 hours; after 12
  transport-reaching attempts the row becomes terminal `failed`. Expiry rules
  no longer revive failed alerts indefinitely. Manual flush ignores the delay
  but uses the same atomic claim path, so concurrent scheduler/flush workers do
  not both send the same queued row.
- **Host creation exposes the fields it accepts.** The add-host drawer now
  includes optional tags, notes, and scan cadence, and the CSV help lists every
  supported optional column. This closes the prior route/UI contract mismatch.
- **Configuration now has one source of truth.** A declarative field table drives
  defaults, env/kv precedence, parsing, bounds, and sensitivity; runtime
  consumers use the resolved `Settings` snapshot instead of re-reading env or
  `kv_store` independently. Blank environment placeholders do not mask saved GUI
  values or lock their controls. Environment values now consistently beat saved
  values for `SMTP_PORT`, `LDAP_CONNECT_TIMEOUT`, and `ALERT_DIGEST_ONLY`; saved
  `oauth_scope`, `ldap_user_filter`, and `webhook_kind` values now take effect.
  Invalid out-of-range saved integers fall back to defaults, and saved booleans
  accept both `true` and `True`. See UPGRADING.md before deploying this change.
- **One way to guard a route; every write guard checks CSRF.** Routes declared
  authorization four different ways, and one of them (`require_admin_form`)
  left CSRF to a separate call each handler had to remember. Every route now
  declares a single guard dependency from `auth/guards.py` (`write_guard` /
  `admin_write_guard` for JSON, `write_form_guard` / `admin_form_guard` /
  `admin_settings_form` for HTML forms, `require_auth` / `require_admin` /
  `admin_page_guard` for reads); a mutation guard cannot be built without
  CSRF, and a test fails any mutating route without exactly one.
  `middleware.py` is split by concern into `security/csrf.py`,
  `security/ratelimit.py`, `security/headers.py`, `auth/request_context.py`
  (one AuthContext builder instead of two) and `auth/guards.py`. The host
  notes, tags and ownership services now enforce tag scope themselves, inside
  the write lock. Nine handlers that exported audit events to the SIEM while
  holding the global write lock now do so after releasing it. No
  authorization decision, redirect or message changes (pinned by a
  2016-observation route x principal matrix).
- **Schema creation now has one source of truth.** Fresh databases and upgrades
  both traverse the numbered migration chain, each migration commits its schema
  work and version row atomically, and migration 0035 reconciles objects that
  older startup code created outside that chain.
- **Audit action names for tag edits are unified.** The HTML and JSON paths now
  share one service, and both record `host.update_tags` / `cert.update_tags`.
  The JSON API previously recorded `host.set_tags` / `cert.set_tags`; audit or
  SIEM filters on the old names need updating.
- **Alerting code now lives exclusively in the `cert_watch.alerting` package.**
  Rules, routing, transports, delivery evidence, the delivery cycle and the
  unified digest engine each have their own module. The deprecated module paths
  `cert_watch.alerts`, `cert_watch.alert_delivery`, `cert_watch.alert_adapters`
  and `cert_watch.digest` have been removed for 1.0; external Python imports
  must use `cert_watch.alerting` or its public submodules.
- **One synchronous, claimed digest engine handles expiry, renewal and orphan
  summaries.** SMTP refusal maps retry only refused recipients, webhook
  fallback runs only after SMTP failure when no claim is busy, and expiry and
  renewal webhooks share the same three-wave retry policy. Renewal webhooks now
  run synchronously within the alert-cycle budget. Orphan notices are claimed
  once per ISO-week period. The old scheduler `kv_store` week keys remain in
  existing databases but are no longer read or written; `digest_deliveries`
  claims are the sole cadence guard. Expiry digest headers now state the actual
  configured cadence window instead of always saying 30 days. The renewal
  webhook subject was fixed at `Renewal Digest (7d)`; it now includes the
  active cadence, for example `Renewal Digest (14d)`.
- **Activity uses one alert-channel vocabulary.** New delivery attempts are
  recorded as `smtp` or `webhook:<kind>` (for example `webhook:teams` and
  `webhook:alertmanager`); legacy ledger names are normalized on read and the
  append-only historical rows are not rewritten.
- **The identifier gate now fails closed everywhere it runs.** The local hooks
  previously exited before invoking the gate whenever no denylist was
  configured, so the always-on swap-file/`.env`/guarded-dir guards and the
  public-repo fail-closed logic never fired outside CI; they are now always
  invoked and the script itself decides. In `--staged` mode the publication
  declaration is read from the index — the bytes the commit actually records —
  not the worktree, and staged type-changes (`T`) are scanned, not just
  adds/copies/modifications. The CI job runs on `pull_request_target` with the
  base ref's script scanning an untrusted PR tree (new `--tree` mode), so fork
  PRs are gated instead of hard-failing on a secret they cannot hold.
- **Information architecture: Home / Browse split.** The landing page is now a
  **Home** view organized around the operator's actual question — "what needs
  a human, and when?" — instead of the raw inventory table. Home shows a
  ranked attention queue (expired → stalled renewals → critical → failing
  scans → warnings, with renewal confidence demoting automated renewals) and a
  12-week expiry horizon with renewal-storm markers. The full inventory table
  (sorting, urgency filters, pivots, calendar, add drawer) moved to **`/browse`**;
  requests to `/` carrying the old dashboard's filter/sort/page/view params
  redirect there (307, query preserved). Nav: Home · Browse · Posture ·
  Activity · Settings.
- CI and E2E jobs install from the committed `uv.lock`, Starlette's test client
  uses its supported `httpx2` backend, and the Docker build pins the `uv` image
  by digest for reproducible builds.

### Removed

- **Per-certificate notes (UI-INVENTORY V1/V2).** Notes are now a single
  host-scoped concept. Migration 0031 concatenates every non-empty
  `certificates.notes` value into the matching `hosts.notes` row and drops the
  column only when no unmatched notes remain. Endpoints removed: `POST /certificates/{id}/notes`,
  `PATCH /api/certificates/{id}/notes`; the `notes` key was also removed from
  `GET /api/certificates/{id}` responses. The three dashboard inline note
  editors were removed — the dashboard shows a read-only note indicator; the
  single editing surface is the Notes panel on the endpoint detail page
  (`POST /hosts/{id}/notes`, JSON: `PATCH /api/hosts/{id}/notes`).
  **Caveat:** notes attached to uploaded certificates with no matching host
  row cannot be merged; they are listed in a WARNING log at migration time and
  remain in the deprecated live column as well as the pre-migration backup.

### Fixed

- **Scheduler crashes recover without restart storms or false readiness.**
  Exceptions in loop setup now retry with exponential backoff (one second up
  to five minutes), make `/readyz` not-ready during recovery, and expose the
  consecutive failure count plus last exception class in `/api/health`.
  Planned bounded-stop handoff remains immediate and separate from crash
  recovery. Immediate scans without an explicit host provider again scan all
  registered hosts. Scheduler wake/delivery routes tolerate missing app state.
  The last-scan metric is absent when no scheduler is attached; if refreshing
  its timestamp hits a database error, `/metrics` serves the last known value.
- **Scheduler restarts and shutdown are now deterministic.** Each application
  owns its scheduler thread, synchronization state, clock, and renewal-webhook
  executor. Restarting after a bounded stop hands off to exactly one new loop
  after the old cycle reaches a safe point, instead of returning early on the
  still-alive old thread and later leaving no scheduler running. Shutdown also
  cancels queued webhook work and cannot wait indefinitely on a hung delivery.
- **Alert delivery outages no longer evict the serving pod.** `/readyz`
  reports overdue pending alerts and stale `sending` leases without failing
  Kubernetes readiness. `/api/health` dates terminal give-ups from their last
  attempt, Activity labels them as requiring operator retry, and `/metrics`
  exports `cert_watch_alerts{status=...}` plus the self-clearing
  `cert_watch_alerts_failed_recent` 24-hour gauge used by the example
  failed-delivery rule.
- **Legacy failed expiry alerts remain deliverable after migration 0036.** The
  migration marks pre-lifecycle `expiry_warning` and `expired` rows but leaves
  them failed. On the next threshold evaluation, only a row for a certificate
  that still exists as the current, unsuperseded leaf, is not marked renewed,
  and represents the most urgent currently crossed threshold is revived once.
  Deleted, renewed, superseded and obsolete-threshold rows stay failed and
  remain available for an operator-initiated **Retry failed**.
- **Delivery recovery no longer waits on stale no-channel backoff.** Saving a
  valid SMTP or webhook channel clears the scheduled delay on pending rows
  deferred solely because no channel existed. Repeated failures keep one
  attempt-count suffix, and a scoped worker no longer reports a deferral after
  another worker steals the row's lease.
- **Pre-transport policy failures now obey bounded give-up.** SSRF blocks and
  invalid webhook channel results consume delivery rounds and eventually
  become operator-visible failures. An estate with no SMTP or webhook instead
  keeps alerts pending on normal backoff without consuming the attempt budget.
- **Cycle-budget deferrals preserve retry pacing and diagnostics.** Alerts
  attempted before a delivery cycle runs out of time retain their last useful
  error and receive persisted backoff; only rows never reached in that cycle
  remain immediately eligible.
- **Manual Flush queue no longer exhausts alert retries.** Operator-initiated
  flushes still record append-only delivery evidence and schedule normal
  backoff after failure, but do not advance the persisted give-up counter.
- **Alert settlement is failure-isolated and prompt.** A second refused
  database update in either evidence-deferral recovery branch no longer aborts
  the delivery cycle. Accepted alerts are marked `sent` immediately, closing
  the lease window in which a long cycle and concurrent flush could resend one.
- **Scoped alert settlement retains lease guards.** The tag-scoped repository
  now forwards dispatch settlement metadata to its inner SQLite repository, so
  evidence deferrals and give-ups transition `sending` rows instead of silently
  leaving them leased.
- **Retry failed no longer reveals cross-team alert IDs.** HTML and API retry
  routes return the same not-found response for missing and out-of-scope
  alerts, while denied attempts are recorded in the audit log.
- **The container image supports LDAP and OAuth sign-in.** The published image
  was built without the optional `ldap3` / `authlib` libraries, so
  `AUTH_PROVIDER=ldap|oauth` could not work in it. The image now installs the
  `auth` extra, and the deploy smoke job checks the imports.
- **Alerts page flash messages.** `/alerts` now shows `?warning=` and `?error=`
  messages (flush busy, flush failures, rate limits); they were silently dropped.
- **Signed compliance reports reject unsigned additions.** Verification now
  requires the file to be exactly what its signed values render to, so an
  added key (anywhere in the document) fails instead of passing.
- **SIEM export no longer runs under the write lock.** Audit events recorded
  inside a transaction are now sent to the SIEM after the transaction commits
  and the global write lock is released, so a slow or unreachable syslog/HEC
  sink cannot stall other writers on those paths, and the event is not sent
  before its row commits.
- **Accounts created in Settings → Users can log in (#59).** The auth provider
  was built without the database path, so the users table was never consulted
  and every locally created account was rejected. Each account is authorized
  by its assigned role (see Security).
- **OAuth/Entra sign-in works (#58).** `/auth/login` was not a public path, so
  the "Sign in with …" button bounced back to `/login`; and the OAuth state
  cookie was `SameSite=Strict`, which browsers withhold on the IdP's cross-site
  redirect back to `/auth/callback`. The route is now public and the cookie is
  `SameSite=Lax` (still `HttpOnly`, 10-minute lifetime).
- **Tag scopes match case-insensitively everywhere (#69).** The per-resource
  read/write gates and the per-tag write tier compared tags case-sensitively,
  so a role scoped to `Payments` saw a host tagged `payments` in lists but could
  not open or edit it.
- **Pending hosts appear in the scoped fleet-pivot drill-down (#69).** The
  drill-down dropped every never-scanned host for a tag-scoped user, so the
  group count and its rows disagreed.
- **The owner and renewal-method pivot drill-downs no longer fail.** The
  loader's host filter referenced an un-aliased table and raised an SQL error
  (`GET /api/pivot/owner/…`, `/api/pivot/renewal_method/…`).
- **Saved settings no longer disable environment-configured renewal webhooks.**
  KV overrides now replace only their declared fields instead of rebuilding and
  silently dropping newer `Settings` fields.
- **Manual alert flushes no longer block or race scheduled delivery.** The
  blocking send runs in a worker thread and skips with a clear busy message
  while a scheduler cycle owns delivery.
- **Digest delivery remains retryable.** Short-lived certificates retain their
  final lifetime-relative threshold in digest mode, and background webhook or
  orphan-notice exceptions are logged and release the weekly in-flight guard
  (#60, #61).
- **Compliance report verification covers derived presentation fields.** Changes
  to metric percentages/displays or remediation counts now fail verification;
  malformed reports fail cleanly instead of raising `KeyError` (#66).
- **Scheduler failures stay isolated and shutdown stays bounded.** Scan-history
  write errors, malformed timestamps, per-host renewal analysis, and deferred
  post-commit work no longer abort unrelated work; queued pool tasks are
  cancelled during shutdown (#67, #68).
- **A genuine renewal now resolves the PagerDuty incident the trigger actually
  opened.** The dedup key was derived from the certificate row id, but an
  unchanged rescan rewrites that row (#57) and carries the alert to the new
  id — so the resolve sent at renewal hashed a row PagerDuty had never seen,
  and the incident stayed open while the log claimed a resolve. Alerts now
  persist the row id they fired against (`trigger_cert_id`, migration 0034),
  and triggers and resolves both key on it; the migration backfills existing
  alerts with their current row id, which is exactly the id their open
  incidents were keyed with.
- **Linter versions are pinned to a family.** `ruff`, `mypy` and `djlint` carried
  open upper bounds, with only `uv.lock` holding them steady — so the next
  routine `uv lock --upgrade` was free to cross a rule-set expansion and redden
  CI on untouched code, blaming whoever regenerated the lock. djlint 1.46 was
  already there, promoting H043 into its defaults and flagging nine unchanged
  templates. Those nine `<button>` tags now carry an explicit `type`, so both
  the current and the next djlint are clean and the upgrade is unblocked.
- **A failing relay no longer stalls the scan cycle in proportion to the alert
  queue.** The retry backoff sat inside the per-alert loop, so each failing
  alert slept its own ~6s: a ten-alert queue blocked the scheduler for 71s, and
  a hundred for roughly twelve minutes — while scanning waited, during exactly
  the outage an operator needs scanning to survive. Retries now run in waves, so
  the sleeps are shared by the queue (ten failing alerts: 71s → 7.6s) while each
  alert still gets its full run of attempts. A wall-clock budget bounds what
  waves cannot: an unreachable relay burns a socket timeout per attempt rather
  than refusing, which no amount of sleep-sharing helps. Alerts the budget cuts
  short stay pending and are reported as deferred, never as failed.
- **One host could stop the whole estate from being scanned.** `scan_interval_hours`
  was unbounded in the add-host form and CSV import, and `last_success +
  timedelta(hours=N)` leaves the representable date range long before `N` does.
  A single such row made `get_hosts_due_for_scan` and the scheduler's wakeup
  calculation raise `OverflowError`, so nothing was scanned at all — while the
  dashboards, which already caught it, kept rendering green. Both write paths
  now bound the cadence to 1–8760 hours, and the scheduler falls back to the
  daily cadence (with a warning) for rows written before the bound existed.
- **A partial CSV import no longer drops rows in silence.** Rows rejected
  alongside successful ones redirected to a bare `/` with nothing said, so an
  operator believed they had imported endpoints that were never added. The
  count and the first few reasons are now reported.
- **The endpoint-settings form is offered only when the POST would accept it.**
  The affordance asked `AuthContext.may_write_any()` while the POST enforces
  `require_write_form` — a different predicate for API-key contexts and for the
  legacy `write_users` path. A user with only per-tag write grants was shown the
  form, filled it in, and was bounced to `/?error=` with their input discarded.
  Both now call one exported gate, `middleware.form_write_error`.
- **The deployment image pointer only moves forward.** A release whose bump
  commit lost the race to a concurrent merge failed non-fast-forward and
  dropped the pointer, while the image itself was already published — a red run
  that was usually benign, which is the worst kind. Rebasing before the push
  would have cleared the rejection and silently published an *older* image
  whenever the losing run finished last. `scripts/bump_deploy_image.py` instead
  re-derives the bump against the current tip on each attempt and withdraws
  when a newer release already points past this one, so the result converges on
  the newest image that actually built, whatever order the runs finish in.
- **A database outage no longer drops a deliverable alert.** Refusing to send
  because the delivery-attempt record could not be written was indistinguishable
  from a transport failure, so it burned the retry budget on every pass and
  marked the alert failed — permanently, even though no destination was ever
  contacted. Such an alert is now left pending and reported as `deferred`, and
  the cycle stops rather than sleeping a backoff it has nothing to back off
  from. A deferral that outlasts the outage is visible rather than merely
  correct: `/api/health` reports `undelivered_alerts` (still pending more than
  24 hours after being raised) and degrades to `warning`, and Activity marks
  each one **Not yet delivered** alongside whatever a transport last said.
- **Renewal notifications preserve ports.** Digests and webhook enrichment use
  exact endpoints for ownership and certificate evidence. Ambiguous legacy
  events do not borrow another endpoint's owner, expiry or renewal history.
- **Settings reach scheduled work.** Refresh scheduled transport and scan
  configuration after saving settings, honor per-host scan intervals, and
  pass configured TLS verification and drift options to manual scans.
- **Readiness uses observed evidence.** Include unscanned monitored endpoints
  as unknown; use the current scanned leaf's actual validity and trust instead
  of treating its first observation as its issuance date. Historical analytics
  no longer invents missing lifetimes or infers automation from incomplete
  validity evidence; partial days round up when compared with validity caps.
- **Consistent investigation.** Home and Browse share expiry-and-trust status
  counts. Inventory links preserve encoded search terms, source, ordering,
  and grouping; fleet views state their population and filters can be cleared.
- **Truthful operational controls.** Home renewal attention follows the
  current renewal condition independently of notification delivery. Remove
  inactive group-webhook inputs while preserving stored values, and describe
  revocation checks as endpoint reachability rather than certificate status.
- **Development dependency audit.** Raise the test-only HTTPX2 floor to 2.12.0
  and lock its matching httpcore2 transport at 2.12.0 to clear newly published
  dependency advisories. Application runtime dependencies are unchanged.
- **Release correctness review.** Align inventory counts, row status, and detail
  status. Show attention
  for each affected deployment of a shared certificate, including unknown and
  self-signed chains. Distinguish configured automation from observed renewal.
- **Endpoint renewal and readiness analytics.** Preserve port identity, rollback
  deployment periods, and the latest certificate lifetime. Add `port` to report
  and analytics results and an optional validated port selector to host analytics.
  Scope overdue detection and deduplication to the endpoint while retaining
  legacy-event compatibility.
- **Accessible mobile investigation.** Present Browse rows as cards, compact
  primary navigation, keep menus/actions and crypto tables reachable, and preserve
  native keyboard activation of tag links inside clickable inventory rows.
- **Scope and health accuracy.** Limit tag suggestions to visible resources;
  report database write/query failures as degraded instead of healthy. Clarify
  that digest settings control a shared weekly window, not per-team schedules.
- **Verified image publication.** Gate images on exact-commit CI, browser/visual,
  and deployment smoke checks. Support validated version-tag builds without
  changing `latest` or deployment manifests; install the IIS preload prerequisite
  in Windows smoke tests without weakening the production verifier.
- **Certificate detail chain guidance and notes editing.** Preserve public-root
  trust validation after loading certificates from the database, fixing false
  incomplete-chain warnings beside a passing scan grade. Identify the expected
  issuer at a chain gap, distinguish missing issuers from untrusted roots, and
  suggest the appropriate bundle or trust-store repair. Label historical grades
  when current chain validation differs. Notes now have one visible view or
  editor, with explicit Edit notes, Cancel editing, and Save notes controls.
- **UI review and branch reconciliation.** Bound Home's horizon to twelve
  calendar weeks, correct expiry summaries, reveal attention-row actions,
  remove closed-drawer shadows, make mobile Browse modes scrollable, stack
  mobile certificate-detail panels, and increase essential secondary-text
  contrast using existing tokens. Reconcile competing migration IDs through
  0031; preserve unmatched notes and distinct note fragments during upgrades.
  Repair the real LDAP test harness and CI's design-provenance checkout.
- **Complete owner renewal digests with case-variant addresses.** Hosts whose
  stored owner emails differ only by letter case are now combined before SMTP
  or webhook delivery. Previously the shared case-insensitive delivery claim
  let the first digest suppress later variants, omitting their hosts.
- **Cross-process digest delivery deduplication and shutdown safety.** Renewal,
  expiry, and orphan digest sends now take atomic per-recipient/channel claims
  in a SQLite delivery ledger (migration 0029). Claims are acquired/renewed
  immediately before each sequential send rather than while queued. Successful
  partial deliveries are skipped on retry; SMTP refusal mappings commit
  accepted recipients and release/retry only refused recipients. Abandoned
  claims become retryable after an expiring lease, and provider idempotency
  identities remain stable (including PagerDuty's dedup key). SMTP remains
  intentionally **at-least-once**: a
  process crash after the relay accepts a message but before the ledger commit
  can produce one duplicate after lease expiry. Scheduler executor shutdown is
  now terminal until explicit startup; stopping during a long scan prevents
  later cycle stages from submitting new work or recreating an executor.
- **Renewal digest cadence.** Durable per-recipient/channel claims now provide
  the weekly guard directly; the older scheduler-wide ISO-week key and
  in-memory in-flight state are no longer part of delivery correctness.
- **Status-colour separation under colour-vision deficiency (WI-145).**
  The dark-theme `--expired` (pink `#fb6f92`) collapsed onto `--ok` under
  deuteranopia (dE76 2.7) and onto `--crit` under tritanopia (dE76 2.7) —
  exactly the pair an operator must not confuse on a triage page. `--expired`
  is now violet in both themes (dark `#a78bfa` / light `#6d28d9`), keeping
  a measured minimum dE76 of 35.1 against the reconciled Patina palette from every status colour under normal vision
  and all three dichromacy simulations. A new ratchet test
  (`tests/test_color_separation.py`) parses `tokens.css` and asserts the
  floors so a future palette refresh can't silently collapse the separation.
- **IIS installer now requires the Application Initialization role service
  (WI-140 follow-up).** `preloadEnabled` is silently ignored by IIS unless
  the feature (`Web-AppInit`, `warmup.dll`) is installed — no warning, no
  error. That trap caused a second silent scan gap on the mvmcitest01 estate:
  preload was configured on 2026-07-27, but after an IIS recycle on
  2026-08-16 the backend never restarted and scanning stopped for 4 days.
  `install-windows.ps1` now verifies feature state, native-module registration,
  and `warmup.dll`; it installs the feature (Server Manager cmdlet or DISM
  fallback) and fails loudly if required state is still missing rather than
  leave an inert preload config. README documents the trap and verification.
- **Scheduler false-success on rolled-back scan transactions (WI-142).**
  `store_scanned` silently returned `""` when its transaction failed and
  rolled back, which the scheduler path recorded as `status='success'` —
  hiding scan-data loss from the operator and skipping fast-retry. It now
  re-raises on rollback (matching the contract of the route-layer path), and
  the scheduler treats an empty leaf-id return from `store_fn` as a failure
  too (defense in depth).
- **SMTP port 465 SSRF IP pinning (WI-143).** Implicit-TLS delivery
  previously fell back to hostname-based connection because `SMTP_SSL`
  cannot override `_host` after connect — reopening a DNS-rebinding window
  for the admin-configured SMTP relay. Resolution and validation now share
  one DNS answer (`resolve_smtp_host`) and the transport connects to the
  pinned IP while retaining the hostname for SNI/cert verification on both
  the 465 and STARTTLS paths.
- **X-Forwarded-For peer validation (WI-144).** Setting
  `CERT_WATCH_TRUSTED_PROXIES` alone caused headers from any TCP peer to be
  trusted. The peer is now required to be in the allowlist before XFF is
  consulted, and malformed chain entries fall back to the peer address.
- **Secret redaction for short SMTP passwords and routing keys (B4).** The
  `>= 4` length gate on `_sanitize_smtp_error` / `_sanitize_webhook_error`
  leaked 1-3 char secrets into `alert.error_message` and WARNING logs.
  Passwords and routing keys are now always redacted, using word-boundary
  regex for short secrets so common substrings like `nope` are not
  corrupted.
- **`_row_to_cert` robustness (B2).** Corrupted `san_dns_names` JSON (manual
  DB edit, disk error, partial migration) no longer crashes every dashboard,
  cert-detail, or list call; the fallback is an empty list.
- **Hostname length cap (B6).** `/hosts` form and CSV import now reject
  hostnames longer than 253 octets (RFC 1035) at the route layer, blocking
  a write-authorized user from bloating dashboard queries with multi-MB
  hostname strings.
- **Real-LDAP E2E selection.** The opt-in real-server test is now marked as an
  integration test and skips before fixture setup, so the ordinary browser job
  no longer tries to start it without LDAP credentials.
- **Mobile dashboard layout.** The wrapped navigation now increases the header
  height instead of overlapping the health banner, and the five-cell status
  strip correctly collapses to two columns at narrow breakpoints.
- **Documentation truth-keeping.** The README now reflects per-scan CAA
  collection, pinned SSRF-safe HTTP delivery, the maintenance-mode database/PDF
  boundaries, and the current readiness, crypto, team, and event endpoints.
- **Immutable release and deployment image tags.** Ordinary `main` builds now
  publish and deploy the commit-SHA image tag; a semantic-version image tag is
  published only when that exact tag points at the build commit. This prevents
  post-release commits from silently overwriting the previous release image.
- **API-key hash migration and key derivation.** New API keys use the
  application `SecurityContext` signing material. Existing raw SHA-256 keys and
  keys hashed with the earlier environment/default pepper remain valid and are
  transparently upgraded on use. The migration now records a valid
  `last_used_at` timestamp instead of corrupting it during the SQL update, and
  a key verifying under a legacy pepper or unkeyed hash is logged at WARNING so
  an operator can spot stragglers that still trail the current signing material.
- **Request-loop responsiveness.** LDAP/local login verification, SMTP tests,
  and webhook tests now run their synchronous network or password-hashing work
  off the async request loop, so a slow external service cannot stall unrelated
  requests.

## [0.9.3] - 2026-06-17

> **Upgrade note (RBAC tier decoupling).** A role whose scope tags are set is
> now *scoped*: it no longer grants its permission tier. Effective tier comes
> from your UNSCOPED (global) roles only; a user holding only scoped roles
> defaults to `viewer`. The built-in `admin`/`operator`/`viewer` roles are
> unscoped, so most setups are unaffected. **If you created a custom SCOPED
> `operator` or `admin` role expecting it to grant that tier, re-assign the
> tier via an unscoped role or clear that role's scope tags** after upgrading.

### Security
- **Tier decoupling for scoped roles (WI-061).** A role whose scope tags are
  set is now *scoped*: it contributes its tags to visibility and alert routing
  only, NEVER to the effective permission tier. The effective tier is the
  highest tier among the user's UNSCOPED (global) roles; a user holding ONLY
  scoped roles defaults to `viewer`. This fixes the footgun where adding a
  second (scoped) role for visibility silently elevated privileges.
- **SMTP alert delivery SSRF validation.** Alert email delivery now resolves
  and validates the SMTP host against the same SSRF policy as webhooks
  (honouring `CERT_WATCH_ALLOW_PRIVATE_IPS`, so internal relays keep working
  by default). Always-blocked ranges (loopback, link-local, metadata) are
  enforced regardless. A blocked host is a delivery failure (logged), never a
  crash of the scan cycle.

### Added
- **Opt-in SNI mode for the Windows installer (WI-062).** `install-windows.ps1
  -SharePort443 -HostName <host>` binds TLS per-host via SNI (`sslFlags=1`,
  `hostnameport=<host>:443`) so sibling tools can share port 443 by hostname.
  The catch-all `0.0.0.0:443` remains the default for single-site installs.
  Both switch directions add the new binding before removing the old one, and
  the SNI path only removes a catch-all whose cert is cert-watch's own (so a
  sibling tool's catch-all is never clobbered).
- **Team tag-subscription model (WI-061).** Roles can now optionally link to
  an alert group: when a role has scope tags set AND a linked alert group,
  members are alerted for certificates carrying those tags via the linked
  group's recipients/webhook. Subscribing to a tag is now one action — see the
  certs AND get alerted for them — with no tier change.
- **Multi-tag scope for roles (WI-061).** The role scope field accepts
  multiple comma-separated tags (mirroring alert-group `match_tags`); existing
  single-tag values keep working.
- **Alert-group tag-match preview (WI-060).** The Alert groups tab shows an
  inline per-group "Tag matches" count and a read-only preview of how many
  certs a candidate tag set would match before you commit it.

### Changed
- **Migration 0026** adds a nullable `alert_group_id` column to the `roles`
  table (additive, no data loss; the existing auto-backup covers it).

## [0.9.2] - 2026-06-17

### Added
- **Alert-group management UI** (WI-059). Alert groups (per-team alert routing
  by tag) were previously CRUD-able only via the REST API. A new server-rendered
  Settings → Alert groups tab now manages them: match tags, recipients, webhook,
  per-group alert threshold, and digest cadence, with audit records on each
  change. No new inline styles; the `settings.html` ratchet still holds.
- **Six env-var-only alert settings are now editable in the GUI** (WI-058):
  drift alerts, renewal-stalled window, alert retention days, daily scan time
  (hour/min), custom webhook headers, and OCSP/CRL revocation checks. These were
  backend-complete but only settable via environment variables. They now
  round-trip through `kv_store` — previously a GUI-saved value was silently
  ignored on load (the merge passed them straight from the env-derived base).
  Environment variables still take precedence (shown with an "env" badge).

### Security
- **Custom webhook headers are now treated as sensitive.** `ALERT_WEBHOOK_HEADERS`
  commonly carries a secret such as `Authorization: Bearer …` (the UI placeholder
  suggests exactly that). It is now encrypted at rest and masked in the UI rather
  than stored and rendered in cleartext. Values written before this release load
  unchanged until they are re-saved (no operator action required on upgrade).

### Changed
- **UI palette retinted** to a warm-charcoal/bronze "instrument" theme
  (token-only; all components inherit it). The Settings page now fills the window
  via a left sidebar nav instead of a constrained horizontal tab strip, and the
  certificate-detail "TIME REMAINING" eyebrow and wordmark are set in mono.

## [0.9.1] - 2026-06-16

> **Upgrade note (RBAC role tiers).** Migration `0024` adds a `permission_tier`
> column to the `roles` table, defaulting every existing role **row** to
> `viewer`. Built-in `admin`/`operator`/`viewer` (which have no role row) are
> unaffected, but any custom role you created in the UI is reset to read-only on
> upgrade — re-assign its tier under Settings → Roles afterwards. The local
> break-glass admin retains full access, so it is your recovery path. Take a copy
> of the SQLite DB before upgrading (the migration also writes a timestamped
> `cert-watch-pre-migration-*.sqlite3` backup automatically).

### Added
- **Tag management in the GUI.** The existing tag system (used for alert-group
  routing) is now editable and visible in the UI: edit a certificate's own tags
  on its detail page and a host's tags on the host page; the certificate page
  shows *effective* tags (its own plus inherited host tags, the latter flagged
  `(host)`). The dashboard's Issuer column is replaced by a Tags column, and the
  dashboard search now also matches tags (with a typeahead of existing tags).
  New routes `POST /certificates/{id}/tags` and `POST /hosts/{id}/tags`.
- **IdP → role mapping moved to the Roles tab, and can target individual users.**
  The LDAP/IdP group → role mapping now lives on the Roles tab (edited per role,
  alongside the role it grants) instead of the Authentication tab. Each role can
  now also be granted to individual IdP users by username/UPN — useful for a user
  who isn't in a suitable group. Group DNs are semicolon-separated (a DN contains
  commas; comma-splitting previously shattered a single DN); usernames are
  comma-separated. `rbac.resolve_roles` matches the username case-insensitively.
- **Local users can be edited.** The Users settings tab now has a per-user edit
  form (inline `<details>`) to change username, email, and role/team, and
  optionally set a new password (left blank, the existing one is kept). New
  `POST /settings/users/{id}` route; the user repository already supported
  update.

### Changed
- **Digest mode is now weekly, and urgent alerts always fire.** Digest mode
  previously sent a summary every day and suppressed *all* per-certificate
  alerts. It now sends the summary once per week, and the final-countdown
  per-certificate alerts (≤3 days to expiry, `URGENT_THRESHOLD_DAYS`) always
  fire individually so an imminent expiry is never buried in a digest. The
  routine heads-up thresholds (14/7-day, chain 30/14/7) are what the weekly
  digest covers. Setting label updated accordingly.

### Security
- **Dependency bumps for three HIGH advisories.** `cryptography` → 49.0.0
  (GHSA-537c-gmf6-5ccf, vulnerable OpenSSL bundled in wheels), `python-multipart`
  → 0.0.32 (CVE-2026-53539, quadratic querystring-parsing DoS), and `starlette`
  → 1.3.1 (CVE-2026-54283, `request.form()` size limits silently ignored → DoS).
  `starlette` is now a direct dependency so the security floor is explicit rather
  than only transitively constrained. This unblocks the release image scan
  (Trivy gate, CRITICAL/HIGH), which had started failing on the merged build.
- **Release pipeline scans the image before publishing it.** The `release`
  workflow pushed the multi-arch image to ghcr *before* the Trivy scan, so a
  build with a fixable HIGH was published to the registry even though the scan
  then failed (and the deploy-manifest bump was correctly withheld). It now
  builds a single-arch image into the local daemon, scans that, and only pushes
  the multi-arch image (reusing the build cache) after the scan passes.

### Fixed
- **Dashboard urgency counts no longer miss same-day expiries.** The pivot
  summary cards and the fleet pivot compared `not_after` against `datetime('now')`
  with a lexicographic string compare. `not_after` is stored as a T-separated ISO
  timestamp (`…T17:00:00+00:00`) while `datetime('now')` is space-separated, so a
  certificate that expired earlier the *same UTC day* sorted as not-yet-expired
  and was counted in the wrong bucket. Both paths now compare with `julianday()`.
  The fleet pivot additionally surfaces the `expired` urgency (a `THEN 0` sentinel
  plus `CAST`-toward-zero had made that bucket unreachable). The pivot urgency
  query was extracted to `pivot_urgency_stats()` and covered with regression tests.
- **Pivot summary cards now respect tag scope (RBAC).** In a pivot view the
  grouped rows were tag-scoped (`list_fleet_pivot`) but the urgency summary cards
  above them aggregated *every* leaf certificate globally, so a tag-scoped
  (non-admin) user saw — and could infer counts of — certificates outside their
  scope, and the card totals disagreed with the scoped group totals.
  `pivot_urgency_stats()` now applies the same scanned-host join and effective
  (cert ∪ host) tag filter as `list_fleet_pivot`.
- **Windows installer works in non-interactive sessions (WI-050).** The Python
  probe in `install-windows.ps1` resolved `py` / `python` / `python3` only from
  PATH, which on a Python-Install-Manager (per-user) host are Windows Store
  execution-alias stubs that fail with "cannot be accessed by the system" over
  SSH / a scheduled task / a service account — breaking remote re-installs. It
  now prefers fully-qualified interpreters (the installer's own shared copy
  under `InstallDir\python`, the Install Manager runtimes, per-machine
  `Program Files\Python3*`) and skips WindowsApps alias stubs. Validated by a
  full remote re-install on the integration VM (Verify-Install 16/16 PASS).
- **venv creation no longer fails when reusing an existing shared Python
  (WI-050).** The hidden/system attribute clear on Python 3.14's
  `venvlauncher.exe` only ran while *copying* a fresh interpreter; on the common
  re-install path (shared Python already present) it was skipped, so
  `python -m venv` failed with "Unable to copy ... venvlauncher.exe". The clear
  now runs unconditionally before venv creation, and the app-pool stop was moved
  *before* venv creation so a running worker can't lock `venv\Scripts\python.exe`.
- **Installed version is reported correctly off package metadata.** Non-Docker
  installs (Windows / `pip install`) read a hand-maintained `_version.txt` /
  hardcoded fallback that had drifted (0.8.1 / 0.6.5 while the package was
  0.9.0). `cert_watch.__version__` now derives from installed package metadata
  (single source of truth: pyproject), with `_version.txt` supplying the commit
  and a source-tree-only version fallback.
- **Installer refreshes the package on upgrade and verifies the result.** Since
  `__version__` reads installed metadata, a re-install that did not actually
  refresh the venv left the GUI reporting a stale version (e.g. 0.8.1 after a
  0.9.0 deploy). `install-windows.ps1` now runs `pip install --upgrade`, fails
  loudly if pip errors, and prints the installed version (warning on drift from
  the source tree) so a stale install is visible at install time.
- **Installer restarts the app pool after an upgrade-in-place.** The pool is
  stopped before touching the venv to release locked files, but it was only
  restarted inside the `-ConfigureIIS` path — so a plain upgrade (no
  `-ConfigureIIS`) left the site stopped and serving HTTP 503. It is now
  restarted at the end whenever the script stopped it and did not run IIS config.
- **Installer no longer surfaces a benign venv message as an error.** Python
  3.14's `python -m venv` can log "Unable to copy ... venvlauncher.exe" while
  still producing a working venv via its fallback. That output is now captured
  and only shown if the venv fails verification; on success a short note explains
  it is cosmetic.

## [0.9.0] — 2026-06-15

Maintenance-entry release (Plan 049) plus the first maintenance-mode batch
(installer hardening, on-demand revocation check). The product surface is
closed; from here only defect/security/installer/docs fixes get in. See
AGENTS.md *Maintenance mode*.

**Breaking:** Certificate Transparency monitoring was removed (see *Changed*),
and the scan-errors Prometheus metric was renamed
`cert_scan_errors_total` → `cert_watch_scan_errors`. Dashboards referencing
the old metric or the `/discover` / `/ct-lookup` endpoints need updating.

### Added
- **On-demand OCSP/CRL revocation check (BC-131).** New
  `GET /api/certificates/{id}/revocation` endpoint and a button on the
  certificate detail page run a live revocation probe for a single cert.
- **Alerts: "Mark all read" and "Flush queue" actions** (WI-030) on the alerts
  page header, write-gated and CSRF-protected.
- **Private-trust CRL freshness checking (WI-042).** Certificates chaining to a
  private/internal CA now automatically have their CRL fetched and validated
  as part of the default scan workflow — no opt-in required. Checks: CRL
  freshness (past nextUpdate), CDP reachability, stale publication interval
  (> 30 days), and CRL signature verification against the issuing CA's public
  key. All findings are warnings, not grade penalties. Public-trust certs are
  unaffected.

### Changed
- **Digest-first alerting recommended.** `ALERT_DIGEST_ONLY=1` is now the
  documented recommended default for new deployments. The digest sends one
  consolidated email per day listing all certificates expiring within 30 days,
  instead of a separate email per threshold crossing. The per-threshold model
  is still available (the default) for operators who want immediate individual
  notifications.
- **Prometheus metrics enhanced.** The `/metrics` endpoint now exposes per-cert
  expiry with a `fingerprint` label, urgency distribution (`cert_watch_certificates_by_urgency`,
  aligned to the dashboard's buckets: healthy/warning/critical/expired), and posture
  grade distribution (`cert_watch_certificates_by_posture`). The scan errors metric
  was renamed from `cert_scan_errors_total` (Counter) to `cert_watch_scan_errors`
  (Gauge) — gauge semantics are correct because old scan records are purged by
  retention. Existing dashboards referencing the old name will need updating.
- **Certificate Transparency monitoring removed.** The CT reconciliation feature
  (`ct_monitor.py`, `ct_lookup.py`, `/discover`, `/ct-lookup`, `/api/ct/reconciliation`)
  has been removed. It depended on crt.sh (a free, rate-limited service) for on-demand
  lookups, which is not continuous monitoring and provided marginal value for the SMB
  target audience. The `expected_issuers` host field and its API (`GET/PUT
  /api/hosts/{id}/issuers`) are retained. `CERT_WATCH_CT_LOG_URL` is no longer read.
- **Expiry alert semantics** (`alerts.evaluate_thresholds`): each threshold now
  fires at most once per certificate — previously, all crossed thresholds fired
  on every evaluation, so a cert at 5 days produced separate alerts for both the
  14-day and 7-day thresholds. Now only the most urgent newly-tripped threshold
  fires, and the `cooldown_hours` parameter is a no-op. The `expired` alert type
  is tracked separately from `expiry_warning`, so a cert that exhausts the 1-day
  warning still fires an `expired` alert. Failed delivery alerts (SMTP failure)
  are excluded from dedup so they retry on the next daily cycle.
- **Rate limiter no longer serialises all requests** (WI-032): the single
  global lock is replaced by 256 sharded locks/caches keyed by client, so
  unrelated keys no longer contend under concurrent load.
- **`routes/settings.py` decomposed into a package** (WI-031): per-section
  sub-routers replace the ~1,450-line module where UI defects concentrated.

### Fixed
- **Config integers are range-validated** (WI-033): out-of-range values such as
  `CERT_WATCH_SCHED_HOUR=25` now warn and fall back to the default instead of
  crashing the scheduler.
- **IPv6 scan targets** (WI-036): IPv6 address literals are bracketed for
  openssl's `-connect` argument (`[::1]:443`) instead of producing a malformed
  argument.
- **openssl output is size-capped** (WI-037): the `s_client` subprocess output
  is bounded (`ScanOutputTooLargeError`) instead of being buffered into memory
  without limit.
- **Windows/IIS installer hardened (WI-046/047/048/049)**, validated on the
  integration VM (clean install → re-install → Verify-Install 14/14):
  `install-windows.ps1` no longer clobbers an existing `web.config` (which
  silently wiped operator `AUTH_PROVIDER`/`LDAP_*`/secret paths and broke auth);
  the TLS cert now binds the catch-all `ipport=0.0.0.0:443` with explicit
  `certstorename=MY` and throws on failure instead of warning; the app pool is
  stopped before `pip install` (releasing locked venv files) and started +
  state-verified after; and `Verify-Install` resolves the site via the
  WebAdministration provider, fixing a false "site not found" warn and a
  `DriveNotFound` throw.
- Plus the post-0.8.0 adversarial-audit batch (security, data-layer, scan, and
  template fixes) and SSRF IP-pinning integration tests (WI-026).

### Docs / tests
- **Restore runbook data-loss fix**: the documented restore now removes the
  `-wal`/`-shm` sidecars before replacing the database. Without this, a stale
  WAL from an unclean shutdown is replayed onto the restored file, silently
  discarding the backup. (Caught by exercising the runbook end-to-end.)
- **SC-081 200-day milestone date corrected** to 2026-03-15 in positioning.md
  (it matches the policy pack, readiness report, and tests; positioning was the
  lone outlier).
- Real-database migration test now smoke-reads the dashboard query helpers
  against a migrated v0.6.x database; SC-081 freeze-time boundary tests cover
  each milestone transition; settings-POST e2e coverage added and its
  password-rotation tests isolated from the login-dependent form tests.

## [0.8.1] — 2026-06-11

Defect release: every fix found by the post-0.8.0 adversarial UI review,
plus the WI-024 connection-lifetime fix. **If you run 0.8.0, upgrade** —
the settings auth tab is inert there (WI-027) and saving a role mapping
silently wipes OAuth settings.

### Fixed
- **Connection leak from short-lived threads** (WI-024): the per-thread SQLite
  connection cache stranded open connections (and their `-wal`/`-shm` file
  handles) when a thread exited — CT refresh workers and idled-out request
  worker threads being the repeat offenders, and the mechanism behind the
  v0.7.3 `-wal` handle leak seen on Windows. The cache now lives in a holder
  that closes its connections deterministically at thread exit, the per-thread
  cache is capped (oldest evicted + closed), and the CT refresh worker releases
  its connection explicitly. Three mutation-verified regression tests.
- **Auth settings tab was inert in real browsers** (WI-027): the LDAP
  role-mapping `<form>` was nested inside the `/settings/auth` form. Browsers
  drop nested form tags, so the inner `</form>` closed the auth form early —
  the "Save authentication settings" button did nothing, role mappings could
  never be saved, and clicking "Save role mapping" silently wiped the OAuth
  kv settings. The role-map inputs now associate with a sibling form via the
  HTML `form` attribute; a form-nesting regression test sweeps every settings
  page.
- **A single trust anchor 500'd the entire dashboard** (WI-028):
  `_build_dashboard_rows` fed raw `trust_anchors` rows (no `is_leaf` column)
  to `_row_to_cert`. Anchors are now converted tolerantly; regression test
  seeds an anchor and renders `/`.
- **"Scan now" on certificate detail always failed with "host not found"**
  (WI-029): the form posted the certificate UUID to `/hosts/{host_id}/scan`,
  which resolves strictly by host id. It now posts `host_id` and the button
  hides when the cert has no host record.
- Compliance report tolerates posture findings without a `message` key
  instead of raising `KeyError`.
- Refreshed the `api-keys` visual baseline left stale by the 0.8.0 inline
  api-keys restyle (the e2e suite was not run with that change).

## [0.8.0] — 2026-06-11

Two things land together: the Plan 047 capability wave (RBAC management, policy
engine, CT mis-issuance closure, SC-081 readiness) and a full UI restyle with a
batch of user-visible defect fixes found by reviewing every page with seeded
data.

### Added
- **RBAC management UI + owner-aware alerting** (Plan 040 foundation, Plan 047
  WS-A; BC-160): roles/users settings pages, owner-aware alert digests, team
  dashboard (`/team`), and authenticated E2E flows.
- **Policy engine** (`policy.py`) with violation alerts and an event model
  (`events.py`) + streaming API (Plan 047 WS-C).
- **CT mis-issuance detection** with per-host expected-issuer allowlists
  (BC-151, WI-007).
- **SC-081 readiness report** (`/readiness`): milestone timeline (200d/100d/47d),
  renewal workload forecast, and per-host margin classification.
- **Lifetime-relative alert thresholds** (Plan 048 WI-1.1): certificates with
  ≤90-day lifetimes alert on percentage of lifetime remaining instead of fixed
  day counts — a 30-day warning is meaningless for a 47-day cert.
- **Renewal analytics + overdue detection** (Plan 048): per-host lifetime and
  cadence inference, renewal-overdue events with dedup, opt-in SC-081 policy
  pack, weekly digest.
- **IIS install automation** — `install-windows.ps1` configures IIS serving
  (HttpPlatformHandler, web.config, 443 binding) behind a flag (BC-157).
- **Populated-dashboard visual baseline.** `tests/e2e/_seed.py` seeds a
  deterministic five-cert demo estate (expired/critical/warning/healthy)
  directly through the upload store; `test_dashboard_populated_visual`
  baselines the dashboard *with rows* — the previous baselines were
  empty-state only, which is exactly where this release's UI bugs hid.
- **Vendored IBM Plex Mono** (woff2, OFL license included) — self-hosted under
  `static/fonts/`, so air-gapped/IIS deployments are unaffected.

### Changed
- **Full UI restyle** ("instrument panel, not SaaS dashboard"): flat
  steel-blue accent replaces the indigo→violet gradient; primary buttons are
  high-contrast neutral; the four stat cards become a single hairline-divided
  stat strip; status pills become dot + colored text; chips quieted; health
  banner is a slim neutral strip (degraded states still tint); tables tighter
  with mono uppercase headers; light theme aligned. Templates keep all
  `data-testid` hooks — no selector or route changes.

### Fixed
- **User-visible copy/rendering defects** (2026-06-11 UI review): "1 hosts"
  pluralization; missing `cw-gap-9`/`cw-gap-14` utility classes collapsing
  header spacing ("Expiry calendarby time period"); redundant day-count prefix
  on expired rows ("4078expired 11 years ago"); raw ISO `T` timestamps in
  alerts, audit, scan history, host detail, and dashboard; zero counts
  rendered in alarm red; double page-title on the readiness report; settings
  panel missing padding; alerts segmented control stretching full-width.
- **samba-container LDAP e2e fixture** raised `NameError` on contact (class
  body self-assignment) and asserted login-rejection copy the app never
  emits — broken on arrival, fixed before first CI execution.
- SMTP double-send; Alertmanager resolve handling; policy route auth;
  alert-deletion ordering; StartTLS TOFU CA capture; LDAP settings form key
  (WI-008/-011/-014/-015/-016/-017).

### Internal
- `scan.py` decomposition (BC-161), dashboard SQL hardening (BC-162),
  coverage raised on security-critical modules (BC-155), admin route
  consolidation, UUID validation, CSP `report-uri`.
- **AGENTS.md:** UI definition-of-done checklist (every item cites a bug that
  shipped), verification rituals (prove a test can fail; skipped is
  invisible; state what was not verified), and the list of decisions agents
  must surface to the human.

## [0.7.3] — 2026-06-08

Windows: fix a SQLite connection-handle leak that could block an in-process database file replace (e.g. restore). Found by running the suite on Windows + Python 3.14.

### Fixed
- **Cached connections were evicted without being closed (`database/connection.py`).** When `_connect` detected that the database file had been replaced/removed (or the handle errored), it popped the stale connection from the per-thread cache but never called `.close()`. The orphaned connection kept the DB's `-wal`/`-shm` handles open — tolerated on POSIX (you can unlink an open file), but on Windows it makes a later file replace fail with `WinError 32`, and on Python 3.14 the orphan lingers in a GC cycle rather than being refcount-closed. Stale connections are now closed on eviction.
- **Deterministic connection close in the backup/init paths.** `migrations.runner._backup` (the `cert-watch backup` source connection) and `database.schema.ensure_base` now use `contextlib.closing` instead of relying on a sqlite3 `with` block (which commits but does not close). Added a public `database.connection.close_connections()` to release the thread-local cache (the in-process equivalent of stopping the service before a restore).

### Validated
- Full test suite passes on **Windows Server 2025 + Python 3.14.5** (1394 passed, 9 skipped) — a new integration-test target in addition to Linux CI.

### Added
- **AD-login E2E for deployed Windows/IIS instances.** `scripts/e2e/ad-login-remote.sh` drives the full browser-shaped login flow against a deployed cert-watch instance (default: the mvmcitest01 IIS VM) and asserts the AD-login round-trip: form POST → 303 redirect → session cookie → authenticated GET. Also guards the `cw_auth` cookie size (BC-145/v0.7.2 regression). Credentials are brokered via Vault AppRole (`~/.cw-vault-ci.env` + `scripts/vault-login.sh`). Complements the local-process `ldap-e2e.sh` and the existing Playwright suite.
- **Vault CI policy.** `deploy/vault/policies/cert-watch-ci.hcl` — a read-only policy for the CI Vault AppRole, granting `read` on `kv/data/cert-watch/ldap/*` and `list` on `kv/metadata/cert-watch/ldap/*`.

### Fixed (BC-159)
- **GUI-configured auth/smtp/alert settings are now merged into boot-time Settings.** Previously, `Settings.from_env()` (the production boot path) only read from environment variables, so GUI-configured LDAP, OAuth, SMTP, and alert settings were silently lost on restart (IIS app-pool recycle, service restart, k8s pod replacement). The lifespan now resolves the signing key, derives the encryption key, and rebuilds Settings via `Settings.from_env_with_kv(db_path, encryption_key)` — the same kv-aware loader that the Settings GUI page uses. Env vars continue to override kv_store (the documented escape hatch), so a web.config / env-based config still wins. 4 regression tests.

## [0.7.2] — 2026-06-08

Bugfix: LDAP/AD users in many directory groups could not stay logged in — after a successful login they were bounced straight back to the login screen.

### Fixed
- **Post-login redirect loop for AD users in many groups.** Since BC-145 the session cookie carried the user's full set of IdP groups so RBAC could resolve roles on every request. For a real AD account, `memberOf` is often dozens of long group DNs — enough to push the `cw_auth` cookie past the browser's ~4 KB per-cookie limit, at which point the browser **silently drops it**. The login itself succeeded (no error), but every subsequent request arrived unauthenticated, so the user was redirected back to `/login` in a loop (over HTTP *and* HTTPS; invisible to the local admin and to tests, since neither carries groups). Only the groups/roles named in `CERT_WATCH_ROLE_MAP` ever affect role resolution, so the session now stores **just those** (none when no role map is configured) — behaviour-preserving, but the cookie stays small. Added a defensive warning when any session token approaches the cookie size limit. 4 regression tests, including proof that the full-`memberOf` token overflows while the filtered one fits and authenticates.

## [0.7.1] — 2026-06-08

Bugfix: the LDAP/SMTP connection-test buttons in Settings returned a 500 (surfacing in the UI as `Request failed: SyntaxError: Unexpected token 'I', "Internal S"... is not valid JSON`) when a numeric field was left blank.

### Fixed
- **"Test Connection" 500 on a blank numeric field.** The LDAP test handler parsed the connect-timeout with an unguarded `int()` *before* its `try/except`; a blank field (the input has no fallback value) made `int("")` raise `ValueError`, which escaped as a 500 with a plain-text `Internal Server Error` body. The frontend's `r.json()` then failed to parse it, surfacing the cryptic `Unexpected token 'I'` message. The parse is now guarded — blank means the default (5s), and a non-numeric value returns a clean JSON error. The **SMTP** test handler had the identical latent bug on `int(port)` (blank → default 587); fixed too. **Frontend hardening:** all three Settings "test" buttons now parse responses defensively, so any future 500 shows `Server error (HTTP 500)` rather than a JSON-parse crash. 4 regression tests.

## [0.7.0] — 2026-06-08

Discover and Compliance maturity: trust-anchor-based private-CA detection, CAA per scan, real CT mis-issuance detection, and UX polish.

### Added
- **Trust-anchor-based private-CA detection (BC-100).** The Discover page no longer uses hardcoded issuer name fragments (`NOT LIKE '%Let%'`) to guess private-CA hosts. Instead, it queries the `scan_posture.chain_status` column, which stores the actual cryptographic trust decision ("private" when anchored by a user-uploaded trust anchor). Migration 0016 adds `chain_status` to `scan_posture`; the scan flow stores it; the Discover view queries it. 4 tests covering migration, storage, query, and public/private counting.
- **CAA per scan for compliance report (BC-121).** The compliance report no longer shows CAA as "Not collected". Migration 0017 adds `caa_present` and `caa_records` to `scan_posture`. The scan flow runs a CAA DNS lookup during posture evaluation and stores the result. The compliance report aggregates real CAA data (e.g., "CAA present for domain — 87% (42/48)"). Posture findings include a CAA pass/info line. 7 tests covering migration, storage, posture findings, and compliance metric collected/not-collected states.
- **CT mis-issuance detection + first-seen capture (BC-151).** The Discover page now detects potential mis-issuance: when a tracked hostname's scanned certificate has a different issuer or fingerprint than what CT logs show, a "Potential mis-issuance detected" table is rendered with the scanned issuer vs. CT issuer. Per-issuer first-seen dates are captured in a new `ct_issuer_first_seen` table (migration 0018) and shown in a "CT issuers — first seen" table. The inline style budget for `discover.html` tightened from 8 → 2 (new CSS utility classes for table padding/width). 4 tests covering migration, first-seen recording, scanned issuer lookup, and ReconciliationResult shape.
- **Webhook alert presets (BC-103).** The Settings → Alerts tab now has a "Webhook preset" dropdown (Slack, Microsoft Teams, PagerDuty, Alertmanager, Custom). Selecting a preset pre-fills the `webhook_kind` hidden field and sets the template textarea to the target's expected JSON shape. No inline `onchange` handler — delegated listener per BC-075.
- **Progressive enhancement for dashboard notes (BC-021).** Each host row in the dashboard now has an inline edit button that toggles a small note form. Saving uses vanilla `fetch` to the `PATCH /api/hosts/{id}/notes` endpoint, updates the note chip in-place, and never reloads the page.

### Changed
- `discover.html` inline style budget tightened from 8 → 2 (new CSS utility classes: `.cw-th-pl-20`, `.cw-th-w-120`, `.cw-td-pl-20`, `.cw-td-pr-20`, `.cw-panel-overflow`, `.cw-panel-hd-pb-13`).

### Resolved
- BC-100, BC-121, BC-151, BC-103, BC-021 — all implemented in this release.

## [0.6.6] — 2026-06-08

Host-level notes for pending and unscanned hosts, plus privacy and test-maintenance cleanup.

### Added
- **Host-level notes (BC-020).** Pending and unscanned hosts now support a free-text `notes` field.
  - Schema: `notes` column on the `hosts` table (with migration for existing DBs).
  - API: `PATCH /api/hosts/{host_id}/notes` and form POST `/hosts/{host_id}/notes`.
  - Add host / bulk import: notes accepted via form field and CSV column.
  - Dashboard: note chip shown in expandable host rows and normal entries.
  - Certificate detail page: inline edit/save toggle for host notes.
  - CSV export: hosts export includes the `notes` column.
  - 16 new tests covering repository, API, form routes, CSV export, and UI rendering.

### Changed
- **Privacy:** Removed Google Fonts CDN dependency; fonts are now self-hosted / local.
- **Test maintenance:** Cleaned up inline `importlib.reload` patterns in ~13 test files.

### Resolved
- BC-131, BC-147, BC-118, BC-137 — stale breadcrumbs resolved in the BC-020 session.

## [0.6.5] — 2026-06-07

Truth-in-advertising hardening pass: fix a silently-inert RBAC path for AD,
remove misleading UI surfaces, and close performance / CI hygiene gaps.

### Fixed
- **BC-150 — RBAC group-DN shredding for LDAP/AD (security).** The session token
  used comma-join encoding for group lists, which shredded every Active Directory
  group DN (commas are separators) into fragments. The result: every AD user
  fell back to `viewer` regardless of `CERT_WATCH_ROLE_MAP`. Encoding is now
  lossless base64url(JSON). RBAC gating now works correctly for AD group DNs.
  Regression test: `tests/test_session_groups.py`.

### Changed
- **Discover honesty (BC-099 / BC-129).** The Discover page no longer shows the
  always-empty "Mis-issuance" stat or the blank Issuer / first-seen columns.
  CT mis-issuance detection and per-issuer first-seen are deferred to 1.1
  (BC-151).
- **Discover performance (BC-097).** The Discover view no longer blocks on live
  crt.sh calls; it renders from the reconciliation cache and warms stale data
  off-thread.
- **Compliance report performance (BC-120 / BC-122).** Replaced the unbounded
  `list_dashboard_rows` load with a dedicated, bounded SQL query that only
  fetches leaf certificates and applies tag filtering at the database. Removes
  the N+1 posture lookup and the memory overhead of materialising full chain
  children + anchor rows.
- **CI / release hygiene (BC-152 / BC-153).** Bumped `astral-sh/setup-uv`,
  `actions/upload-artifact`, and `actions/download-artifact` to Node-24-capable
  pins (GitHub removes Node-20 on 2026-06-16). Added `pip-audit` of the e2e
  extra dependency closure.

## [0.6.0] — 2026-06-06

Locks down role-based access control and machine-to-machine automation, proven
through a full end-to-end UI regression suite.

> **Upgrade note (RBAC is now enforced).** If you set `CERT_WATCH_ROLE_MAP`
> expecting role-based gating, it now **actually takes effect**: IdP groups/roles
> travel in the session token and decide write access on every request and
> form-POST (previously they never reached role resolution, so everyone
> collapsed to read-only or full-access depending on configuration — BC-145).
> Review your role map before upgrading. With **no** role map configured,
> behaviour is unchanged (authenticated users keep full access).

### Added
- **API-key / service-account authentication (Plan 039, BC-104)** — scoped
  bearer tokens for machine-to-machine access to `/api/*` without a browser
  session. Send `Authorization: Bearer cwk_…`. Scopes `read` / `write` / `admin`
  map onto the RBAC roles (viewer / operator / admin). Tokens are stored only as
  a SHA-256 hash (the raw `cwk_…` token is shown **once** at creation); keys are
  created, listed, and revoked from **Settings → API keys** or the admin-scoped
  `/api/api-keys` endpoints. Key creation/revocation and any state-changing call
  made with a key are recorded in the audit log under the key's name.

### Changed
- **RBAC is wired end-to-end (Plan 035 / BC-145).** Groups and roles are now
  carried in the signed session token and resolved against the role map on every
  request, so the dashboard and detail pages hide write controls from viewers,
  form-POST routes reject viewer writes, and the JSON API returns 403 — not just
  the API layer. A read-only dashboard now shows an explicit notice.
- **Dashboard performance (BC-139).** The grouped dashboard view no longer loads
  every certificate into memory; uploaded leaves and pending hosts are queried
  directly, so memory scales with what's shown rather than the whole table.
- **Alerts page (BC-130).** Delivery chips now reflect the channels you've
  actually configured (Email / Webhook) instead of always showing both, with a
  hint when none are set.
- **CI quality gates.** `mypy` is now gated in CI (source is at zero errors —
  BC-093 / BC-146). The Playwright suite is split into a required functional job
  and a non-blocking visual-regression job.

### Testing
- **Full E2E UI regression suite.** 35 functional Playwright tests (every page
  renders; upload/host/delete/settings/API-key flows) plus 8 masked
  visual-regression baselines, all on stable `data-testid` selectors (BC-132).
  RBAC admin-vs-viewer gating is asserted through the browser.

## [0.5.3] — 2026-06-05

Maintenance: CI and deploy-smoke fixes; private-CA LDAPS auth fixes found by the
live AD end-to-end runthrough; TOFU CA auto-provisioning and synthetic-LDAPS CI.

## [0.5.2] — 2026-06-04

Maintenance release: no user-facing behaviour change. Hardens the test suite and
speeds up CI.

### Changed
- **Test suite ~3× faster** (≈273s → ≈95s): parallel by default via pytest-xdist
  (`-n auto --dist loadscope`), `COVERAGE_CORE=sysmon` in CI, retry-backoff sleeps
  neutralized in unit tests, and the CT-reconciliation test mocked at the network
  boundary (was a real crt.sh call). E2E runs serial (`-n0`).
- **Test quality**: ~13 "test theater" cases that passed even with the feature
  broken now assert real behaviour. Coverage 88.9% → 90.1% (`certificates.py`
  70→85%, `routes/settings.py` 75→85%, `scheduler.py` 81→97%), with new
  SMTP-send / LDAP-connect tests.
- **Internal**: `scheduler` per-day work extracted to a module-level `_run_cycle`
  so its failure-isolation contract is unit-testable (no behaviour change).
- Docs: backlog now generated from the agent-notes DB (`OPEN_BREADCRUMBS.txt`)
  rather than hand-maintained.

## [0.5.0] — 2026-06-03

Hardens the integration edges (LDAP, outbound HTTP) and leans into the
regulated-SMB observability story: first-class alert channels, an auditor-facing
compliance report, an ACME renewal-stall alert, SIEM/log export, and a batch of
security-hardening fixes from two adversarial reviews.

> **Upgrade note (breaking, OAuth only):** OAuth login now **requires
> `CERT_WATCH_BASE_URL`**. The redirect URI is no longer derived from the
> request `Host` header (that allowed Host-injection of the OAuth callback —
> review #3). Set `CERT_WATCH_BASE_URL` to your external URL (e.g.
> `https://certs.example.com`) before upgrading if you use OAuth/OIDC.

### Added
- **ACME renewal-stall alert (Plan 027)** — a `renewal_stalled` alert fires when
  a leaf certificate is inside its renewal window
  (`CERT_WATCH_RENEWAL_WINDOW_DAYS`, default 30) and **no successor certificate
  has appeared**, flagging a broken Certbot / cert-manager / ACME job well before
  the generic expiry warning. Distinct signal, distinct remediation; delivered
  through the existing email/webhook/adapter channels. Set the window to `0` to
  disable.
- **SIEM / log export (Plan 028)** — make the audit log consumable by a SIEM.
  **Syslog** (`CERT_WATCH_SYSLOG_HOST`/`_PORT`/`_PROTO`, stdlib RFC-5424 handler,
  serves any SIEM and the Azure AMA path) and **Splunk HEC**
  (`CERT_WATCH_HEC_URL` + `CERT_WATCH_HEC_TOKEN`(`_FILE`), through the SSRF-safe
  opener, delivered on a bounded background pool), plus a **Windows Event Log**
  sink (`CERT_WATCH_EVENTLOG=1`, Application log via pywin32 — install the
  `cert-watch[windows]` extra; disables itself off-Windows). All sinks are
  **fail-open** — a down SIEM never blocks or breaks an audited action; with
  nothing configured the audit path is unchanged.
- **Compliance / Auditor Report (Plan 025)** — a one-click, point-in-time
  posture report for SOC 2 / ISO 27001 / PCI-DSS auditors. `GET
  /reports/compliance` renders a print-optimized HTML page (browser "Save as
  PDF" → clean auditor PDF, zero new dependencies); `GET
  /api/reports/compliance.json` and `.csv` export the same data. Reports are
  **tamper-evident**: a canonical JSON of the report is HMAC-SHA256-signed with
  the app signing key, and `cert-watch verify-report <file.json>` re-checks the
  hash and signature (PASS/FAIL). Covers grade distribution, fleet grade, the
  compliance-metric checklist (no SHA-1, strong key, TLS ≥ 1.2, HSTS; CAA shown
  as "Not collected" pending per-scan storage), and a 7/30/90-day remediation
  schedule. Linked from the Insights page.
- **Alert channel adapters (Plan 022)** — Microsoft Teams (Adaptive Card via
  Workflows), Discord, and PagerDuty (Events API v2, trigger + resolve-on-renewal).
  All delivery routes through the SSRF-safe HTTP opener.
- **SSRF-guarded HTTP opener** (`http_client.ssrf_safe_urlopen`) — resolves and
  checks the initial URL and **every redirect hop** against the scan blocklist,
  enforces an `http(s)` scheme allowlist, and honours the configurable
  `allow_private` / `allowed_subnets` policy. Webhook (incl. digest) and
  OCSP/CRL revocation probes now flow through it. *(Documented residual: urllib
  re-resolves on connect, so this is a large improvement over unvalidated
  `urlopen`, not the airtight pinned-IP guarantee the TLS scanner has — see the
  `http_client` module docstring; **BC-116/BC-117**.)*
- **Configurable LDAP group filter (BC-118)** — `LDAP_GROUP_FILTER`
  with a `{group}` placeholder (defaults to the AD transitive-membership OID),
  unblocking OpenLDAP/FreeIPA `LDAP_REQUIRED_GROUPS`.

### Fixed
- **LDAP authentication bypass (security, BC-115)** — the user-bind step ignored
  `ldap3.bind()`'s return value; ldap3 returns `False` on bad credentials rather
  than raising, so any password authenticated an existing user. The result is now
  checked and a failed bind is rejected. Regression test added.
- **Compliance "TLS ≥ 1.2" metric over-reported.** The check upper-cased the
  protocol string but compared it against mixed-case prefixes, so TLS 1.0/1.1
  were counted as compliant; it also missed the bare `"TLSv1"` string both scan
  paths actually emit for TLS 1.0. TLS-version classification is now a shared
  `posture.tls_version_meets_1_2` helper used by both the posture grade and the
  compliance metric, with the same blind spot fixed in the posture engine's own
  TLS finding.
- **Fleet grade rollup** in the compliance report no longer reports `A+` for an
  all-`A` fleet (grade severity collapsed `A+`/`A`); it now returns the worst
  actual grade present.

### Security (hardening from two adversarial reviews — Plan 029)
- **OAuth ID-token algorithm allowlist** — discovered `alg` values are now
  intersected with an asymmetric allowlist (RS/ES/PS); `none` and the symmetric
  `HS*` family (RS/HS key-confusion) can never be accepted, no matter what the
  IdP advertises. The authlib fallback decode is pinned to the same list.
- **OAuth redirect_uri no longer trusts the Host header** — requires
  `CERT_WATCH_BASE_URL` (see upgrade note above; review #3).
- **OAuth IdP fetches routed through the SSRF-safe opener** — discovery, JWKS,
  and userinfo requests honour the `allow_private`/`allowed_subnets` policy
  instead of fetching arbitrary IdP-supplied URLs (review #8).
- **Stored-XSS guard on `runbook_url`** — http(s) scheme only; a `javascript:`
  runbook link can no longer be planted and rendered on the cert detail page.
- **Login CSRF** — `POST /login` now enforces the double-submit token (review #19).
- **scrypt username-timing oracle fixed** — the username-mismatch dummy hash now
  uses the stored hash's cost parameters, so a custom-cost admin hash no longer
  makes the match path measurably slower than a mismatch (review F#1).
- **Proxy IP trust** — with `CERT_WATCH_TRUST_PROXY=1` and no
  `CERT_WATCH_TRUSTED_PROXIES`, the **rightmost** `X-Forwarded-For` entry is used
  (the hop the trusted proxy appended), not the spoofable leftmost one; a startup
  warning is logged.
- **Compliance report fails closed** (HTTP 503) rather than signing with an empty
  key when the app isn't fully initialized.
- `cw_sid` is now `HttpOnly`; added `Referrer-Policy`, `Permissions-Policy`, and
  `X-Permitted-Cross-Domain-Policies` response headers; `/healthz` no longer
  discloses version/commit.
- **First-run admin password** is no longer written to the log on a file-write
  failure; recovery instructions are logged instead.

### Changed
- **Coverage gate raised to 88%** (Plan 024); suite at ~88.7%.
- Compliance export uses one batched posture query instead of an N+1 over the
  fleet.
- **Configurable CT log** (`CERT_WATCH_CT_LOG_URL`) and a short-TTL cache on CT
  reconciliation; dedicated rate limit on `/api/ct/reconciliation`.
- **Supply chain:** CI pins actions by SHA and adds `pip-audit`; the Docker base
  image is pinned by digest; the example k8s `NetworkPolicy` restricts ingress to
  the ingress/monitoring namespaces (**verify the namespace names match your
  cluster before deploying**).

## [0.4.0] — 2026-06-03

First all-in-one release: repositioned as certificate-lifecycle observability for
small and mid-sized businesses, with the DNS path, OAuth callback, and
first-run-posture hardening below. (The 0.4.0 version was bumped earlier without a
changelog entry; this is the complete, consolidated record.)

### Added
- **`/readyz` endpoint (BC-110)** — split from `/healthz` so k8s liveness and
  readiness probes can be distinguished.
- **`cert_scan_errors_total` counter (BC-109)** on `/metrics`.
- **Scan degradation signal (BC-108)** — `ScannedEntry.chain_incomplete`
  surfaces a degraded-scan reason in the UI; warnings logged on openssl fallback
  and degraded-scan storage.
- **Inline-style ratchet test** — `tests/test_no_inline_styles.py` tracks the
  remaining `style=` attributes that block full CSP tightening.
- **OAuth callback tests (BC-113)** — `tests/test_oauth_callback.py` covers every
  branch of `/auth/callback` (state forgery, state/cookie mismatch, missing
  code/cookie, token-exchange failure, authz denial, happy path), asserting no
  session is minted on any failure. `routes/auth.py` coverage 52% → 83%.

### Changed
- **Positioning** — reframed as an all-in-one certificate-lifecycle observability
  tool for small and mid-sized businesses (README, package description,
  `docs/positioning.md`). The software-factory-2 build-method origin is retained
  as history, not identity.
- **DNS resolution** — the custom-nameserver path (`CERT_WATCH_DNS_SERVERS`) now
  uses **dnspython** instead of a hand-rolled UDP packet parser. dnspython
  validates each response against the query and falls back to TCP on truncation
  (the old path was UDP-only with a fixed 4 KiB buffer and a retrofitted
  anti-spoof check — resolved BC-079). `dnspython` is now a **core** dependency
  (it already backed the CAA lookup), so the custom-DNS feature and CAA checks no
  longer depend on an optional, undocumented install. The unused `[dns]` extra was
  removed.
- **First-run posture decision refactor (BC-114)** — extracted the
  secure-by-default decision (serve open / auto-provision admin / fail closed) out
  of `app.lifespan` into pure functions in `cert_watch/firstrun.py`
  (`is_network_exposed`, `first_run_action` → `FirstRunPosture`). Behaviour is
  unchanged; the decision is now table-tested over all input combinations in
  `tests/test_firstrun_posture.py`.
- **`/metrics` now uses the `prometheus_client` library (BC-111)** instead of
  hand-built exposition.
- **Performance** — `_LOG_RECORD_KEYS` extracted to a module-level frozenset (no
  per-log-line `LogRecord` allocation); `check_rate_limit` guards schema init with
  a `_rate_db_initialized` flag.
- **Kubernetes polish** — added a `PodDisruptionBudget` (with the SQLite
  `Recreate`-strategy rationale) and secret-management reminders in the example
  manifests.

### Fixed
- **BC-106** — stale integration-test mock signatures for `_resolve_host`.
- **BC-107** — `asyncio.run()` event-loop conflicts in `test_bc083_081` and
  `test_middleware_deps`.
- **BC-112** — added a unit test for the `_rate_db_initialized` flag.

## [0.3.0] — 2026-06-03

### Added
- **Insights page** — expiration calendar plus TLS-version and posture-grade fleet trends
- **Discover page** — CT-based coverage reconciliation and private-CA inventory
- **Dashboard redesign** — chip-based filters, fingerprint grouping, SQL-paginated queries
- **Detail page** — per-certificate panel cards with chain visualization, drift history, posture breakdown
- **In-UI password rotation** — change local admin password from Settings (BC-102)
- **CSP nonces** — per-request `script-src` nonce; all inline `on*=` handlers converted to delegated listeners (BC-075)
- **Session revocation** — HMAC session tokens embed per-user version; logout/credential-change invalidates prior sessions (BC-081)
- **Secure-by-default auth** — network-exposed instances auto-provision a local admin on first run (BC-083)
- **Read-only / read-write role tier** — `CERT_WATCH_WRITE_USERS` gates mutation access (BC-086)
- **Scan allowlist** — `CERT_WATCH_ALLOWED_SUBNETS` CIDR list scopes which private ranges are scannable (BC-080)
- **Async scanner** — `scan_host_async()` / `store_scanned_async()` for non-blocking concurrent scans
- **Reusable retry policy** — `retry.backoff_range()` exponential/linear strategy
- **CLI subcommands** — `cert-watch backup`, `cert-watch hash-password`, `cert-watch re-encrypt`
- **Prometheus metrics** — `/metrics` endpoint with optional bearer-token gating
- **CT monitor** — periodic Certificate Transparency reconciliation
- **Bulk CSV import** — `/hosts/import` for adding many hosts at once
- **Alert groups** — group-based routing for alert recipients
- **Audit log** — append-only mutation/login record with configurable retention
- **E2E test suite** — Playwright-based auth, settings, dashboard, upload, and delete flows

### Changed
- Dashboard queries are now SQL-paginated (Plan 018 B2) — no more `sqlite3.Row` leaks into routes
- Auth module decomposed from `auth.py` monolith into `auth/` package (Plan 021)
- `SecurityContext` is an immutable dataclass on `app.state.security`; `create_app()` injects dependencies (Plan 018 B1)
- CSP `style-src` keeps `'unsafe-inline'` (inline `style=` custom properties)
- CSRF is double-submit cookie; token accepted via header/form only, never query string (BC-070)
- `CERT_WATCH_COOKIE_SECURE` defaults to `1`; set `0` only for plain-HTTP local dev

### Fixed
- BC-101: monthly trend chart bucketing with dynamic bar scaling
- BC-090: entrypoint normalizes `--host`/env so BC-083 check sees the real bind
- BC-084: A+ posture for non-443 ports
- BC-087/88/89: audit findings (credential sanitization, error messages)
- BC-071: OAuth ID-token verification fails rather than silently falling back to userinfo
- BC-073: OAuth nonce verification in ID-token claims
- BC-074: `create_app` factory pattern for test isolation
- Scheduler loop bug that could cause missed daily scans
- SMTP password leakage in error messages

## [0.2.0] — 2026-05-26

### Added
- PKCS#12 (`.pfx`/`.p12`) and PKCS#7 (`.p7b`/`.p7c`) upload support
- TLS posture grading (A+/A/B/C/F) with configurable checks
- Drift detection alerts (issuer change, key-size drop, SHA-1 downgrade, TLS/posture downgrade)
- Certificate history snapshots with configurable retention
- Renewal tracking (links renewed certs to predecessors)
- Per-host threshold overrides for alert timing
- CAA record lookup endpoint
- HSTS probe during scans
- Fleet posture lenses (by issuer, owner, renewal method)
- Tags for certificates and hosts
- KV store for persistent settings with encrypted secret storage
- Database migration framework (0001–0011)
- LDAP/AD authentication with STARTTLS and group membership checks
- OAuth/OIDC authentication (Microsoft Entra, Google) with JWKS-based ID-token verification
- Break-glass local admin with scrypt hashing
- Rate limiting (SQLite-backed, proxy-aware)
- Setup wizard for first-run configuration
- Settings page (Auth, SMTP, Alerts tabs)
- Systemd unit with security hardening
- Windows/IIS deployment support (HttpPlatformHandler + ARR reverse proxy)
- Docker Compose deployment
- Kubernetes manifests with Argo CD GitOps
- Multi-arch Docker image (amd64 + arm64)

## [0.1.0] — 2026-05-04

### Added
- Initial release
- Host scanning via TLS handshake
- Certificate upload (PEM, DER)
- Web dashboard with color-coded expiry status
- REST API with pagination
- Email (SMTP) and webhook alerting
- Daily scheduled scans
- Certificate Transparency lookups via crt.sh
- Prometheus metrics endpoint
