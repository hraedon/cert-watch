# Changelog

All notable changes to cert-watch are documented in this file.

## [Unreleased]

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
