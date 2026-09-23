# Upgrading cert-watch

cert-watch stores all state in a single SQLite database (WAL mode). Upgrades are
applied by **numbered schema migrations that run automatically on startup** —
there is no separate migrate command to run. On boot the app calls
`ensure_base()` then `run_pending_migrations()`, which:

1. creates a **pre-migration backup** of the database (WAL-safe `VACUUM INTO`,
   written next to the DB as `<name>-pre-migration-<timestamp>.sqlite3`), then
2. applies every migration not yet recorded in the `schema_version` table, in
   order, each in its own transaction.

If no migrations are pending, startup is a no-op.

## Minimum supported version: 0.9.0

**The supported upgrade source for 1.0 is 0.9.0 or later.** Upgrading a
0.9.x database to 1.0 is covered by an automated test
(`tests/test_upgrade_from_v090.py`) that replays a real v0.9.0 database through
the startup upgrade path and asserts the schema migrates and **no data is lost**.

Older databases are *likely* to migrate too (the migration chain runs from the
baseline forward), but that path is **not tested or supported** for 1.0. If you
are on a pre-0.9.0 release, take the two-step path below.

## Upgrading from 0.9.x → 1.0

1. **Back up first.** The app makes its own pre-migration backup, but take your
   own as well:
   ```bash
   cert-watch backup /backups/cert-watch-pre-upgrade.sqlite3
   ```
   or simply stop the app and copy the `.sqlite3` file (plus any `-wal`/`-shm`).
2. **Deploy 1.0** over the same data directory / volume.
   - **Kubernetes (Argo CD):** sync to the 1.0 image; the existing PVC carries
     the DB and migrations run when the new pod starts.
   - **Docker Compose / systemd:** pull the new image/release and restart; point
     it at the same DB path.
   - **Windows / IIS:** **re-run `install-windows.ps1`** with the same arguments
     as your original install (this is the supported upgrade method — see the
     Windows / IIS section below). It stops the app pool, updates the code/venv,
     and restarts the pool; the app then migrates the existing DB on startup.
3. **Verify.** Watch the startup logs for `applying migration ...` /
   `migration ... applied`, confirm the dashboard loads, and confirm
   `schema_version` is at head. A `*-pre-migration-*.sqlite3` file next to the DB
   confirms the safety backup was taken.

Downgrade is **not** supported — migrations are forward-only. To roll back,
restore the pre-migration backup.

### Behaviour changes in this line to be aware of

- **Everyone signs in again once after upgrading.** The session format
  changed (the version is bound into the session signature), and sessions
  minted by earlier releases are rejected: they cannot say whether they
  belong to a local account, the break-glass admin or a directory user.
  Expect every user, including the break-glass admin, to land on the sign-in
  page on first visit after the upgrade. API keys are unaffected.
- **`CERT_WATCH_ADMINS` now restricts admin when no role map is configured.**
  It was documented as the list of users allowed to reach Settings, but with
  no role map (neither `CERT_WATCH_ROLE_MAP` nor a Settings → Roles mapping)
  every directory user was treated as admin, so the list restricted nothing
  -- and a user outside `CERT_WATCH_WRITE_USERS` could create an API key,
  including a write-scoped one, and write with it. Now, for directory users
  with no role map: when `CERT_WATCH_ADMINS` is set, only its members get
  Settings, API-key management, trust anchors, alert groups and the other
  admin actions (they are refused with `admin required`); when
  `CERT_WATCH_WRITE_USERS` is set, only its members (and listed admins) can
  write, as before. Admin implies write: when only `CERT_WATCH_WRITE_USERS`
  is set, admin also requires membership in it, so a user who cannot write
  data can never administer or create API keys. With neither list set,
  every signed-in user is still full access. The break-glass admin, local accounts and role-map
  deployments are unaffected. **If you set `CERT_WATCH_ADMINS` and your
  administrators are not all in it, add them before upgrading** (or move to
  a role map). API keys minted by now-unlisted users keep working until
  revoked; review Settings → API keys after upgrading.
- **Local accounts are authorized by their own role; the Settings → Roles IdP
  mapping now takes effect.** Review both before upgrading.
  - Accounts created in Settings → Users can now sign in (#59; before, every
    one of them was rejected). Each one's permissions come from its assigned
    role, re-read on every request, whether or not a role map is configured.
    An account with no role, or whose role has been deleted, is **read-only**
    (viewer). The legacy `CERT_WATCH_WRITE_USERS` / `CERT_WATCH_ADMINS` lists
    do not widen a local account, and `CERT_WATCH_ALLOWED_GROUPS` /
    `_ROLES` (a directory login gate) does not apply to one.
  - The break-glass local admin is always admin, including under a role map
    that does not map it.
  - The group/user → role mapping edited on Settings → Roles was saved but
    never read; it is now merged into the role map at startup and on save.
    `CERT_WATCH_ROLE_MAP` wins for any role it names. **Saving any mapping
    switches directory (LDAP/OAuth) users from "no role map = full access" to
    role-based access:** a directory user who matches no mapping becomes a
    viewer. Map your administrators (by group, or by username in the Users
    field) before saving the first mapping, or keep the break-glass admin to
    hand. A group mapping applies from the user's next sign-in (the session
    holds only the groups the map referenced at sign-in); a username mapping
    applies immediately. With no mapping anywhere, directory users keep full
    access as before.
  - A directory user who shares the break-glass username is no longer treated
    as break-glass at sign-in (it was decided by name).
  - Role mappings are stored by role id. On first load after the upgrade,
    name-keyed entries are rewritten to the id of the role with that name,
    and entries for which no such role exists are dropped; name keys are not
    honoured after that.
  - **Mapping is sticky.** If a mapping exists (from an earlier release or
    saved now), cert-watch records that RBAC mapping is configured. Removing
    or clearing every mapping afterwards leaves directory users **read-only**
    rather than restoring "no role map = full access". Only an install that
    never had a UI mapping (and no `CERT_WATCH_ROLE_MAP`) keeps the legacy
    full-access default. To deliberately return to it, delete the kv keys
    `ldap_role_map` and `ldap_role_map_configured`.
  - If persisted settings cannot be read at startup, directory users start
    read-only (unless `CERT_WATCH_ROLE_MAP` maps them) and an error is
    logged; local accounts and the break-glass admin are unaffected.
  - Settings → Users rejects usernames over 128 characters, emails over 254,
    and the break-glass username. Existing accounts are not changed; an
    existing account named like the break-glass admin no longer blocks the
    break-glass password.
  - Renaming a local account signs out sessions under both the old and new
    name, and creating an account signs out any leftover session for that
    name, so an old cookie can never attach to a different account.
  - Scope tags and usernames in role mappings compare by Unicode casefold,
    not only ASCII case: `Payments` matches `payments`, and `straße` matches
    `strasse`.

- **An install with no alert transport no longer reports its queued alerts as
  undelivered.** With neither SMTP nor a webhook configured, `process_pending`
  has always returned immediately, so every alert stays `pending` for ever by
  design. The health banner counted those after 24 hours and sat permanently on
  "N alerts still undelivered", and Activity labelled each one "Not yet
  delivered — still queued past the cycle that should have sent it", for a
  delivery outage that was not happening. `/api/health` now reports
  `alert_delivery_configured` alongside `undelivered_alerts`, and both the
  counter and the chip apply only when a transport exists; the Activity tab
  says once, at the top, that nothing is configured to send the queue. If you
  run such an install, expect the banner to go green on upgrade. Nothing
  changes for an estate that does deliver.
- **An unchanged certificate no longer re-alerts on every scan.** Each scan
  rewrites the endpoint's inventory row under a new id, and the "each threshold
  fires exactly once" dedup was keyed to that id, so a certificate sitting
  inside its expiry window crossed the same threshold again every cycle. With a
  transport configured that meant **a fresh notification per scan** (daily, by
  default) for the same certificate until it was renewed. A rescan that sees the
  same fingerprint now carries the existing alerts onto the rewritten row, so
  the threshold fires once. A genuine renewal is a different certificate and
  still alerts on its own merits. No schema change and no action required: the
  dedup is correct again from the first cycle after upgrade. Alerts already
  duplicated before the upgrade stay in the list as history until they age out
  under `CERT_WATCH_ALERT_RETENTION_DAYS`. Two side effects worth knowing: a
  pending alert now keeps its original `created_at` across rescans, so the
  "undelivered for more than 24h" signal can actually reach its threshold on a
  daily-scan estate; and a `failed` alert is now retried on the next cycle
  instead of being stranded and duplicated.

- **Per-certificate notes are merged into host notes (migration 0031).** Every
  non-empty `certificates.notes` value is concatenated into the matching
  `hosts.notes` row and the column is dropped. Notes on *uploaded*
  certificates with no matching host row (a hostname+port pair in `hosts`)
  cannot be merged: they are listed in a WARNING log at migration time and
  retained in the deprecated `certificates.notes` column in the live database.
  Matched notes are cleared from that column after merging. The column is
  dropped only when no unmatched notes remain; the pre-migration backup is
  also retained. The UI has a single "Notes" panel
  per endpoint (host-scoped); `POST /certificates/{id}/notes`,
  `PATCH /api/certificates/{id}/notes`, and the `notes` key in
  `GET /api/certificates/{id}` are removed.
- **Renewal events are keyed by endpoint (hostname *and* port), and a missing
  port is never guessed.** `cert_renewed` / `renewal_overdue` events written
  by earlier releases carry no port. The weekly renewal digest lists such an
  event as `hostname (port unknown)` under no owner, with no current-certificate
  context, rather than attributing it to whichever endpoint happens to share
  the hostname. This is a one-time transitional effect: it lasts only for the
  digest cycles whose look-back window (default 7 days) still covers events
  from before the upgrade, after which every event carries its port. The
  renewal webhook applies the same rule and no longer assumes port 443 when a
  signal names no port; such a signal is rejected and logged instead of being
  delivered against an endpoint it may not belong to. The scheduler always
  supplies the port, so operators see no change for live scans.
- **The landing page is now Home; the inventory table moved to `/browse`.**
  `/` renders the attention queue (what needs a human, ranked by
  time-to-impact) plus a 12-week expiry horizon. Requests to `/` carrying the
  dashboard's filter/sort/page/view params (old bookmarks) redirect to
  `/browse` with the query preserved.

### Windows / IIS specifics

**Upgrade by re-running `install-windows.ps1`** with the same arguments as your
original install. The script is idempotent and is the supported upgrade path —
you do not stop/start anything by hand:

- It **stops the app pool before touching files** (releasing the database
  handle), rebuilds the venv/code, then **restarts the pool**, at which point the
  app migrates the existing database on startup (writing the
  `*-pre-migration-*.sqlite3` backup). The stop is a clean exit, so the WAL is
  checkpointed and no `-wal` is left orphaned.
- It **never touches the `.sqlite3` file itself** — your data, signing keys, and
  operator-set `web.config` settings are preserved (web.config is no-clobber).
- Bonus: routing every deploy through the installer keeps it continuously
  exercised on Windows, which CI does not cover — so installer regressions
  surface at deploy time rather than lurking.

Behaviour validated on a real Windows host by migrating a 0.9.0 database to
current (migration applied, data preserved, backup written, no `-wal` leak after
the app-pool stop).

Manual file operations (restoring a backup, swapping the DB) are the exception:

- A **running** instance holds the SQLite database open, so its `.sqlite3`,
  `-wal`, and `-shm` files cannot be copied/replaced/restored while the app pool
  is running (you get `WinError 32`, a sharing violation). **Stop the app pool
  first** for any manual file operation (backup restore, DB swap). Once it stops
  cleanly the WAL is checkpointed and the file is a safe standalone copy.

### Migration 0033: `alerts.deferred_since` (bounded evidence deferral, #38)

**What it does.** Adds one nullable column, `alerts.deferred_since`. It records
when delivery of a pending alert was first deferred because the
delivery-evidence store refused the write that must precede a send. The
migration modifies no rows; existing alerts get `NULL`. Startup applies it
automatically after the usual pre-migration backup.

**Behaviour it enables.** An alert whose delivery keeps being deferred for
72 hours on that clock (`EVIDENCE_DEFERRAL_GIVE_UP_HOURS`) is marked `failed`
with a message stating since when. The clock restarts whenever an attempt is
recorded and is cleared by every status change, so a transient lock on an old
alert cannot read as a days-long outage. If the database will not take the
give-up write either, the alert stays pending and the event is logged at
ERROR; the age-based `undelivered_alerts` health count and the Activity view's
"Not yet delivered" chip remain the signal in that case.

**Manual application** (Windows/IIS hosts, or any operator who stages schema
changes by hand). Stop the app pool or service first, take a backup
(`cert-watch backup <path>` or copy the file), then run against the database:

```sql
ALTER TABLE alerts ADD COLUMN deferred_since TEXT;
INSERT INTO schema_version (id, description, applied_at)
VALUES ('0033',
        'add deferred_since to alerts for bounded evidence deferral (#38)',
        strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
```

Running only the `ALTER` is also fine: startup sees the column, skips the
`ALTER`, and records `0033` itself. Both paths are covered by
`tests/test_migrations.py`.

**Verify** with `PRAGMA table_info(alerts);` (a `deferred_since` row is
present) and `SELECT id FROM schema_version WHERE id = '0033';` (one row).

**Rollback.** The column is additive and nullable, and the previous release
never reads it, so rolling back the code needs no database change. (The
`cert-watch routing-report` diagnostic of the previous release will refuse a
snapshot that records `0033`, because it requires an exact schema match.) To
remove the column as well, either restore the `*-pre-migration-*` backup, or
with the app stopped run `ALTER TABLE alerts DROP COLUMN deferred_since;` and
`DELETE FROM schema_version WHERE id = '0033';` (SQLite 3.35 or newer).

### Migration 0034: `alerts.trigger_cert_id` (stable resolve keying, #62)

**What it does.** Adds one nullable column, `alerts.trigger_cert_id`, then
backfills existing alerts with their current `cert_id`. The column records
the certificate row id an alert was created against. Since #57 an unchanged
rescan rewrites the leaf row under a new id and carries its alerts forward;
webhook dedup keys (PagerDuty) are derived from a row id, so keying a
renewal's resolve on the alert's *current* row id would never match the
incident its trigger opened. New alerts stamp the row id they fire against;
that stamp survives every row rewrite, and resolves key on it.

The backfill is exact for every alert a released version can hold: before
this release an alert was deleted together with its certificate row, so the
row an existing alert sits on IS the row it fired against — the id its open
incident was keyed with. (A database that already ran unreleased #57 code may
hold a carried alert pointing at a rewritten row; its backfilled key hashes
that rewritten row id, which is neither better nor worse than the previous
fallback and only affects incidents raised against unreleased code.) Startup
applies the migration automatically after the usual pre-migration backup.

**Manual application** (Windows/IIS hosts, or any operator who stages schema
changes by hand). Stop the app pool or service first, take a backup
(`cert-watch backup <path>` or copy the file), then run against the database:

```sql
ALTER TABLE alerts ADD COLUMN trigger_cert_id TEXT;
UPDATE alerts SET trigger_cert_id = cert_id WHERE trigger_cert_id IS NULL;
INSERT INTO schema_version (id, description, applied_at)
VALUES ('0034',
        'add trigger_cert_id to alerts for stable resolve keying (#62)',
        strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
```

Running only the `ALTER` — or the `ALTER` and the `UPDATE` — is also fine:
startup sees the column, skips it, runs the idempotent backfill, and records
`0034` itself. Both paths are covered by `tests/test_migrations.py`.

**Verify** with `PRAGMA table_info(alerts);` (a `trigger_cert_id` row is
present) and `SELECT id FROM schema_version WHERE id = '0034';` (one row).

**Rollback.** The column is additive and nullable, and the previous release
never reads it, so rolling back the code needs no database change. To remove
the column as well, either restore the `*-pre-migration-*` backup, or with
the app stopped run `ALTER TABLE alerts DROP COLUMN trigger_cert_id;` and
`DELETE FROM schema_version WHERE id = '0034';` (SQLite 3.35 or newer).

## Upgrading from a pre-0.9.0 release

There is no full-fidelity data export/import tool. Two options:

- **Recommended — stage through 0.9.x:** upgrade to a 0.9.x release first (its
  migrations cover the older schema), confirm it runs, then upgrade 0.9.x → 1.0
  as above.
- **Rebuild — fresh 1.0 + re-add hosts:** stand up a clean 1.0 instance and
  re-add tracked hosts with the **CSV bulk import** (Settings → Hosts → Import).
  This re-establishes the host inventory; historical scan/cert/audit history is
  not carried across by this path.

## UI redesign (plan 055)

The web UI was rebuilt around four domains — **Certificates**, **Posture**,
**Activity**, **Settings**. Old URLs redirect permanently, so bookmarks keep
working:

| Old | New |
|---|---|
| `/insights` (calendar) | `/?view=calendar` |
| `/insights?tab=trends`, `/crypto` | `/posture` |
| `/alerts`, `/scan-history`, `/audit` | unchanged (tabs of Activity) |
| `/team` | `/` (the tag-scope model replaces the email-keyed team view) |
| `/settings?tab=X` | `/settings/{section}` (`smtp`+`alerts` merged into `channels`) |
| Trust anchors (dashboard) | `/settings/trust-anchors` |

Behavior changes to note:

- **The audit log is now admin-only** (it exposes actor IPs and fleet-wide
  actions). Grant `settings:admin` to users who need it.
- **Per-tag permission tiers** (migration `0030`, plan 053): a scoped role's
  tier now applies *within its scope tags* — a role with tier `operator` and
  scope `prod` grants writes on `prod`-tagged resources. Existing scoped
  roles were tier-inert before; if you created scoped operator/admin roles
  in the past, they now grant in-scope writes. Set the role's tier back to
  `viewer` (or use per-tag overrides) if that isn't intended. Unscoped-role
  behavior and the global tier are unchanged.
- The CSP tightened (`style-src 'self'`); custom reverse-proxy CSP overrides
  may need updating.

## Notes

- Breaking changes between minor releases (e.g. the CT-monitoring removal and the
  `cert_scan_errors_total` → `cert_watch_scan_errors` metric rename in 0.9.0)
  are called out per release in [CHANGELOG.md](CHANGELOG.md). Read the
  intervening release notes before a multi-version jump.
- Compliance reports are tamper-evident; after an upgrade you can re-verify any
  previously exported report with `cert-watch verify-report <file.json>`.
