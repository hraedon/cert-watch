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
   cert-watch backup            # writes a WAL-safe copy via VACUUM INTO
   ```
   or simply stop the app and copy the `.sqlite3` file (plus any `-wal`/`-shm`).
2. **Deploy 1.0** over the same data directory / volume.
   - **Kubernetes (Argo CD):** sync to the 1.0 image; the existing PVC carries
     the DB and migrations run when the new pod starts.
   - **Docker Compose / systemd:** pull the new image/release and restart; point
     it at the same DB path.
   - **Windows / IIS:** run the 1.0 `install-windows.ps1` against the existing
     site; the app pool restart triggers the migration on first request.
3. **Verify.** Watch the startup logs for `applying migration ...` /
   `migration ... applied`, confirm the dashboard loads, and confirm
   `schema_version` is at head. A `*-pre-migration-*.sqlite3` file next to the DB
   confirms the safety backup was taken.

Downgrade is **not** supported — migrations are forward-only. To roll back,
restore the pre-migration backup.

### Windows / IIS specifics

Validated on a real Windows host by migrating a 0.9.0 database to current:

- A **running** instance holds the SQLite database open, so its `.sqlite3`,
  `-wal`, and `-shm` files cannot be copied/replaced/restored while the app pool
  is running (you get `WinError 32`, a sharing violation). **Stop the app pool
  first** for any manual file operation (backup restore, DB swap).
- A **clean app-pool stop checkpoints the WAL and releases the handle** — the
  `-wal`/`-shm` files disappear and the database becomes a clean standalone file.
  So the normal stop → deploy 1.0 → start sequence is safe: the old process
  releases the DB on stop, the new process migrates it on start (writing the
  `*-pre-migration-*.sqlite3` backup), then serves. No `-wal` is left orphaned.

## Upgrading from a pre-0.9.0 release

There is no full-fidelity data export/import tool. Two options:

- **Recommended — stage through 0.9.x:** upgrade to a 0.9.x release first (its
  migrations cover the older schema), confirm it runs, then upgrade 0.9.x → 1.0
  as above.
- **Rebuild — fresh 1.0 + re-add hosts:** stand up a clean 1.0 instance and
  re-add tracked hosts with the **CSV bulk import** (Settings → Hosts → Import).
  This re-establishes the host inventory; historical scan/cert/audit history is
  not carried across by this path.

## Notes

- Breaking changes between minor releases (e.g. the CT-monitoring removal and the
  `cert_scan_errors_total` → `cert_watch_scan_errors` metric rename in 0.9.0)
  are called out per release in [CHANGELOG.md](CHANGELOG.md). Read the
  intervening release notes before a multi-version jump.
- Compliance reports are tamper-evident; after an upgrade you can re-verify any
  previously exported report with `cert-watch verify-report <file.json>`.
