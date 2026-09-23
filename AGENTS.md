# AGENTS.md

Notes for coding agents working on cert-watch. Start with
[CONTRIBUTING.md](CONTRIBUTING.md): its rules apply to you in full. This file
only adds what is specific to agents.

## Orient

1. Read [CONTRIBUTING.md](CONTRIBUTING.md), then
   [docs/architecture.md](docs/architecture.md).
2. Check open pull requests and recent `main` history before starting. Other
   agents work on this repository too. Fetch before you push, and read the
   push output: a rejected push is easy to miss.
3. This repository is **public**. Stage files by explicit path, keep reviewer
   scratch directories (`.review/`) out of commits, and don't put private host
   names, credentials or work-domain identifiers in code, docs or commit
   messages. The identifier gate catches some of this, not all of it.

## Breadcrumbs

The project is registered with agent-notes (path `/projects/cert-watch`). Use
the `agent-notes` CLI or the breadcrumb skills, and search before filing. Don't
create breadcrumb files in the tree. Historical plans and session reflections
are archived; see [docs/history.md](docs/history.md).

## Seeing the UI

A Playwright MCP server is configured (`.mcp.json`) for looking at the running
app: navigating, clicking through a flow, taking screenshots. Use it to *see* a
change before committing, and the e2e suite to *lock it in*.

## Test estate (mvmcitest01)

A live cert-watch instance is deployed on `mvmcitest01` (Windows/IIS, real AD LDAP auth against `ad.hraedon.com`) for operator-paced validation — the work every reflection flagged as "never happens" because fixtures can't stand in for real certs/tags/routing.

- **Access:** passwordless ssh `cw-admin@mvmcitest01` (creds via the `agent-capability-broker` project). Remote shell is PowerShell — for multi-line Python, pipe a heredoc to `python.exe -` over stdin to avoid PS quote-mangling (inline `python -c "..."` breaks on `"\""`).
- **Layout:** app at `C:\inetpub\cert-watch` (web.config has env vars); venv `C:\ProgramData\cert-watch\venv\Scripts\python.exe`; data dir `C:\ProgramData\cert-watch` (`cert-watch.sqlite3` + WAL). HTTPS at `https://mvmcitest01.ad.hraedon.com`. **Do not read the `secrets\` subdir** (auth/csrf/ldap-bind secrets).
- **Driving it:** the CLI has no scan/add-host subcommand and there are no API keys; LDAP needs a real AD password. Seed via the real scan internals — `SqliteHostRepository.add()` + `scan_host()` + `store_scanned()` against the DB (the same path `scheduler.run_scan_now` calls), or add hosts in the UI and let the scheduler's 1-hour fast-retry scan them. `allow_private=True` (private IPs are scannable; `CERT_WATCH_ALLOW_PRIVATE_IPS=1`).
- **Seeded 2026-06-18** with 12 real hosts across `ad.hraedon.com` (DCs `mvmdc0{1,2,3}` on :636, the box on :443) and `k8s.hraedon.com` (`api.k8s.hraedon.com` :6443 + LE ingress hosts on :443). This is the estate to validate posture/readiness/renewal-analytics/alert-routing heuristics against. Treat it as read-only unless intentionally populating; never mutate the production instance without a reason.
- **WI-073 (resolved 2026-07-01):** The certifi fallback fix in `cert_chain.py` was deployed to mvmcitest01 and validated — all 7 Let's Encrypt certs now grade A (was B) with `chain_status=public` (was `incomplete`). AD CS certs remain B/incomplete as expected (private CA not uploaded as anchor). **BC-153 (resolved 2026-07-02):** `certifi` is now listed as a direct dependency in `pyproject.toml` — the fallback no longer depends on transitive availability.
- **WI-140 (fixed 2026-07-27; second root cause fixed 2026-08-20):** The instance silently stopped scanning for **12 days** (2026-07-15 → 07-27). Root cause: the app pool was `AlwaysRunning` with no idle timeout, but the IIS **application** had no `preloadEnabled=true`, so HttpPlatformHandler only spawned python.exe on the first HTTP request — after a reboot with no traffic, the scheduler never ran. Fixed three ways: `install-windows.ps1` now sets `applicationDefaults.preloadEnabled=true` (+ `deploy/iis/README.md` "AlwaysRunning alone is not enough" section); the live site config was updated in place; and `/metrics` now exports `cert_watch_last_scan_timestamp_seconds` with a `CertWatchScanStalled` PrometheusRule (>36h without a scan) so a stall pages instead of going unnoticed. **Second failure (2026-08-20):** the 07-27 preload config was *silently inert* — the **Application Initialization role service** (`Web-AppInit` / `warmup.dll`) was not installed, and IIS ignores `preloadEnabled` without it. After an IIS recycle on 2026-08-16 the backend never came back (4-day gap, 08-17 → 08-20). Feature installed on mvmcitest01 and validated: python.exe now spawns instantly on pool recycle with zero inbound traffic. `install-windows.ps1` step 2b verifies Windows feature state, native-module registration, and `warmup.dll`, installing the feature and failing loudly if any required state remains absent. Note: applying `applicationDefaults` edits **recycles the site's applications** — it is not a zero-downtime config change. Windows/IIS deploys also have no update cadence story; the box ran a month-old build until manually updated.

## Releasing

Versions come from the git tag. The release workflow stamps
`src/cert_watch/_version.txt` from `GIT_TAG` at build time; the committed file
is the fallback for running from a checkout. To release, set the version in
`pyproject.toml` and `_version.txt`, update `CHANGELOG.md` and `UPGRADING.md`,
merge, and push a `vX.Y.Z` tag. The workflow refuses a tag that doesn't match
`pyproject.toml`. Releases are the maintainer's call.
