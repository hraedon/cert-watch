# Plan 007: Rollout Readiness (credible internal deployment)

> A frozen snapshot of cert-watch exists as the control for the
> software-factory-2 comparison. This plan covers productizing the *live*
> branch enough to deploy it at work credibly. "Credible" in a regulated /
> audit-conscious shop means **trustworthy and operable**, not feature-rich.
> The bar is boring on purpose: auth that covers the data API, an audit
> trail, a safe upgrade path, and an operator runbook.

---

## Scope discipline

This plan is deliberately small. The temptation when "productizing" is to add
impressive capability (Plan 006 Phases 2–8: CT reconciliation, mis-issuance
alerts, fleet lenses, export). **None of those gate a credible rollout** and
they are explicitly out of scope here. Ship Tier 1, then reassess.

| Phase | What | Tier | Status |
|-------|------|------|--------|
| 1 | Lock the data API behind auth | BLOCKER | ✅ done (pre-plan) |
| 2 | Audit log (who did what, when) | BLOCKER | pending |
| 3 | Schema migrations + backup/restore | BLOCKER | pending |
| 4 | "Internal deployment" profile (auth-required, secure defaults) | BLOCKER | pending |
| 5 | Operator runbook | HIGH | pending |
| 6 | `/metrics` exposure decision + scale ceiling doc | MEDIUM | pending |

### Non-goals

- New posture phases, CT work, fleet lenses, or export features.
- Multi-tenant / RBAC beyond "authenticated user." A single trusted-operator
  role is sufficient for v1; per-action authorization is a later plan.
- Changing the storage engine. SQLite single-writer stays; Phase 6 only
  *documents* the ceiling and the trigger for revisiting (BC-031).

---

## Phase 1 — Lock the data API behind auth ✅ DONE

**Done before this plan was written.** `/api/*` was exempt from auth even when
`AUTH_PROVIDER` was set, exposing the full cert/host inventory and
`/api/export/hosts.csv` to any unauthenticated caller — recon-grade exposure
and a likely audit finding.

- `is_public_path()` no longer treats `/api/*` as public; the existing
  401-JSON branch in `auth_middleware` now fires for unauthenticated API calls.
- `/healthz`, `/metrics`, `/static`, and the login flow stay open.
- Regression guard added in `tests/test_auth.py`
  (`test_auth_enabled_redirects_to_login`): `/api/certificates` and
  `/api/export/hosts.csv` → `401` under auth.
- AGENTS.md convention updated.

When `AUTH_PROVIDER` is unset the app stays fully open (backward compatible);
this change only affects deployments that turned auth on — i.e. exactly the
ones that wanted it locked down.

---

## Phase 2 — Audit log (BLOCKER)

### Why

In an audit-conscious shop, an internal security tool that can't answer "who
deleted this certificate record / changed this owner / added this host?" will
not pass review. This is the single most credibility-relevant addition, and it
is a concrete, small-scale instance of the provenance concern the broader
stack cares about.

### Design

**New table `audit_log`** (append-only; never updated or deleted by app code):

```sql
CREATE TABLE IF NOT EXISTS audit_log (
  id          TEXT PRIMARY KEY,        -- uuid4
  ts          TEXT NOT NULL,           -- ISO8601 UTC
  actor       TEXT,                    -- auth_user, or "system"/"anonymous"
  action      TEXT NOT NULL,           -- e.g. "host.add", "cert.delete", "owner.update"
  target_type TEXT,                    -- "host" | "certificate" | "owner" | "trust_anchor"
  target_id   TEXT,
  detail      TEXT,                    -- JSON: before/after or relevant fields
  source_ip   TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_log(target_type, target_id);
```

- **Helper:** `record_audit(db, *, actor, action, target_type, target_id, detail, source_ip)`
  in a new `audit.py`. Best-effort but **logged at WARNING on failure** (unlike
  posture, an audit-write failure is worth surfacing).
- **Actor source:** `request.scope.get("auth_user")` (set by `auth_middleware`),
  falling back to `"anonymous"` when auth is off.
- **Instrument the mutating routes only** (state changes, not reads): host
  add/delete, manual scan trigger, certificate delete, owner/contact update,
  trust-anchor add/delete, bulk import.
- **Surfacing:** a read-only `/audit` UI page (auth-required) and
  `GET /api/audit` (auth-required, paginated), filterable by target and actor.
  No delete/edit path — append-only is the point.

### Acceptance criteria

- AC-1: Every mutating route writes exactly one audit row capturing actor,
  action, target, and source IP.
- AC-2: Deleting a certificate leaves an audit row that survives the cascade
  delete (audit_log is never cascaded).
- AC-3: `/audit` and `/api/audit` require auth and are covered by the Phase 1
  rule (no public exemption).
- AC-4: With auth off, rows still record `actor="anonymous"` (no crash).
- AC-5: Audit-write failure logs WARNING and does **not** fail the user's action.

---

## Phase 3 — Schema migrations + backup/restore (BLOCKER)

### Why

Real data lands the moment this is deployed. The next release *will* change the
schema (Phase 2 alone adds a table). Today schema changes ride on ad-hoc
`PRAGMA table_info` guards in `init_schema` — fine for greenfield, fragile for
a populated production DB. If an upgrade can't migrate cleanly, the rollout
stalls and trust evaporates. (Supersedes FEAT-006.)

### Design

- **Migration tool:** lightweight, versioned, forward-only migrations. Prefer a
  minimal in-repo migration runner (a `schema_version` table + ordered SQL/py
  steps) over pulling in Alembic, unless Alembic's tooling earns its weight —
  decide in the spike. Single SQLite file, single writer makes this tractable.
- **`schema_version` table** records applied migrations; `init_schema` becomes
  "ensure base + run pending migrations" and the `PRAGMA`-sniffing guards get
  folded into numbered migrations over time.
- **Backup:** documented `sqlite3 .backup` (or `VACUUM INTO`) procedure that is
  safe under WAL + live writer; a `cert-watch backup <path>` CLI subcommand
  wrapping it. **Restore:** documented stop → replace file → start sequence
  (the k8s `Recreate` strategy already serializes this).
- **Pre-migration safety:** runner takes an automatic timestamped backup before
  applying migrations.

### Acceptance criteria

- AC-1: Starting a new binary against an older-schema DB applies pending
  migrations idempotently and records them in `schema_version`.
- AC-2: Re-running migrations is a no-op (idempotent).
- AC-3: A pre-migration backup file is produced automatically.
- AC-4: `cert-watch backup` produces a restorable copy while the app is running
  (WAL-safe); a round-trip restore test passes in CI.
- AC-5: Documented, tested restore procedure in the runbook (Phase 5).

---

## Phase 4 — "Internal deployment" profile (BLOCKER)

### Why

The default config is open-by-default (correct for the demo, wrong for work).
A credible rollout ships an opinionated, secure-by-default profile so an
operator can't accidentally stand up an unauthenticated inventory.

### Design

- A documented deployment profile (compose override + k8s overlay) that sets:
  `AUTH_PROVIDER` required, `CERT_WATCH_ALLOW_PRIVATE_IPS` per policy,
  `CERT_WATCH_LOG_FORMAT=json`, secure cookies, and a sane scan cadence.
- **Startup warning:** if the app binds a non-loopback interface with
  `AUTH_PROVIDER` unset, log a prominent WARNING ("running without
  authentication — inventory API is open"). Do not hard-fail (keeps the demo
  and local dev working), but make the exposure loud.
- Document the auth wiring for the likely workplace IdP (Entra/LDAP) end to end,
  including the public-path list so operators know exactly what stays open.

### Acceptance criteria

- AC-1: Following the profile docs yields an auth-required deployment with no
  unauthenticated data routes (verified against the Phase 1 rule).
- AC-2: Unauthenticated + non-loopback bind emits the startup WARNING; test
  asserts the warning fires.
- AC-3: The demo / `AUTH_PROVIDER`-unset path is unchanged (still works open).

---

## Phase 5 — Operator runbook (HIGH)

A single `docs/runbook.md` aimed at whoever operates this at work:

- Deploy + upgrade (incl. the migration step from Phase 3).
- Backup + restore (the tested Phase 3 procedure).
- "A scan is failing" — how to read structured logs, the scan retry behavior,
  private-IP / DNS settings.
- Config reference (env vars) with the secure-profile values called out.
- What's exposed unauthenticated, and the `/metrics` decision from Phase 6.

### Acceptance criteria

- AC-1: A reader can deploy, upgrade-with-migration, back up, and restore using
  only the runbook.
- AC-2: Restore steps match the CI-tested procedure from Phase 3 (no drift).

---

## Phase 6 — `/metrics` decision + scale ceiling (MEDIUM)

- **`/metrics`:** decide deliberately — keep open (internal network, IP-restricted
  at ingress) or require a scrape token / auth. Document the choice and rationale
  in the runbook. Default recommendation: keep open but document that it leaks
  aggregate counts and should be ingress-restricted.
- **Scale ceiling:** document the single-writer SQLite envelope (rough host/scan
  volume it comfortably handles, WAL behavior) and the explicit trigger for
  revisiting Postgres/MSSQL (BC-031) — fleet size, HA requirement, or
  multi-writer need. No code change; this is an honest-limits note so the
  rollout decision is informed.

### Acceptance criteria

- AC-1: Runbook states the `/metrics` exposure decision and how to change it.
- AC-2: Runbook states the scale ceiling and the BC-031 trigger.

---

## Sequencing

1. **Phase 2 (audit)** and **Phase 3 (migrations/backup)** are the two that most
   move credibility and are independent — either can go first. Audit is more
   visible to reviewers; migrations are more dangerous to defer.
2. **Phase 4** depends on nothing but is best landed alongside Phase 2 so the
   secure profile and audit ship together.
3. **Phases 5–6** are documentation and follow once the behavior they describe
   exists.

Ship Tier 1 (Phases 2–4) for a credible v1. Phases 5–6 close it out.
