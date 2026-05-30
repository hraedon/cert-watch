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
| 4 | Auth & authz: group/role gate, Entra+MFA / LDAPS fallback / break-glass admin, DC failover, secure profile | BLOCKER | pending |
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

### Rejected alternative: back the audit log with regista

regista's core is an immutable, append-only, **hash-chained** event log
(`prev_event_hash = SHA-256(prev envelope + signature)`) with pluggable
signing and RFC 3161 timestamping — a stronger audit primitive than a plain
table. It was considered and rejected for cert-watch's audit log:

- **Deployment cost.** regista requires Postgres; cert-watch's credibility
  rests on the single-SQLite-file, single-writer deployment. We'd consume ~5%
  of regista (the event log) and carry the work-item/claim/workflow machinery
  as operational overhead for a need it doesn't have.
- **Context risk.** This tool is being rolled out where agent tooling is
  blocked over audit/provenance gaps. regista is agent-pipeline
  infrastructure; depending on it imports the agent stack into the one tool
  meant to be boring and standalone — a credibility cost in that room.
- **Comparison artifact.** Coupling cert-watch (the traditional-build control
  for software-factory-2) to the agent stack muddies that role too.

The useful relationship runs the other way: cert-watch's human-action audit
need is a clean, non-agent **proving ground** for regista's provenance model.

**Optional tamper-evidence without the dependency:** if the workplace wants a
tamper-evident trail, borrow only the *technique* — add a `prev_hash` column
chaining each audit row to its predecessor (`SHA-256(prev_hash || canonical
row)`). ~80% of the credibility, zero new infrastructure. Defer until it's a
stated requirement.

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

## Phase 4 — Authentication, authorization & secure deployment (BLOCKER)

### Why

Today both auth paths authenticate but don't *authorize* — any valid account
gets full access, which is only marginally better than no auth. This system
holds sensitive (if not strictly confidential) infrastructure data, so v1
needs real group/role gating, MFA where possible, resilience when an IdP is
unavailable, and a secure-by-default deployment posture.

**Provider strategy:** Entra OIDC (+ MFA / conditional access) is the
**primary** path; LDAPS is the **fallback** for shops without Entra or
unwilling to stand up an app registration. A **local break-glass admin** is the
cross-provider last resort.

### 4.1 Authorization model (all providers)

- **Required group/role gate.** A successful authN grants access only if the
  identity holds ≥1 configured allowed group/role; otherwise it is denied even
  with valid credentials. Single "trusted operator" role for v1.
- **Deferred:** group→role split (e.g. admin vs read-only) and per-action RBAC.
- Each provider returns the matched groups/roles on `AuthResult`; the login
  handler enforces the gate; the session carries `actor` + role; Phase 2's
  audit log records `actor` and whether the login was break-glass.

### 4.2 Entra OIDC (primary)

- **App Roles, not the raw `groups` claim.** Define roles on the app
  registration, assign AD groups to them, gate on the `roles` claim. This
  sidesteps the `groups`-claim overage (>~200 groups → Entra sends a Graph
  pointer instead of the list).
- **Verify the ID token signature against the IdP JWKS.** The current code
  base64-decodes the token payload and checks `iss`/`aud` on *unverified*
  claims. Replace with real JWT signature verification (authlib/JWKS), then
  validate `iss`, `aud`, `exp`, and nonce on the verified claims.
- Credential: client secret or (preferred) certificate, via env / `*_FILE` /
  secret. **Secret expiry is a known outage mode** → covered by break-glass.

### 4.3 LDAPS (fallback)

- **Transitive group check** via AD's `LDAP_MATCHING_RULE_IN_CHAIN` OID
  (`1.2.840.113556.1.4.1941`) so nested membership counts:
  `(&(sAMAccountName={user})(memberOf:1.2.840.113556.1.4.1941:=<group-DN>))`.
- **Private-CA trust (fail closed).** AD LDAPS certs are issued by an internal
  CA, never public PKI. Configure `ldap3.Tls(validate=ssl.CERT_REQUIRED,
  ca_certs_file=… | ca_certs_data=…)` — `CERT_REQUIRED` is load-bearing
  (ldap3 defaults to `CERT_NONE`, i.e. encrypted-but-unauthenticated). If
  `ldaps://` is set with no CA, fail with a clear error rather than disabling
  validation. Connect by the **DC FQDN that matches the cert SAN** (no IP).
  Keep this CA **separate** from cert-watch's scan trust-anchor store — auth
  trust must be operator-pinned, not sourced from mutable inventory data.
- **DC failover.** `LDAP_SERVER` accepts a comma-separated list; build an
  `ldap3.ServerPool([dc1, dc2], pool_strategy=FIRST, active=True)` sharing one
  `Tls`, with a short `connect_timeout` so a dead DC fails fast to the next.
  Both DCs chain to the same enterprise CA, so one CA bundle covers the pool.
- Least-privilege bind account; `LDAP_BIND_PASSWORD_FILE`; TLS enforced.

### 4.4 Local break-glass admin (cross-provider fallback)

- **Why:** the primary IdP can be unavailable — DC down, Entra app secret
  expired/misconfigured, discovery failing. A way in that depends on *no*
  external system is required. It also bootstraps first-run setup before SSO is
  wired.
- **Disabled unless explicitly configured:** `CERT_WATCH_LOCAL_ADMIN_USER` +
  `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` (+ `*_FILE`). Store a **hash, never
  plaintext** — stdlib `hashlib.scrypt` (no new dependency), per-account salt,
  `hmac.compare_digest`. Ship a `cert-watch hash-password` CLI helper so the
  plaintext never lands in config.
- **Always usable when configured — NOT gated on provider health.** Rejected
  alternative: "only honor it when the provider is down." Provider-health is
  gameable (an attacker who can DoS the DC *forces* the fallback) and racy.
  Security instead comes from: disabled-by-default, a single known identity, a
  strong hash, and making every use **loud**.
- **Every break-glass login emits a WARNING log + an audit row flagged
  `break_glass=true`** (alert on it). Documented guidance: rotate after use.
- It **bypasses the group gate** (no directory groups → implicit admin role)
  and **bypasses MFA** (inherent to break-glass) — documented as the accepted
  tradeoff, mitigated by a long random secret and alerting.
- **Login UX:** when the provider is OIDC (redirect-based, no form), the login
  page must *still* render a secondary local-admin username/password form when
  a local admin is configured. Primary button = SSO; break-glass = the small
  print.
- **Evaluation order:** submitted username == local-admin user → verify hash
  (works regardless of provider state) → else → provider flow → group/role gate.

### 4.5 Secure deployment profile

- Documented profile (compose override + k8s overlay): `AUTH_PROVIDER` required,
  `CERT_WATCH_ALLOW_PRIVATE_IPS` per policy, `CERT_WATCH_LOG_FORMAT=json`,
  secure cookies, sane scan cadence.
- **Startup warning** if the app binds a non-loopback interface with
  `AUTH_PROVIDER` unset ("running without authentication — inventory API is
  open"). Warn loudly; don't hard-fail (keeps demo/local dev working).
- Document the end-to-end auth wiring (Entra app registration + App Roles; LDAP
  bind account + CA + DC pool; local admin) and the public-path list.

### Acceptance criteria

- AC-1 (authZ): a user not in any allowed group/role is denied despite valid
  credentials — on both the OIDC and LDAP paths.
- AC-2 (OIDC): the ID token signature is verified against JWKS; a token with a
  bad/unknown signing key is rejected; a missing required role is denied.
- AC-3 (LDAPS): the connection validates against the configured private CA;
  an untrusted or missing-CA `ldaps://` fails closed (never silent
  `CERT_NONE`); transitive group membership is honored.
- AC-4 (failover): with two DCs configured, an unreachable DC1 fails over to
  DC2 within `connect_timeout` and authN still succeeds.
- AC-5 (break-glass): disabled when unconfigured; succeeds when the configured
  provider is unreachable; every use emits a WARNING + an audit row flagged
  break-glass; the password is persisted only as a hash and compared in
  constant time.
- AC-6 (secrets): every credential — LDAP bind password, OIDC client secret,
  local-admin hash, LDAP CA bundle — is loadable via a `*_FILE` path for
  k8s/Docker secret mounts.
- AC-7 (profile): the secure profile yields an auth-required deployment with no
  unauthenticated data routes; an open non-loopback bind warns at startup; the
  `AUTH_PROVIDER`-unset demo path is unchanged.

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
