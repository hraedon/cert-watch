# Plan 047 — Capability Roadmap (post-v0.7.3)

**Status:** proposed 2026-06-09
**Author:** Fable 5 (repo scan + portfolio review)
**Strategic role:** Sequence the next three releases so capability work (what the
product can *do*) leads, debt work stays gated behind it, and the plans that
contradict `docs/positioning.md` get an explicit decision instead of silent drift.

## Ground truth at time of writing

- Working tree: 1527 unit tests pass (2:18, no coverage), ruff clean, **mypy has
  5 errors** introduced by the uncommitted hardening-release-3 work
  (`middleware.py` ×2 `ctx` redefinitions, `routes/settings.py` ×3 return-type /
  assignment errors). CI gates mypy, so this tree cannot ship as-is.
- 14 open breadcrumbs; the load-bearing ones are BC-160 (RBAC follow-through),
  BC-136 (authed-flow E2E), BC-151 (CT mis-issuance), BC-121 (CAA per scan),
  BC-161/162 (scan.py / dashboard.py structure).
- Known tooling bug: full suite **hangs under coverage + pytest-xdist** (~300s);
  `-n0` works (2026-06-09 umans-coder reflection). CI currently passes because it
  uses `COVERAGE_CORE=sysmon`, but local agents can't run the canonical command.
- Coverage trap demonstrated: `oauth_provider.py` sat at **16%** while the global
  ratchet stayed ≥88%. Global coverage cannot protect per-module floors.
- Plan-numbering collision: commits and BC-160 call the roles/users work
  "Plan 040", but `plans/040-ct-log-monitoring.md` is CT monitoring. The
  roles/users work corresponds to Plan 035. Fix the references.

---

## Phase 0 — Restore invariants (do first, small, one session)

The project's credibility rests on its gates being real. Right now two are not.

### WI-0.1 — Fix the 5 mypy errors and land the in-flight hardening work
- `middleware.py:809,891` — `ctx` redefined inside the same function (declare
  once before the branch).
- `routes/settings.py:200,237,299` — widen return annotations to include
  `JSONResponse`, and don't reuse a `list[dict]`-typed variable for
  `list[ApiKeyEntry]`.
- Then run the full local gate (ruff, mypy, djlint, pytest) and commit the
  working tree (middleware admin-form helpers + setup CSRF + tests). It is
  finished work being held hostage by type errors.
- **AC:** `mypy src/cert_watch` zero errors; tree committed; CI green.

### WI-0.2 — Per-module coverage floors for security-critical modules
- Add a ratchet test (pattern already exists in the repo: inline-style budgets)
  that parses `coverage.json` and asserts minimum per-module coverage for:
  `auth/ldap_provider.py`, `auth/oauth_provider.py`, `middleware.py`,
  `security.py`, `routes/settings.py`, `scan.py`. Set floors at current
  actuals (don't aspire — ratchet).
- **AC:** dropping any listed module 5 points below its floor fails the suite;
  closes the BC-155 class of problem structurally instead of per-module.

### WI-0.3 — Fix the coverage + xdist hang
- Reproduce: `pytest` with coverage and `-n auto` hangs ~300s; `-n0` fine.
  Suspects: `COVERAGE_CORE` default (local lacks `sysmon` env), a worker
  deadlocking under trace overhead, or coverage combine on teardown.
- Acceptable outcomes: a fixed config in `pyproject.toml`, **or** a documented
  one-true-command in AGENTS.md that all agents use. What's not acceptable is
  every session rediscovering it.
- **AC:** the canonical test command in AGENTS.md completes locally with
  coverage in <5 min, twice in a row.

### WI-0.4 — Repair plan-numbering references
- Update BC-160 text and add a note to `plans/035-role-based-authorization.md`
  that commits `380c1a9`/follow-ups implemented its foundation under the
  mislabel "Plan 040". One-line fixes; prevents future agents grounding on the
  wrong plan file.

---

## Workstream A — Finish the RBAC story (v0.8.0 headline)

Roles/users foundation is merged, but per the 2026-06-05 handoff, **admin and
user still see materially the same UI**, and the new roles/users tabs have zero
E2E coverage. A half-finished authorization story is worse than none in a tool
pitched at regulated shops.

### WI-A.1 — Role-differentiated UI (BC-160 part 1)
- Viewer-role users: read-only dashboard — no "Add host", no rescan/remove/owner
  edit, no settings nav entry. Server-side enforcement already exists
  (`require_write_form` / new `require_admin_form`); this is making the UI tell
  the truth about it.
- **AC:** logged in as `cw-user` (lab AD), no mutating control is rendered;
  direct POSTs still 303-redirect with an error (already covered).

### WI-A.2 — Alert routing by ownership/role (BC-160 part 2)
- Alerts respect cert/host `owner`: a user's alert digest covers their certs;
  admins get fleet-wide. Reuses tags/alert-groups plumbing (Plan 013/015).
- **AC:** two owners, one expiring cert each — each digest contains only its
  owner's cert; admin digest contains both.

### WI-A.3 — E2E for authed flows (BC-136 / Plan 034)
- Extend the existing Playwright E2E harness: login as admin and as viewer
  against the synthetic-LDAP CI fixture (Plan 038 infra), assert the role
  differences from WI-A.1, exercise roles/users settings tabs (create role,
  map group, assign user).
- This is the regression net that makes WI-A.1/A.2 safe to maintain; the three
  LDAP bugs in the 2026-06-05 handoff were all invisible to mocked unit tests.
- **AC:** CI job runs the authed E2E suite headless; failure blocks merge.

---

## Workstream B — Posture & compliance capability (Tier A quick wins)

These are pulled from Plan 017 Tier A and open breadcrumbs. Each is one to two
sessions, fits existing plumbing, and adds genuinely new capability.

### WI-B.1 — Revocation-endpoint health (Plan 017 A1)
- Parse AIA (OCSP URL) + CRL distribution points from the leaf during scan;
  check reachability and well-formedness. Opt-in (`CERT_WATCH_CHECK_REVOCATION`,
  default off). New posture findings + `scan_posture` column.
- A valid cert with a dead OCSP responder is a real failure no competitor in
  this niche surfaces well. Highest capability-per-effort item on the board.
- **AC:** cert with unreachable OCSP/CRL gets a posture finding; toggle off ⇒
  checks skipped, not failed.

### WI-B.2 — CAA presence per scan (BC-121)
- `caa_check.py` exists; persist the result per scan so the compliance report
  can state CAA coverage as a point-in-time metric. Closes a known gap in the
  auditor-facing report (Plan 025).
- **AC:** compliance report shows a CAA metric with per-host detail.

### WI-B.3 — CT mis-issuance detection via existing crt.sh path (BC-151)
- First-seen capture + unexpected-issuer flag on the **existing** crt.sh
  reconciliation — not the Plan 040 RFC-6962 streaming client (see Decisions).
  Alert when a cert for a tracked domain appears in CT from an issuer outside
  the host's observed issuer set.
- **AC:** seeded crt.sh fixture with a rogue-issuer cert produces an alert and
  a Discover finding.

### WI-B.4 — Webhook presets (BC-103)
- Slack and Alertmanager payload presets in `alert_adapters.py` (Teams /
  Discord / PagerDuty already first-class). Small, rounds out the matrix.
- **AC:** preset selectable in settings; adapter unit tests for both payloads.

---

## Workstream C — Policy engine + event streaming (v0.9.0 headline)

Plans 042 and 044 are the right next bets and compose with each other. Both are
self-hosted-pure (no new external dependencies), both generalize machinery that
already exists (`posture.py` rules; `alert_adapters.py` delivery).

### WI-C.1 — Policy engine core (Plan 042 WI-1..3)
- Extract the hard-coded posture checks into a `PolicySet` of `PolicyRule`s;
  ship the current behaviour as the default policy (zero-config invariant: a
  fresh install grades identically to v0.7.x). Add org rules: max validity
  days, issuer allowlist/denylist, key-type constraints.
- **AC:** default policy reproduces existing grades byte-for-byte on the test
  corpus; a custom `max_validity_days=90` rule flags a 365-day cert.

### WI-C.2 — Policy violations as alerts + settings UI (Plan 042 WI-4..5)
- Violations flow through the existing alert pipeline with severity; a
  settings tab edits rules (the settings-tab pattern from the API-keys move is
  the template).
- **AC:** enabling a rule produces alerts on next scan; E2E covers the tab.

### WI-C.3 — Event model + webhook event streaming (Plan 044)
- `cert_added` / `cert_renewed` / `posture_changed` / `scan_failed` /
  `policy_violation` events, fan-out through the adapter registry, per-channel
  event-type subscriptions. `policy_violation` lands free from WI-C.1/2.
- Note the SIEM overlap: events are *operator automation*, SIEM export is
  *audit*. Keep the paths separate (siem.py stays fail-open, append-only).
- **AC:** subscribing a webhook to `posture_changed` fires on a grade drop;
  delivery failures retry via existing `retry.py` semantics and never block a
  scan.

---

## Workstream D — The Windows/AD bet (premise spike, then decide)

Plan 030 (AD CS discovery) is the real differentiator for the stated target
user (regulated, directory-authenticated, self-hosted) and is **blocked on a
premise spike by its own text**. The lab has everything needed: real AD, a
Win Server 2025 box (`mvmcitest01.ad.hraedon.com`, key-auth SSH), and working
LDAPS plumbing.

### WI-D.1 — Spike: read path to AD CS issued-cert inventory (timeboxed)
- Question to answer: can a read-only account enumerate issued certs from the
  lab CA — via LDAP published-cert objects, `certutil -view` over the SSH/WinRM
  bridge, or ICertView? Produce a one-page findings doc in `plans/design/`
  with the chosen path, required permissions, and data shape. **No product
  code.**
- **AC:** findings doc exists; Plan 030 status flips to either "unblocked,
  scoped" or "declined with evidence".

### WI-D.2 — Windows cert-store collector (Plan 017 B2) — only if D.1 lands
- Read-only PowerShell collector emitting cert blobs into the existing upload
  path or a `POST /api/ingest` (API-key auth from Plan 039 already exists).
- **AC:** machine-store certs from the lab VM appear in inventory tagged
  `source="windows-store"`.

---

## Workstream E — Structural debt (gated: pull only when touching the area)

Do these *when a capability item forces you into the file*, not as standalone
sessions — the suite is the safety net and it's strong.

- **BC-161** — split `scan.py` (974 lines): DNS resolution and connection
  logic into `scan_resolver.py` / `scan_conn.py` (both files already exist as
  seams — finish the extraction). Natural moment: WI-B.1 touches scan.
- **BC-162** — `dashboard.py` f-string column interpolation → enum/allowlist
  approach. Natural moment: any dashboard query change in WI-A.1.
- **BC-144a** — config decomposition stays wontfix/deferred unless WI-C.2's
  settings work makes it cheap.

---

## Decisions requested (explicit, so drift doesn't decide instead)

1. **Plan 041 (cloud auto-discovery: AWS/GCP/Azure) — recommend DECLINE** and
   annotate the plan file. It directly contradicts `docs/positioning.md` and
   Plan 017 Tier C ("external cloud-API discovery… exactly the external-SaaS
   dependency the positioning declines"). Exception worth keeping: the
   `static` file source (cheap, air-gap-friendly) and possibly k8s Ingress
   discovery (inside the trust boundary, self-hosted) — if kept, update
   Plan 017 Tier C to record the boundary redrawn.
2. **Plan 040 (RFC-6962 CT streaming client) — recommend DEFER.** WI-B.3 gets
   most of the value through the existing crt.sh path with no new polling
   infrastructure. Revisit only if near-real-time issuance detection becomes a
   hard requirement (Plan 017 Tier C already records the self-hosted
   certstream option for that day).
3. **Plan 043 (Postgres backend) — recommend DEFER.** Single-file SQLite is a
   *feature* for the SMB self-hosted positioning; nothing on this roadmap
   needs multi-writer. Revisit at a concrete scale signal.

## Release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.7.4 | Gates restored | Phase 0 (all four WIs) |
| v0.8.0 | RBAC complete | Workstream A + WI-B.2, WI-B.4 |
| v0.9.0 | Policy & events | Workstream C + WI-B.1, WI-B.3 |
| v0.10.0 | Windows/AD bet | Workstream D outcome (+E items absorbed en route) |

Sequencing rationale: A before C because the policy-engine settings UI and
event subscriptions assume role-aware admin surfaces; B items slot into
whichever release their neighbouring code is open in; D is parallelizable
anytime (the spike needs no code).
