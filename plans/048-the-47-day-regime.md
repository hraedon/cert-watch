# Plan 048 — The 47-Day Regime (post-Plan-047 features)

**Status:** proposed 2026-06-10
**Author:** Fable 5 (repo scan + strategic re-read)
**Strategic role:** Plan 047 shipped in full (Phase 0, Workstreams A/B/C;
Plans 040/041/043 decisions annotated). This plan is the next *feature* bet,
and it revises a prior strategic read. The earlier framing — "a tool serving a
dwindling audience, close to feature complete" — was right about automation
eating the long-term market but wrong about the rate, because CA/Browser Forum
ballot SC-081 is forcing public TLS maximum validity down on a schedule most
estates are not preparing for: **200 days from 2026-03-15, 100 days from
2027-03-15, 47 days from 2029-03-15** (DCV reuse shrinks on a parallel
schedule, to 10 days by 2029). Estates that renew manually do not lose their
certificates problem — it multiplies ~8×, on a deadline, with no automation in
place. That is cert-watch's exact audience (self-hosted, regulated, manual or
semi-manual ops), and almost everything in the tool that quietly assumes "a
certificate lives about a year" breaks in that regime. This plan makes
cert-watch the tool that gets a non-automated estate *through* the transition.

**Honesty clause:** this is a window (roughly 2026–2030), not a reversal of
the long-term trend. By the late 47-day era the laggards have either automated
or churned. The durable post-window market remains the private-CA/internal
estate (where lifetimes stay long and AD CS lives) — which is why Workstream D
carries Plan 047's AD CS spike forward rather than dropping it.

## Ground truth at time of writing

- Plan 047 delivered: invariants restored, RBAC story complete (role UI,
  owner-aware digests, authed E2E), posture/compliance quick wins (revocation
  endpoints, CAA per scan, CT mis-issuance, presets), **policy engine
  (`policy.py`) and event model (`events.py`) live** — both are substrate for
  this plan. Post-release adversarial-review fixes landed 2026-06-10.
- Open breadcrumbs: BC-136 (authed E2E follow-through — **in flight**),
  BC-096 (test monkeypatch coupling, low), BC-144a (wontfix/deferred).
  `OPEN_BREADCRUMBS.txt` is stale (regenerate; it predates the v0.7.x closes).
- **Plan 047 WI-D.1 (AD CS premise spike) was never executed** — no findings
  doc in `plans/design/`. Carried forward here, not re-planned.
- Alert thresholds are fixed day-counts: `LEAF_THRESHOLDS`/`CHAIN_THRESHOLDS
  = (30, 14, 7)` (`alerts.py:22`). For a 47-day certificate, the 30-day
  warning fires with 36% of lifetime already gone — i.e. for most of the
  cert's life — and 30/14/7 collapse into near-permanent alarm. **Fixed-day
  semantics are wrong in the short-lifetime regime**; this is the plan's most
  concrete defect-shaped feature.
- The data for renewal analytics already exists: `cert_history` keeps cert
  lineage per host (`not_after` over time), `scan_history` keeps cadence,
  `events.py` emits `cert_renewed`. Nothing below requires new collection —
  only computation over what's stored.
- Scheduler scans per-host intervals or a default daily cycle — adequate even
  at 47 days; no cadence work needed beyond a guidance finding (WI-3.2).

---

## Workstream 1 — Alerting that understands short lifetimes (v0.11.0 core)

### WI-1.1 — Lifetime-relative alert thresholds
- Add percentage-of-lifetime-remaining thresholds alongside fixed days. A
  cert's effective ladder becomes lifetime-aware: long-lived certs keep
  30/14/7 exactly (behaviour-preserving); certs with lifetime ≤ 90 days use a
  relative ladder (default 50% / 25% / 10% remaining, configurable
  per-host/group like `custom_thresholds` today).
- Rationale for changing short-cert defaults rather than gating behind opt-in:
  the current behaviour for a 47-day cert is not a default anyone chose — it
  is a bug exposed by a regime that didn't exist when the ladder was written.
  Document the change loudly in CHANGELOG.
- **AC:** 365-day cert alert sequence is byte-identical to v0.10.x; a 47-day
  cert produces three sensibly spaced alerts (≈23/12/5 days) and never sits
  in permanent threshold-crossed state; escalation/cooldown semantics
  (AC-02) unchanged.

### WI-1.2 — Renewal-overdue detection (distinct from expiry alarm)
- From `cert_history`, compute each host's observed renewal pattern: median
  lead time (days-remaining at which a new cert historically appears) and
  cadence. When a cert sails past its expected renewal point with no
  successor, raise a `renewal_overdue` signal — *earlier and more specific*
  than the expiry ladder, because it encodes "your process didn't run," not
  "the math says doom approaches."
- Hosts with <2 observed renewals have no pattern: emit nothing (no guessing).
- New event type `renewal_overdue` through the existing event/alert pipeline.
- **AC:** fixture history with a host that always renews at ~20 days
  remaining triggers `renewal_overdue` when a scan shows 12 days and the same
  fingerprint; a host with one lifetime cert triggers nothing.

---

## Workstream 2 — The 47-day readiness report (v0.11.0 headline)

The artifact an ops lead takes to management. All computation over existing
tables; presentation extends the compliance-report pattern (Plan 025).

### WI-2.1 — Renewal analytics over `cert_history`
- Per host: observed lifetimes (and trend), renewal lead times, cadence, and
  an **automation inference**: `likely-automated` (lifetime ≤ 90d, consistent
  cadence, ACME-associated issuer), `manual` (long lifetimes or irregular
  late renewals), `unknown` (insufficient history). Heuristic, labeled as
  such in the UI — never presented as fact (positioning: the tool doesn't
  guess silently).
- Exposed as a queryable module (`renewal_analytics.py`) + JSON API route, so
  WI-1.2, WI-2.2, and dashboards consume one implementation.
- **AC:** fixture estates (automated-ish, manual, mixed) classify correctly;
  classification carries its evidence (the numbers, not just the label).

### WI-2.2 — Readiness view & report section
- New report section / page: the SC-081 milestone timeline (200d / 100d /
  47d, DCV-reuse milestones), each host classified per WI-2.1, and the two
  numbers that make the argument:
  1. **Margin analysis** — historical renewal lead time vs the lifetime in
     force at each milestone ("this host renews with 15 days' margin today;
     at 47-day lifetimes that margin is 32% of the cert's life and your
     current process renews it ~3 days late").
  2. **Workload forecast** — renewals/month for the estate now, at 100d, at
     47d ("your team did 4 renewals last quarter; the 47-day regime makes
     that 31").
- Public-trust certs only drive the risk math; private-CA certs (per
  `chain_status`) appear in a separate annotated band — SC-081 does not bind
  them, and saying otherwise would be the kind of dishonesty the tools we
  build avoid.
- **AC:** report renders from fixture data a manager can read without the
  tool installed (print-friendly, same standard as the compliance report);
  private-CA hosts never counted in public-trust risk totals.

### WI-2.3 — SC-081 policy pack
- A named, versioned, opt-in `PolicySet` ("cab-forum-sc081") for the engine
  shipped in Plan 047 WI-C.1: date-aware max-validity rules keyed to the
  milestone schedule (a public-trust cert *issued after* a milestone with
  validity exceeding that milestone's cap → violation; pre-milestone issuance
  grandfathered). Violations flow through the existing policy-alert path.
- This catches the two real-world cases: a private/internal CA stamping
  398-day certs onto public-facing services past the deadline, and "we
  thought that cert was replaced" drift.
- **AC:** fixture cert issued 2026-04-01 with 300-day validity violates; the
  same cert issued 2026-02-01 does not; pack disabled by default and
  enabling it does not alter existing posture grades.

---

## Workstream 3 — Operating at 8× renewal volume (v0.11.x)

### WI-3.1 — Renewal digest (volume-shaped reporting)
- At 47-day lifetimes, per-event renewal noise becomes fatigue. Add a
  weekly/monthly renewal digest built on `cert_renewed` + WI-1.2: "N renewed
  on schedule, M overdue (list), K lifetimes shortened." Per-owner routing
  reuses the Plan 047 WI-A.2 owner-aware digest plumbing.
- **AC:** fixture week with mixed renewals produces one digest per owner with
  correct buckets; zero-activity weeks send nothing (no empty noise).

### WI-3.2 — Scan-cadence guidance finding
- A posture/ops finding when a host's scan interval is too coarse for its
  cert lifetime (interval > ~10% of lifetime ⇒ renewal/overdue detection
  lags). Finding only — no auto-retuning of the scheduler.
- **AC:** host with 7-day interval and a 47-day cert gets the finding; daily
  default never triggers it.

---

## Workstream D (carried) — AD CS spike, unchanged from Plan 047

WI-D.1 as specified in Plan 047 (timeboxed read-path spike against the lab
CA; findings doc in `plans/design/`; **no product code**). Unexecuted there,
still the right bet here — it is the durable post-window market per the
honesty clause. Nothing in Workstreams 1–3 depends on it; run it parallel
whenever a session has the lab available.

## Explicitly not in this plan

- **Renewal automation / ACME client** — cert-watch observes and warns; it
  does not hold issuance credentials. The closest this plan goes is WI-2.1's
  automation *inference* and the readiness report making the case for the
  estate to adopt automation. Positioning.md holds.
- **Plan 040/041/043** — decisions from Plan 047 stand (defer / decline /
  defer). Nothing here reopens them; WI-2.x deliberately builds on crt.sh
  reconciliation and SQLite as-is.
- **New collection infrastructure** — every feature above computes over data
  the scanner already stores. If a work item discovers it needs new
  collection, that is scope creep; stop and re-plan.

## Maintenance notes (not features)

- Regenerate `OPEN_BREADCRUMBS.txt` (stale, predates v0.7.x closes).
- BC-136 is in flight elsewhere — WI-2.2's page should get authed-E2E
  coverage under whatever harness that work lands.
- Update `docs/positioning.md` with the window thesis (one paragraph): the
  transition audience is concentrated, time-boxed, and exactly the manual
  self-hosted estate; post-window the value rests on the private-CA/AD CS
  story. Recording it prevents the next strategic review from re-deriving
  either the optimism or the pessimism from scratch.

## Release framing

| Release | Headline | Contents |
|---------|----------|----------|
| v0.11.0 | Ready for 47 days | WS-1 + WS-2 (thresholds, overdue, readiness report, policy pack) |
| v0.11.x | Scales with the volume | WS-3 + WI-D.1 findings absorbed |

Sequencing rationale: WI-1.1 first — it is a defect in the new regime, not an
enhancement, and smallest. WI-2.1 before 2.2/1.2 because both consume its
analytics module. The policy pack (2.3) rides the engine that just shipped
while its patterns are fresh. The readiness report is the headline because it
is the artifact that justifies the tool to the people who approve renewals —
and, candidly, the strongest portfolio piece: deterministic analytics over
collected evidence, honestly labeled inference, auditor-facing output.

## Decisions requested

1. **Readiness surface** — section within the existing compliance report
   (recommended: one auditor-facing artifact) vs a standalone page/export.
2. **WI-1.1 default change for short certs** — recommended as a documented
   behaviour change (current behaviour is regime-broken, not chosen); say if
   you want it opt-in instead.
3. **Milestone data source** — hardcode the SC-081 schedule (recommended;
   it's a published ballot, ships with the policy pack version) vs making the
   dates configurable. Configurable invites silent divergence from reality.
