# Plan 049 — Maintenance Entry (close the surface, harden the floor)

**Status:** proposed 2026-06-11
**Author:** Fable 5 (fresh-eyes review + strategic discussion with operator)
**Strategic role:** the last *development* plan. Plan 048 shipped the SC-081
feature wave; the operator's verdict is that the surface is near complete and
development should move to maintenance. This plan is the work that makes that
switch defensible rather than declared. "Maintenance" here means **no new
surface** — not dormancy: SC-081 means demand and defect reports rise through
2027–2029, so the budget is defects, security, dependency updates, and the
date-keyed regime logic.

Ordering rationale: Phase 0 first because its outcomes can legitimately change
everything after it (an AD CS "yes" adds scoped surface; a "no" closes the
product). Phase 1 needs the operator/lab and can interleave with anything.
Phases 2–4 are sequential-ish but items within a phase are independent.

---

## Phase 0 — Decide (one lab session + one writing session)

The open product question. Do not start Phase 2 until this is decided — the
maintenance contract (Phase 4) can't be written around an undecided bet.

- **P0.1 — Execute WI-D.1 (AD CS read-path spike).** As specified in Plan 047
  and carried unexecuted through Plan 048: timeboxed, read-only against the
  lab CA, findings doc in `plans/design/`, **no product code**. Deferred twice;
  goes first now.
- **P0.2 — Record the decision.** Private-CA/AD CS story: in (minimal scoped
  version becomes the one sanctioned surface addition, planned separately) or
  out (written into positioning as a non-goal). Either answer is fine;
  no answer is not.
- **P0.3 — positioning.md window thesis.** The one-paragraph SC-081 window
  thesis Plan 048's maintenance notes called for (still missing as of
  2026-06-11), plus the P0.2 outcome.

## Phase 1 — Validate shipped features against reality (operator + agent)

Plan 048's analytics shipped fixture-validated only. Feature-complete ≠
feature-validated; this phase is the difference.

- **P1.1 — Upgrade the workplace install to v0.8.1** (operator). The published
  v0.8.0 tag has the WI-027 settings defect; 0.8.1 is the floor.
- **P1.2 — Readiness report + renewal analytics against the real estate.**
  Run `/readiness` and the automation-inference classification on the
  production estate; file one breadcrumb per wrong/misleading output. Fix the
  heuristics. (Inference heuristics are always somewhat wrong on first
  contact; this is expected, not failure.)
- **P1.3 — Verify WI-024 on the Windows VM.** The regression tests prove
  close-at-thread-exit; confirm the production symptom — `-wal` handle count
  stable under repeated CT refreshes on `mvmcitest01`.

## Phase 2 — Maintenance entry fee (the debt that never gets paid after the switch)

Maintenance means agents touch this code less often, with less context. The
code has to be safe to touch cold.

- **P2.1 — WI-031: settings.py decomposition.** Extract per-section
  sub-routers (mirror the BC-138 api.py decomposition); settings.py becomes a
  thin aggregator. It is the largest module and where UI defects concentrate —
  do it as one focused effort now rather than enforcing the
  extract-before-extend gate forever.
- **P2.2 — WI-025: bare-except triage.** File-by-file, **alerting, scheduler,
  scan, and SIEM paths first** — a monitoring tool that swallows its own
  errors fails silently for months in maintenance mode, which is worse than no
  monitor. Narrow to expected exception types; let programming errors surface.
  Re-rate from low: this is the highest-leverage reliability item in the plan.
- **P2.3 — WI-026: SSRF integration tests.** The scan/webhook IP-pinning
  boundary is currently proven by mocked urllib only. Real-socket TLS/SNI
  tests (the `@integration` marker + local TLS server pattern exists).
- **P2.4 — E2E: authed POST coverage for every settings form + `/readiness`
  page.** The WI-027 class (form wiring that unit tests can't see) has now
  shipped twice; the populated-baseline work closed the GET half, this closes
  the POST half. `/readiness` e2e was flagged in the 2026-06-11 reflection.

## Phase 3 — Boring operations (upgrades with no feature reward must be uneventful)

- **P3.1 — Real-database migration test.** Commit a sanitized v0.6.x-era
  database fixture; CI migrates it 0001→current and smoke-reads the dashboard
  queries. Fresh-schema tests don't catch what long-lived production DBs hit.
- **P3.2 — Exercise the backup/restore runbook once**, end to end, against a
  populated instance; fix the runbook where it lies.
- **P3.3 — Pin the SC-081 date-flip tests.** The policy pack changes behavior
  on 2027-03-15 and 2029-03-15 by design. Freeze-time tests on each side of
  both milestones, written now while the ballot schedule is fresh — nobody
  will re-derive it in 2029.
- **P3.4 — Define the dependency cadence.** A maintenance-mode security tool
  still answers CVEs: state the expectation (e.g. monthly `uv lock` refresh +
  trivy review; CRITICAL CVEs out-of-cycle) in AGENTS.md.

## Phase 4 — The maintenance contract (one hour; the brake that survives sessions)

- **P4.1 — AGENTS.md "Maintenance mode" section.** What gets in: defect
  fixes, security, dependency updates, SC-081 date-logic upkeep, doc
  truth-keeping. What doesn't: new surface (channels, providers, report
  formats, pages) without a plan that prices its own permanent maintenance
  cost. This matters more here than in human-maintained repos: the
  maintainers are rotating agents, agents default to adding, and the repo's
  docs are the only brake that survives session boundaries.
- **P4.2 — Close this plan in the plan-status list** and regenerate the
  work-item export. Maintenance starts when Phase 4 lands, not when someone
  feels done.

## Explicitly not in this plan

- New alert channels, auth providers, report formats, native PDF — the
  surface is at one-maintainer limits; that is the point of the plan.
- Postgres (Plan 043) — deferred decision stands; SQLite single-writer is a
  documented non-goal boundary.
- Renewal automation / ACME — positioning.md holds; cert-watch observes.
- Anything Phase 0 decides *against* — record and stop.

## Sequencing summary

P0 (decide) → P2 (debt) → P3 (ops) → P4 (contract), with P1 (real-world
validation) interleaved wherever the operator/lab is available. P0 and P1 are
the phases whose findings can change the rest — front-load them. Rough scale:
P0 two sessions, P1 operator-paced plus one session, P2 three–four sessions,
P3 two, P4 one hour.
