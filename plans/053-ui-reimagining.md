# Plan 053 — UI reimagining: triage-first information architecture

**Status:** proposed 2026-07-13 — Phase 1 started same day (branch `ui/reimagining`)
**Strategic role:** The UI is an *inventory viewer that grew features*. The
operator's actual daily question is **"what needs my attention today, and what
breaks next if I do nothing?"** — and no page answers it. This plan reorganizes
the UI around that question without changing the visual language (the token
system from `plans/design/README.md` is settled and stays) and without
regressing the security posture (CSP nonce, no inline handlers, escHtml).

## Ground truth (2026-07-13)

- Flat 7-item nav: Dashboard / Alerts / Scan history / Insights / Team / Audit
  log / Settings. Readiness, Crypto, and Compliance are whole report pages
  reachable only via small text links in the Insights header.
- `/` is a paginated inventory table of *all* certs (healthy included) with
  urgency stat-cards as filters. Triage and lookup are interleaved; both suffer.
  A healthy estate still greets the operator with a table to scan.
- Renewal-stall detection (`renewal_analytics.detect_renewal_overdue`, emitted
  as `renewal_overdue` events + webhook) is the product's differentiator and is
  invisible in the UI except as an alert row and a method chip.
- No temporal visualization exists except the Insights calendar (a list of
  week rows with count chips). Cert lifecycle is fundamentally temporal.
- Table rows carry up to ~8 orthogonal dimensions as chips (chip soup);
  `capChips` JS hides overflow. Every dimension gets equal weight, so none has
  any.
- `base.html` has a hand-rolled `data-action` dispatch switch growing one
  `else if` per feature; dashboard.html carries ~290 lines of bespoke JS.
- `settings.html` is 1,205 lines with client-side tabs (WI-031 flags the
  backing route module too).
- Plan 052 (alert ack/snooze + escalation) is proposed and pre-1.0; this plan
  does **not** duplicate it — Phase 6 integrates it.

## North star

Four concepts instead of ten pages:

| Concept | Question it answers | Absorbs |
|---|---|---|
| **Triage** (home) | What needs me now / what breaks next? | new page + health + renewal stalls |
| **Inventory** | What do we have? Where is X? | current dashboard table, hosts, trust anchors |
| **Posture** | How healthy is the estate? | Insights + Crypto + Readiness + fleet grade |
| **Evidence** | Prove it (auditor face) | Compliance + Audit log + Scan history |

## Phasing

Ordered so every phase is independently shippable, additive first, and the
operator-visible URL changes are isolated into explicitly gated phases.

### Phase 1 — Triage page (additive; no URL or behavior changes) ← THIS SESSION

New route `GET /triage` + nav entry. Two elements:

1. **90-day horizon timeline** (`.cw-timeline`): horizontal axis, "today" at
   left edge, ticks at 0/30/60/90 days. Each leaf cert expiring in the window
   is a marker positioned by `days_remaining/90`, colored by urgency tone,
   clustered per-day (a day with n>1 certs renders one marker with a count),
   `title` tooltip with CN + date, click → cert detail. Pure server-rendered
   HTML/CSS — no chart library, no canvas.
2. **Work queue** (`.cw-queue`): sections in severity order, each only rendered
   when non-empty —
   - **Expired** (leaf certs, days < 0)
   - **Renewal stalled** (`detect_renewal_overdue` over hosts whose current
     leaf cert is within a 60-day window; shows days overdue + confidence)
   - **Critical** (days < 7)
   - **Failed scans** (hosts whose most recent `scan_history` row is `failure`,
     with the error and a Scan-now action for writers)
   - **Failed alert deliveries** (last 24h, links to `/alerts`)
   Each row: identity (mono), the *reason it's here*, and one next action.
   All-empty queue → a single calm "Nothing needs attention" state (ok tone on
   the icon only — zero is not an alarm).

Backend: new `src/cert_watch/database/triage.py` (pure query/assembly
functions, tag-scope aware like the dashboard) + a thin route in `views.py`.
No schema changes. No new dependencies.

Acceptance:
- Renders populated AND empty, dark AND light (AGENTS.md UI DoD; screenshots
  via Playwright MCP before commit).
- Tag-scoped users see only their scope (same `scope_tags_from_auth` path as
  the dashboard).
- Unit tests for queue assembly (each section: present, absent, scoped) that
  have been *seen to fail*; e2e smoke test with `data-testid` anchors.
- djlint/ruff/mypy clean; unit suite green; e2e run locally.

### Phase 2 — Home flip 🔒 GATED (URL semantics change — operator sign-off)

`/` becomes Triage; the inventory table moves to `/inventory`. All existing
query params (`?q=&urgency=&source=&view=&sort_by=…`) redirect
`/ → /inventory` when present, so bookmarks keep working. e2e selectors
updated. **Not started without explicit approval** (AGENTS.md: URL changes are
a surfaced decision). Rollback is a route swap.

### Phase 3 — Inventory row flattening + peek panel

One line per row: CN (mono) · expiry date + bar · urgency pill · grade. All
other dimensions (SANs, tags, owner, renewal method, chain status, source,
notes) move to a **peek panel** — the existing `.cw-slide` pattern opened by
row click, with "Open full page" linking to `/certificates/{id}`. Chip budget
on a table row: **2** (see style guide §Chips). `capChips` JS deleted. The
grouped-by-fingerprint expansion and pivots survive unchanged. Detail page
untouched.

### Phase 4 — Nav consolidation 🔒 GATED (URL changes)

Nav becomes Triage · Inventory · Posture · Evidence (+ Team, Settings on the
right). **Posture** = Insights tabs + Crypto + Readiness merged as tabs of one
page; **Evidence** = Compliance + Audit log + Scan history as tabs. Old URLs
301 to their new homes. This phase is mostly template moves — the routes and
queries already exist.

### Phase 5 — Renewal lifecycle as a first-class object

A pure function derives a lifecycle stage per (host, leaf cert):
`healthy → in-renewal-window → successor-observed → rolled-out`, with
`stalled` as the alarm branch (from `detect_renewal_overdue`). Rendered as a
compact pipeline on the cert detail page and a "Renewals in flight" section on
Triage (in-window certs that are *not yet* stalled — the watch list). Builds
only on existing `cert_history` + renewal analytics; no schema change
expected. This is the differentiator made visible.

### Phase 6 — Alert workflow integration (depends on Plan 052)

When Plan 052 lands ack/snooze, Triage splits "needs attention" from
"acknowledged/being-worked" and the queue rows gain an Ack action. No work
here until 052 ships its schema.

### Phase 7 — htmx adoption (progressive; replaces bespoke JS)

Vendor htmx into `static/` (self-hosted single file, CSP-compatible — it
executes no inline script; verify with the nonce policy + ratchet test).
Convert incrementally: scan-now (row swap, no full reload), pivot lazy-load,
note editing, health banner polling → `hx-trigger="every 30s"` partial.
Delete the corresponding `data-action` branches as each converts; the ratchet
is that base.html's dispatch switch only shrinks. **Flag before starting:** a
new vendored frontend dependency is a surfaced decision (no pip dep, but it's
new third-party code served to browsers).

### Phase 8 — Command palette

`Ctrl+K` / `/` opens a palette: fuzzy match over cert CNs, hostnames, SANs,
and page names; Enter navigates. One small endpoint
(`GET /api/search?q=` — auth-gated, tag-scoped, LIMIT 20) + one vanilla-JS
component (~150 lines, nonce-loaded). No library.

### Phase 9 — Settings decomposition (mechanical; pairs with WI-031)

`/settings` becomes routed subpages (`/settings/auth`, `/settings/alerting`,
`/settings/scanning`, `/settings/retention`) sharing a section nav; the
1,205-line template splits along the same seams as the route module refactor
WI-031 wants. No behavior change; env-override badges and test-connection
affordances keep working per section.

## Cross-cutting rules (all phases)

- **Visual language is frozen.** Everything composes from `tokens.css`
  components; new components (`.cw-timeline`, `.cw-queue`, peek panel) are
  token-native and documented in `docs/design/style-guide.md` (new, this plan).
- **AGENTS.md UI definition of done applies to every phase** — populated+empty
  × dark+light, read the words, zero is not an alarm, grep before using a
  utility class, color budget.
- **`data-testid` is API.** e2e selectors get added/updated in the same commit
  as the template change; run `pytest -m e2e` locally before push.
- **No security-posture drift:** CSP nonce discipline, `escHtml`, no inline
  handlers (ratchet test), CSRF on every mutation, `require_auth`/
  `require_write` dependencies — new routes copy the dashboard's auth/scope
  pattern exactly.
- **Push promptly** — every phase lands as its own PR; no local commit
  backlogs.

## Out of scope

- Alert ack/snooze semantics (Plan 052 owns it).
- Any scanning/alerting/analytics behavior change — this plan renders existing
  signals; it does not create new ones (Phase 5's stage derivation is a pure
  view over existing data).
- React/SPA/build step — explicitly rejected; the server-rendered no-build
  philosophy is a feature.
- Mobile-dedicated layouts (Phases 1+3 improve small screens as a side effect;
  a deliberate mobile pass is future work).

## Risks

- **Phase 1 renewal-stall recomputation cost:** `detect_renewal_overdue` is
  per-host with a few small queries; at SMB scale (≤ a few hundred hosts, and
  only in-window hosts are checked) this is fine on request. If an estate
  proves it wrong, cache per scan cycle (the scheduler already computes it).
- **e2e visual baselines** will churn in Phases 2–4; regenerate deliberately,
  never blindly.
- **The uncommitted WIP on main** (digest/alerts/events, ~630 lines, present
  2026-07-13) touches `views.py`; whichever lands second rebases. This plan's
  Phase 1 additions to `views.py` are one appended route — low collision risk.
