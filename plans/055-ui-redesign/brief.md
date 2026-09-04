# cert-watch UI redesign brief — 2026-08

**Goal (owner's words):** "a tool that feels designed rather than one that has
accreted gadgets and doodads as functionality expanded." Architectural changes
permitted where they rationalize the UI; RBAC/tagging explicitly flagged as the
one area that *needs* it. No obligation to respect the current UI.

Companion docs in this directory (plans/055-ui-redesign/):
- `rbac-report.md` — full RBAC/tagging architecture findings (C1–C15)
- `ui-inventory.md` — full page-by-page inventory + accretion assessment

## Diagnosis (one paragraph)

The current `cw-` system was a real design — warm-charcoal instrument panel,
bronze seal accent, IBM Plex Mono for identities — built for a 5-screen app
(dashboard, detail, alerts, scans, add-host). Ten features later it has: a
7-item flat nav plus three orphan pages reachable only from a `|`-separated
link row inside another page's header; five disclosure mechanisms; two
segmented controls; two empty-state systems; four surfaces configuring alert
routing; three copies of the same section-header CSS in per-page `<style>`
blocks; a Status column carrying two unrelated dimensions (urgency + posture
grade); a Tags column of em-dashes next to "unassigned" owner chips (two
organization paradigms, neither earning its space); trust-anchor admin bolted
below the dashboard's pagination; and a base template that dispatches clicks to
~18 globals defined by whichever page happens to be loaded. The voice is good;
the system around it collapsed under scope growth.

## The three moves

### 1. Information architecture: 7 flat items → 4 domains

| Nav | URL | Absorbs |
|---|---|---|
| **Certificates** (home) | `/` | dashboard, pivots, expiry calendar (a grouping, not a page), team view (a scope filter, not a page) |
| **Posture** | `/posture` | crypto inventory, grade distribution, trends; compliance + SC-081 readiness become *generated report outputs* of this page |
| **Activity** | `/activity` | alerts, scan history, audit log — one operational timeline domain with tabs and ONE filter paradigm |
| **Settings** | `/settings/{section}` | one URL scheme; absorbs events page, trust anchors; access + routing sections rationalized |

Detail pages hang off Certificates: `/certificates/{id}` becomes ONE template
that degrades gracefully when no cert is stored yet (today: two templates
share the URL). Old URLs 301 to their new homes. `data-testid`s preserved
wherever the element survives.

Chrome: topbar keeps wordmark + 4 nav items + user + theme. NEW: a scope
indicator chip when the user's view is tag-scoped (fixes C12 — today scoped
users get zero indication their view is filtered).

### 2. RBAC/tagging: one paradigm, made honest

Tags become the single organizing concept with three explicit facets, shown
with one visual grammar everywhere: **label** (filter/group), **access** (who
sees / who edits, per-tag), **routing** (which alert groups match).

Backend work (rationalize, not rewrite):
- **Implement Plan 053 phases 1–3** (`role_tag_tiers` table, `may_write_tags()`
  at the existing `scope_write_denied` seam, role editor rows). Decision
  register was human-approved 2026-07-27. Makes "operator for prod"
  expressible (fixes C3).
- **Fix C9**: compliance report must filter on effective (cert ∪ host) tags
  like every other scope path — today it silently omits host-tagged certs.
- **C5, strict-defaults**: audit log + scan history currently leak fleet-wide
  data to scoped viewers; scope-filter scan history, admin-gate the audit log
  (it shows actor IPs and cross-scope actions).
- **Retire `/team`**: the email-keyed mechanism (roles.email ↔ hosts.owner_email)
  is local-users-only and permanently broken for IdP users. The page becomes a
  "my scope" filter on `/`. roles.email survives only as an alert-routing
  recipient field, relabeled as such.
- **Settings → Access**: one section presenting roles/users/API keys together;
  the role form stops implying tier and scope are independent (per-tag tier
  rows per 053). A **tag registry view** (Settings → Tags): every tag in use,
  count, which roles scope to it, which alert groups match it — because today
  renaming a tag silently revokes access and nothing shows that.
- **C1 (users.role_id inert)** — deepest issue: local users' role assignment
  confers no permissions (no role map → everyone is admin; role map → claim
  matching only). DECISION DEFERRED to implementation with code in hand;
  options: (a) resolve users.role_id directly in build_auth_context (union
  with role-map), keeping full-access fallback only when RBAC is entirely
  unconfigured; (b) keep behavior, make the UI stop implying otherwise.
  Lean (a) + prominent flag in the final report (AGENTS.md: auth-posture
  changes must be surfaced to the human).
- **C6 (API keys see whole fleet)**: surface it honestly in the API-keys UI
  ("keys are not tag-scoped") this pass; per-key scope tags are a follow-up.

### 3. Design system v2: keep the voice, rebuild the system

**Keep:** warm-charcoal + bronze seal identity, Plex Mono for identities/
numbers, dot+text status (no pills), instrument-strip stats, dark + light,
status color budget (ok/warn/crit/expired reserved for status; accent for
links/focus/active only; zero renders neutral).

**Rebuild:**
- tokens.css v2: tokens + ~20 components, no pixel-utility layer. Spacing via
  the 4px scale only. ONE toggle, ONE segmented control, ONE chip system with
  defined tones, ONE table recipe (numeric cells right-aligned everywhere),
  ONE empty state, ONE disclosure mechanism (native `<details>`), ONE
  inline-edit pattern, ONE destructive-action treatment (confirmed, always —
  user delete today lacks confirmation), ONE filter-bar pattern, ONE stat-strip
  macro, print styles in the sheet (not per-page `<style>` blocks).
- JS: `static/js/` modules (CSP already allows 'self') — a small core
  (theme, health poll, confirm, details-enhancement) + one file per page that
  needs it. Delete the base.html data-action → global-function registry.
- Charts (posture trends, calendar bars, meters): inline SVG with *attributes*
  (not style=) for dynamic values → drive `tests/test_no_inline_styles.py`
  ratchet to zero → drop `'unsafe-inline'` from `style-src` (the docstring
  says this is exactly what's blocking it).
- Jinja macros: page_header, stat_strip, filter_bar, chip, empty_state,
  drawer, section — used by every page; no copy-pasted stat markup.

## Verification contract (AGENTS.md)

- `pytest -m e2e tests/e2e -q --no-cov -n0` locally; update selectors where
  pages merged; re-baseline visuals (precedent: aa7bd5d).
- The embarrassment checklist per changed page: populated AND empty, dark AND
  light, read the words, zero-is-neutral, color budget.
- Break-the-code ritual for the 053 enforcement tests.
- Final summary states what was NOT verified.

## Out of scope

Plan 053 D3 (local-user M2M — explicitly deferred in the decision register),
ABAC, JSON roles API, tags-in-columns schema change, PostgreSQL, htmx/React
(vanilla JS + Jinja stays), per-key scope tags (documented instead).
