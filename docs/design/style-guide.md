# cert-watch UI style guide

**Status:** authoritative for all UI work as of 2026-07-13 (Plan 053).
This consolidates the settled design system (`plans/design/README.md` +
`src/cert_watch/static/css/tokens.css`) with the hard-won rules from
AGENTS.md's "UI definition of done", and adds the rules for Plan 053's new
components. When this file and an old template disagree, this file wins;
when this file and `tokens.css` disagree about a value, `tokens.css` wins
(values live in code, rules live here).

## 1. Foundations (settled — do not relitigate)

- **Fonts:** IBM Plex Sans (UI) + IBM Plex Mono, self-hosted in
  `static/fonts/`. **Mono is load-bearing, not decorative:** every cert
  identity, hostname, date, serial, fingerprint, and number is `.mono` /
  `--font-mono`. Numbers use `tabular-nums`.
- **Themes:** dark is default; light via `data-theme="light"` on `<html>`.
  Both themes are first-class — every change is checked in both.
- **Type scale:** page title 21/600 · section title 13.5/600 · body 13 ·
  table cell 12.5–13.5 · labels/sub 11–12 · stat value from `.cw-stat-val`.
  **Never below 11px.**
- **Spacing:** 4/6/8/10/12/14/16/18/22/26. Radius: 6/8/9/12
  (`--radius-sm/md/lg`). Page padding: `.cw-page-wrap` (22px 26px).
- **Icons:** inline SVG paths only (macro `macros/icons.html`), 24×24
  viewBox, `stroke="currentColor"`, stroke width ~1.7, no fill, no icon
  library.

## 2. Color: the budget rule

Semantic tones and what they are **reserved** for:

| Token | Meaning | Allowed uses |
|---|---|---|
| `--ok` | healthy / success | status pills, status dots, grade A, success confirmation |
| `--warn` | warning (7–29 days, degraded) | status only |
| `--crit` | critical (< 7 days, failure) | status only |
| `--expired` | expired | status only |
| `--accent` | interactive | links, focus rings, primary buttons, active nav/filter |

Rules:

- **Chrome stays neutral.** Panels, borders, labels, icons-as-decoration use
  `--text-*` / `--border*` — never a status tone.
- **Zero is not an alarm.** A count of 0 failures/expired renders in neutral
  tones, never red. Tone follows the *value*, not the metric's worst case.
- **Status color implies status meaning.** If something is green, it must
  mean "healthy" — not "this section is about certificates".
- Every status tone has a `--*-soft` translucent companion for fills; text
  on a soft fill uses the full-strength tone.

## 3. Urgency model (single source of truth)

Computed from days-until-expiry by `filters.compute_urgency`; templates use
the `urgency` / `urgency_tone` filters and `macros/urgency.html` — **never
re-derive thresholds in a template or JS**.

```
days < 0  → expired   (--expired)
days < 7  → critical  (--crit)
days < 30 → warning   (--warn)
else      → healthy   (--ok)
```

(no cert / not scanned → `gray`, neutral.)

## 4. Component inventory

Compose pages from these (all in `tokens.css`); if a new component is
needed, add it there + document it here in the same PR.

- **`.cw-panel`** — the only card/container. Tables live inside
  `.cw-panel.cw-table-wrap`.
- **`.cw-stat`** (in `.cw-stats` grid) — KPI tiles: label row, mono value,
  muted sub-line, optional tone accents. Stat cards acting as filters are
  links with `.cw-stat-active` for the applied state.
- **`.cw-pill`** — status dot + colored text; class = urgency bucket name
  (whitelisted in JS). Status only.
- **`.cw-chip`** — small bordered metadata tag (tones: `tone-warn`,
  `tone-crit`, `tone-accent`; variants: `san`, `more`, muted). See §5.
- **`.cw-table`** — the table; sortable headers via `.cw-sort-link`; row
  navigation via `.cw-row-link` (+ `tabindex="0"` and a `role`); hover-only
  actions in `.cw-rowact`.
- **`.cw-seg`** — segmented control for exclusive views/filters/tabs.
- **`.cw-toolbar` / `.cw-search`** — filter row above tables.
- **`.cw-btn`** (`primary` / `ghost` / `danger` / `sm`) — one primary action
  per view; destructive actions are `danger` + `confirm-form`.
- **`.cw-slide` + `.cw-slide-bg`** — right slide-over (452px) for intake
  forms and (Plan 053 Phase 3) the row peek panel. Dialog semantics: `role`,
  `aria-modal`, focus trap, Escape closes, focus returns to trigger.
- **`.cw-empty`** — icon tile + title + one-line hint. Every list/table has
  a designed empty state; empty-with-filters says so and hints at clearing.
- **`.cw-flash-error` / `.cw-flash-warn`**, **`.cw-health-banner`**,
  **`.cw-menu`**, **`.cw-breadcrumb`**, **`.cw-bar`** (expiry proportion),
  **`.cw-grade`** (posture letter, tone by grade).

### New in Plan 053

- **`.cw-timeline`** — the 90-day horizon strip (Triage). A `.cw-panel`
  containing a horizontal axis: today at 0%, ticks at 0/30/60/90 days,
  hairline in `--border`. Each expiring cert(-day) is a **marker**
  (`.cw-timeline-marker`) positioned `left: days/90 * 100%`, colored by
  urgency tone, sized up when it aggregates >1 cert of that day (count
  rendered inside). Markers are links (single cert → detail) or open the
  day's list (multiple). Ticks and labels are neutral; only markers carry
  status color. Empty window → `.cw-empty`, calm.
- **`.cw-queue`** — Triage work-queue sections. Each section is a
  `.cw-panel` with a header (icon + section title + neutral mono count) and
  rows: identity (mono) · reason-it's-here (plain words) · one action.
  A section that is empty is **not rendered** — the queue only shows work.
  All sections empty → one calm all-clear state for the whole queue
  (ok tone on the icon only).

## 5. Chips: the discipline rule

Chips caused the old row soup; the budget is now structural:

- **A table row may carry at most 2 chips**, and only for facts that change
  what the operator does *from the list* (e.g. `chain invalid`, `stalled`).
  Everything else (SANs, tags, owner, method, source, notes) belongs to the
  peek panel / detail page (Phase 3).
- Detail/peek surfaces have no chip budget — that's where enumerations live.
- Chip text is lowercase, ≤ 3 words, no punctuation; tone classes only when
  the *fact* is a warning/critical fact.
- Never re-implement chip overflow in JS. If a budget is exceeded, move
  data, don't truncate it.

## 6. Words on the screen

- Read every string rendered, in a browser, before calling it done. Shipped
  bug classes to check for: redundant prefixes ("4078expired 11 years ago"),
  missing pluralization ("1 hosts"), raw ISO timestamps with the `T` shown.
- Dates: ISO `YYYY-MM-DD` in mono for facts; relative strings
  (`relative_short`) for urgency context; timestamps formatted, never raw.
- Sentence case for titles, labels, buttons. No exclamation marks. Empty
  states state a fact plus at most one hint.
- Counts: "N cert{s}", "N host{s}" — pluralize; prefer words over
  arrow/slash shorthand.

## 7. Interaction & security constraints (hard)

- **CSP:** per-request nonce; **zero inline `on*=` handlers** (ratchet test
  `test_no_inline_handlers.py` enforces). Behavior binds via
  `data-action` + the delegated listener in `base.html` — or, from Phase 7,
  htmx attributes. The `data-action` dispatch switch may only shrink.
- All dynamic text through `escHtml`; urgency classes pass the whitelist.
- Every mutation is a POST with CSRF (`_csrf_token` field or
  `x-csrf-token`); destructive ones add `confirm-form` + `data-confirm`.
- New page routes copy the dashboard's auth + tag-scope pattern
  (`scope_tags_from_auth`); `/api/*` routes use `Depends(require_auth)` /
  `require_write`.
- Keyboard: everything clickable is reachable (real links/buttons, or
  `tabindex="0"` + role for rows); dialogs trap focus; tablists implement
  arrow-key WAI-ARIA navigation; `data-testid` on everything e2e touches
  (they are API — never rename casually).

## 8. Definition of done (per UI change)

1. View every changed page **populated and empty, dark and light**
   (seed: `tests/e2e/_seed.py`; look with Playwright MCP before committing).
2. Read the words (§6). Zero is not an alarm (§2).
3. Grep `tokens.css` for any utility class you used — an undefined class
   silently does nothing.
4. djlint + ruff + mypy clean; unit suite green; **run
   `pytest -m e2e tests/e2e -q --no-cov -n0` locally**; new tests seen to
   fail once.
5. State in the handoff what you did **not** verify.
