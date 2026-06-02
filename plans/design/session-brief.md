# Claude Design — session brief (what to look at)

Companion to `plans/design/README.md` (the existing high-fidelity prototype +
tokens). That handoff already covers the **dashboard, certificate detail,
alerts, scan history, and the add-host/upload/bulk-import slide-over**. This
brief is the *gap list*: screens and states the prototype doesn't cover, feature
surfaces that shipped after it was made, and the cross-cutting constraints to
design within. Use it to decide where the session's time goes.

---

## A. Already designed — implement + reconcile (don't redesign)

The prototype is "final" for these. The work is recreating them in Jinja and
making sure they reflect the *current* data model:

1. **Dashboard table** — the headline change (clean CN + SAN chips, friendly
   issuer label, raw DN/serial/fingerprint moved to detail). Verify it covers
   the data we actually serve now: **fingerprint grouping** (host-count badge,
   expand/collapse), **fleet pivots** (`?view=issuer|owner|renewal_method`),
   **posture grade chips**, **owner chip + renewal status**, **tags**, and the
   **urgency pill** semantics. Pagination/sort/filter are SQL-backed now
   (`list_dashboard_page` / `list_dashboard_grouped_page`).
2. **Certificate detail** — posture findings, chain visualization, owner/renewal,
   runbook link. Check the prototype's chain UI matches signature-verified chain
   status (public/private/incomplete/invalid/self-signed).
3. **Alerts / scan history** — confirm the prototype handles the **drift alert**
   type (issuer change, key-size drop, SHA-1/TLS downgrade, grade drop) and the
   paginated lists.
4. **Add-host slide-over** — now also needs the **allowed-subnets** context
   (scanning a private host outside `CERT_WATCH_ALLOWED_SUBNETS` returns a
   specific error — design the error/empty state for "this range isn't allowed").

## B. Screens that exist but the prototype never covered — need design

These are live, server-rendered, and currently use ad-hoc/old styling:

5. **Settings page** (`/settings`) — tabbed Auth / SMTP / Alerts. "Test
   connection" / "send test email" result states, the env-var-override badge
   ("set via env var — GUI value ignored"), validation errors. This is where an
   operator configures LDAP/OAuth without restarting; it deserves real design.
6. **Setup wizard** (`/setup`) — first-run local-admin creation, now also asks
   for **allowed scan ranges** (CIDR field + help text). Design the wizard as a
   guided first-run, including the empty/guidance states.
7. **Audit log** (`/audit`) — append-only event table, filterable/paginated.
   Currently minimal. Decide the columns, filters, and how break-glass / failed
   events are visually flagged.
8. **Login** (`/login`) — provider-aware (LDAP form vs OAuth button vs local
   admin), error states, rate-limit message.

## C. Feature surfaces that are API-only today — decide if/how to surface

Real backend features with **no HTML screen** yet. The big design question is
which of these earn UI vs. stay API/report-only:

9. **Calendar / expiry timeline** (`GET /api/calendar`) — a renewal calendar or
   timeline is arguably the most operator-friendly view of "what's expiring
   when." Strong candidate for a real screen.
10. **Trends** (`GET /api/trends/tls-versions`, `/grades`) — fleet TLS-version
    and posture-grade trends over time. Charts? A small dashboard panel?
11. **CT reconciliation** (`GET /api/ct/reconciliation?domain=`) — "certs seen
    in CT logs for your domain that you're NOT tracking" (coverage gaps). A
    high-value security view with no UI today.
12. **Alert groups / routing** (`/api/alert-groups`) — team-based routing by tag.
    Currently JSON-only; decide whether it gets a management screen (likely a
    Settings sub-tab or its own page).
13. **CSV reports** (`/api/reports/inventory.csv`, `/expiring.csv`) — surface as
    download buttons somewhere obvious (dashboard header? reports menu?).

## D. Cross-cutting states & flows (easy to forget, cheap to get wrong)

14. **Empty states** — fresh install (no certs/hosts) should guide to first
    action (add host / upload / configure). Per-screen empties (no alerts, no
    audit, no scan history, no CT gaps).
15. **Read-only mode** (planned, BC-086) — design how the UI looks for a
    **view-only** user: mutation controls (add host, delete, scan-now, settings)
    hidden or disabled, with a subtle "read-only" indicator. The server 403 is
    the real gate; this is the cosmetic half.
16. **Unauthenticated / setup-required state** (planned, BC-083) — secure-by-
    default means a non-loopback instance with no auth will hard-redirect to
    setup or show a "configure auth" wall. Design that wall.
17. **Health banner** — the existing top-of-page banner (scheduler down, last
    scan failed, failed alerts). Fold into the new visual language.
18. **Error / loading / partial states** — scan-in-progress, scan-failed
    (yellow-warning not red-error, per current UX), pivot/group AJAX expand
    spinners, form validation.
19. **Light + dark themes** — both are in scope (tokens.css ships both). Toggle
    is in the top bar.
20. **Responsive / density** — infra operators often run narrow side-by-side
    windows; the table needs a sane narrow layout.

## E. Hard constraint for the implementer (don't design around it, design *with* it)

- **No inline event-handler attributes.** We want to re-enable a strict CSP
  (nonce-based `script-src`, no `'unsafe-inline'` — see BC-075), which **cannot**
  whitelist `onclick=`/`onchange=` attributes. The redesign should use
  `data-*` attributes + delegated `addEventListener` in a single nonce'd
  `<script>`, not inline handlers. Getting this right in the rewrite avoids a
  repeat of the regression that forced the CSP revert.
- **Server-rendered Jinja + vanilla JS only** — no React/SPA (prototype uses
  React only as a rendering medium). State lives in the URL (filters, sort,
  pivot, page).
- **Accessibility:** the chips/pills/grade colors must not rely on color alone
  (urgency + posture grade need text/iconography too).

## Suggested priority for the session

1. Land the prototype's dashboard + detail (the core, already-final designs) with
   the current data model + the no-inline-handlers pattern.
2. Design the **un-prototyped live screens**: Settings, Setup wizard, Audit, Login.
3. Decide + design the **highest-value API-only surfaces**: expiry calendar (#9)
   and CT reconciliation gaps (#11) are the two I'd push for.
4. Nail the **cross-cutting states**: empty states, read-only mode, setup wall.

## Open questions to resolve in-session

- Which API-only features become screens vs. stay reports? (calendar, trends,
  CT recon, alert groups)
- Is there a global nav/IA beyond the current top bar (Dashboard / Alerts / Scan
  history / Audit)? Where do Settings, Reports, CT recon live?
- Read-only mode: hide vs. disable mutation controls?
- Reports/exports: a dedicated menu, or contextual download buttons?
