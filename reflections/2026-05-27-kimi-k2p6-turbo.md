---
model: accounts/fireworks/routers/kimi-k2p6-turbo
datetime: 2026-05-27T17:10 UTC
project: cert-watch
---

# Session Reflection — 2026-05-27

**Work summary:** Merged the separate "Tracked hosts" and "Certificates" tables on the dashboard into a single unified, sortable list. Pending (unscanned) hosts now appear alongside scanned hosts and uploaded certs, with inline detail panels for chain/notes. Added server-side sorting by name, issue date, last scan, expiry, and days. Updated unit and E2E tests for the new DOM; installed Playwright system deps locally to get E2E running.

---

## On the project

cert-watch is a solid, compact FastAPI/SQLite app with good separation between the domain model (`certificate_model.py`), storage (`database.py`), and presentation. The spec-driven approach (one `wi_*.md` per FR) makes intent clear. The repo feels actively maintained — there are open breadcrumbs, a CI story, and even agent-notes integration.

After touching the dashboard, I think the biggest architectural tension is that the UI is still server-rendered HTML with full page reloads for almost every action (sort, filter, pagination, notes save, delete, scan-now). That was fine for the original MVP, but the new expandable detail panels and sortable columns are pushing the boundary of what’s comfortable without at least HTMX. A small amount of progressive enhancement would make the UX much snappier without turning it into a SPA.

The database layer is clean but SQLite-centric; if the project ever needs multi-writer deployment, the `Recreate` rollout strategy and WAL mode mentioned in AGENTS.md will become a bottleneck.

## On the work done

The unified-list change went smoothly. The trickiest part was not the template or CSS — it was making `list_unified_entries()` in `database.py` coherent. Merging three tables (hosts, certificates, scan_history) while preserving pagination, filtering, and the existing API contract took more care than expected. I ended up keeping `list_dashboard_rows()` alive for the REST API and building `list_unified_entries()` for the HTML view. That duplication is a mild code smell, but it avoids breaking external consumers of `/api/certificates`.

I’m confident in the data model change. I’m less confident in the E2E selector updates — they now rely on `.entry-summary td` and `.entry-group` classes, which will break again if the table structure changes. Adding `data-testid` attributes to key elements would be a cheap resilience win.

The CSS dark-mode fix (adding `--yellow-text` and `--yellow-border`) was a real bug I caught by inspection — those variables were referenced by `.badge.private` etc. but never defined in either theme. It’s a sign that the dark mode stylesheet hasn’t been thoroughly exercised.

## On what remains

**Obvious next steps:**
1. **Host-level notes** — The `hosts` table has no `notes` column, so pending hosts show a detail panel with metadata but no notes textarea. Users who click a pending host expecting to add a note will be surprised. Adding `notes` to `hosts` (and a matching `PATCH /api/hosts/{id}/notes`) would close this gap.
2. **AJAX/HTMX for sorting & notes** — Clicking a sort header currently round-trips the whole page. Swapping the table body via `fetch()` or HTMX would feel much faster.
3. **Dedicated detail page** — The inline detail panel works for 5–10 entries but gets cramped with long chains or verbose notes. A standalone `/entries/{id}` (or `/certificates/{id}` for uploaded, `/hosts/{id}` for scanned) page would scale better.

**Nice to have:**
- Bulk select/delete in the unified table (checkboxes + toolbar).
- Search across chain certificate subjects, not just leaf subject/issuer.
- Docker-based E2E runner so Playwright system deps aren’t a local machine concern.

## Gaps to flag

- **`database.py:782` `list_dashboard_rows()` vs `list_unified_entries()`** — Two similar functions. The REST API still uses the old one. If the API is meant to stay aligned with the dashboard, they should converge or `list_dashboard_rows` should include `kind` and `host_id` fields.
- **`database.py:scan_history JOIN`** — `list_unified_entries` fetches all of `scan_history` into Python and builds a dict. For large histories this is wasteful. A SQL `LATERAL` or correlated subquery per host would be more efficient.
- **Missing `data-testid` attributes** — E2E selectors rely on CSS classes: `.entry-summary`, `.entry-group`, `.badge.pending`. Adding `data-testid` to the summary row, detail panel, and action buttons would make the test suite far more resilient.
- **`tests/e2e/test_upload_and_host.py:107`** — The `test_add_host_creates_row` assertion uses `page.locator(".entry-summary td", has_text=hostname)`. This will match any cell containing the hostname substring. If the scan error message happens to include the hostname, it could match the wrong cell. Using `exact=True` or `data-testid` would be safer.
- **CSS variable gap** — `--yellow-text` and `--yellow-border` were missing from both light and dark themes. I added them, but there may be other undefined variables (e.g. `--yellow-text` is used in `.badge.private` and `.badge.self-signed` but the colors are inconsistent between light and dark).
- **`app.py:360-385` auth middleware** — The auth middleware checks `request.cookies.get(SESSION_COOKIE)` but does not rotate/regenerate the session on every request. That’s fine for now, but if auth becomes more heavily used, session fixation resistance should be considered.
- **`tests/e2e/conftest.py`** — The E2E server fixture spins up a subprocess with `sys.executable -m cert_watch`. It works, but it doesn’t expose stdout on failure unless the healthz loop times out. Capturing and printing stderr on any test failure would speed up debugging.
