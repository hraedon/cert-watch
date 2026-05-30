# Plan 005: Ops-Centric Certificate Detail Page

> "The page is a good certificate description but a weak operational tool."
> — Opus feedback

## Problem

The certificate detail page answers "what is this certificate?" thoroughly but barely
answers "what do I do about it?" Operational facts — who owns it, how it renews, its
renewal history, and misconfiguration severity — are missing or buried.

---

## Phases

### Phase 1 — Schema: add renewal_method + runbook_url to hosts (HIGH)

**Why:** These are the structured fields that replace the freeform Notes overuse.
Without them, the rest of the plan has no data to display.

**Changes:**

1. **`database/schema.py`** — add two columns to `hosts`:
   ```sql
   renewal_method TEXT NOT NULL DEFAULT ''  -- 'acme','cert-manager','manual',''
   runbook_url TEXT NOT NULL DEFAULT ''
   ```
   Add migration in `init_schema()` (same pattern as `owner_name` etc.).

2. **`database/repo.py`** — `HostEntry` dataclass: add `renewal_method: str = ""`
   and `runbook_url: str = ""`. Update `add()`, `get()`, `list_all()` to read/write
   them. Add `update_renewal()` method (or extend `update_owner()` to accept
   `renewal_method` and `runbook_url`).

3. **`database/queries.py`** — `list_unified_entries()`: add `renewal_method` and
   `runbook_url` to entries (from host_rows).

**Valid values for `renewal_method`:**
- `acme` — auto-renewed via ACME (Let's Encrypt, etc.)
- `cert-manager` — managed by cert-manager (Kubernetes)
- `manual` — human must act
- `""` (empty) — unknown / not set

---

### Phase 2 — Detail page: lead with operational context (HIGH)

**Why:** This is the single highest-leverage change. Right now the top of the page
is SHA-256 fingerprint and serial number. It should lead with ownership, renewal
method, and chain health.

**Current layout (left column):**
```
HEADER: subject_cn | Healthy pill
       Scanned chip | "scanned from host:port"
TIME REMAINING panel
SANs panel
Certificate details panel (SUBJECT, ISSUER, KEY, SIG, SERIAL, FINGERPRINT, ISSUED, LAST SCANNED)
Notes panel
```

**New layout (left column):**
```
HEADER: subject_cn | urgency pill
       Scanned chip | "scanned from host:port"

OPERATIONAL SUMMARY panel (new, top of left column)
  ┌─────────────────────────────────────────────────────┐
  │ Owner         platform-team                         │
  │ Renewal       cert-manager · auto-renews · no action│
  │               needed                                │
  │ Runbook       https://wiki/...  (link, if set)     │
  │ Last renewed  2026-03-27  (from renewal history)    │
  │ Chain         ⚠ incomplete — server missing          │
  │               intermediate(s)                       │
  └─────────────────────────────────────────────────────┘

TIME REMAINING panel (unchanged)

SANs panel (unchanged)

Certificate details panel — demote SUBJECT row (it repeats H1):
  - Remove SUBJECT row entirely
  - Keep ISSUER, KEY, SIGNATURE, SERIAL, FINGERPRINT (collapsible in future?)
  - Keep ISSUED, LAST SCANNED

RENEWAL HISTORY panel (new, see Phase 3)

Notes panel (unchanged, but now focused — not the only place for owner info)
```

**Right column (chain):** unchanged structurally, but the chain_status banner
for "incomplete" should use a warn/crit tone matching the top-level operational
summary.

**Route changes (`routes/certificates.py`):**
- Fetch host info (owner, renewal_method, runbook_url, renewal_status) from
  `SqliteHostRepository` when `hostname` is set.
- Pass `host` dict to template.
- Fetch renewal history (Phase 3).

**Template changes:**
- Remove duplicate "Healthy" pill (line 102-105 — the right-side pill in the
  time remaining panel; keep only the header pill).
- Remove SUBJECT row from certificate details (it's the H1).
- Add operational summary panel.
- Show `renewal_method` with human-friendly label + auto/manual indicator.
- Show chain_status as a prominent callout if "incomplete" or "invalid".

---

### Phase 3 — Renewal history timeline (HIGH)

**Why:** "A cert tracker lives on cadence" — showing that automation is actually
working is arguably the whole point.

**Query (`database/queries.py`):**
```python
def get_renewal_history(db_path, cert_id, limit=10):
    """Walk the replaces_cert_id chain backwards from this cert.
    Returns list of dicts: [{id, subject_cn, fingerprint, not_before, not_after,
    replaces_cert_id, created_at}, ...] oldest-first."""
```

Walk: start from `cert_id`, repeatedly query
`SELECT id, subject, fingerprint_sha256, not_before, not_after, replaces_cert_id, created_at FROM certificates WHERE id = ?`
following `replaces_cert_id` backward, up to `limit` entries. Then also check
forward: `SELECT id, ... FROM certificates WHERE replaces_cert_id = ?` to find
if this cert was itself replaced (so we know it's not the latest).

**UI — "Renewal history" panel (left column, after SANs):**
```
Renewal history
  ─── 2026-03-27  *current*   RSA 2048 · FP: a3:f2:...
  ─── 2025-12-28  renewed     RSA 2048 · FP: 7b:c1:...
  ─── 2025-09-29  renewed     RSA 2048 · FP: 4e:8d:...
                                  ↑ every ~90d, on schedule
```

Each entry is a small timeline node (reuse chain-node CSS). Include:
- Date (not_before or created_at, whichever is more useful)
- Fingerprint (truncated, 8 chars)
- "current" label for the active cert
- Link to that cert's detail page

If renewal history is empty (single cert, no `replaces_cert_id`), show a muted
"No renewal history" message.

---

### Phase 4 — Incomplete chain = top-line severity (MEDIUM)

**Why:** "Server did not send intermediate(s)" is a real misconfiguration that
breaks some clients, but it's a soft footnote at the bottom of the right rail.
For a cert tool it's a primary finding.

**Changes:**

1. **Detail page header:** If `chain_status == "incomplete"` or `chain_status == "invalid"`,
   override the urgency pill. Currently urgency is computed from days_remaining.
   Add a secondary "Chain issue" indicator in the header:
   ```
   subject_cn | Critical pill | ⚠ Incomplete chain
   ```

2. **Dashboard:** In `_build_dashboard_rows()`, when `chain_status` is "incomplete"
   or "invalid", consider promoting urgency. At minimum, show a visible
   chain-status chip in the cert row. Currently "incomplete" shows as a chip
   alongside "public" — make it more prominent (use `cw-chip-incomplete`
   which is already styled in warn colors).

3. **Template:** In the chain banner section, for "incomplete" status, change
   the banner to use crit tone instead of warn tone. The icon should be
   `alert` (already), but the background should be more prominent.

**No schema changes needed** — `chain_status` is already computed at query time
from `chain_status()`.

---

### Phase 5 — Validity bar "now" marker (MEDIUM)

**Why:** The gradient fill shows elapsed-vs-remaining but has no "today" marker,
so you can't tell at a glance where you are in the validity window.

**Change in `certificate_detail.html`:**
Add a thin vertical line/marker at the "now" position on the validity bar.
The bar currently uses `width:pct%` fill. Add an absolutely-positioned marker:

```css
.cw-validity-now-marker {
  position: absolute;
  top: -2px; bottom: -2px;
  width: 2px;
  background: var(--text);
  border-radius: 1px;
  z-index: 2;
}
```

The position is the same `pct` already computed. Place it relative to the
`.cw-validity-bar-track`.

---

### Phase 6 — Small detail fixes (LOW)

**6a. Duplicate Healthy pill.** The detail page shows the urgency pill twice:
once in the header (line 52-55) and once in the time-remaining panel (line 102-105).
Remove the second one (inside the time-remaining panel, keep only the days count).

**6b. Download button clarity.** Change the "Download" button text to
"Download PEM" or add a small dropdown: "Download ▼" → "Leaf PEM" / "Full chain PEM".
Minimum: change label to "Download PEM" to remove ambiguity.

**6c. SUBJECT row removal.** Covered in Phase 2 — the H1 already shows
`subject_cn`, so the full SUBJECT row in certificate details is redundant.
Remove it or collapse it into the ISSUER row (show `CN=…` as a subtitle under
the H1 and keep only `ISSUER` in the details grid).

---

### Phase 7 — Dashboard chip hard limit (LOW)

**Why:** On a messier dataset than four healthy certs, the cert cell stacks
`public / incomplete / renewed / renewing / owner + two SANs + "+N more"`.
That gets noisy fast.

**Change:** In `dashboard.html`, cap visible chips per row at 4. After 4, show
`+N more` as a single muted chip. Priority order for which chips to keep:
1. urgency-status chips (incomplete, invalid)
2. renewal chips (renewed, renewing)
3. source chip
4. owner chip

No schema changes; purely template logic.

---

### Phase 8 — Light theme verification (MEDIUM)

**Why:** Opus flagged this and it's a regression risk.

**Action:** Manually verify (or write an E2E visual test for) each of these
in light mode:
- Chain banners (ok/warn/crit/incomplete/self-signed)
- Pills (healthy/warning/critical/expired)
- Validity gradient bars
- Stat cards
- All chip variants

No code changes expected unless regressions are found.

---

### Phase 9 — CSS cleanup strategy (LOW, ongoing)

**Why:** ~150 single-purpose utility classes with no scale. The right move is
tokens + components as the system; utilities as escape hatch.

**Strategy** (not a single PR — ongoing):
- Don't add new single-purpose utility classes.
- When touching a component, extract repeated utility combos into a component
  class (e.g., `.cw-detail-row` instead of `.cw-flex .cw-items-center .cw-gap-8`).
- The existing utilities stay (they work), but new UI should prefer component
  classes or CSS custom properties.
- Document this convention in AGENTS.md.

No immediate PR — just a convention shift, enforced in review.

---

## Implementation order

| Phase | Priority | Scope | Estimated effort |
|-------|----------|-------|-----------------|
| 1 | HIGH | Schema + repo changes | Small (1 file) |
| 2 | HIGH | Detail page restructure | Medium (template + route) |
| 3 | HIGH | Renewal history query + UI | Medium (queries + template) |
| 4 | MEDIUM | Chain severity promotion | Small (template + minor route) |
| 5 | MEDIUM | Validity "now" marker | Small (CSS + template) |
| 6a-c | LOW | Small detail fixes | Small (template tweaks) |
| 7 | LOW | Dashboard chip limit | Small (template logic) |
| 8 | MEDIUM | Light theme verification | Manual or E2E |
| 9 | LOW | CSS strategy | Ongoing convention |

**Recommended sequence:** 1 → 5 → 6a → 6b → 6c → 2 → 3 → 4 → 7 → 8 → 9

Phases 1 and 6 are quick wins. Phase 2-3 are the meat. Phase 4 follows naturally.
Phase 5 can ship independently. Phase 8 is verification. Phase 9 is long-term.

---

## What we're NOT doing from Opus's feedback

- **"Decide what the dashboard's first answer is"** — Already done. Default sort
  is `days` ascending (= expiry soonest-first). The urgency segmentation is
  prominent.

- **Full UI redesign** — The bones (palette, chain viz, pills, Plex pairing)
  are good. We're adding operational context, not re-skinning.

- **Collapsible crypto details block** — Good idea for a future iteration; not
  in this pass. Keep it in mind for Phase 9 iterations when the detail page
  gets long enough to warrant progressive disclosure.