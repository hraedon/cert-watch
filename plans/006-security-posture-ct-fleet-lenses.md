# Plan 006: Security Posture, CT Reconciliation, and Fleet Lenses

> Functional feedback from Opus: the scan data we collect is under-served.
> We throw away TLS handshake posture, we don't close the CT loop,
> we don't surface cadence or concentration risk, and alerts route by
> hostname instead of by meaning.

---

## Summary of what we're doing

| Area | What | Priority |
|------|------|----------|
| Inspect | TLS posture grade + policy lint on detail page | HIGH |
| Inspect | Revocation status (OCSP/CRL) — informational only | MEDIUM |
| Discover | CT reconciliation: inventory gap report | HIGH |
| Discover | CT mis-issuance / shadow-IT alerts | MEDIUM |
| Track | Renewal history timeline (already in Plan 005 Phase 3) | HIGH (in 005) |
| Track | Fleet calendar / expiry concentration view | LOW |
| Notify | Alert routing by owner/team + runbook (already in Plan 005 Phase 2) | HIGH (in 005) |
| Fleet | Dashboard lenses: by-issuer, by-owner, by-renewal-method pivots | MEDIUM |

---

## Phase 1 — TLS posture grade + policy lint (HIGH)

### Why

We already do the TLS handshake. We parse the cert's key type and signature
algorithm for the detail page, but we don't check:
- Protocol version (TLS 1.0–1.3 offered)
- Cipher suite strength
- OCSP stapling / must-staple
- HSTS presence
- Whether RSA key size is < 2048, or signature is SHA-1

These are all derivable from data we already have or can cheaply acquire during
the scan. A "B / TLS 1.0 enabled" chip next to a green expiry pill is exactly
the kind of thing that's invisible today.

### Design

**New module: `src/cert_watch/posture.py`**

```python
@dataclass
class PostureResult:
    grade: str               # "A+", "A", "B", "C", "F"
    findings: list[Finding]  # individual checks with pass/fail
    protocol_versions: list[str]  # e.g. ["TLS 1.2", "TLS 1.3"]
    ocsp_stapling: bool | None    # None = not checked
    hsts: bool | None
    must_staple: bool

@dataclass
class Finding:
    check: str      # e.g. "tls_1.0_enabled", "sha1_signature", "rsa_1024"
    status: str     # "pass", "warn", "fail"
    message: str    # e.g. "TLS 1.0 is enabled — consider disabling"
```

**Grade computation:**
- Start at A
- TLS 1.0 or 1.1 offered → drop to B
- SHA-1 signature → drop to C
- RSA key < 2048 bits → drop to C
- Validity > 398 days (CA/B forum limit) → warn (doesn't drop grade)
- Self-signed in production position → warn
- OCSP must-staple without stapling → warn
- No HSTS → informational (no grade impact)
- Missing intermediate (chain_status incomplete) → drop to B

**Protocol version detection:**
Extend `scan_host()` / `_scan_via_openssl()` to also capture the negotiated
protocol version from the SSLSocket (`ssl_sock.version()`) or from
`openssl s_client` output. Store in `scan_history` or a new
`scan_posture` table.

**Policy lint:** Purely data-driven from the Certificate object we already
parse — no network calls needed:
- SHA-1 signature algorithm
- RSA < 2048 / ECDSA < P-256
- Validity > 398 days
- Self-signed leaf

### Schema changes

**New table: `scan_posture`**

```sql
CREATE TABLE IF NOT EXISTS scan_posture (
    id TEXT PRIMARY KEY,
    cert_id TEXT NOT NULL,
    hostname TEXT,
    port INTEGER,
    grade TEXT NOT NULL,          -- 'A+', 'A', 'B', 'C', 'F'
    protocol_version TEXT,        -- e.g. 'TLSv1.3'
    ocsp_stapling INTEGER,       -- 1=true, 0=false, NULL=unknown
    hsts INTEGER,                -- 1=true, 0=false, NULL=unknown
    must_staple INTEGER DEFAULT 0,
    findings TEXT NOT NULL,      -- JSON array of Finding dicts
    scanned_at TEXT NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(id)
);
```

Alternatively, add posture columns to `scan_history`. The separate table
keeps scan_history lean and allows posture to be NULL for scans that
didn't check posture.

### UI: Detail page

Add a **"Security posture"** panel between the operational summary (Plan 005
Phase 2) and the SANs panel. Shows:

```
Security posture                    B
  ⚠ TLS 1.0 offered
  ⚠ SHA-1 signature algorithm
  ✓ RSA 2048 key
  ✓ OCSP must-staple
  — No HSTS header detected
```

The grade chip (`B`) appears next to the expiry pill in the header and on
the dashboard row.

### UI: Dashboard

Add a posture grade chip next to the status pill. Format:
`<urgency-pill> <grade-chip>` — e.g. `Healthy A` or `Warning B`.

Only show the grade chip when posture data exists for that cert (graceful
degradation for uploaded certs or scans before this feature).

### Implementation order

1. Create `posture.py` with `evaluate_posture(cert, protocol_version=None, ocsp_stapling=None, hsts=None)` → `PostureResult`
2. Add `scan_posture` table to `schema.py` + migration
3. Extend `_scan_host_once()` and `_scan_host_via_openssl()` to capture protocol version
4. Store posture result alongside the scan in `store_scanned()`
5. Add posture grade + chip to dashboard template
6. Add posture panel to detail template
7. Tests

---

## Phase 2 — Revocation status (MEDIUM)

### Why

A healthy-but-revoked cert is the scariest blind spot. Purely informational
for now — affects posture grade but doesn't generate alerts independently.

### Design

**New function in `posture.py`:**

```python
def check_revocation(cert: Certificate, chain: list[Certificate]) -> RevocationResult:
    """Check OCSP and/or CRL for revocation status.
    Returns RevocationResult with status: 'good', 'revoked', 'unknown'.
    Best-effort — network errors return 'unknown', not errors."""
```

This uses `cryptography`'s OCSP builder to construct an OCSP request from
the leaf cert's AIA extension, sends it, and checks the response. Falls back
to CRL URL from the CRL Distribution Points extension if OCSP fails.

**Only checked on explicit request** (button on detail page, or scheduler
config). Not checked on every scan — too slow and too many network calls.

### UI

On the detail page, add a "Check revocation" button that triggers an async
check. Result shows as a chip: `✓ Not revoked` / `✗ REVOKED` / `? Unknown`.

If revoked, drops posture grade to F regardless of other findings.

### Implementation

- Pure addition, no schema changes needed for MVP (result shown in real-time,
  not persisted initially)
- Future: persist last revocation check time + result in `scan_posture`

---

## Phase 3 — CT reconciliation (inventory gap) (HIGH)

### Why

`ct_lookup.py` and `ct_monitor.py` exist but only log "new cert found".
The highest-value CT use is the **inventory gap**: "CT shows 19 hostnames
under your domain; you're tracking 4." This turns CT from a lookup feature
into a coverage map.

### Design

**New function in `ct_monitor.py`:**

```python
def ct_reconciliation(db_path, domain) -> ReconciliationResult:
    """Compare CT log entries against tracked certificates.
    Returns:
      - tracked_hostnames: hostnames we're actively scanning
      - ct_only_hostnames: hostnames in CT but not tracked (gaps)
      - tracked_only_hostnames: hostnames tracked but not seen in CT (stale?)
    """
```

**New route: `GET /ct/reconciliation`**

Returns JSON (and a future HTML dashboard section) showing:
- Total CT results for each tracked domain
- Untracked hostnames found in CT
- Coverage percentage

### UI: Dashboard section

A small "CT coverage" stat card or detail section:
```
CT Coverage: 4 tracked / 19 found (21%)
3 untracked hostnames: api.staging.hraedon.com, ...
```

Each untracked hostname gets a one-click "Add host" button.

### Implementation

1. Extend `ct_monitor.py` with `ct_reconciliation()` function
2. Add reconciliation results to the scheduler's periodic run
3. Add `/api/ct/reconciliation` API endpoint
4. Dashboard: add a "CT Coverage" section (behind a setting, since
   it requires CT logs to be reachable)
5. Tests with mocked crt.sh responses

---

## Phase 4 — CT mis-issuance / shadow-IT alerts (MEDIUM)

### Why

"A cert for your domain was just issued by an issuer you've never used" or
"with a SAN you don't recognize" — strictly informational, never acting.

### Design

Extend `ct_monitor.py` to track known issuers per domain:

```python
def detect_misissuance(
    domain: str, ct_entries: list[CTEntry], known_issuers: set[str], known_sans: set[str]
) -> list[MisissuanceAlert]:
    """Flag CT entries with unknown issuers or unexpected SANs."""
```

A mis-issuance alert is written to the `alerts` table with
`alert_type = "mis_issuance"` and includes the CN, issuer, and SANs
that don't match any known pattern.

### Alert message format

```
[cert-watch] Mis-issuance alert: certificate for *.staging.hraedon.com
issued by Unknown Issuer (serial XXX) — not seen on any tracked host.
SANs: api.staging.hraedon.com, internal-staging.hraedon.com
```

### Implementation

- Requires the CT reconciliation infrastructure from Phase 3
- Add `alert_type = "mis_issuance"` to the alerts schema (already a freeform
  string column)
- Wire into scheduler alongside `run_ct_monitor()`
- Rate-limit: one mis-issuance alert per (domain, issuer, day) to avoid noise

---

## Phase 5 — Fleet-level dashboard lenses (MEDIUM)

### Why

The dashboard is per-cert today. Pivoting the same data gives concentration-risk
views for free. The most valuable pivots:
- **By issuer**: "12 certs depend on LE R12; that intermediate expires 2027-03"
- **By owner**: filter the dashboard to show only certs owned by a team
- **By renewal method**: "manual" certs need action; "cert-manager" certs don't

### Design

These are **dashboard view toggles**, not separate pages. Add a pivot/segment
control to the existing dashboard toolbar:

```
[All] [By issuer] [By owner] [By renewal method]
```

**By issuer:** Groups entries by `friendly_issuer(e.issuer)`. Shows a summary
table: issuer name → count, earliest expiry, worst urgency. Click expands to
filtered cert list.

**By owner:** Uses `owner_name` from the `hosts` table. Entries without an
owner show under "Unassigned".

**By renewal method:** Uses `renewal_method` from `hosts` table (added in
Plan 005 Phase 1). Groups: cert-manager, ACME, manual, unknown.

### Implementation

- Add pivot views to the dashboard route (`views.py`) with query params
  `?view=issuer`, `?view=owner`, `?view=renewal_method`
- Template: conditionally render the grouped view instead of the normal table
- Database queries: add GROUP BY + aggregate queries to `queries.py`
- Depends on Plan 005 Phase 1 (renewal_method field)

---

## Phase 6 — Fleet calendar / expiry timeline (LOW)

### Why

"Five certs expiring the same week is a risk even if each is green."
This is a visualization concern, not a data concern — we have all the dates.

### Design

A calendar/timeline view showing all cert expiries grouped by week/month.
Detects "renewal storms" — weeks with N+ expiries.

This is a **new route** (`GET /timeline`) or a toggle on the dashboard.

Implementation is lightweight:
- Query all leaf certs' `not_after` dates
- Bucket by ISO week
- Flag weeks where count ≥ threshold (default: 3)
- Render as a simple horizontal timeline or calendar heat strip

### Implementation

- New route and template
- No schema changes
- `queries.py`: `list_expiry_buckets(db_path, weeks_ahead=26)` → `{week_str: count}`
- Template: simple timeline strip with week labels and count badges
- Depends on Plan 005 Phase 1 for renewal_method overlay (optional)

---

## Phase 7 — Enhanced alert routing (partly in Plan 005)

### Why

The metadata layer (owner, team, renewal method, runbook) already exists
partially (owner_name, owner_email, owner_slack on hosts) and is being
extended in Plan 005. The missing piece is using these in alert routing
and dashboard filtering.

### What's in Plan 005 already

- `renewal_method` and `runbook_url` host fields (Phase 1)
- These flow into `owner_info` in `evaluate_all_certs()` in `alerts.py`
- Alert messages already include owner info

### What's new here

**Per-owner digest:** When `ALERT_DIGEST_ONLY=1`, group alerts by owner
and send one digest per owner/team instead of one global digest.

**Escalation tiers:** If an alert for a cert owned by team X hasn't been
acknowledged within N hours, escalate to a secondary contact (configurable
via host `owner_slack` or a new `escalation_hours` field).

**Audit snapshot export:** `GET /api/export/posture.json` — a read-only
JSON dump of the full fleet posture at a point in time. Useful for compliance.

### Implementation

- Extend `send_expiry_digest()` to group by owner
- Add `escalation_hours` column to `hosts` table (nullable int)
- Add scheduler task for escalation checking
- Add `/api/export/posture.json` endpoint querying `certificates` + `hosts` +
  `scan_posture` (Phase 1)
- Tests

---

## Phase 8 — Export fleet posture as CSV/PDF (LOW)

### Why

Compliance teams love point-in-time reports. "Fleet posture as of date" is
naturally read-only and great for audits.

### Design

Extend existing export infrastructure (`/api/export/certificates.csv`,
`/api/export/hosts.csv`) with:
- `/api/export/posture.csv` — current posture grades + findings per cert
- `/api/export/posture.json` — same data as JSON (for programmatic use)

PDF is a stretch goal — generates from the JSON/CSV with a simple template.

### Implementation

- Depends on Phase 1 (posture data)
- Add export routes alongside existing ones
- No PDF in v1 — JSON/CSV only

---

## Implementation order

| Phase | Priority | Depends on | Estimated effort |
|-------|----------|------------|-----------------|
| 1 | HIGH | — | Medium (new module + schema + scan changes) |
| 2 | MEDIUM | Phase 1 | Small (add to posture.py) |
| 3 | HIGH | — | Medium (extend ct_monitor + new route) |
| 4 | MEDIUM | Phase 3 | Small (alerts + mis-issuance detection) |
| 5 | MEDIUM | Plan 005 Ph 1 | Medium (dashboard views) |
| 6 | LOW | — | Small (new route + template) |
| 7 | HIGH* | Plan 005 | Small (extend existing alerts) |
| 8 | LOW | Phase 1 | Small (export routes) |

*Phase 7 relies on Plan 005's `renewal_method` field.

**Recommended sequence:** 1 → 3 → 5 → 4 → 2 → 7 → 6 → 8

Phase 1 (posture) and Phase 3 (CT recon) are independent and high-value.
Phase 5 (fleet lenses) depends on Plan 005's schema changes. Phase 4
(mis-issuance) builds on Phase 3. Phase 2 (revocation) is additive.
Phase 7 (alert routing) is a natural follow-on to Plan 005. Phases 6 and 8
are nice-to-haves.

---

## What we're NOT doing

- **Full SSL-Labs-style scanner** — we're not doing protocol version
  enumeration (checking all TLS versions 1.0–1.3 by connecting with each),
  cipher suite enumeration, or protocol downgrade detection. We capture the
  negotiated protocol and check cert-level findings only. A future iteration
  could add cipher enumeration if there's demand.

- **Active CRL/OCSP checking on every scan** — too slow and too many network
  calls. Phase 2 is on-demand only.

- **CT monitoring as a real-time push system** — we poll crt.sh on a schedule.
  Not subscribing to CT logs in real-time (would require a completely different
  architecture).

- **PDF report generation** — out of scope for now. JSON/CSV exports (Phase 8)
  are sufficient. PDF can be added later with a template engine.

- **Escalation tiers with PagerDuty/Slack integration** — Phase 7 adds the
  metadata layer for this, but actual integration with external services
  (PagerDuty, Slack, Opsgenie) is a separate project. Webhooks (already
  exist) are the handoff point.