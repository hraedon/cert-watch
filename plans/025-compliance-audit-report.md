# Plan 025: Compliance / Auditor Report

> **Status:** draft for review. Implements Plan 023 §D ("Compliance / Auditor
> Export"). Scoped as the **last feature of the current release** (after the
> security batch + Plan 022 adapters + Plan 024 coverage). Grounded in the code
> on `release/0.5.0`.

## Goal

A one-click, point-in-time **Compliance Report** an SMB can hand to a SOC 2 / ISO
27001 / PCI-DSS auditor: "here is the posture of every TLS certificate we
monitor, and here is what's being remediated." Aggregated, human-readable, and
**tamper-evident** (verifiable that it wasn't edited after generation).

This is the regulated-SMB differentiator — the thing none of the alternatives in
`docs/positioning.md` bundle.

## What already exists (build on, don't rebuild)

- **Posture grading** (`posture.py`): per-cert grade `A+/A/B/C/F` and `Finding`
  objects with `check`/`status`/`message` — RSA key size (<2048 → fail), EC keys,
  SHA-1 signature detection, TLS protocol version, chain completeness, HSTS,
  optional revocation reachability. **The compliance signals already exist per
  cert.**
- **Fleet aggregation**: `get_posture_grades_for_certs`, `list_fleet_pivot`,
  fleet-grade rollup, `list_grade_trends`, `list_tls_version_trends`,
  `list_calendar` (expiry).
- **Raw exports**: `/api/export/certificates.csv` (labelled "for compliance
  reporting"), `/api/reports/inventory.csv`, `/api/export/certificates.json`.

So this plan adds the **summary + remediation + signing layer** on top, not new
data collection.

## Non-goals

- Not a new posture engine — it reads stored posture, doesn't re-grade.
- Not continuous attestation / external trust — point-in-time, self-hosted.
- Not the audit *log* report (who-did-what); that's a possible appendix (see open
  questions), not the core.

## Report contents

1. **Header / provenance** — instance identifier, generated-at (UTC), scope
   (tag/filter applied, "all monitored certs"), total cert + host counts,
   cert-watch version.
2. **Posture summary** — grade distribution (count + % at A+/A/B/C/F) and the
   fleet grade.
3. **Compliance metrics** (the auditor's checklist), each as "N of M (X%)":
   - No SHA-1 signature (SHA-256+)
   - Strong key (RSA ≥ 2048 or ECDSA)
   - TLS ≥ 1.2 at last scan
   - HSTS present (443)
   - CAA present for the domain *(see CAA caveat below)*
4. **Remediation schedule** — certs expiring within 7 / 30 / 90 days, and every
   cert with a `fail` finding, each with the specific finding text and owner tag.
5. **Appendix (optional)** — the per-cert table (already the existing CSV).

## Rendering & export — the key decision

**No PDF library is in the dependency set** (jinja2 only). Options:

- **(Recommended) HTML report, print-optimized.** A `/reports/compliance` route
  renders a self-contained, print-CSS HTML page; the browser's "Save as PDF"
  produces a clean auditor PDF. **Zero new dependencies**, matches the SMB
  "minimal footprint" stance. Plus a **signed CSV** of the metrics + per-cert
  rows for spreadsheet ingestion.
- **(Deferred) Native server-side PDF** via `weasyprint` — nicer for emailing a
  scheduled report unattended, but pulls a heavy native dependency (cairo/pango).
  Defer behind an optional extra until there's demand for unattended PDF.

Ship HTML + signed CSV first; native PDF is a follow-on, not in this release.

## Tamper-evidence (makes "signed" real)

The point of an *auditor* export is that it can't be quietly edited. Mechanism:

1. Build a **canonical JSON** of the report data (sorted keys, fixed number
   formatting) — this is the signed artifact.
2. Compute `sha256(canonical_json)` and an **HMAC-SHA256 signature** using the
   app signing key (`SecurityContext.signing_key`, already persisted).
3. Stamp the HTML/CSV footer with: generated-at, content SHA-256, and the
   signature.
4. Add a CLI verifier: `cert-watch verify-report <file>` recomputes the hash and
   checks the signature, printing PASS/FAIL. (Mirrors the existing
   `cert-watch backup` / `hash-password` subcommand pattern.)

Caveat to document: rotating `CERT_WATCH_AUTH_SECRET` invalidates verification of
previously-issued reports (same trade-off already noted for sessions/kv in the
README). The report footer records which key epoch signed it if we want to get
fancy later; v1 just documents it.

## Slices

1. **Aggregation core** — a pure `build_compliance_report(db_path, scope) ->
   ComplianceReport` that reads stored posture + certs and computes the summary,
   metrics, and remediation buckets. Plus `GET /api/reports/compliance.json`.
   Golden-tested against a seeded fleet.
2. **HTML report view** — `GET /reports/compliance` (admin/auth-gated), print
   CSS, scope filter by tag. Links from the Insights page.
3. **Signed CSV export + verifier** — `GET /api/reports/compliance.csv` with the
   signature footer, and `cert-watch verify-report`.
4. **(Deferred)** native PDF via an optional `[pdf]` extra (`weasyprint`).

## Testing

- **Aggregation**: golden tests — a seeded fleet (mix of A+/F, SHA-1, RSA-1024,
  TLS 1.0, expiring soon) → asserted percentages and remediation buckets. Pure
  function, no I/O.
- **Signing**: round-trip — sign a report, mutate one byte, assert `verify-report`
  fails; unmutated passes.
- **Route**: auth-gating (anon/non-admin blocked), scope filter, content-type.

## Risks / decisions

- **CAA coverage data gap.** CAA is currently an on-demand lookup (`/caa-check`,
  `caa_check.py`), not stored per cert. "% CAA present" therefore needs either a
  stored CAA result (new column / periodic check) or computing it on-demand at
  report time (slow for large fleets). **Decision for v1:** mark the CAA metric
  "not collected" unless a stored signal exists, rather than block the report or
  do N live DNS lookups during an export. Storing CAA per scan is a small
  follow-on.
- **Signing key rotation** breaks old-report verification (documented).
- **Print-to-PDF vs native PDF** (see above) — recommend HTML-print for v1.

## Open questions

1. **Native PDF in this release or HTML-print-only?** (Recommend HTML-print; defer
   weasyprint.)
2. **Include an audit-log appendix** (recent privileged actions / logins from the
   `audit_log`) in the report, for the SOC 2 "access" control? Useful, but it's a
   different data source — could be a v2 section.
3. **CAA metric:** ship as "not collected" in v1, or add per-scan CAA storage now?
