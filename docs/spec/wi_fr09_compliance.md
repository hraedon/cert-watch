# Interface Specification: FR-09 Compliance Report

## Dependencies

- `interface_ref`: `posture`
- `interface_ref`: `database_layer`
- `interface_ref`: `certificate_model`

## AC-01: Report Generation

`build_compliance_report(db_path, scope_tag=, version=, commit=, signing_key=) -> ComplianceReport` must:
- Read all stored posture + certificates from the database.
- Compute grade distribution: count of A+/A/B/C/F certificates.
- Determine fleet grade: worst grade present (A+ only if all are A+; otherwise the worst actual grade).
- Compute compliance metrics:
  - No SHA-1: percentage of certificates without SHA-1
  - Strong key: percentage with RSA ≥ 2048 or ECDSA P-256+
  - TLS ≥ 1.2: percentage meeting TLS 1.2+ (using `tls_version_meets_1_2()`)
  - HSTS: percentage with HSTS present
  - CAA present: percentage with CAA records (from `scan_posture.caa_present`)
- Compute remediation buckets:
  - 7-day expiry: certificates expiring within 7 days
  - 30-day expiry: within 30 days
  - 90-day expiry: within 90 days
  - Failed posture: grade C or F

## AC-02: Report Export Formats

Three export routes must be available:

1. `GET /api/reports/compliance.json` — signed JSON with HMAC-SHA256 tamper-evidence signature.
2. `GET /api/reports/compliance.csv` — signed CSV with tamper-evidence footer (`---SIGNATURE---` block).
3. `GET /reports/compliance` — print-optimized HTML with CSS `@media print` rules.

## AC-03: Tamper-Evident Signing

- `sign_report(report, signing_key)` HMAC-SHA256-signs the canonical JSON representation of the report.
- `verify_report_signature(report_dict, signing_key)` returns `(ok, message)`.
- CLI `cert-watch verify-report <file.json>` re-checks the hash and signature (PASS/FAIL).
- The report includes `content_sha256` of the canonical JSON and `signature` as base64.
- Signature verification is independent of the report's `generated_at` timestamp.

## AC-04: Report Content

The report must include:
- `generated_at`: ISO 8601 timestamp
- `version`: cert-watch version
- `commit`: git commit hash
- `scope_tag`: optional tag filter (e.g., "production", "staging")
- `fleet_grade`: overall fleet grade
- `grade_distribution`: counts per grade
- `compliance_metrics`: list of `{name, pass_count, total_count, percentage}`
- `remediation`: list of `{bucket, certs: [{cert_id, hostname, subject, days_remaining, grade}]}`
- `signature`: HMAC-SHA256 signature as base64
- `content_sha256`: SHA-256 of the canonical JSON content

## AC-05: HTML Report

- Print-optimized with CSS `@media print` for clean PDF output.
- Includes all metrics, grade distribution chart, and remediation tables.
- Linked from the Insights page.
- No external dependencies (no `weasyprint` required); browser "Save as PDF" produces clean output.

## AC-06: Fail-Closed

- If the signing key is empty or the app isn't fully initialized, return HTTP 503 rather than signing with an empty key.
- `ComplianceReport` dataclass is immutable after creation.
