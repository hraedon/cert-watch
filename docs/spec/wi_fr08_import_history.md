# Interface Specification: FR-08 Bulk Import & Certificate History

## Dependencies

- `interface_ref`: `certificate_model`
- `interface_ref`: `database_layer`
- `interface_ref`: `tls_scan`

## AC-01: Bulk CSV Import

`POST /hosts/import` must:
- Accept a CSV file upload with columns: `hostname`, `port` (optional, default 443), `notes` (optional, BC-020).
- Validate each row: hostname must be a valid DNS name or IP address.
- Skip invalid rows and report them in the response.
- Add valid hosts to the database via `SqliteHostRepository.add()`.
- Return a summary: `{added: N, skipped: M, errors: [{row, reason}]}`.
- Accept `multipart/form-data` with a `file` field.

## AC-02: Certificate Upload

`POST /upload` must:
- Accept PEM, DER, CER, CRT, PKCS#12 (`.pfx`/`.p12`), and PKCS#7 (`.p7b`/`.p7c`) files.
- Extract leaf certificate and chain certificates automatically.
- For PKCS#12: prompt for password if the file is encrypted.
- For PKCS#7: extract all certificates from the signed-data structure.
- Store the leaf certificate and chain certificates via `store_uploaded()`.
- Return a redirect to the dashboard with the uploaded certificate highlighted.

## AC-03: Certificate History

`cert_history` table (migration 0009) must store:
- `cert_id`: reference to the certificate row
- `scanned_at`: timestamp of the scan
- `grade`: posture grade at the time
- `tls_version`: TLS version at the time
- `findings`: JSON of posture findings
- `issuer`: issuer DN
- `subject`: subject DN
- `not_after`: expiry date
- `key_size`: key size
- `signature_algorithm`: signature algorithm

History is recorded on every successful scan by `store_scanned()`.

## AC-04: Renewal Tracking

- `renewed_cert_id` column on `certificates` links a renewed certificate to its predecessor.
- `store_scanned()` detects renewal when a new certificate for the same hostname/port has a different fingerprint but the same subject.
- `evaluate_renewal_window()` checks if a certificate inside its renewal window has a successor.
- Renewal links are shown on the certificate detail page.
- `renewal_stalled` alert fires when a certificate is in its renewal window but has no successor (BC-027).

## AC-05: History Retention

- `CERT_WATCH_HISTORY_RETENTION_DAYS` (default 365) controls how many days of history to keep.
- `purge_old_history()` trims history older than the retention window.
- Retention purge runs at startup and daily.
- `0` disables retention (keep all history).

## AC-06: Host-Level Notes

- `hosts.notes` column (BC-020) stores free-text notes per host.
- `PATCH /api/hosts/{host_id}/notes` and form POST `/hosts/{host_id}/notes` update notes.
- Notes accepted via CSV import (`notes` column).
- Dashboard shows note chip in expandable host rows.
- Certificate detail page shows inline edit/save toggle for host notes.
- CSV export includes the `notes` column.
