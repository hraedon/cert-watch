# Interface Specification: FR-07 Certificate Transparency & Discover

## Dependencies

- `interface_ref`: `tls_scan`
- `interface_ref`: `database_layer`

## AC-01: CT Log Lookup

`ct_lookup.query_crtsh(hostname: str) -> list[CTEntry]` must:
- Query crt.sh (or configurable `CERT_WATCH_CT_LOG_URL`) for certificates by hostname.
- Return entries with: `issuer`, `not_before`, `not_after`, `serial`, `fingerprint`.
- Use a short-TTL cache to avoid repeated lookups.
- Apply a dedicated rate limit on `/api/ct/reconciliation`.

## AC-02: CT Reconciliation

`ct_monitor.run_ct_monitor(db_path) -> dict` must:
- Query crt.sh for every tracked host domain.
- Compare CT-observed certificates against tracked certificates.
- Surface: certificates seen in CT but not tracked, and tracked certificates with CT discrepancies.
- Store reconciliation results in `ct_reconciliation` cache table.
- Run off-thread during Discover page render (don't block page load on live crt.sh calls).

## AC-03: Discover Page

`GET /discover` must render:
- **CT Coverage Reconciliation**: hostnames seen in CT but not tracked, with "Add to monitoring" action.
- **Private-CA Inventory**: hosts whose trust anchor is a user-uploaded CA (not a public root), using `scan_posture.chain_status` (BC-100).
- **CT Mis-issuance Detection** (BC-151): when a tracked hostname's scanned certificate has a different issuer or fingerprint than CT shows, render "Potential mis-issuance detected" table with scanned vs. CT issuer.
- **CT Issuers — First Seen** (BC-151): per-issuer first-seen dates from `ct_issuer_first_seen` table.
- "Reconciling…" / "Updated Ns ago" indicator when data is stale or being refreshed.

## AC-04: Mis-issuance Detection

- `CTMisIssuanceResult` dataclass: `hostname`, `scanned_issuer`, `ct_issuer`, `scanned_fingerprint`, `ct_fingerprint`, `first_seen`.
- First-seen dates captured in `ct_issuer_first_seen` table (migration 0018).
- Mis-issuance table only shown when a real discrepancy exists (not empty stubs).

## AC-05: Private-CA Detection

- No longer uses hardcoded issuer name fragments (`NOT LIKE '%Let%'`).
- Queries `scan_posture.chain_status` which stores the actual cryptographic trust decision ("private" when anchored by a user-uploaded trust anchor).
- Migration 0016 added `chain_status` to `scan_posture`.
- `discover.html` queries `scan_posture` for private-CA hosts.

## AC-06: Auto-Discovery (Deferred)

- Auto-Discovery (Plan 041) is not yet implemented. The Discover page is read-only reconciliation.
- The spec for auto-discovery (DNS zone enumeration, ADCS enumeration, CT-based hostname finding) is deferred to a future release.
