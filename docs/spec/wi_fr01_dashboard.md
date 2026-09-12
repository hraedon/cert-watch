# Interface Specification: FR-01 Dashboard

## Dependencies

- `interface_ref`: `database_layer`

## AC-01: Dashboard Route
`GET /` renders Home's attention queue and expiry horizon. `GET /browse`
renders the inventory. Legacy inventory query parameters on `/` redirect to
`/browse` while preserving the query.

## AC-02: Color-Coded Status
Each inventory row and its summary bucket use the same computed status:
- Expired: certificate validity has ended
- Critical: fewer than 7 days remain
- Warning: fewer than 30 days remain, or chain trust needs attention
- Healthy: at least 30 days remain and the chain is trusted
- Unknown: a pending endpoint has no certificate to evaluate

Home status cards use these definitions and link to individual inventory
entries whose total matches the card. Expiry-only horizons remain separate.
Status describes expiry and trust; posture grades describe the last TLS scan.

## AC-03: Sort by Urgency
The dashboard list must be sorted by days remaining ascending (most urgent first).

## AC-04: Display Fields
Each certificate row must show: hostname/port, subject, issuer, expiry date, days remaining.

## AC-05: Error State
If no certificates exist, the dashboard must display an empty-state message (not a server error).

## AC-06: Investigation Context
Inventory sorting, pagination, status filters, and search must preserve the
selected search text, source, grouping, and ordering where applicable. Query
values must be URL-encoded. Active filters must have a clear action. Summary
totals describe the search/source population independently of the selected
status bucket; pagination counts describe the displayed result set.

Fleet group views describe scanned endpoints and pending hosts; the calendar
includes scanned and uploaded certificates. Their links leave inventory
filters explicitly, and empty groups must not fall back to the inventory.
