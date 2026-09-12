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

## AC-07: Observation Freshness
Home must count the visible registered endpoints with current successful scans,
using effective host/scanned-leaf tags and excluding uploaded files. Current
means before the next configured daily/custom observation deadline and without
a later incomplete attempt. Overdue, unobserved, incomplete and unknown timing
remain distinguishable. Counts must include endpoints without certificates.

Browse must identify stale scan evidence per endpoint, including the individual
deployments of a grouped certificate. Details must show the last success, latest
attempt and outcome, observation deadline and next eligible attempt separately.
The scheduler and display must share cadence calculation; failed retries never
refresh the observation deadline. Uploaded files have no scan cadence.

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

Grouped certificate rows must apply effective-tag visibility to each endpoint
before computing group membership, counts, status and child details. Sharing a
fingerprint does not grant access to another deployment.

## AC-08: Endpoint Settings
The detail page permits authorized endpoint writers to edit scan cadence,
threshold and operator-reported renewal status through a CSRF-protected form.
Blank values restore daily cadence/automatic thresholds. Unchanged legacy
cadence values survive unrelated edits. The UI states the suppression/reset
effects of renewal reports; a report is not proof of observed replacement.
Writes are audited and wake the scheduler. Inactive expected-issuer storage is
read-only legacy information for administrators, with no monitoring promise.
