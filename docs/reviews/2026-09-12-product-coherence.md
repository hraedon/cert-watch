# Product coherence review — 2026-09-12

Reviewed the product, runtime wiring, evidence model, and operator UI from
`ea96f68e88465fc94a115faf038072b1bf484034`, the alert-routing evidence branch.
The changes are stacked on PR #25. The review used isolated checkouts and
synthetic databases; it did not inspect or modify a production database.

## Judgment

The useful core is a small self-hosted observability tool: find the endpoint
that needs work, explain the evidence, and reach the right owner. FastAPI,
server-rendered templates, SQLite, and the existing five-section navigation
fit that job. Replacing the stack or redrawing every page would not resolve
the defects found here. The costly decisions were duplicated definitions and
controls disconnected from runtime behavior.

This review therefore consolidates the definitions at their consumption
boundaries: scheduler configuration, scan eligibility, renewal eligibility,
readiness population, and inventory navigation. No runtime dependency,
database migration, authentication default, or report JSON shape changes.

## Reproduced problems and corrections

### Saved settings did not govern the running scheduler

The settings page replaced `app.state.settings`, while scheduled callbacks
retained the original immutable settings object and transport configuration.
A saved SMTP relay and daily scan time could appear effective in the UI while
the scheduler continued with the previous relay and time.

The scheduler now refreshes its settings and matching transport configuration
as one snapshot and wakes to recalculate its schedule. A job takes a stable
snapshot for its run. Environment overrides continue to take precedence.

### Per-host intervals and manual scan settings were bypassed

The scheduler context selected all registered hosts, bypassing the existing
due-host selector. Its wakeup calculation also ignored custom intervals after
the first successful scan. A fresh host configured for 72-hour scans was
scanned early; an hourly host could wait until the next daily boundary.

Selection and wakeups now use one due-time policy. Custom intervals follow
the latest successful scan; default hosts follow the configured daily UTC
boundary. Failed attempts retain a retry delay. Explicit manual scans remain
immediate and now forward the configured TLS-verification and drift options,
which the shared form/import handler previously omitted.

### Readiness confused absent observations with favorable evidence

A registered host with no certificate history disappeared from both the
report total and the unknown count. Separately, a certificate valid for 365
days but first observed five days before expiry could be presented as a
five-day certificate when its history row lacked an issuance timestamp.
That produced favorable margins and an inflated renewal workload forecast.

Readiness now starts from registered `(hostname, port)` endpoints, preserving
the report's host-tag visibility boundary. The current scanned leaf supplies
both validity and trust; historical analytics enrich renewal behavior only.
Missing observations or unusable dates remain unknown. Uploads and another
port's certificate cannot supply missing endpoint evidence.

The same inference also made three genuinely 365-day certificates look like
90-, 80-, and 70-day certificates, producing a false decreasing-lifetime trend
and an automated-renewal classification. Historical analytics now retains
only known validity durations, can recover missing dates from a later
observation of the same contiguous deployment, and marks incomplete lifetime
evidence as unknown. Rollback boundaries remain distinct. Integer day values
round up so a partial day cannot make a certificate appear under a validity
cap. The report qualifies inferred automation and identifies the coverage of
its current workload estimate.

### Notification state changed the apparent renewal condition

Home relied on a pending `renewal_stalled` alert. Marking that notification
sent or failed downgraded the unchanged endpoint from stalled to warning.
An already-resolved condition could also retain its pending alert.

Home and alert evaluation now share a read-only renewal-window predicate:
current leaf, within the configured window, no successor, and no recorded
renewal resolution. Alert evaluation owns notification creation and
deduplication; Home does not write alerts or interpret delivery as resolution.
Home additionally requires a monitored endpoint before calling a renewal
stalled. A static uploaded file retains its expiry status and replacement
guidance; an uploaded artifact alone cannot establish a renewal-process state.

### Summary cards and their destinations disagreed

Home showed two healthy certificates in the synthetic fleet, but following
Healthy opened an empty inventory. Home counted expiry alone; Browse also
considered trust. Grouping and filtered totals created additional count
ambiguity. Links corrupted search terms containing `&` and silently dropped
selected grouping or sort order.

Home now uses Browse's status definition and opens individual inventory
entries. Browse separates summary totals from the current status-filtered
result count. One URL builder encodes parameters and preserves the relevant
selection across sorting, filtering, and pagination. Search retains those
parameters; active filters have an explicit recovery action. Fleet pivots and
the calendar state their population instead of displaying ignored filters.
The separate expiry horizon retains its time-only meaning.

### Controls and labels promised behavior that did not exist

Per-group webhook inputs saved values that delivery never consumed. They are
removed from ordinary forms, while stored legacy values survive unrelated
edits and receive an explanatory notice. The active global alert webhook
remains in Channels. Copy now explains that matching-group recipients join
global SMTP recipients and that the webhook is a fallback after SMTP failure.

Revocation controls previously implied a revoked-status check. Their actual
operation checks OCSP/CRL endpoint reachability; labels, help text, and failure
messages now describe that operation without implying protocol validation.

## Remaining boundaries

Historical records without issuance dates can now produce fewer known
lifetimes and an unknown classification. No migration manufactures missing
evidence. This review does not establish that a configured renewal method is
running, that an HTTP-reachable responder returned a valid
revocation response, or that production notification destinations received
messages.

Local browser checks use a synthetic loopback preview with background jobs
disabled in that preview process. Automated receipt tests use local SMTP and
HTTP receivers. Final unit, type, template, browser, coverage, and exact-head
CI results belong in the pull request; runner visual baselines must come from
the GitHub Ubuntu artifact. Production release promotion remains separate.
