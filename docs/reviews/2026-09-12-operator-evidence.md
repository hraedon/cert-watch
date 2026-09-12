# Endpoint identity and operator evidence

Follow-up to the product-coherence review, authorized on 2026-09-12. Plan 055
records scope and qualification expectations.

## Correct endpoint, owner and certificate

A two-port reproduction showed an overdue event for port 443 entering the digest
for port 636's owner, with the other certificate's expiry. Renewal digests now
keep hostname and port together for ownership, current scanned certificate and
qualified historical analytics. Webhook enrichment uses the affected endpoint
and rejects conflicting ports. Missing/invalid legacy event ports are explicitly
unknown and unowned; no migration guesses their identity.

## Current observation versus latest attempt

Home, Browse and endpoint details now use scan evidence that distinguishes last
success, latest attempt, observation due time and retry eligibility. The same
cadence function serves scheduler selection and display. A failed retry cannot
make old evidence current. A successful record beyond the current clock, or
unusable timing, remains unknown.

Fleet coverage includes visible registered endpoints with no certificate and
excludes uploads. Grouped rows identify current observations across their visible
deployments. Integration review exposed a pre-existing scope leak: selecting an
authorized fingerprint expanded every endpoint sharing it. Scope filtering now
applies to leaves before grouping and again before materializing child details.
Uploaded certificates cannot enter a scanned group by sharing its fingerprint.

## Effective endpoint controls

The endpoint form edits cadence, alert threshold and operator-reported renewal
status without overwriting owner/contact/runbook fields. It preserves existing
legacy cadence values when unchanged and explains blank defaults. Successful
writes are scoped, CSRF-protected, audited and wake the scheduler.

An in-progress report suppresses new renewal-stalled notices. Complete additionally
suppresses new expiry notices until the next successful scan resets the report.
The UI states those consequences and does not equate an operator report with an
observed replacement. Expected issuers turned out to be inactive storage after
CT monitoring removal; existing values remain read-only and explicitly legacy
for administrators, rather than gaining an ineffective policy control.

## Notification explanations and retained observations

Each notification exposes its recorded triggering message/threshold. Delivery
attempts record a start before transport, then a separate outcome. A missing
completion stays unknown; a completion-write failure does not cause a second
send. SMTP relay acceptance and refusal are distinct from mailbox receipt.
Transport errors retain fixed categories and HTTP codes, not secrets, response
bodies, URLs, raw exceptions or message bodies.

Attempted recipients combine global addresses at send time with queued addresses.
Group matches describe configuration at that attempt; they do not manufacture
queue-time routing causation. Recipient/group details are restricted to admins;
other authorized viewers see only outcome summaries. Old records without evidence
remain explicitly unknown. Finished notifications with evidence survive routine
rescans under their original historical certificate reference and remain subject
to alert retention. Obsolete pending notifications keep the existing discard
behavior.

## Verification scope

Focused regressions were run red before their fixes. The freshness mutation
using latest-attempt time instead of last-success time failed its regression.
The browser persistence mutation acknowledged a save without writing it and was
caught by the editor round-trip test. New transport evidence is also checked with
local TLS/AUTH SMTP and HTTP receivers. Final full-suite and exact-head hosted
results belong in the pull request qualification record.

The first hosted source qualification at `777b7df` passed 2,926 unit tests
(one optional Patina-checkout skip), all nine module coverage floors and 24
transport receipt cases, with 91.69% Linux coverage. Local Windows qualification
passed 2,925 unit tests before the final API compatibility case, then that case
and its focused suite; local functional Chromium passed 81 cases. Windows total
coverage was 91.63%; its platform-specific LDAP/scan values did not meet the
Linux module floors, which were verified by the hosted Linux gate.

Ubuntu screenshots from e2e run `34703583382` were reviewed before adopting the
exact artifact bytes for Home, populated Home and the unauthenticated login
redirect. All three changes are the added Scan coverage panel. The login case
now explicitly asserts its Home destination; it is not a login-form baseline.
Final browser and deployment qualification is recorded on PR #27 at its final
revision rather than inferred from this first run.

The first Linux browser run exposed a test-harness race: a function-scoped unit
fixture replaces `time.sleep`, so the new endpoint fixture exhausted the shared
startup helper's polling loop before its subprocess could start. A fresh Linux
checkout reproduced both failures. The helper now uses a monotonic deadline and
an independent event wait, retaining startup logs and reaping failed children.
Endpoint editing and the other shared-helper access-control cases then passed
on Linux with the same dev/e2e extras as CI.

Interactive views use synthetic loopback fixtures with scheduling disabled in
the preview process. This work does not establish production deployment, real
directory authentication on the user's estate or production recipient receipt.
