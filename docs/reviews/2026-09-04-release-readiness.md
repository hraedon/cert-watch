# Release readiness review — 2026-09-04

## UI assessment

This review treats cert-watch as an operator console rather than a certificate catalogue. The primary job is to answer four questions in order:

1. Which deployed endpoint needs attention?
2. Why, and how soon, will it affect service or trust?
3. How current and complete is the evidence?
4. What is the next safe action, and who owns it?

The resulting information model separates concepts that were previously easy to conflate. **Status** describes certificate expiry and chain trust. **Grade** is evidence from the last live TLS scan, not a property inferred from an uploaded certificate. Uploaded artifacts contribute to cryptographic inventory, while monitored endpoints contribute deployment, renewal, scan, and fleet-posture evidence. Home ranks actionable deployments; Browse supports investigation across the complete inventory; Posture aggregates evidence and makes its coverage limits explicit; Activity records alerts, delivery, scans, and audit events.

Release readiness is tracked by PR #24 and its final combined CI results. This document records the independent UI assessment and implemented corrections; it does not assert production readiness.

## Verified defects and implemented changes

### Mobile investigation was blocked by clipped data

At 390 px, Browse's table container measured 364 px wide with 751 px of scroll content, while the effective `overflow-x` was `hidden`. The Status and Grade columns were unreachable. The Posture crypto table had the same container-specificity problem, and its right edge extended to approximately 653 px.

The generic panel table container now permits horizontal scrolling at the mobile breakpoint. More importantly, Browse inventory becomes a compact card layout on small screens. Certificate identity, expiry date and remaining days, status, latest scan grade, source, tags, and the detail action remain visible together. The expiry cell now owns an internal two-column layout with a full-width horizon bar, preventing its date, relative time, and bar from competing as independent flex children.

### Navigation consumed the working viewport

The original mobile header wrapped the full primary navigation across multiple rows and occupied roughly 146 px before page content. It also left little capacity for scoped sessions and long authenticated usernames.

Small screens now use one compact section control that names the current section and opens an accessible primary-navigation menu. The desktop and mobile link sets do not duplicate test IDs. Long account names retain accessible text and a title without widening the header; scope text truncates within a bounded pill, and signed-in chrome collapses the decorative wordmark text when necessary. The content viewport begins after one header row.

### Menus and actions escaped the viewport

The Posture report menu began at approximately x=-34 px on a 390 px viewport. Activity's action group extended to approximately x=403 px. Menus now align and clamp within the viewport, while page actions wrap. Mobile attention actions remain visible without relying on hover.

### Home mixed artifacts with deployments

A shared certificate deployed to multiple hosts can have different owners, renewal methods, and scan outcomes. A certificate-level attention item hid those operational differences. Home now consumes per-deployment queue entries and uses each entry's computed urgency. Detail links lead to the affected certificate while endpoint, owner, renewal confidence, scan failure, and chain reason stay attached to the deployment that produced them. Uploaded artifacts retain certificate detail links but do not present host actions.

### Copy overstated evidence

“Healthy — no action needed” implied operational health when the value only described expiry. Browse now defines healthy certificate status as at least 30 days remaining with a trusted chain; Home keeps separate expiry-only statistics. Unknown, self-signed, incomplete, and invalid chains receive a warning floor without altering grades or trust decisions. Posture explains that uploaded files contribute to crypto inventory, while fleet grades and TLS trends require live host scans. Grade presentation is explicitly tied to the last TLS scan. Activity describes its actual domains, and actions that are provably no-ops in the empty state are disabled.

### Important actions lacked a clear affordance

Home used a chevron-only detail link, which made the next step difficult to identify. Attention items now expose a visible **Review** action. Browse mobile cards keep their action visible. Keyboard activation of linked rows and interactive descendants was reviewed and corrected separately in the shared interaction layer; the release suite should remain the gate for that behavior.

## Evidence

The first audit exercised Home, Browse, certificate detail, Posture, Settings, and Activity in empty and populated states at desktop and 390 px widths, in light and dark themes. The richer follow-up included dense synthetic attention and inventory geometry, an uploaded certificate, long authenticated identity text, and a scoped-session indicator. No live third-party scans were used.

Artifacts from the assessment are available in the local review environment:

- Initial broad matrix and measurements: `/tmp/cert-watch-release-ui-audit/`
- Implemented UI matrix: `/tmp/cert-watch-release-ui/`
- Reconciled integration matrix: `/tmp/cert-watch-ui-integration-shots/`
- Mobile contact sheet: `/tmp/cert-watch-release-ui/contact-mobile.jpg`
- Desktop contact sheet: `/tmp/cert-watch-release-ui/contact-desktop.jpg`

Browser regressions cover compact navigation and current-section identification, viewport-contained menus and actions, table overflow behavior, empty no-op actions, expiry-specific language, dense attention rows, long authenticated chrome, and expiry-cell geometry. Snapshot baselines were intentionally not updated locally; CI artifacts remain the source for baseline review.

## Remaining product improvements

These are candidates for later work rather than release blockers established by this review.

- **Unify the verdict around evidence.** Each endpoint should have one evidence-based verdict that combines expiry, trust, live posture, and evidence freshness without collapsing those dimensions into one unexplained color. The view should show the current scan age beside the verdict and distinguish “passing,” “failing,” and “unknown because evidence is stale or absent.”
- **Make evidence coverage inspectable.** Fleet summaries should expose how many endpoints were graded, when the oldest contributing scan ran, and which inventory entries are uploads only. This prevents a strong aggregate grade from implying complete estate coverage.
- **Shorten navigation labels if the information architecture grows.** The compact section menu fits the current five sections. Additional top-level destinations should trigger a naming and grouping review instead of making the mobile control wider or adding another header row.
- **Validate a real deployment path before release promotion.** Run an actual browser check against a benign deployed environment and exercise the live IIS pre-tag workflow. Synthetic fixtures verify layout and state transitions, but they cannot establish proxy headers, authentication integration, platform certificate stores, or IIS metadata behavior.

The design should continue to preserve the distinction between an observed artifact and a monitored deployment. New summaries or automation should always state their evidence source and age; otherwise they recreate the ambiguity this release removes.

## Backend and release corrections

- Inventory statistics now use the same computed urgency as displayed rows. Home retains separate expiry-only counts. Attention tracks individual deployments instead of borrowing the owner, chain, renewal method, or certificate link from a representative wildcard deployment.
- Renewal analytics retain `(hostname, port)` identity, preserve non-contiguous fingerprint reuse as separate deployment periods, and tolerate legacy history with no port. Readiness reports the latest observed lifetime rather than a historical median. Report/analytics JSON gains an additive `port` field; the single-host analytics API accepts a validated `?port=` selector. Omitted-port calls retain their legacy combined-host behavior; callers needing endpoint-specific results should supply the port.
- Overdue detection uses the start of the current deployment period on the exact endpoint. Event deduplication includes the port, preserves the 24-hour guard for legacy events without a port, and ignores malformed historical payloads without aborting the scan cycle.
- Tag suggestions use the existing effective-tag scope, matching visibility of certificate and host resources. This changes read filtering, not permissions or write policy.
- Readiness tolerates transient SQLite contention, but reports read-only/storage failures as degraded. Failed health queries no longer produce a healthy banner.
- Image publication now depends on CI, browser/visual checks, and deployment smoke for the exact commit. Semantic version tags trigger versioned image publication, must agree with package/fallback metadata, and cannot update deployment manifests or move `latest`. The Windows gate installs and verifies Web-AppInit while retaining the production install verifier.
- Digest configuration now describes a shared weekly window. Independent per-team send schedules remain unsupported. SMTP-first delivery with webhook fallback remains the tested behavior; configuring both does not promise duplicate delivery through both channels.

No SQLite migration, runtime dependency, version bump, or release tag is part of this change. Chain-aware inventory totals now compute validation over all matching rows; this improves agreement but adds work compared with expiry-only SQL counts. Large-estate performance should be measured before substantially expanding deployment size.

## Validation boundary

New regressions were observed failing without their corresponding fixes. Validation includes source/type/template checks, workflow actionlint, isolated execution of the actual version-tag shell, unit tests, browser interactions, and integration tests. Final counts and CI links are recorded in the pull request after its last update. Visual baseline changes must come from the GitHub Ubuntu artifact.

Live Windows/IIS upgrade/reboot, real production AD sign-in, outbound notification delivery, and production certificate scanning have not been exercised in this review. The configured real-AD checks remain opt-in; synthetic and hosted-runner checks do not substitute for these operator checks before release promotion.
