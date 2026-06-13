# Prior art & positioning

cert-watch is not the first TLS-certificate monitor, and this document says so
plainly. The point of writing it down is to make the build-vs-adopt decision
**legible**: a reader should be able to see that the alternatives were surveyed
and understand why this exists anyway.

## Why this project exists

1. **All-in-one certificate observability for an SMB.** The purpose is to be the
   single self-hosted tool a small or mid-sized business can point at its whole
   estate and answer "is every certificate we depend on healthy?" — not just
   "what expires next." That means breadth in one unit: live host scanning **and**
   offline cert-file upload, read-only signature-verified chain validation, TLS
   posture grading, CT *reconciliation* (coverage gaps, not just lookup), and
   fleet-level analytics. An SMB otherwise assembles this from several
   single-purpose tools; cert-watch is the bundle.

2. **No external-SaaS dependency in the trust path, with first-class directory
   auth.** It runs self-hosted with no third-party cloud service in the trust
   path of a security tool, and treats LDAP/Entra authentication, an append-only
   audit log, and Windows/IIS hosting as first-class rather than out of scope.
   This makes it a natural fit for the more regulated / audited end of the SMB
   range, where a directory and an audit trail are non-negotiable — but the tool
   no longer presumes that environment.

3. **Origin (historical).** cert-watch began as a hand-/single-agent-built
   comparison point for
   [software-factory-2](https://github.com/hraedon/software-factory-2) — the same
   MVP spec produced without factory orchestration. That comparison still holds
   for anyone studying the build method, but it has been overtaken by the tool's
   actual use: it is now maintained as software people run, not as an artifact.

Reasons 1 and 2 are the identity. Reason 3 is how it got here, not what it is
for.

## Where the alternatives are genuinely better

Stating this is what makes the rest credible:

- **Uptime Kuma** — if you only need "alert me before a cert expires," it does
  that well, with a far larger community, and bundles general uptime monitoring.
  For simple expiry alerting it is the rational choice.
- **SSLMate Cert Spotter** — a battle-tested, focused CT-log monitor. For pure
  CT watch with nothing else, it is more proven than cert-watch's CT module.
- **Certimate** — if you want certificate *operations* (ACME issuance,
  deployment, renewal), that is a different and complementary tool.
- **Certsentry** — a single Go binary with an embedded frontend; if avoiding a
  Python runtime matters, that packaging is simpler.

cert-watch's claim is bounded: deep, read-only, all-in-one certificate
observability that an SMB can self-host, with directory auth and an audit trail
as first-class. It is not trying to beat Uptime Kuma's community or be a
certificate-lifecycle *automation* platform (issuance/renewal) — it observes the
lifecycle, it doesn't drive it.

## Landscape

| Tool | Primary domain | Live scan | Offline upload | Sig-verified chain | Posture grade | CT monitor | Dir. auth (LDAP/OIDC) | Audit log | No cloud dep | Stack |
|------|----------------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|------|
| **cert-watch** | cert observability | ✓ | ✓ | ✓ | ✓ | ✓ (lookup + reconciliation) | ✓ | ✓ | ✓ | Python / FastAPI / SQLite |
| Uptime Kuma | uptime (SSL secondary) | ✓ | — | — | — | — | — | — | ✓ | Node / Vue |
| Cert Spotter | CT monitoring | n/a | n/a | — | — | ✓ | n/a | — | ✓ | Go (CLI) |
| Certimate | cert operations (ACME) | — | — | — | — | — | — | — | ✓ | Go / React |
| Certsentry | cert monitoring | ✓ | — | ✓ | — | ✓ | — | — | ✓ | Go (single binary) |
| cw-agent | agent + cloud sync | ✓ | — | ✓ | — | — | — | — | ✗ (cloud) | Go agent |
| Doomsday / certwatcher | expiry warning | ✓ | — | — | — | — | — | — | ✓ | Go |

Legend: ✓ present · — not observed in the survey (not necessarily absent) ·
n/a not applicable to that tool's model. Star counts and feature sets are a
2026-Q2 snapshot (see the prior-art research); treat blanks as "undocumented at
survey time," not as a definitive claim of absence.

## Note on convergence

A near-functional clone (**Certsentry**) appeared in early 2026 with the same
core combination — host scan, dashboard, CT, alerts, SQLite. Independent
convergence on this feature set is evidence the niche is real and underserved,
not crowded. cert-watch's differentiation against it is the all-in-one breadth
an SMB wants without stitching tools together: directory auth + audit log +
posture grading + offline upload, on top of the shared core.

## How this informs the roadmap

**Delivered in 0.5.0** (the regulated-SMB differentiators this lens prioritized):
a one-click, tamper-evident **compliance/auditor report**; first-class **Teams /
Discord / PagerDuty** channels; **SIEM/log export** (syslog, Splunk HEC, Windows
Event Log) so cert-watch lands next to everything else a SOC already watches; and
a **renewal-stall alert** that catches a broken ACME/cert-manager job before
outage — observability of the *renewal automation* without becoming an ACME
client itself (the line stays "no external-SaaS dependency").

The positioning above is the lens for what we build next. Concretely:

- **Lean into observability depth and environment fit** — certificate change
  history & drift detection (plan 016), and the differentiators an audited SMB
  values: discovery (AD CS / Windows cert stores), revocation-endpoint health,
  and audit-grade reporting (plan 017).
- **Fold multi-channel alerting into alert groups** (plan 015) rather than
  treating it as a separate epic.
- **Deliberately decline** features that make an external cloud service a
  dependency, or that drift toward a different product class — external
  cloud-API discovery, reliance on a hosted CT-streaming feed, active network
  scanning, ACME renewal automation, and **private-CA / AD CS certificate
  inventory**. cert-watch observes public-trust TLS certificates; private-CA
  lifecycle management is a different product class (the CA itself already has
  an issuance log). (Self-hostable versions of some declined features stay on
  the table; the line is *no external-SaaS dependency*, not *no egress*.)
  Plan 017 records *why*, so the comparison stays legible.

## The SC-081 window

The CA/Browser Forum's Ballot SC-081 phases the maximum TLS-certificate
validity from 398 days (current) down through 200 days (2026-03-15) and 100
days (2027-03-15) to a final 47 days (2029-03-15). This is the one predictable
demand shock in the certificate-observability niche: every public-trust
certificate in an SMB's estate must be re-issued more frequently, and renewal
failures that were tolerable on a 12-month cadence become outages on a 47-day
one. cert-watch's SC-081 readiness report (Plan 048), lifetime-relative alert
thresholds, and per-host renewal-analytics are the specific response. The
window is 2026–2029: demand for renewal monitoring rises, cert-watch is
positioned for it, and the maintenance-mode plan (Plan 049) keeps the date-keyed
policy logic accurate through the milestone transitions without expanding the
product surface.
