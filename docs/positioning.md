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
   posture grading, and fleet-level analytics. An SMB otherwise assembles this from several
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
  CT watch with nothing else, it is more proven than anything cert-watch offered.
  (cert-watch dropped its own CT monitoring before 1.0; see the changelog.)
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

| Tool | Primary domain | Live scan | Offline upload | Sig-verified chain | Posture grade | Dir. auth (LDAP/OIDC) | Audit log | No cloud dep | Stack |
|------|----------------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|------|
| **cert-watch** | cert observability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Python / FastAPI / SQLite |
| Uptime Kuma | uptime (SSL secondary) | ✓ | — | — | — | — | — | ✓ | Node / Vue |
| Cert Spotter | CT monitoring | n/a | n/a | — | — | n/a | — | ✓ | Go (CLI) |
| Certimate | cert operations (ACME) | — | — | — | — | — | — | ✓ | Go / React |
| Certsentry | cert monitoring | ✓ | — | ✓ | — | — | — | ✓ | Go (single binary) |
| cw-agent | agent + cloud sync | ✓ | — | ✓ | — | — | — | — | ✗ (cloud) | Go agent |
| Doomsday / certwatcher | expiry warning | ✓ | — | — | — | — | — | — | ✓ | Go |

Legend: ✓ present · — not observed in the survey (not necessarily absent) ·
n/a not applicable to that tool's model. Star counts and feature sets are a
2026-Q2 snapshot (see the prior-art research); treat blanks as "undocumented at
survey time," not as a definitive claim of absence.

## Note on convergence

A near-functional clone (**Certsentry**) appeared in early 2026 with the same
core combination — host scan, dashboard, alerts, SQLite. Independent
convergence on this feature set is evidence the niche is real and underserved,
not crowded. cert-watch's differentiation against it is the all-in-one breadth
an SMB wants without stitching tools together: directory auth + audit log +
posture grading + offline upload, on top of the shared core.

## What that means for the product

cert-watch 1.0 is the whole of that bundle, built to be run and maintained
rather than extended indefinitely. Its scope is:

- **Observe everything about a certificate estate, read-only.** Scanning,
  uploads, chain validation, posture, drift, renewal tracking, compliance
  reporting.
- **Tell the right person, provably.** Routing by tag and ownership, a
  persisted delivery lifecycle, and evidence for every attempt.
- **Fit an audited environment.** Directory sign-in, role mapping and scoping,
  an audit log with SIEM export, Windows/IIS as a first-class host.

It deliberately declines anything that makes an external cloud service a
dependency, or that turns it into a different product:

- cloud-API discovery;
- a hosted CT-streaming feed;
- active network sweeps;
- ACME issuance and renewal automation;
- inventory of a private CA's issuance log.

The line is *no external-SaaS dependency in the trust path*, not *no
outbound traffic*, and *observe the lifecycle*, not *drive it*. The renewal
webhook is where observation hands off to automation you already run.

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
positioned for it. The date-keyed policy pack
(`policy_packs/cab_forum_sc081.py`) is pinned by freeze-time tests at each
milestone, so it stays correct as the dates pass.
