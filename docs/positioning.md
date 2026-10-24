# Prior art & positioning

cert-watch is not the first TLS-certificate monitor. This page surveys the
alternatives and says why cert-watch exists anyway, so the build-versus-adopt
decision is visible.

## Why this project exists

1. **All-in-one certificate observability for an SMB.** cert-watch is the
   single self-hosted tool a small or mid-sized business points at its whole
   estate to answer "is every certificate we depend on healthy?", not just
   "what expires next." That takes breadth in one unit: live host scanning
   **and** offline cert-file upload, read-only signature-verified chain
   validation, TLS posture grading, and fleet-level analytics. Otherwise an
   SMB assembles this from several single-purpose tools. cert-watch is the
   bundle.

2. **No external-SaaS dependency in the trust path, with first-class directory
   auth.** It is self-hosted, with no third-party cloud service in the trust
   path of a security tool. LDAP/Entra authentication, an append-only audit
   log and Windows/IIS hosting are first-class, not out of scope. That suits
   the more regulated, audited end of the SMB range, where a directory and an
   audit trail are non-negotiable. The tool no longer presumes that
   environment.

3. **Origin (historical).** cert-watch began as a hand- or single-agent-built
   comparison point for
   [software-factory-2](https://github.com/hraedon/software-factory-2): the
   same MVP spec, produced without factory orchestration. The comparison still
   holds for anyone studying the build method, but real use has overtaken it.
   cert-watch is now maintained as software people run, not as an artifact.

Reasons 1 and 2 are the identity. Reason 3 is how it got here, not what it is
for.

## Where the alternatives are genuinely better

- **Uptime Kuma.** If you only need "alert me before a cert expires," it does
  that well, has a far larger community, and bundles general uptime
  monitoring. For simple expiry alerting it is the rational choice.
- **SSLMate Cert Spotter.** A battle-tested, focused CT-log monitor. For pure
  CT watch it is more proven than anything cert-watch offered. (cert-watch
  dropped its own CT monitoring before 1.0; see the changelog.)
- **Certimate.** For certificate *operations* (ACME issuance, deployment,
  renewal), it is a different, complementary tool.
- **Certsentry.** A single Go binary with an embedded frontend. If avoiding a
  Python runtime matters, that packaging is simpler.

cert-watch's claim is bounded: deep, read-only, all-in-one certificate
observability that an SMB can self-host, with directory auth and an audit trail
as first-class. It doesn't try to beat Uptime Kuma's community or to be a
certificate-lifecycle *automation* platform (issuance and renewal). It observes
the lifecycle; it doesn't drive it.

## Landscape

| Tool | Primary domain | Live scan | Offline upload | Sig-verified chain | Posture grade | Dir. auth (LDAP/OIDC) | Audit log | No cloud dep | Stack |
|------|----------------|:--:|:--:|:--:|:--:|:--:|:--:|:--:|------|
| **cert-watch** | cert observability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | Python / FastAPI / SQLite |
| Uptime Kuma | uptime (SSL secondary) | ✓ | — | — | — | — | — | ✓ | Node / Vue |
| Cert Spotter | CT monitoring | n/a | n/a | — | — | n/a | — | ✓ | Go (CLI) |
| Certimate | cert operations (ACME) | — | — | — | — | — | — | ✓ | Go / React |
| Certsentry | cert monitoring | ✓ | — | ✓ | — | — | — | ✓ | Go (single binary) |
| cw-agent | agent + cloud sync | ✓ | — | ✓ | — | — | — | ✗ (cloud) | Go agent |
| Doomsday / certwatcher | expiry warning | ✓ | — | — | — | — | — | ✓ | Go |

Legend: ✓ present · ✗ documented as absent (cw-agent depends on a cloud
service) · — not observed in the survey (not necessarily absent) ·
n/a not applicable to that tool's model. Star counts and feature sets are a
2026-Q2 snapshot (see the prior-art research); treat blanks as "undocumented at
survey time," not as a definitive claim of absence.

## Note on convergence

A near-functional clone (**Certsentry**) appeared in early 2026 with the same
core combination: host scan, dashboard, alerts, SQLite. Independent convergence
on this feature set is evidence that the niche is real and underserved, not
crowded. Against it, cert-watch differentiates on all-in-one breadth, without
stitching tools together: directory auth, audit log, posture grading and
offline upload on top of the shared core.

## What that means for the product

cert-watch 1.0 is the whole of that bundle, built to be run and maintained
rather than extended indefinitely. Its scope:

- **Observe everything about a certificate estate, read-only.** Scanning,
  uploads, chain validation, posture, drift, renewal tracking, compliance
  reporting.
- **Tell the right person, provably.** Routing by tag and ownership, a
  persisted delivery lifecycle, and evidence for every attempt.
- **Fit an audited environment.** Directory sign-in, role mapping and scoping,
  an audit log with SIEM export, Windows/IIS as a first-class host.

It deliberately declines anything that makes an external cloud service a dependency or turns
it into a different product:

- cloud-API discovery;
- a hosted CT-streaming feed;
- active network sweeps;
- ACME issuance and renewal automation;
- inventory of a private CA's issuance log.

The line is *no external-SaaS dependency in the trust path*, not *no outbound
traffic*; and *observe the lifecycle*, not *drive it*. The renewal webhook is
where observation hands off to automation you already run.

## The SC-081 window

The CA/Browser Forum's Ballot SC-081 phases the maximum TLS-certificate
validity down from 398 days (current) to 200 days (2026-03-15), 100 days
(2027-03-15) and finally 47 days (2029-03-15). It is the one predictable demand
shock in the certificate-observability niche. Every public-trust certificate
in an SMB's estate must be re-issued more often, and renewal failures that were
tolerable on a 12-month cadence become outages on a 47-day one. The window is
2026-2029: demand for renewal monitoring rises, and cert-watch is positioned
for it. Its response is the SC-081 readiness report, lifetime-relative alert
thresholds and per-host renewal analytics. The date-keyed policy pack
(`policy_packs/cab_forum_sc081.py`) is pinned by freeze-time tests at each
milestone, so it stays correct as the dates pass.
