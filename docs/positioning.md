# Prior art & positioning

cert-watch is not the first TLS-certificate monitor, and this document says so
plainly. The point of writing it down is to make the build-vs-adopt decision
**legible**: a reader should be able to see that the alternatives were surveyed
and understand why this exists anyway.

## Why this project exists

1. **It started as a controlled build-method experiment.** cert-watch is the
   hand-/single-agent-built comparison point for
   [software-factory-2](https://github.com/hraedon/software-factory-2): the same
   MVP spec, produced without factory orchestration. The artifact *is* the
   point — adopting an off-the-shelf tool would have produced zero signal about
   the build method. This is the primary reason and it is independent of any
   feature comparison.

2. **It targets a regulated, directory-centric, self-hosted environment.** The
   intended home is an audited Active Directory shop that will not make a
   third-party cloud service a dependency in the trust path of a security tool.
   (This is a governance choice, not a network constraint — the environment has
   egress; it just declines external-SaaS dependencies.) That makes a specific
   combination first-class: LDAP/Entra authentication, an append-only audit log,
   no dependency on an external cloud service, and Windows/IIS hosting. Most of
   the prior art treats one or more of those as out of scope.

3. **It goes deep on certificate *observability* specifically.** Read-only,
   signature-verified chain validation; TLS posture grading; CT *reconciliation*
   (coverage gaps, not just lookup); offline cert-file upload; and fleet-level
   analytics — bundled in one self-contained unit.

Reasons 1 and 2 are the durable ones. Reason 3 is true today but is the kind of
depth a competitor can close, so it is a supporting argument, not the identity.

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

cert-watch's claim is narrow: deep, read-only certificate observability inside
an audited, directory-authenticated, self-hosted environment — built to compare
build methods. It is not trying to beat Uptime Kuma's community or be a
certificate-lifecycle automation platform.

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
not crowded. cert-watch's differentiation against it is the directory
auth + audit log + posture grading + offline upload that a regulated shop needs.

## How this informs the roadmap

The positioning above is the lens for what we build next. Concretely:

- **Lean into observability depth and environment fit** — certificate change
  history & drift detection (plan 016), and the regulated-environment
  differentiators: discovery (AD CS / Windows cert stores), revocation-endpoint
  health, and audit-grade reporting (plan 017).
- **Fold multi-channel alerting into alert groups** (plan 015) rather than
  treating it as a separate epic.
- **Deliberately decline** features that make an external cloud service a
  dependency, or that drift toward a different product class — external
  cloud-API discovery, reliance on a hosted CT-streaming feed, active network
  scanning, and ACME renewal automation. (Self-hostable versions of some of
  these stay on the table; the line is *no external-SaaS dependency*, not *no
  egress*.) Plan 017 records *why*, so the comparison stays legible.
