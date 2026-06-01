# Plan 017: Differentiation Backlog — Discovery, Revocation Health, Reporting

> **Status:** backlog, **not** a sequenced build. Each section is a
> self-contained spec a developer can pull independently. This plan exists to
> capture the *deliberate* feature decisions from the competitive review
> (see `docs/positioning.md`) — including what we are **declining** and why, so
> the project's scope stays legible against software-factory-2.

These are the features that align with cert-watch's actual differentiation:
deep observability for a **regulated, directory-authenticated, self-hosted**
environment. They are tiered by cost/fit, not bundled into one release.

---

## Tier A — cheap, fits the architecture, serves the regulated user

### A1. Revocation-endpoint health (OCSP / CRL)
A valid cert with a dead OCSP responder or unreachable CRL distribution point
is a real operational problem the posture grader doesn't catch today.

- Extend the posture evaluation (`posture.py`): parse the AIA (OCSP URL) and
  CRL distribution points from the leaf; check reachability + a well-formed
  response (OCSP: `good`/`revoked`/`unknown`; CRL: fetchable + parses + not
  expired). Respect `allow_private` / egress constraints — these are outbound
  fetches, so make them **opt-in** via `CERT_WATCH_CHECK_REVOCATION=0` default
  (a regulated/air-gapped install may not permit the egress).
- Add findings to the posture result (new checks) and a column to `scan_posture`.
- **AC:** a cert with an unreachable OCSP/CRL endpoint gets a posture finding;
  checks are skipped (not failed) when the toggle is off.

### A2. Audit-grade reporting / export
Scheduled CSV/PDF exports as audit evidence — disproportionately valuable in a
regulated shop (this is the environment cert-watch targets).

- `GET /api/reports/inventory.csv` and `.../expiring.csv` (reuse the existing
  CSV export plumbing in `routes/hosts.py`). PDF optional (server-side render
  of the same data).
- Optional scheduled email of the report via the existing alert/SMTP path
  (reuse `alerts.send_*`), gated by an env toggle + cron-ish schedule.
- **AC:** an operator can export current inventory + upcoming expirations as
  CSV; the scheduled job emails it when configured.

---

## Tier B — the deliberate bigger bet (environment-specific differentiator)

### B1. AD CS discovery (read-only)
The biggest blind spot for a Windows/AD shop, and the place cert-watch can do
something the off-the-shelf tools don't. Pull the internal CA's issued-cert
inventory so the team sees certs they never manually added.

- Reuse the **existing LDAP plumbing** (`auth.py` LDAP/AD support, `ldap3`):
  query AD CS issued-certificate data (e.g., the CA database via the published
  cert stores / `pKICertificate` objects, or a read-only ICertView/WinRM bridge
  on the CA host — confirm the access path available in the target environment).
- Import discovered certs as `source="adcs-discovery"`, read-only, so they show
  up in inventory/expiry/posture without a live host scan.
- Strictly read-only; no issuance. Gated by explicit config
  (`CERT_WATCH_ADCS_*`); off by default.
- **AC:** configured against a test CA, issued certs appear in inventory tagged
  by source, without manual entry.
- **Effort:** real (multi-session). Scope as its own project when prioritized;
  this section is the design seed, not a small task.

### B2. Windows cert-store scanning (PowerShell / WinRM)
Pull certs from IIS bindings, RDS, and local machine stores on Windows hosts
into the dashboard — complements AD CS discovery for the same environment.

- A small read-only collector (PowerShell over WinRM, or a script the operator
  runs) that emits cert blobs cert-watch ingests via the **existing upload
  path** (`upload.py`) or a new `POST /api/ingest`.
- Read-only; no remote changes. Off by default.
- **AC:** certs from a Windows host's machine store appear in inventory via the
  collector, no manual upload.

---

## Tier C — deliberately declined (record the reasoning)

These were on the review's list. We are **not** building them now; documenting
why keeps the scope legible and is itself the evidence of an informed decision.

- **Real-time CT streaming (certstream).** A persistent outbound connection and
  a new failure mode, to replace a daily crt.sh poll that is adequate for the
  intended use. Reconsider only if near-real-time unauthorized-issuance
  detection becomes a hard requirement.
- **External cloud-API discovery (ACM / Key Vault / DigiCert / Vault).**
  Requires outbound credentials and egress to third-party SaaS — a governance
  event in a regulated/air-gapped environment, contrary to the self-contained,
  no-cloud positioning. (AD CS/Windows discovery serves the same "find forgotten
  certs" need *inside* the trust boundary.)
- **Active network (CIDR) scanning.** Security-sensitive active scanning that
  can trip IDS/IR; high blast radius for a convenience feature.
- **ACME renewal automation.** That is a certificate-*operations* product
  (cf. Certimate), a different class from cert-watch's read-only observability.
  Monitoring an ACME account read-only could fit later; *performing* renewals
  does not.

---

## How to use this plan
Pull Tier A items as quick wins (they fit the existing posture/export plumbing).
Treat Tier B as a funded, deliberate bet with its own scoping when cert-watch is
confirmed as a product for Windows/AD shops. Revisit Tier C only when a concrete
requirement overrides the reasoning above — and update this file if so.
