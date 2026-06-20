# Plan 051 — Estate discovery (post-1.0 major feature)

**Status:** scoped 2026-06-20 (deferred to post-1.0 by operator)
**Strategic role:** Close the deepest form of the "point it at your whole estate"
promise. Today the operator must already *know* every `host:port`; bulk CSV
import (`/hosts/import`) helps, but the hard problem in real cert management is
the cert you *forgot*. This is the highest-value, largest-scope input-side
addition — deliberately sequenced after 1.0 because it adds a new surface and
brushes against the "no active network scanning" line that positioning declines.

## The line this must not cross

`docs/positioning.md` declines **active network scanning** and **external
cloud-API discovery**. Discovery here must stay **seeded / passive / infra-native**
— enumerate sources the operator already owns and points us at, never sweep
address space. Each source below is judged against that line.

## Candidate sources (in rough value order)

### A. Kubernetes-native (strongest fit)
cert-watch already deploys on k8s. A read-only, in-cluster pass can enumerate:
- `Ingress` objects → host names + TLS secret refs
- `Secret`s of type `kubernetes.io/tls` → the certs themselves (offline parse,
  no scan needed)
No external API, no egress, no address sweep. Requires a (namespaced, read-only)
ServiceAccount RBAC grant; document the least-privilege Role. **Open question:**
in-cluster only, or allow a kubeconfig for an external cluster (egress, but to an
operator-supplied endpoint — arguably still "seeded")?

### B. Config / filesystem import (simple, safe)
- Walk an operator-supplied cert directory (`/etc/ssl/...`, a PEM dir) and import
  every leaf found → offline parse, zero network.
- Parse nginx / HAProxy / Apache `server` blocks for `listen ... ssl` + `server_name`
  → produces a seed list of `host:port` to scan with the normal path.

### C. Load-balancer / inventory file import
Generic: accept an operator export (F5, HAProxy, a CMDB CSV richer than today's)
and map it to hosts. Low novelty, but cheap once B's parser exists.

## Explicitly out (restate to keep legible)
- CIDR/subnet sweeps, port scanning, internet-wide CT feeds, cloud provider
  cert-manager API polling. These are a different product class and/or cross the
  declined line.

## Open decisions to pin before building
1. **k8s scope:** in-cluster ServiceAccount only, or external kubeconfig too?
2. **Discovery → inventory model:** do discovered hosts land as normal `hosts`
   rows (re-scanned on the usual cadence), or a separate "discovered, unconfirmed"
   staging state an operator promotes? The latter avoids auto-scanning things the
   operator hasn't vetted (SSRF/scope hygiene) but adds a workflow.
3. **De-dup:** discovery will re-surface hosts already tracked; key on
   `(hostname, port)` and treat as upsert, or show a reconciliation diff?
4. **Grade/posture of offline-discovered certs (k8s Secrets, dir walk):** these
   arrive as cert *files*, not live scans — route them through the existing
   upload path (chain validation, no TLS posture) rather than the scan path.

## Why post-1.0
It's a new surface with its own permanent maintenance cost (k8s API shapes,
config-format drift), exactly the kind of thing the maintenance contract
(Plan 049 P4) says must be priced deliberately. 1.0 ships the observability of a
known estate; discovery is the 1.x headline feature.
