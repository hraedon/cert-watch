# cert-watch threat model

Status: living design document

Last reviewed: 2026-09-21

Code reviewed through: `e6e223d` plus the Plan 056 maintenance worktree

Review method: source and deployment-manifest review; no live environment assessment

## System and scope

cert-watch is a FastAPI service with a server-rendered UI, JSON API, CLI,
in-process scheduler, and SQLite persistence. It inventories certificates,
connects to operator-selected TLS and STARTTLS endpoints, evaluates stored and
observed certificate posture, and sends alerts and audit events to configured
external systems. The supported deployments run one application instance
against local SQLite state; the Kubernetes manifest enforces one replica with a
`Recreate` strategy (`deploy/k8s/deployment.yaml:8-12`).

This model covers the application, its checked-in deployment examples, the data
it persists, and the network flows it initiates. It does not establish the
security of a particular cluster, Windows host, identity provider, SMTP relay,
webhook receiver, DNS service, monitored endpoint, backup system, or GitHub
organization. Their responses are treated as untrusted even when an
administrator chooses their addresses.

## Security objectives

- An exposed first run establishes authentication or fails closed. Deliberately
  unauthenticated operation is limited to a loopback or otherwise unexposed bind,
  or an explicit operator choice (`src/cert_watch/firstrun.py:16-61`,
  `src/cert_watch/app.py:215-258`).
- Session cookies and API keys remain authentic, expirable, revocable, and
  limited by role and tag scope. Cookie-authenticated mutations require CSRF
  validation (`src/cert_watch/middleware.py:422-449`,
  `src/cert_watch/routes/_scoped.py:68-178`).
- Every attacker-influenced network destination passes the applicable address
  and TLS policy. HTTP redirects are resolved, revalidated, and pinned again
  (`src/cert_watch/http_client.py:33-78`,
  `src/cert_watch/http_client.py:183-257`).
- Certificate uploads, parsers, subprocess output, network calls, retries, and
  concurrency remain bounded. Uploaded private keys are never persisted
  (`src/cert_watch/upload.py:36-145`,
  `src/cert_watch/routes/certificates.py:532-588`).
- Inventory, credentials, trust anchors, audit evidence, and release artifacts
  retain their integrity and are disclosed only to their intended recipients.

## Assets

| Asset | Security properties |
| --- | --- |
| Certificate inventory, host ownership, tags, notes, history, posture, and alert state | Confidentiality of internal inventory; integrity; freshness; availability |
| Local password hashes, sessions, API-key hashes, role maps, and tag scopes | Authentication integrity; least privilege; revocability |
| Authentication signing secret, CSRF key material, and persisted-setting encryption key | Confidentiality; integrity; stable persistence across restart |
| LDAP, OAuth, SMTP, PagerDuty, webhook, and HEC credentials and destinations | Credential confidentiality; destination integrity; controlled disclosure |
| Uploaded trust anchors and recorded chain/revocation decisions | Integrity; provenance; auditability |
| Audit records, scan/delivery outcomes, reports, backups, and metrics | Integrity; availability; bounded metadata disclosure |
| GitHub workflow authority, GHCR images, and deployment image references | Artifact provenance; controlled publication |

The primary data model is visible in `src/cert_watch/database/schema.py:20-175`.
Sensitive settings are encrypted before SQLite persistence using key material
derived from the authentication secret (`src/cert_watch/database/encryption.py:20-88`).

## Trust boundaries

### HTTP clients to the application

Browsers and API clients cross authentication, rate-limit, CSRF, RBAC, and
tag-scope controls before reaching inventory-bearing routes. Only health,
readiness, login/setup flow, static files, and token-gated metrics may bypass the
normal session/API-key path (`src/cert_watch/middleware.py:519-554`,
`src/cert_watch/middleware.py:664-718`).

An authenticated viewer can read only the inventory permitted by its role and
tag scope. Operators and write-scoped API keys can mutate in-scope inventory,
initiate scans, upload certificates, and add or remove trust anchors. Admins can
change integration and identity settings. When authentication is enabled and no
role map exists, authenticated users receive administrator access for backward
compatibility (`src/cert_watch/auth/rbac.py:76-109`). This is a material
deployment assumption, not tenant isolation.

### Application to SQLite and local secrets

SQLite stores inventory, identity metadata, configuration, and operational
evidence. The application uses WAL, foreign keys, a busy timeout, transactions,
and a process-local write lock (`src/cert_watch/database/connection.py:14-33`,
`src/cert_watch/database/connection.py:88-160`). The lock does not coordinate
multiple processes or replicas. Deployment filesystem and backup ACLs must
protect the database and root authentication secret together.

### Scanner to DNS and monitored endpoints

Authenticated write users select scan targets. Hostname and resolved-address
checks always block loopback, link-local, unspecified, and similar unsafe ranges;
private-address access is controlled by deployment policy. Connections are
pinned to validated addresses, and STARTTLS protocols are allowlisted
(`src/cert_watch/scan_resolver.py:54-110`,
`src/cert_watch/scan_conn.py:186-297`). The checked-in Kubernetes and IIS
examples enable private-address scanning because internal certificate discovery
is a core use case.

### Application to external integrations

SMTP, webhooks, SIEM targets, OAuth/OIDC, LDAP, OCSP, and CRL services receive
application requests and control their responses and availability. HTTP
consumers use address validation, DNS pinning, and redirect revalidation.
OIDC validates issuer, audience, nonce, and algorithm. SMTP uses verified TLS
when configured (`src/cert_watch/http_client.py:33-257`,
`src/cert_watch/auth/oauth_provider.py:224-332`,
`src/cert_watch/alerting/transports/smtp.py:38-105`).

### Uploaded data to parsers and trust decisions

Authorized writers can submit malformed or complex PEM, DER, PKCS#7, and
PKCS#12 data. Routes cap uploads at 10 MiB and parsers cap bundle sizes.
Temporary files are removed in `finally` blocks. PKCS#12 private keys are
discarded. Operator-level write permission also permits trust-anchor changes
(`src/cert_watch/routes/certificates.py:591-673`,
`src/cert_watch/upload.py:76-145`).

### Reverse proxy to application identity

Forwarded client addresses affect rate limits and audit attribution only when
proxy trust is enabled; an optional peer allowlist can constrain trusted
forwarders (`src/cert_watch/middleware.py:169-201`). TLS commonly terminates at
IIS or an ingress, so secure-cookie behavior and accurate client attribution
depend on matching proxy configuration.

### Repository governance to release artifacts

The release workflow waits for CI, browser, and deployment-smoke checks, scans
the built image before publication, and verifies branch state before updating
deployment image references (`.github/workflows/release.yml:1-39`,
`.github/workflows/release.yml:103-186`). A maintainer, tag authority, or
compromised release job remains capable of publishing trusted artifacts.

## Threats and current controls

| Priority | Scenario | Existing controls | Residual concern |
| --- | --- | --- | --- |
| High | A stolen session, API key, or mis-mapped identity reads or changes inventory outside its intended scope. | Signed/expiring sessions, hashed API keys, CSRF, permission tiers, per-tag read/write checks, audit records. | Empty role maps grant admin for compatibility; operators can modify trust anchors. Deployments must define and test their intended role map. |
| High | A write-capable user uses scanning or an integration URL to reach unintended internal services. | Hostname validation, always-blocked address classes, configurable private-network policy, DNS pinning, redirect revalidation, protocol allowlists, time/output limits. | Private scanning is intentionally enabled in checked-in deployment examples. Write access therefore carries internal network reach within the configured policy. |
| High | An attacker obtains the SQLite database and signing secret from a host, PVC, backup, or secret store. | Non-root containers, read-only root filesystem, generated-secret mode `0600`, encrypted sensitive KV values, deployment ACL guidance. | Possession of both values defeats session/API-key key derivation and persisted-secret encryption. Real storage, backup, and retention controls are environment-specific. |
| High | A writer adds a malicious or inappropriate trust anchor and changes posture decisions. | Write authentication, CSRF, CA validation, audit events. | Trust-anchor administration currently uses operator/write permission rather than an admin-only permission. This authority must be explicit in deployment role design. |
| High | Repository or CI authority publishes an unreviewed image. | Required workflow gates, image scan, metadata validation, branch-race checks, scoped workflow permissions. | Maintainer and workflow-token compromise remain outside application controls. GitHub branch, tag, and environment protection must supply the outer boundary. |
| Medium | Malformed certificates or hostile endpoints consume CPU, memory, file descriptors, or worker time. | Upload/count limits, bounded reads, connection/subprocess timeouts, output caps, limited retries, temporary-file cleanup. | Parser-library defects and aggregate load remain possible; resource limits and monitoring are deployment responsibilities. |
| Medium | A compromised external integration exfiltrates fleet metadata or returns malicious content. | Admin-only configuration, destination validation, TLS verification, bounded responses, selected payload fields. | Administrators choose recipients, and the receiver necessarily learns the payload sent to it. |
| Medium | Incorrect proxy trust allows source-IP spoofing or collapses all users to the ingress address. | Proxy headers are ignored unless explicitly trusted; optional trusted-proxy allowlist. | The checked-in Kubernetes deployment does not enable proxy trust, so audit/rate-limit identity is normally the ingress peer rather than the end client. |
| Medium | Multiple application instances concurrently write the same SQLite database. | Process-local lock; single-replica `Recreate` Kubernetes deployment. | External process managers must preserve the single-active-writer topology. |
| Low | Metrics or health endpoints disclose more than intended. | Health responses are narrow; metrics requires normal authentication when no bearer token is set and becomes public-path only when bearer-gated. | Ingress restrictions are still recommended because metrics describes fleet behavior. |

## Deployment assumptions and unresolved questions

These items are not accepted risks. They require an operator decision or a
follow-up code/documentation change:

1. `deploy/iis/web.config` declares `CERT_WATCH_CSRF_SECRET_FILE`, but
   `_resolve_security` reads only `CERT_WATCH_CSRF_SECRET` and otherwise derives
   the CSRF secret from the authentication secret
   (`deploy/iis/web.config:43-46`, `src/cert_watch/app.py:102-117`). Decide
   whether IIS needs a separately loaded CSRF file or whether the configuration
   should document derivation.
2. The startup metrics warning says an absent metrics token leaves metrics
   unauthenticated, while the middleware keeps `/metrics` behind normal
   authentication when the token is absent
   (`src/cert_watch/app.py:290-301`, `src/cert_watch/middleware.py:524-554`).
   Align the warning with effective behavior.
3. Decide whether Kubernetes should trust selected ingress proxy peers so audit
   records and rate limits identify end clients. The current safe default uses
   the ingress peer.
4. Confirm that administrator fallback for an empty role map and operator-level
   trust-anchor changes match the long-term authorization model.
5. Record production filesystem/PVC ACLs, backup destinations, retention, and
   encryption-at-rest controls in the environment runbook.
6. Confirm whether ingress-to-Service HTTP is inside the deployment's trusted
   cluster boundary.

## Review triggers

Update this threat model in the same change whenever code or deployment
configuration alters:

- authentication, sessions, CSRF, API keys, role mapping, or tag scoping;
- scan destination policy, private-address access, DNS pinning, redirects, or
  supported scan protocols;
- certificate upload/parsing bounds or trust-anchor permissions;
- secret loading, encryption, SQLite topology, backups, or filesystem paths;
- payloads, credentials, or destinations for SMTP, webhook, SIEM, LDAP, OAuth,
  OCSP, or CRL integrations;
- reverse-proxy trust, public paths, metrics exposure, or security headers; or
- release authority, artifact publication, or deployment image provenance.

The review should name the affected assets and boundaries, verify the effective
deployment configuration, update relevant tests, and record unresolved operator
decisions instead of assuming acceptance.
