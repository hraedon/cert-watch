# Plan 030: AD CS Discovery (Workstream H)

> **Status:** **draft — BLOCKED on a premise spike before any code.** Grounded
> in the LDAP auth plumbing (`auth/ldap_provider.py`), trust anchor upload
> (`upload.py`), private CA chain validation (`cert_chain.py`), and the Discover
> page CT reconciliation (`ct_monitor.py`). Implements Plan 017 §B1.
> **Medium-large; 0.6.0 candidate *if the spike validates the approach*.**
>
> ## ⚠ Premise to validate first (the load-bearing assumption)
>
> The discovery query (see "Signal definition") targets
> `(&(objectClass=user)(userCertificate=*))` and EKU-filters for Server Auth.
> **This likely won't find the TLS server certs operators actually care about:**
> - TLS *server* certs in AD CS are issued to **computer** accounts, not user
>   objects — so at minimum the query must also cover `objectClass=computer`.
> - More fundamentally, the common **Web Server** templates frequently **do not
>   publish the issued cert to AD at all** (publishing to AD is the default for
>   user certs — smartcard/EFS — not for web-server certs). When a cert isn't
>   published, it exists only in the **CA database**, which LDAP cannot see.
> - The authoritative "what did this CA issue" source is the CA database
>   (certutil / `ICertView` / DCOM), which this plan rules out as a non-goal for
>   cross-platform reasons.
>
> **So the LDAP-only approach trades correctness for portability and may
> discover very few real TLS certs.** Full cross-platform coverage probably
> requires reopening the CA-database path (Windows-only DCOM/`certutil`, or an
> agent), which is the hard part the cross-platform goal runs into. **Action:
> run a spike against a real AD CS lab** — confirm, per target environment,
> where web-server certs live (object class + whether published to AD) and what
> fraction LDAP can actually see. If LDAP coverage is poor, this becomes either
> a Windows-only feature (CA-database query) or is deprioritized. Do not build
> the slices below until the spike resolves this.

## Goal

Discover certificates issued by an Active Directory Certificate Services (AD CS)
CA and surface them in cert-watch's inventory — so an operator in a hybrid
Windows network can see internal PKI certificates alongside public ones without
manual upload.

The critical design problem: **an ADCS CA can have thousands of issued certs**
(user certs, computer certs, code-signing, etc.). Surfacing all of them in the
main dashboard would drown the TLS monitoring use case. This plan solves that
with **scoped discovery** — only certificates bound to TLS server
authentication, filtered by template and OU, with a dedicated "Internal PKI"
view separate from the main dashboard.

## What already exists (build on, don't rebuild)

- **LDAP plumbing** (`auth/ldap_provider.py`): `ldap3` library, STARTTLS with
  `CERT_REQUIRED`, DC failover, service account binding. The connection
  infrastructure is complete; only the query logic is new.
- **Trust anchor upload** (`upload.py`): operators can upload private CA roots
  for chain validation. ADCS discovery would auto-register the CA cert.
- **Private CA chain status** (`cert_chain.py`): `chain_status()` returns
  `"private"` when anchored by a user-uploaded root. The inventory already
  distinguishes public vs. private.
- **Discover page** (`routes/views.py`): CT reconciliation view showing coverage
  gaps. A parallel "Internal PKI" tab is the natural home for ADCS data.
- **Host model** (`database/repo.py`): `hosts` table with `hostname`, `port`,
  `renewal_method`, `source` columns. A new `source="adcs"` differentiates
  discovered hosts from manually added ones.

## The scale problem and how we solve it

A typical mid-size AD CS deployment issues **thousands** of certificates:
- User certificates (smartcard logon, EFS, email) — **not relevant**
- Computer certificates (machine auth, RDP) — **not relevant**
- Web server / TLS certificates — **relevant**
- Code signing — **not relevant**

If we naively import everything, cert-watch drowns in noise. The solution:

### 1. Template-scoped discovery (the primary filter)

AD CS certificate templates have an `pKIExtendedKeyUsage` attribute. We filter
to templates whose EKU includes **Server Authentication**
(`1.3.6.1.5.5.7.3.1`). This is the single most important filter — it
eliminates user certs, computer certs, and code-signing automatically.

Operators can further restrict via `CERT_WATCH_ADCS_TEMPLATES` (comma-separated
template CNs) to include only specific templates (e.g., `WebServer-Internal`).

### 2. OU-scoped discovery (optional secondary filter)

`CERT_WATCH_ADCS_SEARCH_OU` restricts the LDAP search base to a specific OU
(e.g., `OU=Servers,DC=corp,DC=example,DC=com`). This is optional but valuable
for large forests.

### 3. Dedicated "Internal PKI" view (noise isolation)

ADCS-discovered certs live in a **separate view**, not the main dashboard. The
main dashboard stays focused on TLS monitoring for manually-tracked and
CT-discovered hosts. The Internal PKI view shows:
- Issued certificates with template name, subject, SAN, expiry, status
- Expiry heatmap (how many certs expire in 7/30/90 days)
- Missing from cert-watch (issued by CA but not being monitored for TLS)

### 4. Selective promotion to main inventory

Operators can "promote" an ADCS-discovered cert to the main inventory (adds a
host entry with `source="adcs"` and begins TLS scanning). This is the bridge
between discovery and monitoring — only certs the operator cares about get
scanned.

## Non-goals

- Not enrolling for certificates from ADCS. Read-only discovery.
- Not querying the CA database directly (WinRM/DCOM). LDAP-only, which works
  cross-platform and reuses existing plumbing.
- Not discovering non-AD CS private CAs (step-ca, Vault PKI, EJBCA). Those
  would be a separate plan; the trust-anchor + upload path covers them today.
- Not auto-adding discovered certs to the scan inventory. Promotion is manual
  to prevent scan noise.

## Signal definition

An ADCS-discovered certificate is identified by querying the AD DS
`pKICertificate` object class (the published certificate store in AD). The LDAP
search:

```
Base: CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{domain_dn}
Filter: (objectClass=pKIEnrollmentService)
→ Returns CA name, DNS name, certificate template list
```

Then for each CA, query issued certificates:

```
Base: {search_base} (configurable OU or domain root)
Filter: (&(objectClass=user)(userCertificate=*))
→ Returns user objects with published certificates
```

Parse the `userCertificate` attribute (DER-encoded X.509), extract:
- Subject, SAN, Serial, NotBefore, NotAfter
- Template name from Certificate Template extension OID (1.3.6.1.4.1.311.20.2)
- EKU extension (filter to Server Authentication)

## Config

- `CERT_WATCH_ADCS_ENABLED` — `1` to enable discovery (default 0).
- `CERT_WATCH_ADCS_LDAP_URL` — LDAP(S) URL for AD DS (falls back to
  `AUTH_LDAP_SERVERS` if set).
- `CERT_WATCH_ADCS_BIND_DN` — service account DN for LDAP bind.
- `CERT_WATCH_ADCS_BIND_PASSWORD` — bind password (`_FILE` supported).
- `CERT_WATCH_ADCS_SEARCH_BASE` — LDAP search base (default: domain root
  from domain controller).
- `CERT_WATCH_ADCS_SEARCH_OU` — optional OU restriction (e.g.,
  `OU=Servers,DC=corp,DC=example,DC=com`).
- `CERT_WATCH_ADCS_TEMPLATES` — comma-separated template CNs to include
  (default: all Server Authentication templates).
- `CERT_WATCH_ADCS_SYNC_INTERVAL_HOURS` — how often to re-sync (default 24).
  `0` disables periodic sync (manual only via API).
- `CERT_WATCH_ADCS_CA_CERT` — CA certificate PEM for chain validation (`_FILE`
  supported). Auto-discovered from the enrollment services object if not set.

## Slices

1. **LDAP query module** (`adcs.py`): `discover_adcs_certs(config) -> list[ADCSCert]`.
   Pure function: connects to LDAP, queries enrollment services, queries issued
   certificates, filters by EKU and template, returns structured results.
   Includes the CA cert auto-discovery.
2. **Storage**: new table `adcs_certificates` (id, ca_name, template, subject,
   san, serial, not_before, not_after, fingerprint, raw_der, discovered_at,
   promoted_host_id). Migration 0014. Upsert on re-sync (match by fingerprint).
3. **Scheduler integration**: wire ADCS sync into the scheduler cycle as a new
   stage (after CT, before alerts). Runs at the configured interval, not every
   cycle.
4. **Internal PKI view** (`routes/views.py` + `templates/internal_pki.html`):
   dedicated page showing discovered certs, expiry heatmap, template breakdown,
   and "promote to inventory" action. Separate from the main dashboard.
5. **Promotion endpoint** (`routes/api.py`): `POST /api/adcs/promote` with
   `{cert_id, hostname, port}` — creates a host entry with `source="adcs"`,
   links via `promoted_host_id`, begins TLS scanning on next cycle.
6. **Auto-register CA cert**: when ADCS discovery finds a CA cert not already in
   trust anchors, auto-upload it (or prompt the operator to confirm, depending
   on a `CERT_WATCH_ADCS_AUTO_TRUST` flag).
7. **UI integration**: "Internal PKI" nav item (visible only when
   `CERT_WATCH_ADCS_ENABLED=1`).

## Testing

- **LDAP query**: mock `ldap3.Connection`; assert correct search base, filter,
  and attribute extraction. Test with multiple CAs, multiple templates.
- **EKU filtering**: seed certs with and without Server Authentication EKU;
  assert only SA certs are returned.
- **Template filtering**: set `CERT_WATCH_ADCS_TEMPLATES=WebServer`; assert
  only matching template CNs are returned.
- **OU scoping**: set search OU; assert search base is constructed correctly.
- **Re-sync idempotency**: run discovery twice with same data; assert no
  duplicate rows (upsert by fingerprint).
- **Promotion**: promote a cert; assert host entry created with `source="adcs"`,
  assert `promoted_host_id` is set on the `adcs_certificates` row.
- **No-config**: with `CERT_WATCH_ADCS_ENABLED=0`, zero overhead and no LDAP
  connections.

## Risks / decisions

- **LDAP permissions** — the service account needs read access to the
  Configuration partition (to enumerate CAs) and the target OU (to read
  published certificates). This is a broader scope than typical LDAP auth
  binds. Document the required permissions clearly.
- **Cross-forest / multi-domain** — initial scope is single-domain. Multi-
  forest discovery would require multiple search bases and potentially multiple
  bind accounts. Defer to a follow-up; document the limitation.
- **Certificate volume** — even with EKU filtering, a large AD CS deployment
  may have hundreds of TLS certs. The "promote to inventory" model keeps the
  scan inventory curated. The Internal PKI view can paginate aggressively.
- **Stale certificates** — AD CS does not remove expired certs from the
  published store automatically. The discovery view should distinguish "expired"
  from "valid" and optionally hide expired certs by default.
- **LDAP vs. WinRM** — LDAP queries the AD DS published certificate store, not
  the CA database directly. Certificates that were issued but not published to
  AD (rare, but possible with custom templates) will not be discovered. This is
  an acceptable trade-off for cross-platform compatibility.
