# UI-INVENTORY — cert-watch

**Rule (content-model contract, patina plan 008): one concept, one control.**
Every concept a record exposes has exactly one editing control across the UI.
Any PR that adds, removes, or relocates a field, control, or editing surface
must diff this file in the same PR; a UI change without a matching inventory
diff fails review.

Paths are relative to `src/cert_watch/`. Endpoints marked **(no UI caller)**
exist but are invoked by no template or bundled JS. State inventoried:
branch `redesign/attention-home`, 2026-08-30 (V1 + V2 implemented; notes are
host-scoped only).

IA note: the landing page is now **Home** (`/`, `templates/home.html` — ranked
attention queue + expiry horizon) and the inventory table lives at
**/browse** (`templates/dashboard.html`, including the add-certificates
drawer). Home introduces **no new editing controls** — its only mutating
surface is the per-item "scan now" button, which posts to the pre-existing
`POST /hosts/{id}/scan` (same endpoint the detail page and Browse rows use).

## Certificate (`certificates` table)

| Concept | Column | Editing control today | Write endpoint | Single owner (proposed) |
|---|---|---|---|---|
| ~~Notes & procedures~~ | **REMOVED** — `certificates.notes` dropped by migration 0031 (merged into `hosts.notes`) | — | `POST /certificates/{id}/notes` and `PATCH /api/certificates/{id}/notes` **removed** | Host-scoped notes won (V1, implemented 2026-08-30) |
| Own tags | `certificates.tags` | Text input (datalist), cert detail — `certificate_detail.html:370-374` | `POST /certificates/{id}/tags` (routes/certificates.py:516); `PUT /api/certificates/{id}/tags` (routes/api/certificates.py:216) (no UI caller) | Cert-detail tags editor (host tags inherited, shown `(host)` — OK) |
| Lifecycle (create/delete) | row | Add drawer: upload tab `dashboard.html:377`; delete `certificate_detail.html:72` | `POST /upload` (routes/certificates.py:674); `POST /certificates/{id}/delete` (:459) | As-is |

## Host (`hosts` table)

| Concept | Column(s) | Editing control(s) today | Write endpoint(s) | Single owner (proposed) |
|---|---|---|---|---|
| Ownership & renewal contact | `owner_name`, `owner_email`, `owner_slack`, `renewal_method`, `runbook_url` (schema.py:72-77) | One form ("Operational summary → Edit"), cert detail — `certificate_detail.html:138-166` | `POST /certificates/{cert_id\|host_id}/owner` (routes/certificates.py:559 — writes to **hosts**, resolves host when no cert); `PATCH /api/hosts/{id}/owner` (routes/api/hosts.py:85) (no UI caller) | Cert-detail owner form (already single); rename endpoint under `/hosts/` when convenient |
| Host notes | `hosts.notes` (schema.py:78) | **ONE editing control:** textarea ("Notes" panel), endpoint detail page — `certificate_detail.html` (V2 resolved 2026-08-30: the 3 dashboard inline editors in `static/js/dashboard.js` were removed; the dashboard now shows a read-only note indicator chip). Creation-time seeds: `notes` param on `POST /hosts` (routes/hosts.py:139, no drawer field) and CSV `notes` column (:296) | `POST /hosts/{id}/notes` (routes/hosts.py:364); `PATCH /api/hosts/{id}/notes` (routes/api/hosts.py:191) (no UI caller — JSON API path); `POST /hosts` (:130); CSV `POST /hosts/import` (:231) | Detail-page Notes panel — **resolved (V1/V2)** |
| Host tags | `hosts.tags` (schema.py:70) | Text input (datalist), cert/host detail (host branch of shared form) — `certificate_detail.html:370-374`; also add-host route param (routes/hosts.py:136, **no drawer field**) and CSV `tags` column (:295) | `POST /hosts/{id}/tags` (routes/hosts.py:397); `PUT /api/hosts/{id}/tags` (routes/api/hosts.py:226) (no UI caller); `POST /hosts`; `POST /hosts/import` | Detail-page tags editor; drawer/CSV are creation-time seeds, label them as such |
| Scan target (hostname, port, TLS mode, common-ports) | `hostname`, `port` + scan params | Add drawer, scan tab — `dashboard.html:339-372` | `POST /hosts` (routes/hosts.py:130) | Create-only by design — OK |
| Alert threshold | `threshold_days` (schema.py:69) | Create-only: drawer `dashboard.html:352`; CSV column | `POST /hosts`; `POST /hosts/import` | No post-creation edit control exists (displayed read-only, `certificate_detail.html:191`) — see "Latent / unsurfaced fields" |
| Lifecycle (delete, scan) | row | `certificate_detail.html:78` (delete), :64 (scan) | `POST /hosts/{id}/delete` (routes/hosts.py:476); `POST /hosts/{id}/scan` (:561) | As-is |

## Tags (cross-cutting registry)

| Concept | Store | Control | Endpoint | Owner |
|---|---|---|---|---|
| Tag registry (usage, access scoping, alert routing dependents) | derived from `hosts.tags` + `certificates.tags` + roles + alert groups | **Read-only** table, Settings → Tags — `templates/settings/tags.html:22-58`; correctly states tags are edited on detail pages | — | Detail pages own edits; registry stays read-only — OK |

## Alert routing & delivery config (`kv_store` / `alert_groups`)

| Concept | Store | Control | Write endpoint | Owner |
|---|---|---|---|---|
| SMTP transport + global recipients | kv | Form, Settings → Channels — `settings/channels.html:10-56` | `POST /settings/smtp` (routes/settings/smtp.py:45) | As-is |
| Alert webhook (preset/URL/template/headers) + schedule/retention | kv | Form, Settings → Channels — `settings/channels.html:64-153` | `POST /settings/alerts` (routes/settings/alerts.py:14) | As-is; see V3 (label collision) |
| Event forwarding (webhook sink, adapter kind, rate limit, PagerDuty key) | kv | Form, Settings → Events — `settings/events.html:18-62` | `POST /settings/events` (routes/settings/events.py:58) | As-is; see V3 |
| Alert groups (name, match tags, recipients, group webhook, threshold, digest cadence) | `alert_groups` (schema.py:139) | Create + per-group edit forms — `settings/alert_groups.html:70,136,143` | `POST /settings/alert-groups[/{id}[/delete]]` (routes/settings/alert_groups.py:208,242,281) | As-is; see V3 |

## Access & administration

| Concept | Store | Control | Write endpoint | Owner |
|---|---|---|---|---|
| Auth providers (LDAP/OAuth), own password | kv / users | Settings → Auth — `settings/auth.html:10,205` | `POST /settings/auth` (routes/settings/auth.py:24); `POST /settings/change-password` (routes/settings/password.py:28) | As-is |
| Roles (name, scope tag, per-tag tiers, email), LDAP role map | roles tables | Settings → Roles — `settings/roles.html:74,115,126,145` | `POST /settings/roles[/{id}[/delete]]` (routes/settings/roles.py:87,125,166); `POST /settings/ldap-role-map` (routes/settings/auth.py:43) | As-is |
| Local users | users | Settings → Users — `settings/users.html:24,73,103` | `POST /settings/users[/{id}[/delete]]` (routes/settings/roles.py:199,238,287) | As-is |
| API keys | `api_keys` (schema.py:129) | Settings → API keys — `settings/api_keys.html:48,89` | `POST /settings/api-keys[/{id}/revoke]` (routes/settings/api_keys.py:33,68) | As-is |
| Policy rules | kv | Settings → Policy — `settings/policy.html:19,108` | `POST /settings/policy` (routes/settings/policy.py:20) | As-is |
| Trust anchors | `trust_anchors` (schema.py:84) | Settings → Trust anchors — `settings/trust_anchors.html:21,45` | `POST /trust-anchors[/{id}/delete]` (routes/certificates.py:724,789) | As-is |

## Violations & open decisions

- **V1 — RESOLVED 2026-08-30 (branch `redesign/attention-home`).** Two
  near-identical notes textareas on the detail page (`hosts.notes` at
  `certificate_detail.html:229`, `certificates.notes` at `:413`).
  Per the 2026-08-14 adjudication (merge to ONE host-scoped field):
  migration **0031** concatenates every non-empty `certificates.notes` into
  the matching `hosts.notes` (matched on hostname+port) and drops the column.
  Notes on uploaded certificates with **no matching host row** cannot be
  merged — they survive only in the migration runner's pre-migration backup
  and are listed in a `WARNING` log (`cert_watch.migrations.0031`).
  Both endpoints removed: `POST /certificates/{id}/notes`,
  `PATCH /api/certificates/{id}/notes`. The single "Notes" panel is scoped
  "operational notes for this host". Certificate-less uploaded certs have no
  notes surface.
- **V2 — RESOLVED 2026-08-30 (same branch).** The three dashboard
  single-line inline note editors were removed from `static/js/dashboard.js`
  and `dashboard.html`; the dashboard now renders a **read-only** note
  indicator chip (hover tooltip) that deep-links nothing — editing happens on
  the detail-page Notes panel (`POST /hosts/{id}/notes`, form POST).
  `PATCH /api/hosts/{id}/notes` remains as the JSON API path (no UI caller).
  One concept, one control, one verb.
- **V3 — "Webhook URL" names three distinct concepts.** Alert webhook
  (`settings/channels.html:77`), event-forwarding sink
  (`settings/events.html:36`), per-alert-group webhook
  (`settings/alert_groups.html:29`). Same noun, three stores, three delivery
  behaviors — violates "same noun, same verb". Proposed: qualify the labels
  (e.g. "Alert webhook URL" / "Event sink URL" / "Group webhook URL").
- **V4 — Owner edits ride a certificate-namespaced endpoint.**
  `POST /certificates/{id}/owner` (routes/certificates.py:559) mutates the
  *hosts* table and accepts a bare `host_id` on cert-less pages
  (`certificate_detail.html:138`). Works, but the URL misstates the record
  owner; `PATCH /api/hosts/{id}/owner` already exists unused.
- **V5 — Add-host route accepts fields the drawer never offers.**
  `POST /hosts` accepts `tags` (routes/hosts.py:136), `notes` (:139), and
  `scan_interval_hours` (:137); the drawer form (`dashboard.html:339-372`)
  exposes none of them. CSV import likewise accepts `tags`, `notes`,
  `scan_interval_hours` (routes/hosts.py:295-297) while the drawer's inline
  docs (`dashboard.html:401,405`) document only `hostname,port,threshold_days`.
  Decide: surface the fields, or drop them from the route/docs mismatch.

## Latent / unsurfaced fields

| Column | Write path(s) | UI surface |
|---|---|---|
| `hosts.expected_issuers` (schema.py:79) | `POST /hosts/{id}/expected-issuers` (routes/hosts.py:439, admin-gated form endpoint); `PUT /api/hosts/{id}/issuers` (routes/api/hosts.py:285) | **None.** No template or JS references either endpoint — a form endpoint with no form. |
| `hosts.renewal_status` (schema.py:75) | `PATCH /api/hosts/{id}/owner` only (routes/api/hosts.py:85,100-106) | **None** editable; rendered indirectly via renewal chips only. |
| `hosts.scan_interval_hours` (schema.py:71) | `POST /hosts` (:137) and CSV (:297) — API/CSV only | **None** (no drawer field, no post-creation editor). |
| `hosts.threshold_days` post-creation | none | Create-only (drawer/CSV); displayed read-only at `certificate_detail.html:191`. No edit endpoint exists. |
