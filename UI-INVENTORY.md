# UI-INVENTORY — cert-watch

**Rule (content-model contract, patina plan 008): one concept, one control.**
Every concept a record exposes has exactly one editing control across the UI.
Any PR that adds, removes, or relocates a field, control, or editing surface
must diff this file in the same PR; a UI change without a matching inventory
diff fails review.

Paths are relative to `src/cert_watch/`. The HTML UI and JSON API are both
first-class consumers of the application services named below. State inventoried:
branch `review/product-coherence-20260912`, 2026-09-12 (V1 + V2 implemented;
notes are host-scoped only; inactive group-webhook controls removed).

IA note: the landing page is now **Home** (`/`, `templates/home.html` — ranked
attention queue + expiry horizon) and the inventory table lives at
**/browse** (`templates/dashboard.html`, including the add-certificates
drawer). Home introduces **no new editing controls** — its only mutating
surface is the per-item "scan now" button, which posts to the pre-existing
`POST /hosts/{id}/scan` (same endpoint the detail page and Browse rows use).
Home status cards now use Browse's expiry-and-trust definitions and link to
individual inventory entries so their counts match the destination. Browse's
search retains the selected status, source, sort, and grouping; a clear-filters
link resets the selection. Fleet grouping and calendar links open their full
visible population, with the scope stated on the selected view.

## Certificate (`certificates` table)

| Concept | Column | Editing control today | Write endpoint | Single owner (proposed) |
|---|---|---|---|---|
| ~~Notes & procedures~~ | **REMOVED** — `certificates.notes` merged by migration 0031 (deprecated column retained for unmatched notes) | — | `POST /certificates/{id}/notes` and `PATCH /api/certificates/{id}/notes` **removed** | Host-scoped notes won (V1, implemented 2026-08-30) |
| Own tags | `certificates.tags` | Text input (datalist), cert detail — `certificate_detail.html:370-374` | `POST /certificates/{id}/tags` and `PUT /api/certificates/{id}/tags` are adapters over `services.resource_metadata.update_certificate_tags` | Cert-detail tags editor (host tags inherited, shown `(host)` — OK) |
| Lifecycle (create/delete) | row | Add drawer: upload tab `dashboard.html:377`; delete `certificate_detail.html:72` | `POST /upload` + `POST /api/certificates/upload`; `POST /certificates/{id}/delete` + `DELETE /api/certificates/{id}` use `services.certificate_management` | HTML and JSON are equal adapters |

## Host (`hosts` table)

| Concept | Column(s) | Editing control(s) today | Write endpoint(s) | Single owner (proposed) |
|---|---|---|---|---|
| Ownership & renewal contact | `owner_name`, `owner_email`, `owner_slack`, `renewal_method`, `runbook_url` (schema.py:72-77) | One form ("Operational summary → Edit"), cert detail — `certificate_detail.html:138-166` | `POST /hosts/{id}/owner` and `PATCH /api/hosts/{id}/owner` are adapters over the single `services.host_ownership.update_host_ownership` transaction; legacy `POST /certificates/{id}/owner` remains callable for compatibility | Shared ownership service; host-namespaced UI path (V4 resolved) |
| Host notes | `hosts.notes` (schema.py:78) | **ONE editing control:** textarea ("Notes" panel), endpoint detail page — `certificate_detail.html` (V2 resolved 2026-08-30: the 3 dashboard inline editors in `static/js/dashboard.js` were removed; the dashboard now shows a read-only note indicator chip). Creation-time seeds: `notes` param on `POST /hosts` and CSV `notes` column | `POST /hosts/{id}/notes` and `PATCH /api/hosts/{id}/notes` are adapters over `services.resource_metadata.update_host_notes`; host creation is `POST /hosts` + `POST /api/hosts`; CSV import is `POST /hosts/import` + `POST /api/hosts/import` | Detail-page Notes panel — **resolved (V1/V2)** |
| Host tags | `hosts.tags` (schema.py:70) | Text input (datalist), cert/host detail (host branch of shared form) — `certificate_detail.html:370-374`; also creation-time seeds | `POST /hosts/{id}/tags` and `PUT /api/hosts/{id}/tags` are adapters over `services.resource_metadata.update_host_tags`; creation uses `POST /hosts` + `POST /api/hosts`; import uses `POST /hosts/import` + `POST /api/hosts/import` | Detail-page tags editor; drawer/CSV are creation-time seeds |
| Scan target (hostname, port, TLS mode, common-ports) | `hostname`, `port` + scan params | Add drawer, scan tab — `dashboard.html:339-372` | `POST /hosts` + `POST /api/hosts`, through `services.host_management.create_hosts` | Create-only by design — OK |
| Alert threshold | `threshold_days` (schema.py:69) | Create-only: drawer `dashboard.html:352`; CSV column | `POST /hosts` + `POST /api/hosts`; `POST /hosts/import` + `POST /api/hosts/import` | Endpoint settings owns post-creation edits via its HTML/API pair; see below |
| Lifecycle (delete, scan) | row | `certificate_detail.html:78` (delete), :64 (scan) | `POST /hosts/{id}/delete` + `DELETE /api/hosts/{id}`; `POST /hosts/{id}/scan` + `POST /api/hosts/{id}/scan`, through `services.host_management` | HTML and JSON are equal adapters |

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
| Alert groups (name, match tags, recipients, threshold, digest cadence) | `alert_groups` (schema.py:139) | Create + per-group edit forms — `settings/alert_groups.html`; legacy webhook presence is read-only | `POST /settings/alert-groups[/{id}[/delete]]` (routes/settings/alert_groups.py) | Group webhook has no delivery consumer: no editing control; ordinary edits preserve stored values. Channels owns the active alert webhook. |

## Access & administration

| Concept | Store | Control | Write endpoint | Owner |
|---|---|---|---|---|
| Auth providers (LDAP/OAuth), own password | kv / users | Settings → Auth — `settings/auth.html:10,205` | `POST /settings/auth` (routes/settings/auth.py:24); `POST /settings/change-password` (routes/settings/password.py:28) | As-is |
| Roles (name, scope tag, per-tag tiers, email), LDAP role map | roles tables | Settings → Roles — `settings/roles.html:74,115,126,145` | `POST /settings/roles[/{id}[/delete]]` (routes/settings/roles.py:87,125,166); `POST /settings/ldap-role-map` (routes/settings/auth.py:43) | As-is |
| Local users | users | Settings → Users — `settings/users.html:24,73,103` | `POST /settings/users[/{id}[/delete]]` (routes/settings/roles.py:199,238,287) | As-is |
| API keys | `api_keys` (schema.py:129) | Settings → API keys — `settings/api_keys.html:48,89` | `POST /settings/api-keys[/{id}/revoke]` (routes/settings/api_keys.py:33,68) | As-is |
| Policy rules | kv | Settings → Policy — `settings/policy.html:19,108` | `POST /settings/policy` (routes/settings/policy.py:20) | As-is |
| Trust anchors | `trust_anchors` (schema.py:84) | Settings → Trust anchors — `settings/trust_anchors.html:21,45` | `POST /trust-anchors` + `POST /api/trust-anchors`; `POST /trust-anchors/{id}/delete` + `DELETE /api/trust-anchors/{id}`, through `services.certificate_management` | HTML and JSON are equal adapters |

## Resolved inventory decisions

- **V1 — RESOLVED 2026-08-30 (branch `redesign/attention-home`).** Two
  near-identical notes textareas on the detail page (`hosts.notes` at
  `certificate_detail.html:229`, `certificates.notes` at `:413`).
  Per the 2026-08-14 adjudication (merge to ONE host-scoped field):
  migration **0031** concatenates every non-empty `certificates.notes` into
  the matching `hosts.notes` (matched on hostname+port) and drops the column only when no unmatched notes remain.
  Notes on uploaded certificates with **no matching host row** cannot be
  merged — they remain in the live deprecated column and the pre-migration backup
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
  `PATCH /api/hosts/{id}/notes` is the first-class JSON API adapter for the
  same service used by the detail-page form.
  One concept, one control, one verb.
- **V3 — inactive group webhook removed, 2026-09-12.** The group webhook
  field had no delivery consumer. Create/edit forms no longer offer it;
  existing values remain stored and receive a read-only explanatory notice.
  Ordinary form edits do not erase those values. Channels owns the active
  alert webhook; Events owns the independent event-forwarding sink. Channel
  copy states SMTP-first delivery, webhook fallback, and the union of global
  SMTP recipients with matching group recipients.
- **V4 — RESOLVED 2026-09-22.** The ownership form now posts to the coherent
  host-namespaced `POST /hosts/{id}/owner`, paired with
  `PATCH /api/hosts/{id}/owner`; both call the ownership service. The former
  `POST /certificates/{id}/owner` adapter remains callable for compatibility
  and delegates to the same service.
- **V5 — RESOLVED 2026-09-22.** The add-host drawer now surfaces optional
  `tags`, `notes`, and `scan_interval_hours`, and its bulk-import help documents
  every accepted optional CSV field, including `starttls_mode`.

## Endpoint settings and scan evidence (2026-09-12)

The detail page's **Edit endpoint settings** form owns post-creation edits to
`scan_interval_hours`, `threshold_days`, and `renewal_status`, through
`POST /hosts/{host_id}/settings`. It is available to permitted endpoint writers,
uses CSRF protection, records `host.update_settings`, and wakes the scheduler.
Blank cadence uses the configured daily UTC schedule; blank threshold uses
automatic thresholds. Existing owner/contact/method/runbook editing stays in
its existing form. The two forms do not overwrite each other's fields.

Renewal status is explicitly an operator report: in-progress suppresses new
stalled notices and the Home stalled status. It never suppresses expiry or
expired alerts. Completion is observed only when a scan sees a successor
certificate; operators cannot report a completed renewal manually.

Home's **Scan coverage** panel counts the visible registered endpoints, excluding
uploads. Browse shows per-endpoint scan evidence, including grouped deployments.
The detail **Scan evidence** panel distinguishes last success, latest attempt,
observation due time and retry eligibility. It replaces the ambiguous old
“Last scanned” field. These are read-only views.

Activity's **Why and delivery details** disclosure shows the recorded trigger;
administrators can inspect durable transport attempts and routing inputs at the
attempt. Existing alerts without evidence say so. Configured-channel and current
group chips were removed because they did not establish historical delivery.

## Legacy and creation-only fields

| Column | Write path(s) | UI surface |
|---|---|---|
| `hosts.expected_issuers` | Existing admin form/API write paths retained for compatibility | Read-only legacy value on details for admins, explicitly not monitored after CT removal. No new policy editor. |
| `hosts.renewal_status` | `POST /hosts/{id}/settings`; existing `PATCH /api/hosts/{id}/owner` | Endpoint settings; `pending` or operator-reported `in_progress`, which suppresses only renewal-stalled notices. |
| `hosts.scan_interval_hours` | `POST /hosts`, CSV, and `POST /hosts/{id}/settings` | Endpoint settings editor; no creation drawer field. |
| `hosts.threshold_days` | `POST /hosts`, CSV, and `POST /hosts/{id}/settings` | Creation drawer and endpoint settings editor. |

## Executable write contracts

This table is machine-read by `tests/test_ui_inventory_contract.py`. Keep one
row per HTML/API adapter pair; the service symbol is the single mutation owner.
Bulk import and scan-all are included even though they are collection actions,
because the HTML and JSON adapters must share their mutation owner too.

| Concept | HTML endpoint | JSON endpoint | Service symbol |
|---|---|---|---|
| certificate tags | `POST /certificates/{cert_id}/tags` | `PUT /api/certificates/{cert_id}/tags` | `resource_metadata.update_certificate_tags` |
| certificate upload | `POST /upload` | `POST /api/certificates/upload` | `certificate_management.upload_certificate_bytes` |
| certificate delete | `POST /certificates/{cert_id}/delete` | `DELETE /api/certificates/{cert_id}` | `certificate_management.delete_certificate` |
| host ownership | `POST /hosts/{host_id}/owner` | `PATCH /api/hosts/{host_id}/owner` | `host_ownership.update_host_ownership` |
| host notes | `POST /hosts/{host_id}/notes` | `PATCH /api/hosts/{host_id}/notes` | `resource_metadata.update_host_notes` |
| host tags | `POST /hosts/{host_id}/tags` | `PUT /api/hosts/{host_id}/tags` | `resource_metadata.update_host_tags` |
| host create | `POST /hosts` | `POST /api/hosts` | `host_management.create_hosts` |
| host import | `POST /hosts/import` | `POST /api/hosts/import` | `host_management.import_hosts_csv` |
| host scan all | `POST /hosts/all/scan` | `POST /api/hosts/scan` | `host_management.scan_all_hosts` |
| host settings | `POST /hosts/{host_id}/settings` | `PATCH /api/hosts/{host_id}/settings` | `host_management.update_host_settings` |
| expected issuers | `POST /hosts/{host_id}/expected-issuers` | `PUT /api/hosts/{host_id}/issuers` | `host_management.update_expected_issuers` |
| host delete | `POST /hosts/{host_id}/delete` | `DELETE /api/hosts/{host_id}` | `host_management.delete_host` |
| host scan | `POST /hosts/{host_id}/scan` | `POST /api/hosts/{host_id}/scan` | `host_management.scan_host_now` |
| trust anchor add | `POST /trust-anchors` | `POST /api/trust-anchors` | `certificate_management.add_trust_anchor` |
| trust anchor delete | `POST /trust-anchors/{anchor_id}/delete` | `DELETE /api/trust-anchors/{anchor_id}` | `certificate_management.delete_trust_anchor` |
| alert group create | `POST /settings/alert-groups` | `POST /api/alert-groups` | `alert_groups.create_alert_group` |
| alert group update | `POST /settings/alert-groups/{group_id}` | `PATCH /api/alert-groups/{group_id}` | `alert_groups.update_alert_group` |
| alert group delete | `POST /settings/alert-groups/{group_id}/delete` | `DELETE /api/alert-groups/{group_id}` | `alert_groups.delete_alert_group` |
| mark all alerts read | `POST /alerts/mark-all-read` | `POST /api/alerts/mark-all-read` | `alert_state.mark_all_alerts_read` |
