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

IA note: the landing page is now **Home** (`/`, `templates/home.html` —
certificate risk, monitoring gaps, delivery/routing, and expiry horizon) and
the inventory table lives at
**/browse** (`templates/dashboard.html`, including the add-certificates
drawer). Home introduces **no editing controls**. The old per-item "scan now"
control moved off Home; endpoint detail remains its owner through
`POST /hosts/{id}/scan`. Every Home count and twelve-week bucket links to the
same scoped SQL population in Browse. Chain-trust problems are read-only,
collapsed by issuer, and link to an exact issuer filter. Browse's search
retains the selected status, source, sort, and grouping; a clear-filters link
resets the selection. Fleet grouping and calendar links open their full visible
population, with the scope stated on the selected view.

Certificate and pending-host detail now use the **Detail A** diagnosis-first
layout: hostname and tags; the canonical Certificate / Monitoring / Renewal /
Alerts axes; state-derived actions; routing; one **Edit host** disclosure; and
collapsed Certificate facts and History. The detail page does not duplicate
status computation and does not show the estate-wide health strip beside its
endpoint-specific monitoring state.

## Certificate (`certificates` table)

| Concept | Column | Editing control today | Write endpoint | Single owner (proposed) |
|---|---|---|---|---|
| ~~Notes & procedures~~ | **REMOVED** — `certificates.notes` merged by migration 0031 (deprecated column retained for unmatched notes) | — | `POST /certificates/{id}/notes` and `PATCH /api/certificates/{id}/notes` **removed** | Host-scoped notes won (V1, implemented 2026-08-30) |
| Own tags | `certificates.tags` | The top-level **Edit** disclosure on certificate detail; scanned certificates use the combined **Edit host** form, while uploaded certificates use **Edit certificate** because they have no host. Inherited host tags remain read-only and shown `(host)` | `POST /hosts/{resource_id}/edit` and `PUT /api/hosts/{resource_id}` use `services.host_edit.edit_host`; upload-only and legacy tag-only adapters remain callable | Detail A's top-level editor |
| Lifecycle (create/delete) | row | Add drawer: upload tab `dashboard.html:377`; delete `certificate_detail.html:72` | `POST /upload` + `POST /api/certificates/upload`; `POST /certificates/{id}/delete` + `DELETE /api/certificates/{id}` use `services.certificate_management` | HTML and JSON are equal adapters |

## Host (`hosts` table)

| Concept | Column(s) | Editing control(s) today | Write endpoint(s) | Single owner (proposed) |
|---|---|---|---|---|
| Ownership & renewal contact | `owner_name`, `owner_email`, `owner_slack`, `renewal_method`, `runbook_url` (schema.py:72-77) | The one **Edit host** form on endpoint detail; creation-time seeds are also accepted by Add, JSON, and CSV | `POST /hosts/{resource_id}/edit` and `PUT /api/hosts/{resource_id}` use `services.host_edit.edit_host`; field-specific adapters remain callable for compatibility; creation and import use the shared length-bounded ownership validator | Detail A's combined editor (V6); Add/import are creation-time seeds (S5) |
| Host notes | `hosts.notes` (schema.py:78) | The one **Edit host** form on endpoint detail; dashboard remains read-only. Creation-time seeds: `notes` param on `POST /hosts` and CSV `notes` column | Combined edit uses `services.host_edit.edit_host`; legacy notes-only adapters remain callable; creation/import paths are unchanged | Detail A's combined editor (V1/V2/V6) |
| Host tags | `hosts.tags` (schema.py:70) | The one **Edit host** form on pending-host detail; certificate detail edits certificate-own tags instead. Creation-time seeds remain. | Combined edit uses `services.host_edit.edit_host`; legacy tag-only adapters and creation/import remain callable | Detail A's combined editor (V6) |
| Scan target (hostname, port, TLS mode, common-ports) | `hostname`, `port` + scan params | Add drawer, scan tab — `dashboard.html:339-372` | `POST /hosts` + `POST /api/hosts`, through `services.host_management.create_hosts` | Create-only by design — OK |
| Cadence, alert threshold, renewal progress | `scan_interval_hours`, `threshold_days`, `renewal_status` | Creation/import seeds where supported; one **Edit host** form for post-creation edits | Combined edit uses `services.host_edit.edit_host`; legacy settings adapters remain callable | Detail A's combined editor (V6) |
| Lifecycle (delete, scan) | row | `certificate_detail.html:78` (delete), :64 (scan) | `POST /hosts/{id}/delete` + `DELETE /api/hosts/{id}`; `POST /hosts/{id}/scan` + `POST /api/hosts/{id}/scan`, through `services.host_management` | HTML and JSON are equal adapters |

## Tags (cross-cutting registry)

| Concept | Store | Control | Endpoint | Owner |
|---|---|---|---|---|
| Tag registry (usage, access scoping, alert routing dependents) | derived from `hosts.tags` + `certificates.tags` + roles + alert groups | **Read-only** table, Settings → Tags — `templates/settings/tags.html:22-58`; correctly states tags are edited on detail pages | — | Detail pages own edits; registry stays read-only — OK |

## Alert routing & delivery config (`kv_store` / `alert_groups`)

| Concept | Store | Control | Write endpoint | Owner |
|---|---|---|---|---|
| SMTP transport + global recipients | kv | Form, Settings → Channels — `settings/channels.html:10-56` | `POST /settings/smtp` (routes/settings/smtp.py:45) | As-is |
| Alert webhook (preset/URL/template/headers) + alert retention | kv | Form, Settings → Channels — `settings/channels.html` | `POST /settings/alerts` (routes/settings/alerts.py) | Channels owns delivery behavior; see V3 |
| Event forwarding (webhook sink, adapter kind, rate limit, PagerDuty key) | kv | Form, Settings → Events — `settings/events.html:18-62` | `POST /settings/events` (routes/settings/events.py:58) | As-is; see V3 |
| Alert groups (name, match tags, recipients, threshold, digest cadence) | `alert_groups` (schema.py:139) | Create + per-group edit forms — `settings/alert_groups.html`; legacy webhook presence is read-only | `POST /settings/alert-groups[/{id}[/delete]]` (routes/settings/alert_groups.py) | Group webhook has no delivery consumer: no editing control; ordinary edits preserve stored values. Channels owns the active alert webhook. |

## Access & administration

| Concept | Store | Control | Write endpoint | Owner |
|---|---|---|---|---|
| Auth providers (LDAP/OAuth), own password | kv / users | Settings → Auth — `settings/auth.html:10,205` | `POST /settings/auth` (routes/settings/auth.py:24); `POST /settings/change-password` (routes/settings/password.py:28) | As-is |
| Roles (name, scope tag, per-tag tiers, email), IdP role map | roles tables | Settings → Access → Roles & IdP mapping — `settings/access.html` + `settings/roles.html`; old `/settings/roles` links redirect to `#roles` | `POST /settings/roles[/{id}[/delete]]` (routes/settings/roles.py); `POST /settings/ldap-role-map` (routes/settings/auth.py) | One Access workflow (S5) |
| Local users | users | Settings → Access → Local users — `settings/access.html` + `settings/users.html`; old `/settings/users` links redirect to `#local-users` | `POST /settings/users[/{id}[/delete]]` (routes/settings/roles.py) | One Access workflow (S5) |
| API keys (scope plus immutable all-endpoints/host-tag binding) | `api_keys` | Settings → API keys — `settings/api_keys.html` | `POST /settings/api-keys[/{id}/revoke]`; JSON peer `POST/DELETE /api/api-keys[/{id}]` | API-key settings own issuance and revocation; bindings change only by revoking and reissuing |
| Daily scan time | `sched_hour`, `sched_min` kv keys (unchanged) | Settings → Policy → Scan schedule — `settings/policy.html`; Channels retains a moved-control anchor/link | `POST /settings/policy` with the schedule form marker; `PUT /api/policy` with `sched_hour` + `sched_min` | Policy owns monitoring cadence; both adapters share strict range validation (S5) |
| Policy rules | kv | Settings → Policy — `settings/policy.html` | `POST /settings/policy` (routes/settings/policy.py) | As-is |
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
- **V6 — RESOLVED 2026-09-26 (#126 S4).** Certificate and pending-host
  detail have one **Edit host** disclosure for owner/contact, renewal method,
  runbook, cadence, thresholds, operator-reported renewal progress, tags and
  notes. `POST /hosts/{resource_id}/edit` and
  `PUT /api/hosts/{resource_id}` share one atomic service and retain scope,
  CSRF, renewed-id refusal and in-transaction scope recheck guarantees. The
  service authorizes host fields against the host and certificate tags against
  the certificate; a combined edit requires both. Submitted tags must be in
  write-tier scope, and scoped writers cannot remove their last writable tag.
  Uploaded certificates expose their tag editor under the same top-level Edit
  location, labelled **Edit certificate** because no host exists. The
  field-specific endpoints remain compatible API surfaces, but no longer own
  separate controls on detail.

## Endpoint settings and scan evidence (2026-09-12)

The detail page's single **Edit host** form owns post-creation edits to
`scan_interval_hours`, `threshold_days`, and `renewal_status`, together with
ownership, contact, renewal method, runbook, tags and notes, through
`POST /hosts/{resource_id}/edit`. It is available to permitted endpoint writers,
uses CSRF protection, records `host.edit`, and wakes the scheduler.
Blank cadence uses the configured daily UTC schedule; blank threshold uses
automatic thresholds. The JSON peer requires the complete form shape so a
partial client cannot silently overwrite fields it did not read.

Renewal status is explicitly an operator report: in-progress suppresses new
stalled notices and the Home stalled status. It never suppresses expiry or
expired alerts. Completion is observed only when a scan sees a successor
certificate; operators cannot report a completed renewal manually.

Home's **Monitoring gaps** block counts the visible registered endpoints,
excluding uploads, and shows bounded failed, overdue, and never-scanned rows
plus the latest scoped scan activity and next scheduler run. Browse shows
per-endpoint scan evidence, including grouped deployments.
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
| `hosts.renewal_status` | `POST /hosts/{id}/settings`; existing `PATCH /api/hosts/{id}/owner` | Compatibility write-through: `in_progress` starts a leased durable attempt and `pending` cancels active work. Reads derive the same two values from the current attempt. |
| `hosts.scan_interval_hours` | `POST /hosts`, CSV, and `POST /hosts/{id}/settings` | Add drawer creation seed and endpoint settings editor. |
| `hosts.threshold_days` | `POST /hosts`, CSV, and `POST /hosts/{id}/settings` | Creation drawer and endpoint settings editor. |

## Executable write contracts

This table is machine-read by `tests/test_ui_inventory_contract.py`. Keep one
row per HTML/API adapter pair; the service symbol is the single mutation owner.
Bulk import and scan-all are included even though they are collection actions,
because the HTML and JSON adapters must share their mutation owner too.

| Concept | HTML endpoint | JSON endpoint | Service symbol |
|---|---|---|---|
| detail host edit | `POST /hosts/{resource_id}/edit` | `PUT /api/hosts/{resource_id}` | `host_edit.edit_host` |
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
| renewal failure clear | `POST /hosts/{host_id}/renewal-failure/clear` | `POST /api/hosts/{host_id}/renewal-failure/clear` | `renewal_reports.clear_renewal_failure` |
| expected issuers | `POST /hosts/{host_id}/expected-issuers` | `PUT /api/hosts/{host_id}/issuers` | `host_management.update_expected_issuers` |
| host delete | `POST /hosts/{host_id}/delete` | `DELETE /api/hosts/{host_id}` | `host_management.delete_host` |
| host scan | `POST /hosts/{host_id}/scan` | `POST /api/hosts/{host_id}/scan` | `host_management.scan_host_now` |
| trust anchor add | `POST /trust-anchors` | `POST /api/trust-anchors` | `certificate_management.add_trust_anchor` |
| trust anchor delete | `POST /trust-anchors/{anchor_id}/delete` | `DELETE /api/trust-anchors/{anchor_id}` | `certificate_management.delete_trust_anchor` |
| alert group create | `POST /settings/alert-groups` | `POST /api/alert-groups` | `alert_groups.create_alert_group` |
| alert group update | `POST /settings/alert-groups/{group_id}` | `PATCH /api/alert-groups/{group_id}` | `alert_groups.update_alert_group` |
| alert group delete | `POST /settings/alert-groups/{group_id}/delete` | `DELETE /api/alert-groups/{group_id}` | `alert_groups.delete_alert_group` |
| mark all alerts read | `POST /alerts/mark-all-read` | `POST /api/alerts/mark-all-read` | `alert_state.mark_all_alerts_read` |
