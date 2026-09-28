# Upgrading cert-watch

## How upgrades work

Install the new version over the same data directory and start it. On
startup, cert-watch:

1. takes a lock so a second process starting at the same time waits;
2. writes a backup of the database next to it
   (`cert-watch-pre-migration-<timestamp>-<id>.sqlite3`);
3. applies each pending schema migration in its own transaction, recorded in
   `schema_version`.

A migration that fails leaves the database exactly as it was, and startup
stops with the error. There is no separate migrate command.

Upgrades only go forward. To roll back, stop cert-watch, restore the
pre-migration backup (see [operations.md](docs/operations.md#restoring)), and
start the previous version.

**Supported upgrade path: 0.9.x to 1.0.** A test replays a real 0.9.0
database through the upgrade and checks that nothing is lost. For an older
release, upgrade to 0.9.x first. Or start a fresh 1.0 and re-add your hosts
with the CSV import; history is not carried over that way.

## Upgrading from 1.1.1 (unreleased)

### Migration 0045

Migration **0045** adds an explicit binding and bound-tag list to API keys.
Every existing `read`, `write` and `admin` key is assigned `binding='all'`, so
its access does not change. New `renewal-report` keys must deliberately choose
all endpoints or at least one host tag.

Renewal-report key hashes use a format older binaries do not recognize, so an
older cert-watch rejects those credentials. Database rollback is not
supported: stop cert-watch and restore the pre-migration backup before
starting an older binary. Do not point an older binary at the migrated
database.

### Migration 0046

Migration **0046** adds the append-only renewal report ledger with opaque public
identifiers and an internal non-reusing sequence, retained attempt and
correlation history, a one-current-attempt-per-endpoint projection, and
source-and-endpoint-scoped idempotency records. It does not backfill or
reinterpret the existing `renewal_status` column; that compatibility
transition is intentionally deferred to the next slice. Endpoint deletion
removes all of the new endpoint-owned data.

### Migration 0047

Migration **0047** converts every host stored as `in_progress` into an open
renewal attempt. Its lease begins at upgrade time and lasts for
`renewal_report_lease_hours` (24 hours by default). Each conversion is written
to the audit log. The compatibility column remains in this release, but reads
derive `renewal_status` from the attempt and all existing writes create or
cancel durable reports.

Hosts left “in progress” for weeks will therefore start receiving
renewal-stalled notices 24 hours after the upgrade. Re-marking the same served
certificate shows work as in progress but does not stop those notices because
the migration used that leaf's one stall-suppressing lease. A new certificate,
or the lease lapsing followed by an actual renewal, stops them.

### Migration 0048

Migration **0048** adds verification counters and timestamps, including the
accepted-success time that anchors grace and check bands, to renewal
attempts and a short-lived endpoint scan-claim table. Existing attempts keep
their current state. New successful reports are verified by normal stored
scans; the request path performs no network I/O. Configure the grace before an
unchanged scan can raise `renewal_not_deployed` with
`renewal_verify_grace_minutes` (5 minutes by default, accepted range 5–15).
Rollback requires restoring the pre-migration backup.

## Upgrading from 1.1.0 to 1.1.1

API-key audit actors now use the stable `api_key:<id>` format instead of the
key's display name. The display name is retained as `api_key_name` in the
audit event's `detail` object. Update SIEM rules or other audit consumers that
match API-key events by actor name; human-user actor values are unchanged.
The Activity actor filter accepts the stored value, a bare full id, the
displayed eight-digit short id, or the API-key display name. Key rows are
labelled as API keys even when a human and a key share the same name.

Generic webhook templates use JSON mode only when, after leading BOMs and
whitespace are removed, they start with `{` and parse as a JSON object after
neutral placeholder substitution. JSON string values are escaped for one JSON
level; JSON embedded inside a string is not escaped a second time. Text
templates remain `text/plain`, have control characters removed from values,
and are not escaped for structured formats such as form encoding.

After this version, a generic webhook template that starts with `{` after
leading BOMs and whitespace but is not valid JSON after neutral substitution
is refused when saved and at send time, as is a JSON template with any
unquoted placeholder other than `{{threshold_days}}`. This is the only
delivery behaviour change for existing templates; startup logs a warning naming the generic
channel when an environment-provided or previously saved template would be
refused.

### Migration 0044

Migration **0044** adds a classifier version to each persisted endpoint
renewal result and backfills the rows using the current classifier. On later
upgrades, startup refreshes only rows written by an older classifier version;
reads ignore a mismatched row, so they never serve an old classification.

The migration also replaces the certificate-history insert trigger. A
chronologically appended observation of the current fingerprint preserves the
cached classification when it cannot add classifier evidence. New fingerprint
periods, out-of-order observations, a later observation that supplies missing
certificate validity, retention pruning, and every history update or delete
still invalidate or recompute the affected endpoint.

## Upgrading from 1.0.4 to 1.1.0

1.1.0 describes every endpoint with four separate facts -- certificate
condition (expiry only), monitoring (is the scan current), renewal, and alert
delivery -- and rebuilds Home, Browse, certificate detail and Posture around
them. One schema migration is applied on startup; nothing needs
reconfiguring. Several API responses and exports change shape, and recipient
details are now hidden from read-only callers, so check any scripts against
the list below before upgrading.

### Migration 0043

Migration **0043** adds a small per-endpoint renewal-analytics table and
backfills it from retained certificate history using the same Python
classifier used by the renewal API, readiness report, digest and webhook.
Startup time grows with retained history while this one-time backfill runs.
Afterward, successful scans, history retention and certificate deletion
update the result in the same transaction as the history change. If history
is changed outside cert-watch, a database trigger invalidates the affected
result and Browse shows its renewal evidence as *Unknown* until that
endpoint's next successful scan refreshes it; it never uses stale evidence.

### Recipient details are visible only to writers

Recipient identities -- alert-group names and recipient addresses (group
members, the host owner, global and role-member recipients) -- and a host's
`owner_email` and `owner_slack` are now shown only to administrators and to
callers with write access to that certificate: a global write tier, a per-tag
write tier on one of its effective tags, or a `write` or `admin` API key.
Everyone else who can see the certificate still gets the delivery state,
channel types and anonymous counts, and `owner_name` stays visible. With
authentication disabled nothing is hidden.

For a caller without write access to the certificate:

- The detail page shows *Configured · hidden for read-only access* in place
  of the owner's email address, and the recipient table shows counts
  (*2 recipients*, *1 matched alert group*) instead of addresses and group
  names.
- `GET /api/certificates`, `GET /api/hosts`,
  `GET /api/export/certificates.json`, `GET /api/export/hosts.csv` and pivot
  group rows (`GET /api/pivot/...`) return `owner_email` and `owner_slack` as
  empty strings. The fields are still present.
- Every `status.delivery` block (see below) holds only `state`,
  `recipient_count`, `matching_group_count` and, per channel, `channel` and
  `route_count`.
- `GET /api/certificates/{id}/alert-routing` **omits** `matched_groups` and
  `recipients` altogether, returning only `cert_id`, `effective_tags` and the
  reduced `delivery` block.

**A script that uses a `read` API key and reads owner contacts or alert
recipients will get empty or missing values after the upgrade.** Give it a
`write` key if it needs them.

### API and export changes

- **`urgency` now reports the endpoint, not only its certificate.** In
  `GET /api/certificates`, `GET /api/export/certificates.json` and pivot
  group rows, an endpoint whose scans are failing or overdue now has
  `urgency: "failing"` (a new value; the pivot `urgency_label` is *Scan
  failing*) instead of its certificate's expiry state, and one that has never
  been scanned has `"gray"`. The same value is repeated in a new
  `overall_state` field; `leaf_urgency` is unchanged. The `urgency` of each
  entry in `GET /api/reports/compliance.json` follows the same rule.
- **CSV column renamed.** The `urgency` column of
  `/api/export/certificates.csv`, `/api/reports/inventory.csv` and
  `/api/reports/expiring.csv` is now `overall_status`, with the same values
  as `overall_state`. `certificates.csv` and `inventory.csv` also gain
  `condition`, `monitoring`, `renewal` and `delivery` columns at the end of
  each row, and the `port` column of `inventory.csv` and `expiring.csv`,
  which was always empty, is now filled in. The compliance CSV
  (`/api/reports/compliance.csv`) replaces its *Urgency* column with
  *Condition*, *Monitoring*, *Renewal* and *Delivery*. Compliance reports
  signed by 1.0.4 or earlier still verify.
- **New fields.** Certificate list and export rows gain the four facts
  (`condition`, `monitoring`, `renewal`, `delivery`), their evidence
  (`monitoring_*`, `renewal_source`, `renewal_analytics`, `has_successor`),
  `hostname`, `port`, `scan_interval_hours`, and a nested `status` object
  with `condition`, `monitoring` (including a plain-language `cause` and the
  `raw_error`), `renewal`, `delivery`, `chain_status` and
  `chain_trust_problem`. `GET /api/certificates/{id}` gains the same `status`
  object (`null` when the certificate is not an inventory row, for example a
  chain certificate). Each `GET /api/hosts` entry gains `renewal_method` and
  `status`. `GET /api/certificates/{id}/alert-routing` gains `delivery`.
- **New filters.** `GET /api/certificates`, `GET /api/hosts` and Browse
  accept `condition=expired|le7|8to30|ok`,
  `monitoring=current|failing|never_scanned`,
  `renewal=automation_configured|manual|stalled|in_progress|unknown` and
  `delivery=ok|failing|unrouted`, combinable with each other and with
  pagination. On the two JSON APIs **an unknown or empty value returns
  `400`** (`{"error": "invalid condition filter: ..."}`); Browse ignores it
  and says so. Browse also accepts `routing_gap=1`, `chain_problem=1` (with
  an optional `issuer`) and `expiry_week=YYYY-MM-DD`, which Home's links use.
- **`GET /api/hosts` scope.** A tag-scoped caller now also sees a host whose
  certificate carries one of their tags even when the host itself does not,
  as Browse and `GET /api/certificates` already did. `/api/export/hosts.csv`
  still matches on host tags only. Ordering (by date added) and the page-size
  limit (200) are unchanged.
- **Daily scan time in the policy API.** `GET /api/policy` and the
  `PUT /api/policy` response include `sched_hour` and `sched_min`.
  `PUT /api/policy` now accepts them (both together; hour 0-23, minute 0-59,
  otherwise `400`) and applies them immediately. 1.0.4 ignored them.
- **`/metrics`.** `cert_watch_certificates_by_urgency` counts the same
  endpoint state as `overall_state`, so it has two new label values,
  `failing` and `gray`, and an endpoint whose scans are failing moves out of
  its certificate's expiry bucket into `failing`.
- **Browser 404 page.** A browser request (`Accept: text/html`) for an
  unknown page outside `/api/` now gets an HTML *Not found* page. API paths
  and other clients still get `404 {"detail": "Not Found"}`.

### Writes: new endpoints and stricter validation

- **Edit host.** On an endpoint's detail page, the separate owner, renewal,
  tags, cadence and threshold, and notes editors are replaced by one *Edit
  host* form, saved in one transaction by `POST /hosts/{id}/edit`. (An
  uploaded certificate with no host keeps a tags-only *Edit certificate*
  form.) Its JSON peer is `PUT /api/hosts/{id}`, which requires exactly these
  fields: `owner_name`, `owner_email`, `owner_slack`, `renewal_method`,
  `runbook_url`, `scan_interval_hours`, `threshold_days`, `renewal_status`,
  `notes` and `tags`. `{id}` may be a host id or a current certificate id;
  addressed by certificate, `tags` sets the certificate's own tags (the
  response says `"tags_apply_to": "certificate"`), otherwise the host's. The
  host fields are authorized against the host's own tags and the tags against
  the certificate, so a caller needs write access to both.
- **The field-specific endpoints are still accepted:**
  `POST /hosts/{id}/owner`, `/settings`, `/notes` and `/tags`;
  `POST /certificates/{id}/owner` and `/tags`;
  `PATCH /api/hosts/{id}/owner`, `/settings` and `/notes`;
  `PUT /api/hosts/{id}/tags` and `PUT /api/certificates/{id}/tags`. Apart
  from the host-scope, tag and ownership rules below, the only difference is
  that `POST /hosts/{id}/settings` now redirects to `#edit-host` instead of
  `#endpoint-settings`.
- **Host fields are authorized against the host on every route.** Every
  write of host-level fields (owner, owner email and Slack handle, renewal
  method and status, runbook) is judged by the host's own tags, before and
  inside the write transaction, even when the route is addressed by a
  certificate id. This closes a 1.0.4 gap: `POST /certificates/{id}/owner`
  was judged by the certificate's effective tags, so a tag-scoped operator
  whose only write access came from a tag set on the certificate could change
  the owner email -- an alert recipient -- of a host belonging to another
  team. Such a request is now refused (*operation not permitted outside your
  team scope*). If a scoped team edited ownership through a certificate tag,
  give it a writable tag on the host, or have an administrator make the
  change.
- **Tag writes need write access to every tag.** For a tag-scoped user,
  every tag submitted -- when editing host or certificate tags, adding or
  importing hosts, or uploading a certificate -- must be one their role can
  write; a tag they can only read is refused (`403` from the JSON APIs:
  *your access to tag '...' is read-only*). The scope tags merged in
  automatically when such a user adds or imports hosts or uploads a
  certificate are now only the ones they can write. A scoped user also
  cannot remove the last tag through which they can write a host or
  certificate (*at least one tag in your writable team scope must remain on
  the resource*); for a certificate, the host's tags count toward this.
  Administrators, unscoped users and API keys are unaffected.
- **Ownership on Add, JSON create and CSV import.** `POST /hosts` (the Add
  drawer offers owner name, owner email and renewal method),
  `POST /api/hosts` (which rejected these fields in 1.0.4) and CSV import
  accept `owner_name`, `owner_email`, `owner_slack`, `renewal_method` and
  `runbook_url`, validated like the ownership editor. They apply only to a
  newly added endpoint; an endpoint that was already monitored keeps its
  ownership, and Add and `POST /api/hosts` say so (the JSON response gains a
  `notice`). Because CSV import now reads these columns, re-importing an
  exported `hosts.csv` sets ownership on the endpoints it adds, and a row
  with an invalid owner email or renewal method is reported as an error
  instead of being imported without them.
- **Ownership field limits.** Every write path -- Add, `POST /api/hosts`,
  CSV import, *Edit host* (`POST /hosts/{id}/edit`, `PUT /api/hosts/{id}`)
  and the field-specific ownership endpoints (`POST /hosts/{id}/owner`,
  `POST /certificates/{id}/owner`, `PATCH /api/hosts/{id}/owner`) -- trims
  surrounding whitespace and refuses values longer than 200 characters
  (`owner_name`), 254 (`owner_email`), 100 (`owner_slack`) or 2048
  (`runbook_url`); 1.0.4 stored them as sent. Values already stored are not
  changed by the upgrade.
- **Daily scan time moved to Policy.** The daily scan time now lives on
  Settings → Policy and is saved by `POST /settings/policy`, which rejects an
  hour outside 0-23 or a minute outside 0-59. The Channels form
  (`POST /settings/alerts`) **no longer saves `sched_hour` or `sched_min`**
  and ignores them if sent. The configuration keys and the
  `CERT_WATCH_SCHED_HOUR` / `CERT_WATCH_SCHED_MIN` environment variables are
  unchanged.
- **Roles, IdP role mapping and local users** share one page, Settings →
  Access (`/settings/access`). `/settings/roles`, `/settings/users` and
  `/settings?tab=roles|users` redirect to its `#roles` and `#local-users`
  sections, and the role, role-map and user forms return there after saving.
  Permissions are unchanged.

### What looks different

- **Home** is three blocks -- certificate risk, monitoring gaps, and alert
  delivery and routing -- in place of the urgency cards and the *Needs
  attention* queue. Every number opens the matching Browse rows. The
  *Monitoring pipeline healthy* status strip no longer appears on Home or on
  certificate detail pages; other pages still show it.
- **Browse** rows state the certificate's condition in days and show
  monitoring, chain, renewal and delivery only when they need attention. An
  endpoint whose scans are failing, overdue or have never succeeded is no
  longer shown as healthy because its last certificate was fine.
- **Certificate detail** leads with the four facts and numbered next steps,
  puts *Scan now* in the header, lists who gets alerted, and collapses
  certificate facts (including the grade) and history.
- **Posture** shows the grade distribution and the lowest-grade certificates
  instead of one fleet grade set by the worst certificate. Grade and TLS
  trends appear once visible history spans more than 30 days.
- **Colour means status only.** Links, focus rings and the wordmark are
  neutral; expired shares the critical colour with the word *Expired*; a
  failing scan is shown as a warning, not critical.

## Upgrading from 1.0.3 to 1.0.4

The manual `renewed` host status has been removed. Operators can still mark a
renewal `in_progress`, which suppresses renewal-stalled notices only; expiry
warnings and expired alerts always remain active until a scan observes a
successor certificate.

Migration **0041** changes every stored `renewed` status to `pending` and
writes one audit-log row for each host changed. Scripts that send
`renewal_status: "renewed"` to either host write API must be updated: the
request now receives a `400` or `422` validation error instead of being
accepted. Use `in_progress` only while work is underway, or omit the field/use
`pending` when it is not.

Four schema migrations are applied on startup; nothing else to reconfigure.

- **0039** adds a cached chain status to each certificate row
  (`chain_status`, `chain_status_basis`). The cache is filled on the first
  page load after the upgrade, one chain verification per certificate. Until
  a certificate's entry is filled -- and whenever its chain, the trust
  anchors or the system CA bundle change, until it is re-verified -- it
  counts as *unverified* (Warning), never Healthy.
- **0040** adds `alerts.failed_at`, the time an alert gave up, which
  `/api/health` `failed_alerts_24h` and `cert_watch_alerts_failed_recent`
  now count by. Existing failed alerts are dated by their last delivery
  attempt; one that failed without any attempt is dated to the upgrade, so
  it shows as a recent failure for the first 24 hours rather than possibly
  being missed.
- **0042** adds `certificate_lineage`, an internal record of renewals (old
  certificate id, new id, host and port) that the scan writes with each
  renewal. Links to a renewed certificate follow it, so they no longer stop
  working when events age out of the event-log retention period or when
  `cert_renewed` is switched off under Settings → Event stream. The record
  is backfilled from stored certificates and from any `cert_renewed` events
  still retained whose chain reaches a stored certificate on the same host
  and port; the startup log reports how many of each. It is kept for good
  (one small row per renewal) and is not part of the event stream.

Behaviour to be aware of: Home's *Needs attention* panel lists the 50 most
urgent items and says how many there are, and expanding a group in the
issuer, owner or renewal-method views loads 100 rows at a time. Tag scopes
now match tags stored with spaces (`staging, edge` is in scope `edge`)
everywhere, as grouped Browse already did.

Bulk actions now act only on what the caller may change. For a user whose
role gives write access on some tags and read-only access on others, *Scan
all*, *Mark all read* and *Flush* cover only the writable tags (they used to
include read-only ones), and a user with no writable tag gets nothing selected.
*Scan all*, adding hosts and CSV import report a `refused` count or per-row
message when a host moves out of the caller's scope while its scan is running,
instead of failing the whole request.

One more behaviour change affects access control:

- **Certificate tags are now durable grants.** A scan no longer wipes the
  tags set on a certificate itself, and a renewal carries them to the new
  certificate. In 1.0.3 and earlier the next scan cleared them, so removing
  a team's tag from the *host* was enough to revoke that team's access within
  a scan cycle. Now a team keeps access through a tag set on the certificate
  until that tag is removed too. Before relying on a host tag change to revoke
  access, check the certificate's own tags on its detail page. (Tags that
  earlier releases already wiped are not restored.)

## Upgrading from 1.0.2 to 1.0.3

One schema migration, **0038**, rewrites every stored host name to one
canonical spelling (lower-case IDNA A-labels without a trailing dot; the
compressed form for IP literals) across `hosts`, `certificates`,
`scan_history`, `cert_history`, `scan_posture`, `alerts`, event payloads and
alert dedupe keys. Read [CHANGELOG.md](CHANGELOG.md) for why. Three things to
know:

- **It can take a while on a large database.** Each table is rewritten in a
  single pass, so a few thousand hosts with tens of thousands of events take
  seconds, not minutes, but the pre-migration backup copies the whole
  database file first. The application does not open its port until
  migrations finish. On Kubernetes, `deploy/k8s/deployment.yaml` now has a
  `startupProbe` (15 minutes) for that reason; if you use your own manifest
  with only a liveness probe, add one or raise the liveness
  `failureThreshold` before upgrading, or a long migration is killed and
  retried indefinitely. On IIS the startup limit is 60 s
  (`deploy/iis/web.config`). If the database is large, migrate before
  starting the site: stop the site, run `cert-watch` from a console with the
  same `CERT_WATCH_*` environment the site uses (at least the database
  path), wait for the `migration 0038 applied` log line, stop it with
  Ctrl+C, then start the site.
- **Two rows that spell one endpoint are collapsed.** If both rows carry the
  same tags, they are merged. If they carry different tags, the migration
  fails closed: the surviving row keeps only the tags both had (none, if
  disjoint, which makes the endpoint visible to administrators only); every
  other field (owner, notes, threshold, scan interval, expected issuers,
  STARTTLS mode, renewal status and method, runbook) is kept only where both
  agreed and otherwise reset to its default; the certificates under that
  endpoint lose their per-certificate tags and any alert-group assignment
  not shared by both; and alerts still queued for them are sent to the
  global recipients only, not to the recipients they were queued with.
  Nothing is deleted from the history. Every such collapse is a
  `WARNING` line in the startup log and an audit entry with action
  `host.merge_alias` that holds the removed row and every dropped value in
  full. **After upgrading, an administrator should open the audit log,
  filter for `host.merge_alias`, and re-tag or re-own the affected endpoints
  deliberately.**
- **`/readyz` and `/api/health` return a shallow body to non-administrators.**
  Status codes are unchanged, so Kubernetes probes, the Docker health check
  and `Verify-Install` are unaffected. A script that reads the detailed body
  with a non-administrator account or a `read`/`write` API key now gets only
  `{"status": ...}` / `{"overall": ...}`; use `/readyz` with the metrics
  token, or an `admin` API key.
- Host names typed as legacy numeric IPv4 forms (`010.010.010.010`,
  `8.8.2056`, `0x08080808`) are rejected from now on; write the dotted quad.
  Stored ones are folded into the dotted-quad row by the migration.

## Upgrading from 1.0.1 to 1.0.2

Nothing to migrate or reconfigure. Two behaviour changes to be aware of:

- JSON API request bodies are limited to 256 KiB and 64 levels of nesting;
  larger or deeper bodies get `400`. Every JSON endpoint takes small bodies
  (the largest real one is a host note, capped at 10,000 characters), so
  this only affects a client that sends far more than the API uses.
- The container image runs Python 3.14 and no longer contains `pip`. If you
  extend the image or run `pip` inside the container, install it in your own
  layer.

## Upgrading from 1.0.0 to 1.0.1

Nothing to migrate and nothing to reconfigure: install the new version and
restart. On Windows/IIS, re-run the installer from the 1.0.1 source with your
original arguments. The IIS steps under [Upgrade](#upgrade) below show how
to recover them from the live site; from 1.0.1 on, the installer records
them in `install-args.json`.

If you ran `scripts\Verify-Install.ps1` on an earlier version, delete any
`verify-report.json` / `verify-report.md` it wrote (by default in
`<InstallDir>\logs\`, or the directory you ran it from when that folder
didn't exist) and any copies you shared: they can contain your
`web.config` verbatim, including secrets set inline rather than through a
`*_FILE` variable. See the 1.0.1 entry in [CHANGELOG.md](CHANGELOG.md).

## Upgrading from 0.9 to 1.0

1.0 is the release where cert-watch's defaults became strict. Most
installations need to do nothing, but go through this list first: several
items can lock someone out or change who gets alerted.

### Before you upgrade

- [ ] **Back up the database and its secrets.** On a command-line install, run
      `cert-watch backup /backups/cert-watch-pre-1.0.sqlite3` and keep the data
      directory's `.auth_secret` if cert-watch generated it.

      For Docker Compose, first write the WAL-safe backup inside the persistent
      `/var/lib/cert-watch` mount, then copy it out of the volume:

      ```bash
      docker compose exec cert-watch cert-watch backup \
        /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3
      docker compose cp \
        cert-watch:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3 \
        ./cert-watch-pre-1.0.sqlite3
      # If the app generated its signing key in the data directory, copy it too.
      docker compose cp cert-watch:/var/lib/cert-watch/.auth_secret ./.auth_secret
      ```

      With plain Docker, the equivalent commands are `docker exec cert-watch
      cert-watch backup /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3` and
      `docker cp cert-watch:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3 .`;
      copy `.auth_secret` too if it exists. If the signing key is supplied by
      container configuration instead, preserve it in that secret store.

      On Kubernetes, target the pod, write the backup inside the PVC mount, and
      copy it out:

      ```bash
      pod=$(kubectl get pod -n cert-watch \
        -l app.kubernetes.io/name=cert-watch \
        -o jsonpath='{.items[0].metadata.name}')
      kubectl exec -n cert-watch "$pod" -- cert-watch backup \
        /var/lib/cert-watch/cert-watch-pre-1.0.sqlite3
      kubectl cp -n cert-watch \
        "${pod}:/var/lib/cert-watch/cert-watch-pre-1.0.sqlite3" \
        ./cert-watch-pre-1.0.sqlite3
      ```

      The supplied Kubernetes deployment reads its signing keys from the
      `cert-watch-secrets` Kubernetes Secret, not from the data directory. Keep
      that Secret in your secret-management system, or export it separately
      and protect the exported file; never commit it:

      ```bash
      kubectl get secret -n cert-watch cert-watch-secrets -o yaml \
        > cert-watch-secrets.yaml
      ```

      A Windows/IIS install instead uses `secrets\auth_secret` and
      `secrets\csrf_secret` through the `*_FILE` settings in `web.config`. Its
      CLI is inside the install directory and does not inherit the environment
      variables from `web.config`; for a default install, use an elevated
      PowerShell:

      ```powershell
      $dataDir = "C:\ProgramData\cert-watch"
      $env:CERT_WATCH_DATA_DIR = $dataDir
      & "$dataDir\venv\Scripts\cert-watch.exe" backup "C:\backups\cert-watch-pre-1.0.sqlite3"
      Copy-Item "$dataDir\secrets\auth_secret", "$dataDir\secrets\csrf_secret" "C:\backups"
      ```

      Set `$dataDir` and `CERT_WATCH_DATA_DIR` to the actual data directory if
      `-InstallDir` was used.
- [ ] **LDAP over plain `ldap://` is refused.** A simple bind now needs
      `ldaps://` or `LDAP_START_TLS=1`. If you can't change that yet, set
      `CERT_WATCH_LDAP_ALLOW_INSECURE=1`, knowing it sends directory
      passwords in cleartext.
- [ ] **If you use `CERT_WATCH_ADMINS` or `CERT_WATCH_WRITE_USERS` without a
      role mapping,** they are now enforced. Make sure every administrator is
      in `CERT_WATCH_ADMINS`. With only `CERT_WATCH_WRITE_USERS` set,
      administration is limited to those users too.
- [ ] **If you have saved a role mapping under Settings → Roles,** it now
      takes effect. It had been saved but never used. Directory users who
      match no mapping become read-only, so map your administrators first.
      Once a mapping has been saved there, clearing it leaves directory users
      read-only rather than restoring full access. See
      [access-control.md](docs/access-control.md#1-role-mapping-recommended).
- [ ] **Review three saved settings** that earlier releases saved but
      ignored, because they now apply: the OAuth scope, the LDAP user filter,
      and the alert webhook kind. Where an environment variable and a saved
      value both set `SMTP_PORT`, `LDAP_CONNECT_TIMEOUT` or
      `ALERT_DIGEST_ONLY`, the environment variable now wins.
- [ ] **Prometheus:** set `CERT_WATCH_METRICS_TOKEN` and scrape with it.
      Without a token, `/metrics` answers only an administrator's browser
      session.
- [ ] **API clients:** JSON writes must send `Content-Type:
      application/json` and a JSON object. Creating and revoking API keys now
      needs an administrator's browser session; an API key can't manage keys.
- [ ] **Anything that imports cert-watch in Python:** `cert_watch.alerts`,
      `cert_watch.alert_delivery`, `cert_watch.alert_adapters` and
      `cert_watch.digest` are gone. Import from `cert_watch.alerting`.
- [ ] **Alert-webhook consumers that match the renewal digest's subject:** it
      now shows the digest window, e.g. `Renewal Digest (14d)`, instead of a
      fixed `(7d)`.
- [ ] **If you scan carrier-grade NAT addresses (`100.64.0.0/10`)**, they now
      count as private: allow private addresses, and include the range in
      `CERT_WATCH_ALLOWED_SUBNETS` if you use it.
- [ ] **If you run with authentication disabled and reach it by a name other
      than `localhost`**, set `CERT_WATCH_BASE_URL` to that name. Requests
      for other host names are refused.

### Upgrade

- **Container / Compose:** pull `ghcr.io/hraedon/cert-watch:v1.0.0`, verify it
  ([install.md](docs/install.md#verifying-an-image)), and restart on the same
  volume.
- **Kubernetes:** update the image and apply. The `Recreate` strategy ensures
  the old pod has stopped before the new one migrates.
- **Linux:** re-run `scripts/install-linux.sh`, or install the new version into
  the existing virtual environment and restart the service. The script
  rewrites the unit file, so keep local settings in a drop-in
  (`systemctl edit cert-watch`), not in the unit itself.
- **Windows / IIS:** download and extract the `vX.Y.Z` source archive from the
  repository's GitHub **Tags** page (or a release page's generated **Source
  code** link), then run `scripts\install-windows.ps1` from that extracted
  tree with your original arguments. The release workflow publishes container
  images; it does not attach a Windows installer asset.

  Recover the values the live IIS site actually uses before re-running the
  installer. The following also shows child applications, because one can
  override the root site's pool or physical path:

  ```powershell
  Import-Module WebAdministration
  $site = Get-Website -Name "cert-watch"
  $site | Select-Object Name, physicalPath, applicationPool
  Get-WebApplication -Site "cert-watch" |
      Select-Object Path, physicalPath, applicationPool
  $pool = [string]$site.applicationPool
  Get-Item "IIS:\AppPools\$pool" | Select-Object Name, State

  $sitePath = [Environment]::ExpandEnvironmentVariables([string]$site.physicalPath)
  [xml]$webConfig = Get-Content (Join-Path $sitePath "web.config")
  $httpPlatform = $webConfig.configuration.'system.webServer'.httpPlatform
  $python = [Environment]::ExpandEnvironmentVariables([string]$httpPlatform.processPath)
  $installDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $python))
  $dataSetting = $httpPlatform.environmentVariables.environmentVariable |
      Where-Object name -eq "CERT_WATCH_DATA_DIR"
  $dataDir = [Environment]::ExpandEnvironmentVariables([string]$dataSetting.value)
  [pscustomobject]@{ InstallDir = $installDir; DataDir = $dataDir; AppPool = $pool; SitePath = $sitePath }

  $argsRecord = Join-Path $installDir "install-args.json"
  if (Test-Path $argsRecord) { Get-Content $argsRecord }

  & $python -m pip show ldap3 authlib
  Get-WebBinding -Name cert-watch -Protocol https |
      Select-Object bindingInformation, sslFlags
  netsh http show sslcert ipport=0.0.0.0:443
  # For an SNI binding, use the host from bindingInformation instead:
  netsh http show sslcert hostnameport=certs.example.com:443
  ```

  The Python path identifies `-InstallDir`; the root site's `physicalPath` is
  `-SitePath`; and its `applicationPool` is `-AppPool`. If the cert-watch
  application is a child application, use the corresponding
  `Get-WebApplication` row instead. If both Python packages are present,
  retain `-WithAuthExtras`. An IIS binding such as
  `*:443:certs.example.com` supplies `-HostName certs.example.com`;
  `sslFlags=1` supplies `-SharePort443`. The matching `netsh` entry reports the
  certificate hash to pass as `-TlsCertThumbprint`.

  Installers from 1.0.1 on also write the supplied, non-secret installer
  arguments and a reusable command to `<InstallDir>\install-args.json`; use
  that record on later upgrades when it is present. Older installs have no
  record, so use the live IIS values above.

  The script stops only the pool supplied as `-AppPool`. With `-ConfigureIIS`,
  it then assigns the existing `cert-watch` site to the supplied pool and sets
  its physical path to `-SitePath`. **Omitting custom values can therefore
  leave the real pool running during the install and repoint the site to the
  default pool or path.** Also keep the existing binding arguments: with no
  `-HostName` or `-SharePort443`, the installer rewrites the HTTPS binding to
  `*:443:` and switches out of SNI mode. (`-SharePort443` by itself is
  rejected.)

  The installer stops the application pool, which releases the database,
  updates the code, and starts the pool again. It does not replace the database,
  signing keys, or an existing `web.config`; the restarted application applies
  the pending database migrations. For any *manual* file operation, such as
  restoring a backup, stop the pool first; Windows won't let you replace an
  open database.

  The script upgrades pip, then runs `pip install --upgrade` for the cert-watch
  project in the extracted source tree; it does not install from `uv.lock`.
  With pip's default `only-if-needed` upgrade strategy, already-installed
  dependencies remain in place unless they no longer satisfy cert-watch's
  declared ranges. Any dependency resolution uses pip's configured package
  index, which is not necessarily PyPI.

Then watch the log for `backed up …` and `applying migration …` lines, and open
the web interface. Those lines are visible from 1.0.1 onward. Independently of
the application version, confirm that a new
`cert-watch-pre-migration-*.sqlite3` file appeared beside the database and
inspect the database's `schema_version` table. Windows does not include a
`sqlite3` executable, so use the installation's Python. Reuse `$python` and
`$dataDir` from the live IIS inspection above (the default `$python` is
`C:\ProgramData\cert-watch\venv\Scripts\python.exe`):

```powershell
& $python -c "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute('select max(id), count(*) from schema_version').fetchone())" (Join-Path $dataDir "cert-watch.sqlite3")
```

The default bare-metal Linux install uses `/opt/cert-watch/venv`; run:

```bash
sudo /opt/cert-watch/venv/bin/python -c \
  'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute("select max(id), count(*) from schema_version").fetchone())' \
  /var/lib/cert-watch/cert-watch.sqlite3
```

Inside a Compose container, the equivalent check is:

```bash
docker compose exec cert-watch python -c \
  'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print(c.execute("select max(id), count(*) from schema_version").fetchone())' \
  /var/lib/cert-watch/cert-watch.sqlite3
```

Every migration registered by the target release must have a row. For 1.0,
an unmodified ledger prints `('0037', 37)`.

### What to expect afterwards

**Everyone signs in again once,** including the break-glass administrator,
because the session format changed. API keys keep working. On Windows/IIS, a
form left open across the upgrade fails once, because the CSRF secret file is
now honoured; reload the page.

**A v0.9.5 database runs nine migrations, 0029–0037:**

- **0029** adds the durable digest-delivery claim ledger.
- **0030** adds per-tag permission tiers to roles.
- **0031** merges certificate notes into matching host notes. If any note has
  no matching host, it remains in the deprecated `certificates.notes` column;
  that column is dropped only when no unmatched notes remain.
- **0032** adds append-only alert-delivery evidence.
- **0033** adds the clock used to bound alert-evidence deferral.
- **0034** records the certificate that triggered each alert.
- **0035** reconciles the schema of databases that had drifted from a fresh
  install: it adds `hosts.notes` and four indexes, and drops a duplicate column.
- **0036** gives alerts a delivery lifecycle.
- **0037** gives each alert a dedupe key and a saved routing snapshot.

The runner applies every registered migration whose ID is absent from
`schema_version`, in registry order; it does not assume that every ID at or
below the highest recorded ID is present. For the unchanged schemas in the
0.9.x release tags, the pending ranges are:

- **v0.9.0:** 0024–0037.
- **v0.9.1 and v0.9.2:** 0026–0037.
- **v0.9.3:** 0027–0037.
- **v0.9.4 and v0.9.5:** 0029–0037.

**Alerting behaves better, and slightly differently.** See
[alerting.md](docs/alerting.md) for the whole picture.

- Failed deliveries back off and retry (1 h, 4 h, 12 h), and give up after 12
  attempts. A given-up alert stays **failed** until someone selects **Retry**.
  `cert_watch_alerts_failed_recent` lets you alert on that.
- Alerts that were already failed before the upgrade stay failed. The one
  exception: a failed alert for a certificate that is still current, at its
  current threshold, is retried once on the next evaluation, which is what
  0.9 would have done.
- A renewal-stalled alert fires once per certificate and endpoint, and policy
  alerts fire once while the violation persists. Neither repeats every scan.
- Policy and drift alerts now go to matching alert groups, host owners and
  roles, not only to the global recipients, so some people start receiving
  them.
- A certificate served on several endpoints alerts each endpoint's owner.
- Recipients are fixed when an alert is raised. A group change affects new
  alerts, not ones already queued.
- Alerts made obsolete by a replaced or deleted certificate are kept as
  **cancelled** instead of deleted.
- Digests are claimed per recipient and period: never sent twice, and a
  partial failure retries only who missed it. The orphan notice goes out once
  a week.

**Access control is tighter.**

- Accounts created under Settings → Users can finally sign in. Each one gets
  its role's permissions; no role means read-only.
- A tag-scoped user can no longer add or import hosts with another team's
  tags.
- CSRF is enforced even with authentication disabled.
- Login throttling counts per user and address (10 per 5 minutes), with a
  higher ceiling per address (50).
- Request bodies over 12 MiB are refused.

**New and moved:**

- Every change you can make in the UI now has a JSON API equivalent (see the
  [changelog](CHANGELOG.md) for the list). No existing API path moved.
- The ownership form posts to `/hosts/{id}/owner`; the old path still works.
- The landing page is **Home**, and the inventory is at **/browse**. Old links
  redirect.
- The audit log is administrator-only.

The [changelog](CHANGELOG.md) has every change in detail, with the issue each
one fixes.
