# Plan 013: Tagging + Alert Groups

> Goal: route expiry alerts to the right team. A certificate should reach a
> team's mailbox/webhook based on **tags** (which can be applied in bulk at the
> host level) or by **manual per-cert assignment** — without every cert needing
> hand-wiring.

## Decisions (2026-06-01)

- **Tags attach to hosts *and* certs, with inheritance.** A cert's *effective*
  tags = its own tags ∪ the tags of its host `(hostname, port)`. Hosts already
  have a free-form `tags` column; certs gain the same. Uploaded certs with no
  host can be tagged directly.
- **Alert groups are DB-managed via a JSON API.** The dashboard UI is built
  separately (Claude Design); this plan delivers the wired primitives the UI
  sits on. The existing global `ALERT_RECIPIENTS` / webhook config remains the
  **default group** used when a cert matches no group.
- **Tag format:** comma-separated free-form labels. Parsing trims whitespace,
  drops empties, and de-dupes case-insensitively while preserving first-seen
  casing and order. (Reuses the existing `hosts.tags` string convention rather
  than introducing a normalized tag table — appropriate at current scale.)

## Routing semantics

For each leaf cert that crosses a threshold:
1. Compute effective tags.
2. A group **matches** if `group.match_tags ∩ effective_tags ≠ ∅` **or** the
   cert is manually assigned to it (`alert_group_certs`).
3. Recipients = union of every matching group's email recipients, merged with
   the host `owner_email` (existing behavior) via the alert's
   `extra_recipients`. `send_alert` already unions `extra_recipients` with the
   global `config.recipients`.
4. If **no** group matches, the global default recipients alone are used
   (unchanged behavior — backward compatible).

Per-group **webhooks** are a follow-up: the webhook send path is currently a
single global config. Phase 2 adds per-group webhook fan-out. Email routing
lands first because team distribution lists are the primary ask.

## Schema

**Migration 0006 — cert tags (this slice):**
- `ALTER TABLE certificates ADD COLUMN tags TEXT NOT NULL DEFAULT ''`

**Migration 0007 — alert groups (next slice):**
```sql
CREATE TABLE alert_groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    recipients TEXT NOT NULL DEFAULT '',   -- csv of emails
    webhook_url TEXT NOT NULL DEFAULT '',  -- Phase 2
    match_tags TEXT NOT NULL DEFAULT '',   -- csv of tags
    created_at TEXT NOT NULL
);
CREATE TABLE alert_group_certs (          -- manual per-cert assignment
    group_id TEXT NOT NULL,
    cert_id TEXT NOT NULL,
    PRIMARY KEY (group_id, cert_id)
);
CREATE INDEX idx_alert_group_certs_cert ON alert_group_certs(cert_id);
```

## API (JSON, authed)

**Tags (slice 1):**
- `GET  /api/tags` — distinct tags across hosts + certs (for UI autocomplete).
- `PUT  /api/certificates/{id}/tags` — set a cert's own tags (body: `{"tags": [...]}` or csv).
- `PUT  /api/hosts/{id}/tags` — set a host's tags.
- Cert detail responses include `tags` (own) and `effective_tags`.

**Alert groups (slice 2):**
- `GET/POST /api/alert-groups`, `GET/PATCH/DELETE /api/alert-groups/{id}`
- `POST/DELETE /api/alert-groups/{id}/certs/{cert_id}` — manual assignment.
- `GET /api/certificates/{id}/alert-routing` — preview matching groups +
  resolved recipients (drives the UI's "who gets alerted" view).

## Slices

1. **Tagging foundation** (this turn): migration 0006, `tags.py` parse/format
   helpers, cert tag get/set in the repo, the tag API endpoints, effective-tag
   computation, tests.
2. **Alert groups**: migration 0007, `AlertGroupRepository`, routing in
   `evaluate_all_certs`, the alert-group API, tests.
3. **Per-group webhooks** (follow-up): fan out webhook delivery per matching
   group.

## Acceptance criteria

- AC-1: A cert's effective tags include its host's tags plus its own.
- AC-2: Setting/clearing tags via the API persists and round-trips.
- AC-3: A cert whose effective tags match a group's `match_tags` adds that
  group's recipients to its alerts.
- AC-4: A cert manually assigned to a group routes to it regardless of tags.
- AC-5: A cert matching no group still alerts to the global default recipients.
- AC-6: Existing alert behavior is unchanged when no groups are defined.
