# Plan 015: Alert Groups & Routing

> **Status:** ready for implementation. This is **slice 2 of Plan 013**
> (slice 1, tagging, shipped in commit `881cbe8`). Self-contained for a
> developer. Grounded in the code as of `881cbe8`.

## Goal

Route expiry alerts to the right team. A cert reaches a group's recipients
when its **effective tags** match the group's `match_tags` **or** it's
**manually assigned** to the group. Certs matching no group fall back to the
global `ALERT_RECIPIENTS` (unchanged behavior).

The dashboard UI is built separately (Claude Design); **this plan delivers the
DB + routing + JSON API primitives** it sits on.

## Depends on
- Tagging slice 1 (done): `tags.py`, `SqliteCertificateRepository.effective_tags`,
  `distinct_tags`.

---

## Schema — migration 0007 (or next free; current max is 0006 — see note below)

```sql
CREATE TABLE alert_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    recipients  TEXT NOT NULL DEFAULT '',   -- csv of emails
    webhook_url TEXT NOT NULL DEFAULT '',   -- Phase 2 (see below); store now
    match_tags  TEXT NOT NULL DEFAULT '',   -- csv of tags (reuse tags.py)
    created_at  TEXT NOT NULL
);
CREATE TABLE alert_group_certs (            -- manual per-cert assignment
    group_id TEXT NOT NULL,
    cert_id  TEXT NOT NULL,
    PRIMARY KEY (group_id, cert_id)
);
CREATE INDEX idx_alert_group_certs_cert ON alert_group_certs(cert_id);
```
- Add to `_BASE_TABLES` / `_BASE_INDEXES` in `schema.py` **and**
  `migrations/m0007_alert_groups.py`, registered in `registry.py`.

> **Migration-number coordination:** Plan 014 (onboarding) also adds a
> migration (`kv_store`). Whichever lands first takes `0007`, the other `0008`.
> Use the next free integer at implementation time.

---

## Repository — `database/repo.py`: `SqliteAlertGroupRepository`

```python
@dataclass
class AlertGroup:
    id: str
    name: str
    recipients: list[str]      # parsed from csv
    match_tags: list[str]
    webhook_url: str = ""

class SqliteAlertGroupRepository:
    def __init__(self, db_path): ...
    def create(self, name, recipients: list[str], match_tags: list[str], webhook_url="") -> str
    def get(self, group_id) -> AlertGroup | None
    def get_by_name(self, name) -> AlertGroup | None
    def list_all(self) -> list[AlertGroup]
    def update(self, group_id, *, name=None, recipients=None, match_tags=None, webhook_url=None) -> bool
    def delete(self, group_id) -> bool
    def assign_cert(self, group_id, cert_id) -> None      # INSERT OR IGNORE
    def unassign_cert(self, group_id, cert_id) -> None
    def groups_for_cert_manual(self, cert_id) -> list[str]  # group_ids
```
- Store `recipients`/`match_tags` via `tags.format_tags(...)` (normalizes,
  de-dupes). Parse back with `tags.parse_tags(...)`.
- Export the repo + `AlertGroup` from `database/__init__.py`.

---

## Routing — the core integration

**Integration point:** `alerts.evaluate_all_certs` (`alerts.py:134`) already
loops every leaf, joins per-host owner info, and calls `evaluate_thresholds`,
which puts `owner_email` into `Alert.extra_recipients` (`alerts.py:121`).
`send_alert` already unions `config.recipients + alert.extra_recipients`
(`alerts.py:240`). **So group email recipients should flow through
`extra_recipients`** — no change to `send_alert` needed.

### Implementation
1. Add a resolver (new `alerts.py` helper or small `alert_routing.py`):
   ```python
   def resolve_group_recipients(db_path, cert_id, cert_repo, group_repo) -> list[str]:
       eff = cert_repo.effective_tags(cert_id)
       manual = set(group_repo.groups_for_cert_manual(cert_id))
       out: list[str] = []
       for g in group_repo.list_all():
           if g.id in manual or tags_match(eff, g.match_tags):
               out.extend(g.recipients)
       return out  # de-duped by caller's merge
   ```
2. In `evaluate_all_certs`, build the group repo once, and for each leaf pass
   the resolved recipients into `evaluate_thresholds` so they're merged into
   `extra_recipients` alongside `owner_email`. Add a param:
   `evaluate_thresholds(..., extra_recipients: list[str] | None = None)` and
   union there (keep `owner_email` behavior).
3. **No group match → no `extra_recipients` added → global default only.**
   Backward compatible (AC-6).

### Per-group webhooks — **Phase 2, out of scope here**
`send_webhook` uses a single global `WebhookConfig`. Per-group webhook fan-out
needs the send loop to dispatch per group; defer. Store `webhook_url` now so
the schema/API are stable, but don't wire delivery yet. Note this clearly in
code + README.

---

## JSON API — extend `routes/api.py`

Reuse `_require_api_auth` (reads) and `_require_api_write` (auth+CSRF, added in
slice 1) and `record_audit`.

| Method | Path | Body / notes |
|--------|------|--------------|
| `GET`  | `/api/alert-groups` | list groups (recipients + match_tags as arrays) |
| `POST` | `/api/alert-groups` | `{name, recipients[], match_tags[], webhook_url?}` → 201; 409 on dup name |
| `GET`  | `/api/alert-groups/{id}` | one group; 404 if missing |
| `PATCH`| `/api/alert-groups/{id}` | partial update |
| `DELETE`| `/api/alert-groups/{id}` | 204/200; also clears its `alert_group_certs` |
| `POST` | `/api/alert-groups/{id}/certs/{cert_id}` | manual assign |
| `DELETE`| `/api/alert-groups/{id}/certs/{cert_id}` | manual unassign |
| `GET`  | `/api/certificates/{id}/alert-routing` | preview: `{matched_groups:[{id,name,reason:"tag"|"manual"}], recipients:[...]}` — drives the UI's "who gets alerted" view |

- Validate emails minimally (contains `@`); reject non-string list items (mirror
  `_tags_from_body`).
- Audit actions: `alert_group.create/update/delete`, `alert_group.assign_cert`,
  `alert_group.unassign_cert`.

---

## Tests (`tests/test_alert_groups.py`)
- Repo: CRUD round-trips; recipients/match_tags normalized; assign/unassign;
  `delete` cascades `alert_group_certs`; unique-name enforced.
- Routing: cert with effective tag matching a group → group recipients appear
  in the created alert's `extra_recipients` (**AC-3**); manual assignment routes
  regardless of tags (**AC-4**); no match → only global default (**AC-5**);
  no groups defined → behavior identical to today (**AC-6**); inherited host tag
  drives routing (**AC-1** dependency).
- API: each endpoint's happy path + 404 + 409(dup) + 400(bad body) + authz
  (401 when auth on, no session).
- `/alert-routing` preview returns correct groups + de-duped recipients.

## Acceptance criteria (from Plan 013)
- AC-3..AC-6 above. Existing alert tests must stay green (no behavior change
  when no groups exist).

## Sequencing
1. Schema + migration + repo (+ tests).
2. Routing in `evaluate_all_certs` (+ tests) — the behavior-changing part;
   land with the alert regression suite green.
3. JSON API (+ tests).
4. README: API table rows + a short "Alert routing" section; AGENTS.md note.
5. Mark Plan 013 slice 2 done; leave slice 3 (per-group webhooks) as a tracked
   follow-up breadcrumb.

## Risk notes
- The only behavior change to existing installs is in `evaluate_all_certs`;
  keep the "no groups → unchanged" path obviously correct and covered.
- `list_all()` per evaluation is fine at current scale (few groups); if group
  count ever grows, cache per cycle.
