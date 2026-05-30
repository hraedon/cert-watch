# Plan 008: Audit Log (Rollout Readiness Phase 2)

> Implements Plan 007 §Phase 2. Append-only "who did what, when" trail — the
> single most credibility-relevant addition for a regulated rollout, and the
> substrate Phase 4's break-glass logging depends on.

## Goal

Every state-changing action is recorded in an immutable `audit_log` table,
viewable (read-only) by authenticated operators. No edit/delete path.

## Schema (per 007 §2)

`audit_log(id, ts, actor, action, target_type, target_id, detail, source_ip)`
with indexes on `ts` and `(target_type, target_id)`. Added idempotently in
`schema.py` the same way `scan_posture` is.

## Implementation steps

1. **schema.py** — add the `audit_log` table to `init_schema` (idempotent
   `CREATE TABLE IF NOT EXISTS` + indexes).
2. **`audit.py` (new)** — `record_audit(db, *, actor, action, target_type,
   target_id, detail=None, source_ip=None)`. Inserts one row. On failure, log
   at **WARNING** (not silently swallowed — unlike posture, a missing audit row
   matters) but never raise into the caller's request.
3. **Actor/IP helper** — resolve `actor` from `request.scope.get("auth_user")`
   (falls back to `"anonymous"` when auth is off) and `source_ip` from
   `request.client`.
4. **Instrument mutating routes only** (not reads): host add/delete, manual
   scan trigger, certificate delete, owner/contact update, trust-anchor
   add/delete, bulk import. Each writes exactly one row with a stable `action`
   string (`host.add`, `cert.delete`, …) and a `detail` JSON of the salient
   before/after fields.
5. **Read surface** — `routes/audit.py`: `GET /audit` (HTML, `audit.html`) and
   `GET /api/audit` (paginated JSON, filter by `target`/`actor`). Both are
   covered by the Phase 1 rule — **not** public; require auth when enabled.
6. **Cascade safety** — `audit_log` is never cascaded. Confirm
   `delete_certificate_cascade` leaves the audit rows intact (target_id is a
   plain column, no FK).

## Files

`schema.py`, `audit.py` (new), `routes/audit.py` (new), the mutating routes
under `routes/`, `templates/audit.html`, `database/__init__.py` (exports),
`tests/test_audit.py` (new).

## Acceptance criteria

Per 007 §2 AC-1…AC-5 (one row per mutating action; survives cascade delete;
endpoints auth-gated; `anonymous` actor when auth off; write-failure logs
WARNING without failing the action).

## Test plan

Drive each mutating route and assert exactly one row with the right
actor/action/target; delete a cert and assert its audit rows remain; assert
`/audit` + `/api/audit` → 401 under auth; assert `anonymous` actor with auth
off; monkeypatch the insert to raise and assert WARNING + action still succeeds.

## Dependencies

None. **Unblocks** Plan 010 slice 2 (break-glass `break_glass=true` audit row).
