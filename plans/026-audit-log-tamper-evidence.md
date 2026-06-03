# Plan 026: Audit-Log Tamper-Evidence (Hash Chaining)

> **Status:** draft for review. Grounded in `audit.py` and the migration system
> on `release/0.5.0`. Implements the "audit-log tamper-evidence (hash chaining)"
> item that Plan 023 deferred as "the real compliance hardening beyond export."
> **Recommended target: 0.5.1**, not 0.5.0 — rushing tamper-evidence is
> self-defeating, and the concurrency/purge correctness below wants its own
> review cycle. See "Sequencing & risk".

## Goal

Make the audit log **tamper-evident**: any insertion, deletion, edit, or
reordering of a past `audit_log` row becomes detectable. Today the table
(`id, ts, actor, action, target_type, target_id, detail, source_ip`) is
append-only by *convention* only — anyone with DB write access can edit or
delete a row and leave no trace. For the regulated-SMB / SOC 2 "audit trail
integrity" control, that's the gap the compliance *report* (Plan 025) doesn't
close: the report says "here is our posture," a tamper-evident log says "and here
is un-forgeable proof of who changed what."

This is the stronger differentiator for the target market, and it composes with
SIEM export (Plan 028 / 023 §F): periodically pushing the chain **head hash** to
an external SIEM gives an *external anchor*, which is what upgrades the property
from "tamper-evident to a local verifier" toward "tamper-evident against the
instance operator too."

## What already exists (build on, don't rebuild)

- **`record_audit()`** (`audit.py:16`) — single best-effort INSERT, swallows
  exceptions, never raises. This is the one write path; every mutation/login
  routes through it.
- **`purge_old_audit()`** (`audit.py:47`) — `DELETE FROM audit_log WHERE ts < ?`.
  **This is the central tension:** naive row deletion breaks a naive chain (see
  below).
- **Migration system** — ordered `m0001..m0012`; next is **`m0013`**. Add the
  chain columns there (idempotent `ALTER TABLE ... ADD COLUMN`, matching the
  existing migration style).
- **Signing key** — `SecurityContext.signing_key` (persisted `.auth_secret`),
  already used by the compliance report's HMAC. Reuse for the head-hash
  signature, with the same key-rotation caveat.
- **`ssrf_safe_urlopen`** + Plan 028 sinks — for pushing the head hash out.

## Design

### Chain construction

Add two columns to `audit_log` (migration m0013):

- `prev_hash TEXT` — the `entry_hash` of the immediately preceding row.
- `entry_hash TEXT` — `sha256(canonical(prev_hash, ts, actor, action,
  target_type, target_id, detail, source_ip, id))`, hex.

`canonical(...)` is a fixed, documented serialization (same discipline as
`compliance._canonical_json`: sorted keys, explicit separators, UTF-8) so the
verifier recomputes byte-for-byte. The **genesis** row uses a fixed sentinel
`prev_hash` (e.g. `"GENESIS"`); its `entry_hash` chains everything after it.

### Concurrency — the correctness crux

`record_audit` must (1) read the current head's `entry_hash`, then (2) insert a
new row whose `prev_hash` is that value. If two writers interleave between (1)
and (2), the chain **forks** (two rows share a `prev_hash`) and verification
fails on legitimate data.

SQLite serializes writers, but a read-then-write is two statements. The fix:
wrap the read+insert in a single **`BEGIN IMMEDIATE`** transaction so the write
lock is held across the head read. Then "latest row" is unambiguous and the
chain stays linear. This must be tested with concurrent writers (threads) to
prove no fork under contention — it's the one place this plan can be subtly
wrong.

> Note: `_connect` currently opens a connection per call and `record_audit`
> commits immediately. The chained version needs explicit transaction control
> (`isolation_level=None` + `BEGIN IMMEDIATE`, or equivalent). Verify the
> connection helper's isolation settings before implementing — don't assume.

### Purge vs. chain — the second correctness problem

`purge_old_audit` deletes old rows. Deleting row *N* means the verifier, walking
from genesis, hits a `prev_hash` it can't reproduce → false "tampered" verdict.
Three options, in order of preference for v1:

1. **(Recommended) Sealed checkpoints.** Before deleting, write one
   **checkpoint row** (`action="audit_checkpoint"`) whose detail records: the
   `entry_hash` of the last row being purged, the count purged, and the time
   range. The checkpoint's own `entry_hash` continues the chain. The verifier
   treats a checkpoint as a valid chain anchor: it verifies the post-checkpoint
   segment fully, and trusts the checkpoint's recorded hash for the
   (now-deleted) prefix. Tamper-evidence is preserved *forward* of each
   checkpoint; the deleted prefix is vouched for by the (signed) checkpoint.
2. **Don't delete chained rows** — retention by archival/export only. Simplest
   and strongest, but changes long-standing purge behavior; opt-in via config.
3. Truncation marker (a degenerate checkpoint). Folds into option 1.

**Decision for v1:** option 1. Document that integrity is guaranteed *from the
most recent checkpoint forward*, and that checkpoints are themselves signed.

### Verification

`cert-watch verify-audit-log` (new subcommand, mirrors `verify-report`):

- Walk rows in chain order from genesis (or the earliest checkpoint), recompute
  each `entry_hash`, and report the **first broken link** (row id + ts) or PASS.
- Verify the **head signature** (HMAC over the head `entry_hash` with the
  signing key) so a wholesale chain rewrite by someone *without* the key is
  caught. (A holder of the key can still recompute a forged chain — see
  "Honest limits".)
- Exit non-zero on FAIL, like `verify-report`.

### DB-enforced append-only (defense-in-depth, from review #18)

Add SQLite `BEFORE UPDATE` / `BEFORE DELETE` triggers on `audit_log` that
`RAISE(ABORT, 'audit_log is append-only')`, so a stray `UPDATE`/`DELETE` through
the app's own connection is refused. **Honest scope:** this stops accidental and
in-app tampering, **not** an attacker with direct SQLite/file access (they can
drop the triggers or edit the file). It is a cheap complement to — not a
replacement for — the hash chain, which is what actually *detects* offline
edits. Note the interaction with purge: the checkpoint-sealing purge (above) must
be the *only* sanctioned deleter, so either the trigger allows a guarded delete
path (e.g. a session flag) or purge runs via a maintenance path that recreates
the table. Decide at implementation; the hash chain is the real guarantee.

### Head attestation & external anchor

- Stamp the current head `entry_hash` + signature into the **compliance report**
  footer (Plan 025), so an exported report also attests the audit-trail state at
  generation time.
- Optionally (composes with Plan 028) push the signed head hash to the SIEM on a
  schedule. Once the head is recorded somewhere the operator can't rewrite, the
  property strengthens from "tamper-evident to a local verifier" toward
  "tamper-evident against the instance operator." This is the real compliance
  win and the reason to sequence this *with* F.

## Honest limits (document these; do not over-claim)

- **Tamper-evident, not non-repudiable in v1.** The chain + HMAC prove the log
  wasn't edited *by someone without the signing key*. The instance itself holds
  the key and could recompute a consistent forged chain. External anchoring
  (head hash → SIEM) is what mitigates this; without it, the guarantee is
  "detects edits by anyone who can't read `.auth_secret`."
- **Key rotation** invalidates old head signatures (same trade-off as sessions /
  kv / compliance report). The chain hashes themselves don't depend on the key
  and stay verifiable; only the signature attestation re-bases.
- **Best-effort write tension.** `record_audit` currently never raises. With
  chaining, a failed write must *not* silently break the chain. Decide:
  either keep best-effort (and record a gap marker so the verifier reports a
  known, logged gap rather than "tampered"), or make audit writes
  fail-loud for state-changing actions. **Open question below.**

## Slices

1. **Schema + chain write.** m0013 adds `prev_hash`/`entry_hash`; `record_audit`
   computes the chain under `BEGIN IMMEDIATE`. Backfill existing rows once at
   migration time (chain them in `ts, id` order from genesis). Concurrency test.
2. **Verifier.** `cert-watch verify-audit-log` + a pure
   `verify_audit_chain(rows) -> (ok, first_bad_id)` golden-tested over: clean
   chain, edited row, deleted row, reordered rows, forked chain.
3. **Purge checkpointing.** Rework `purge_old_audit` to seal a checkpoint before
   delete; verifier understands checkpoints.
4. **Head attestation.** HMAC the head; surface it in the compliance report
   footer and via a `GET /api/audit/head` (auth-gated) for external anchoring.
5. **(Composes with Plan 028)** scheduled head-hash push to SIEM.

## Testing

- **Chain**: golden tests for build + verify; a concurrency test (N threads each
  calling `record_audit`, assert a single linear chain with no forks).
- **Tamper**: edit/delete/reorder one row → verifier names the first bad link.
- **Purge**: purge across a checkpoint → verifier still PASSes the retained
  segment; deleting a *retained* row after a checkpoint still FAILs.
- **Migration**: backfill an existing unchained table → verifier PASSes.

## Risks / decisions

- **Concurrency fork** (mitigated by `BEGIN IMMEDIATE`; must be proven by test).
- **Purge semantics change** — checkpoints alter what `purge_old_audit` does;
  call it out in CHANGELOG and runbook.
- **Performance** — the head read per write adds a serialized round-trip to every
  audited action. Acceptable for this app's write volume (human-driven
  mutations, not high-throughput), but note it.

## Open questions

1. **Best-effort vs. fail-loud audit writes** under chaining (see Honest limits).
   Recommend: keep best-effort but on failure write a logged **gap marker** so
   the verifier reports `GAP at <ts>` distinct from `TAMPERED`.
2. **Purge default** — ship checkpoint-sealing as the new default, or keep plain
   delete unless `CERT_WATCH_AUDIT_CHAIN=1`? Recommend gated by an explicit
   `CERT_WATCH_AUDIT_TAMPER_EVIDENT` flag for v1 so existing deployments are
   unchanged until opted in.
3. **Detail mutability** — `detail` is JSON; confirm canonical serialization is
   stable across Python versions (sort_keys + separators, as in Plan 025).
