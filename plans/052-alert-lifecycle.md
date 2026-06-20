# Plan 052 — Alert lifecycle: acknowledge / snooze + escalation (pre-1.0)

**Status:** proposed 2026-06-20 — **targeted to land before 1.0** (operator call)
**Strategic role:** Close the gap between cert-watch's strong alert *routing* and
a thin alert *lifecycle*. Routing (groups, owner, role, digests, channels) is
mature; what a single alert can *do* is not — it fires once per threshold and
that's it. For an on-call team this is the difference between "great routing" and
"great alerting," and it's a credibility item for the regulated/audited SMB the
product targets.

## Current behavior (ground truth)
- `evaluate_thresholds` creates one pending alert per newly-crossed threshold;
  each `(alert_type, threshold)` fires **exactly once** (no re-fire).
- `read` flag exists (m0014) for unread tracking in the UI.
- `renewal_status == "renewed"` suppresses further alerts for a host.
- There is **no** operator-facing ack/snooze, and **no** escalation if an alert
  is ignored.

## In scope

### WI-1 — Acknowledge / snooze
- **Acknowledge:** an operator marks an alert acknowledged (who + when, audit-
  logged). Acknowledged alerts are visually separated and excluded from the
  "needs attention" counts. Distinct from `read` (seen ≠ being-worked).
- **Snooze:** suppress re-surfacing / re-notification for a chosen window
  (e.g. 24h/7d) — for "renewal is in flight, stop nagging." On expiry of the
  window the alert returns to active if the cert still trips the threshold.
- Schema: add `ack_state` / `ack_by` / `ack_at` / `snooze_until` to `alerts`
  (one migration). Audit every transition.

### WI-2 — Escalation tiers
- If an alert is neither acknowledged nor resolved within an escalation window,
  route a second notification to an escalation recipient set (e.g. the alert
  group's escalation list, or admin-tier users — reuse the orphan-notice
  `_admin_emails` pattern from Plan 050).
- Config lives on the alert group (escalate-after-N-hours + escalation
  recipients). Default off (no behavior change on upgrade).
- Determinism: escalation is evaluated in the daily cycle, keyed off
  `created_at` + ack/snooze state; one escalation per alert, audit-logged.

## Out of scope
- Full incident-management workflow (PagerDuty already owns that for teams who
  want it; the PagerDuty adapter integrates there). This is lightweight in-tool
  lifecycle, not a competing on-call platform.

## Open decisions to pin before building
1. **Snooze granularity:** per-alert only, or also per-cert / per-host ("mute
   this host while we migrate it")? Per-host is more useful operationally but
   interacts with scope/RBAC (WI-078).
2. **Ack vs. read:** keep both, or does ack subsume read? (Recommend: keep both
   — read is passive, ack is a deliberate "I own this.")
3. **Escalation recipients source:** new field on alert group vs. reuse
   admin-tier. (Recommend: alert-group field, falling back to admin-tier.)

## Why pre-1.0
A 1.0 that markets routing + RBAC but can't ack or snooze an alert feels
unfinished to an operator on the receiving end. It's contained (mostly `alerts`
+ one migration + UI), and it's the kind of lifecycle promise that's awkward to
add *after* a stability freeze because it changes the alerts table contract.
