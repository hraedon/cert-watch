# Plan 027: ACME Renewal-Window Alert (Workstream E)

> **Status:** draft for review. Grounded in the renewal tracking in
> `database/queries.py` (`replaces_cert_id`, `renewal_status`) and the alert
> evaluation path in `alerts.py`. Implements Plan 023 §E. **Small; targeted for
> 0.5.0.**

## Goal

Emit a distinct alert when a certificate **should have been renewed by automation
but hasn't been** — i.e. it is inside its renewal window and no successor cert has
appeared. This flags a broken Certbot / cert-manager / ACME job *days to weeks
before* the generic expiry alarm would, when there's still ample time to fix the
pipeline rather than scramble.

The value is the **distinction** from `expiry_warning`: expiry warnings fire on
calendar thresholds for every cert; a renewal-stall alert says specifically "your
automation is broken," and carries different remediation text ("check your ACME
client / cert-manager") and can fire earlier.

## What already exists (build on, don't rebuild)

- **Renewal linkage**: `store_*` writes `replaces_cert_id` when a new leaf
  supersedes an old one for the same `host:port` (`queries.py:145,199`), and
  maintains `hosts.renewal_status` / `renewal_method`.
- **Alert model + evaluation**: `evaluate_thresholds` / `evaluate_all_certs`
  (`alerts.py:50,148`) create pending `Alert` rows with an `alert_type` string
  (`expiry_warning`, `expired`, drift types) and per-host thresholds; the
  scheduler runs the evaluator once per cycle via `alert_fn`.
- **Delivery**: alerts flow through the same SMTP/webhook/adapter path (Plan 022)
  — a new `alert_type` needs no new delivery code, only formatting.

## Signal definition

A leaf certificate `C` for `host:port` is **renewal-stalled** when *all* hold:

1. `C` is the **current** leaf for `host:port` (nothing has replaced it — no row
   has `replaces_cert_id = C.id`, and `C` is the latest by `not_after`).
2. `now >= not_after - renewal_window_days` (inside the renewal window).
3. `not_after > now` (not already expired — once expired, `expired` owns it).

`renewal_window_days` is a new config knob (default **30**), deliberately *wider*
than the default leaf expiry threshold so the stall signal precedes the expiry
warning. Optionally scope to hosts whose `renewal_method` indicates automation
(ACME/cert-manager) once that field is reliably populated — but **default to all
leaves**, since a stalled manual renewal is just as worth flagging. (Confirm the
exact "is current leaf / has no successor" query against `queries.py` at
implementation — do not assume `renewal_status` alone is sufficient; it is reset
to `pending` on renewal at `queries.py:250` and is host-scoped, not cert-scoped.)

## Non-goals

- Not predicting *whether* renewal will happen — purely "window open + no
  successor yet."
- Not a new delivery channel — reuses existing alert plumbing.
- Not de-duplicating against `expiry_warning`; the two are intentionally distinct
  signals and a cert can legitimately raise both (with different remediation).

## Slices

1. **Config**: `CERT_WATCH_RENEWAL_WINDOW_DAYS` (default 30) on `Settings`;
   `0` disables the check.
2. **Evaluation**: `evaluate_renewal_window(db_path, window_days) -> list[Alert]`
   producing `alert_type="renewal_stalled"`, idempotent per cert (one pending
   alert per cert per window, matching the existing cooldown discipline in
   `evaluate_thresholds`). Wire into `evaluate_all_certs` / the scheduler
   `alert_fn`.
3. **Formatting**: a clear message + remediation line in email/webhook/adapter
   templates; PagerDuty severity `warning`, distinct dedup key from expiry.
4. **UI (small)**: surface the alert_type on the cert detail / alerts view with
   its own label so it reads as "automation broken," not "expiring soon."

## Testing

- Golden: seed a fleet where one leaf is inside the window with no successor
  (→ alert), one inside the window *with* a successor present (→ no alert), one
  outside the window (→ no alert), one already expired (→ no alert, `expired`
  owns it). Assert exactly the stalled one fires.
- Idempotency: re-run the evaluator → no duplicate pending alert.
- `window_days = 0` disables.

## Risks / decisions

- **"Has no successor" query correctness** — the one place to get wrong; test the
  with-successor case explicitly (see Testing). Don't rely on `renewal_status`
  alone (host-scoped, reset on renewal).
- **Double-signalling** with `expiry_warning` near expiry is acceptable and
  intended; document it so it doesn't read as a bug.
