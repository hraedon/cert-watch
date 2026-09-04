# Plan 055 status — executed 2026-08-12

Branch: `redesign/ui-v2` (unpushed). All three moves from brief.md landed.

## Landed

**IA**: 4-domain nav (Certificates / Posture / Activity / Settings) + scope
indicator chip. Old URLs redirect: /insights → /?view=calendar or /posture,
/crypto → /posture, /team → /, /activity → /alerts, /settings?tab=X →
/settings/{section}. host_detail.html merged into certificate_detail.html
(one template, degrades when no cert). Trust anchors → Settings.

**Design system v2**: tokens.css rebuilt (tone-as-modifier grammar; one
toggle/segmented/chip/table/empty/disclosure/drawer/filter-bar), legacy.css
and the pixel-utility layer deleted, shared ui.html macros, JS in
static/js/{core,dashboard,detail,activity,settings}.js (base.html
data-action registry gone). ZERO inline style attributes → **style-src
'unsafe-inline' dropped from the CSP**. Charts are server-rendered SVG
with attribute geometry; palette validated with the dataviz checker
(3-series status encoding; C+F merged — crit/expired fail CVD adjacency).

**RBAC/tagging**: Plan 053 phases 1–3 implemented (m0029 role_tag_tiers,
AuthContext.tag_tiers / may_write_any / may_write_tags, scope_write_denied
seam, role-editor per-tag field, break-the-code ritual run). Tags registry
page (Settings → Tags) shows each tag's label/access/routing dependents.
C9 fixed (compliance effective-tags + regression test). Audit log
admin-gated (C5). Users delete gets its missing confirmation.

## Explicitly NOT done (owner decisions / follow-ups)

- **C1 — users.role_id confers no permissions.** UI now states this
  honestly (Users section callout); actually wiring local users' role_id
  into build_auth_context is an auth-posture change needing sign-off
  (AGENTS.md). Options in rbac-report.md §5.
- **C6 — API keys see the whole fleet.** Honesty note added to the API-keys
  section; per-key scope tags are additive follow-up work.
- **Scan history is not scope-filtered** (C5 remainder): scoped viewers
  still see fleet-wide batch hostnames on /scan-history. Needs a
  hosts-join tag filter in list_scan_batches.
- **/posture crypto inventory is fleet-wide** for scoped users
  (analyze_fleet_crypto has no scope_tags param) — same leak class.
- Plan 053 D3 (local-user multi-role M2M) stays deferred per the decision
  register.

## Verification record

- Unit: 2518 passed / 0 failed; ruff clean; mypy clean except a
  pre-existing cryptography-stub error in posture.py.
- Break-the-code: removing the may_write_tags enforcement line fails
  test_tag_viewer_denied_in_scope_host; restored and re-verified.
- Embarrassment checklist: every rebuilt page screenshotted populated and
  empty, dark and light (dev loop scripts/dev-screenshot.py); words read;
  zeroes render neutral; accent never used for status (the old grade-B
  chart color violated this and was fixed).
- e2e: see final session report (run in progress at time of writing).
