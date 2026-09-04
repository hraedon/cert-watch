# cert-watch UI and project review — 2026-09-04

The attention-first Home is the right direction for a certificate-monitoring tool: an operator can identify urgent work before opening the inventory. Browse retains the detailed search, grouping, calendar, and export controls. The neutral bronze/charcoal design is coherent, and the split Settings pages are easier to navigate than the previous long form.

## Verified defects corrected

- Home selected twelve occupied expiry buckets, allowing dates months beyond its advertised twelve-week horizon. The date boundary is now enforced.
- Home counted expired certificates as “expiring”; Healthy and empty-horizon text implied more assurance than the data supported. Copy and counts now describe their actual meaning.
- Attention actions inherited table-only hover styling and stayed invisible outside the table. Hover, keyboard focus, and touch now expose them.
- An off-screen closed drawer cast a visible shadow over the mobile page. The shadow now exists only while open; Browse mode tabs can scroll on narrow screens.
- Certificate-detail columns clipped beyond a 390px viewport because a later base rule overrode the responsive rule. The panels now stack. A test checks actual descendant bounds, since body overflow clipping hid the defect from document-width assertions.
- Essential secondary text used a token measuring roughly 3.7–4.0:1 in dark mode and 2.9–3.2:1 in light mode on common surfaces. It now uses the existing text-2 token, exceeding 4.5:1. Decorative and disabled styling is unchanged.
- The expired palette remains violet and distinct from other statuses in both themes and simulated color-vision deficiencies. The vendor stylesheet remains intact; the app-owned token carries the change.
- Renewal digests grouped owner addresses case-sensitively while delivery claims were case-insensitive. Case variants now combine before delivery, preventing omitted hosts.
- Both pending branches used migration 0029. Canonical order is digest ledger 0029, role tiers 0030, host-note consolidation 0031. The final migration converges already-run feature schemas as well as published releases.
- Unmatched certificate notes are preserved in the live deprecated column. Matched notes migrate to host notes; substring containment no longer silently discards a distinct note. The column drops only when no unmatched notes remain.
- The opt-in real LDAP harness used obsolete configuration names, redirects, a fixed data directory, and an unused launcher process. Configuration and selectors are repaired; group-rejection coverage now requires real out-of-group credentials instead of pretending an invalid login proves group enforcement.
- CI now fetches the history required by the Patina provenance check and retains generated baseline candidates for newly covered pages.

## Branch reconciliation

PR #22 combines PR #20, PR #21, and the unpublished mvmcc03 continuation. The attention-home branch contains the entire UI-v2 branch plus Patina adoption and content-model work. The standalone action-pin branch was already applied to main; the dependency update on main was retained. Original histories remain reachable through the merge commits.

The reconciliation branch is published on GitHub and available in both `/projects/cert-watch` on mvmcc02 and `~/projects/personal/cert-watch` on mvmcc03. Final merge/check status is recorded by [PR #22](https://github.com/hraedon/cert-watch/pull/22).

## Validation and limits

The combined unit run passed 2,684 tests, with two environment skips (Python 3.13 chain retrieval on the local Python 3.12 interpreter; optional live Patina drift checking). The separate coverage-floor pass passed all nine checks. Subsequent migration regressions passed the 28-test migration/upgrade set. Ruff, mypy, template lint, functional browser tests, and Samba integration checks were run. GitHub checks on the final PR commit are the authoritative final-state gates.

Browser inspection covered Home, Browse, certificate detail, and Settings with synthetic data at desktop/mobile sizes and both themes, including empty and populated states. No browser console errors were observed. Visual baselines come from GitHub's Ubuntu artifacts, not local snapshot regeneration.

This was a correctness and UI review, not an exhaustive security audit. Real production AD login, Windows/IIS upgrade/reboot, and live production certificate scanning were not performed. The repaired real-AD tests remain opt-in. Retained unmatched notes have no new UI editor; they remain recoverable in the database and backup.

## Suggested next improvements

1. **Gate image publication/deployment on successful checks for the exact commit.** `release.yml` still runs independently of the test/visual workflows. PR discipline reduces risk, but direct main pushes and post-merge failures can deploy before their failures are known. This deserves an explicit deployment-policy decision.
2. **Make mobile navigation more compact.** At 390px, the brand and wrapped navigation consume about 112px. Compare a compact menu with a deliberate scrollable navigation strip, keeping the active location and keyboard access clear.
3. **Improve the monitoring story before expanding features.** Preserve the attention-first approach and add realistic endpoint/owner/renewal examples to operator validation. The inventory is mature; trustworthy prioritization, upgrade behavior, and delivery evidence offer more value than additional dashboards.
4. **Keep branch lifetimes short.** Migration-number collisions and stale UI selectors came from long-lived, independently green branches. Land bounded changes with their upgrade and browser checks close to implementation.

The attempted agent-notes backlog updates were blocked by its Regista backend: schema `cert_watch` is missing Regista migrations 45–50. Those are separate from cert-watch's SQLite migrations. No backend migration was attempted as part of this review; the recommendations are retained here, and existing WI-140/WI-145 tracking may remain stale.
