# Plan 054 — Private-Root Trust Anchors: close the B/incomplete gap

**Status:** proposed 2026-07-26
**Author:** glm-5.2
**Strategic role:** finish an **in-bounds** feature. The backend already
validates private-CA chains end-to-end; the gaps are a missing UI form and two
scan-path edge cases. This is **not** the declined "AD CS / private-CA
inventory" (positioning.md §non-goals) — that decline covers *active discovery*
of private certs. Trust-anchor upload is the documented minimalist alternative
(Plan 030 §"existing functionality"; `templates/readiness.html:178` already
directs operators to upload roots).

## 1. The problem, precisely

On mvmcitest01, AD-CS-issued certs grade **B/incomplete**. AGENTS.md calls this
"expected (private CA not uploaded as anchor)." The research found the backend
already supports anchoring — the gaps are operational, not architectural:

| Capability | Status | Location |
|---|---|---|
| `trust_anchors` table + repo | ✅ | `database/schema.py:84`, `repo.py:512` |
| `chain_status()` consults uploaded anchors → `"private"` | ✅ | `cert_chain.py:408` (`_is_signature_anchored_by_user`) |
| Scan loads anchors → passes to `chain_status` | ✅ (when chain non-empty) | `scan.py:522-530` |
| Posture grades `"private"` as complete (A) | ✅ (fall-through) | `posture.py:543` |
| Backend `POST /trust-anchors` route | ✅ | `routes/certificates.py:697` |
| **UI upload form** | ❌ **gap A** | no template posts to `/trust-anchors` |
| **Empty-chain anchor consult** | ❌ **gap B** | `scan.py:530` short-circuits to `None` |
| **Chain-PEM upload UX** | ❌ **gap C** | route takes `entry.leaf` (not a CA) → rejects bundles |
| Test: `chain_status="private"` → grade A | ❌ missing | `test_posture.py` (implicit fall-through only) |

**Root cause of the mvmcitest01 B grades:** no operator has uploaded the root,
because **there is no button to click** (gap A). The `dashboard.html` "Trust
anchors" panel renders a *delete* form only; the "Add certificates" slide-over
has tabs for scan/upload/bulk but none for anchors.

## 2. Positioning boundary (what this is NOT)

- **In scope:** "here is my private root; validate my internal certs against
  it." Operator-driven trust configuration. This is *observability* — same
  class as uploading an offline cert for monitoring.
- **Out of scope (the declined Plan 030 / positioning §non-goals):** actively
  discovering/querying AD CS or CA databases to surface private certs; private
  PKI lifecycle management. The line is *no active private-cert discovery* —
  the operator brings the anchor, cert-watch never goes looking.

Evidence this is sanctioned: Plan 030 lists trust-anchor upload as *existing*
functionality the declined discovery would have built on; `readiness.html:178`
already tells operators to "Upload the root CA as a trust anchor."

## 3. Phased work breakdown

### Phase 1 — UI upload form (unblocks the estate; no logic change)
- P1.1 Add an upload form to the "Trust anchors" panel in `dashboard.html`
  (a file input + CSRF, posting to `POST /trust-anchors`). Reuse the
  slide-over's tab styling or a small inline form — either fits the existing
  conventions.
- P1.2 Surface success/error via the existing flash mechanism (the route
  already redirects with `?anchor_added=1` / `?error=...`).
- P1.3 Audit log entry already written (`trust_anchor.add`) — confirm it
  renders in the audit trail.
- **Verify:** e2e `test_settings_post.py`-style test for the upload; manual
  check on mvmcitest01 (upload the Hraedon lab root, re-scan an AD CS host,
  confirm grade lifts B → A and `chain_status` flips `incomplete → private`).

### Phase 2 — Empty-chain anchor consult (correctness)
- P2.1 `scan.py:530` currently: `cs = chain_status(cert, chain, anchors) if chain else None`.
  When the TLS service sends **leaf only**, `chain` is `[]` → `chain_status` is
  never called → anchors ignored → cert lands in the
  `chain_status is None and not self_signed` branch (posture.py:526) → B.
- **Fix:** when `chain` is empty, still ask whether the leaf is *directly*
  issued by an uploaded anchor (signature check against anchors, reusing
  `_is_signed_by(leaf, anchor)`). If so, treat as a complete private chain
  (`chain_status = "private"`); else fall back to the current `None` behavior.
  Keep it a leaf-terminating check — do **not** synthesize intermediates or
  chase AIA (that drifts toward discovery).
- P2.2 New test: leaf-only scan with a matching anchor → `"private"` → A;
  leaf-only scan with no anchor → unchanged (`None` → B, "incomplete").

### Phase 3 — Chain-PEM upload UX (robustness)
- P3.1 `routes/certificates.py:697` takes `entry.leaf` and validates it as a CA.
  A chain PEM (leaf+intermediate+root) has a non-CA leaf → rejected (today's
  `test_add_trust_anchor_valid` actually asserts the rejection — misnamed).
- **Fix:** accept any CA cert in the bundle, preferring the self-signed root
  (last cert). Reject if no cert in the bundle has `BasicConstraints.ca=True`.
- P3.2 Rename/replace the misnamed test; add a positive chain-PEM case.

### Phase 4 — Test the implicit A path + close
- P4.1 Explicit test: `chain_status="private"` → posture grade A (closes the
  fall-through gap in `test_posture.py`). Break-the-code ritual: flip the
  `else` branch to confirm the test catches it.
- P4.2 Docs: README trust-anchor section; AGENTS.md note updated ("AD CS certs
  grade B/incomplete **unless** the operator uploads the root").
- P4.3 Close via cross-lineage review.

## 4. Decision register (human inputs)

1. **Phase 2 scope** — is leaf-terminating anchor check acceptable, or should
   we require the server to serve intermediates (no scan-side help)? Recommend
   the leaf-terminating check (it's pure trust validation, not discovery).
2. **Re-grade on upload** — when an anchor is added, should existing certs be
   re-evaluated automatically (background re-scan) or only on next scan?
   Recommend: do **not** auto-trigger scans (maintenance simplicity); document
   that a re-scan lifts the grade. (An explicit "re-evaluate posture" button is
   a separate, optional slice.)

## 5. Why this is the right "way to correct" the B/incomplete issue

- **No new product class.** cert-watch already validates private chains; this
  surfaces the existing capability and fixes two edge cases. It does not make
  cert-watch a CA manager.
- **Bounded.** Three gaps, each independently shippable; Phase 1 alone unblocks
  the deployed estate.
- **Positioning-consistent.** Anchor upload is the documented alternative to
  the declined discovery feature; the readiness page already tells operators to
  do it.
- **The alternative (auto-discovering private roots) is the declined Plan 030**
  and would require crossing the positioning line. Not recommended.
