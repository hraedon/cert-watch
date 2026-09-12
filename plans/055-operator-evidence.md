# Plan 055: Endpoint identity and operator evidence

Authorized by the operator on 2026-09-12 after the product-coherence review.
This is a bounded extension of maintenance scope to finish four existing workflows.

1. Keep hostname and port together through renewal digest and webhook enrichment.
   Ambiguous historical events cannot borrow an endpoint's owner or certificate.
2. Present scan freshness using the scheduler's daily/custom cadence, with last
   success, latest attempt, observation deadline and retry eligibility distinct.
   Count the visible registered endpoint population; exclude static uploads.
3. Edit effective cadence, alert threshold and operator-reported renewal status
   on endpoint details. Explain suppression and reset semantics. Expected issuer
   values are inactive legacy data after CT monitoring removal, not a new policy.
4. Record and show per-alert delivery attempts, including routing inputs at the
   time of attempt. Distinguish those inputs from historical routing causation,
   and relay acceptance from recipient receipt. Protect recipient details with
   administrative access. Old alerts have no manufactured delivery history.

The endpoint form route and additive delivery-evidence migration are intentional.
Existing auth/session/CSRF defaults, runtime dependencies, deploy manifests and
public response contracts remain outside this change.

Qualification: failing regressions, focused behavior tests, full unit suite and
coverage floors, Ruff/mypy/template lint, local browser suite and populated/empty
light/dark inspection, followed by exact-revision hosted checks. This change does
not claim production deployment or external recipient acceptance.
