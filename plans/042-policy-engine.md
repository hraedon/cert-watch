# Plan 042 — Configurable Policy Engine

**Status:** proposed 2026-06-06
**Author:** Opus 4.8 (portfolio review)
**Strategic role:** Posture grading (A+/A/B/C/F) is a useful default, but every organization has its own policy. A configurable rule engine lets operators define org-specific constraints and surface violations as first-class alerts.

## Why now

`posture.py` already evaluates: key size, SHA-1, ECDSA curves, chain completeness, TLS version, validity length, self-signed, OCSP must-staple, HSTS. The evaluation is hard-coded. A policy engine extracts these rules into a configurable structure, adds custom constraints (e.g., "no certs from vendor X", "max validity 90 days"), and makes violations actionable alerts.

This is the natural evolution of the existing `evaluate_posture()` + `evaluate_thresholds()` pipeline.

## Scope

### WI-1 — Policy rule model
- `cert_watch.policy` module with a `PolicyRule` dataclass:
  - `rule_id: str` — unique identifier (e.g., `key_size_rsa`, `validity_max_days`, `issuer_allowlist`).
  - `category: str` — `key`, `hash`, `chain`, `tls`, `validity`, `issuer`, `custom`.
  - `severity: str` — `critical`, `warning`, `info`.
  - `enabled: bool`.
  - `parameters: dict` — rule-specific config (e.g., `{"min_rsa": 2048}`, `{"max_days": 90}`, `{"allowed_issuers": ["DigiCert", "Let's Encrypt"]}`).

- A `PolicySet` dataclass holds the ordered list of rules and a default severity.

### WI-2 — Built-in rule library
- `key_size_rsa` — fail if RSA key size < `min_rsa` (default 2048).
- `key_size_ec` — fail if ECDSA curve not in `allowed_curves` (default P-256, P-384, P-521).
- `hash_algorithm` — fail if SHA-1 or MD5.
- `chain_completeness` — fail if chain is incomplete (existing `chain_incomplete` check).
- `tls_version` — fail if negotiated TLS < `min_tls` (default 1.2).
- `validity_max_days` — fail if validity period > `max_days` (default 398, i.e., ~13 months).
- `self_signed` — fail if self-signed (configurable, default warn).
- `issuer_allowlist` — fail if issuer CN not in `allowed_issuers` (default disabled).
- `sans_required` — fail if no SANs present (default disabled).
- `ocsp_must_staple` — fail if no OCSP must-staple extension (default info).
- `hsts_required` — fail if no HSTS header on HTTPS probe (default info).

### WI-3 — Policy evaluation engine
- `evaluate_policy(cert, chain, posture, ruleset) -> list[PolicyViolation]`:
  - Runs each enabled rule in order.
  - Returns a `PolicyViolation` with `rule_id`, `severity`, `message`, and `remediation`.
  - A `critical` violation overrides the posture grade to `F` regardless of the posture score.
  - A `warning` violation caps the grade at `C`.

### WI-4 — Policy alerts
- `alerts.py` adds a new alert type: `policy_violation`.
- `evaluate_thresholds` (or a new `evaluate_policy_alerts`) creates pending alerts for each `critical` or `warning` violation.
- The alert message includes the rule name, severity, and suggested remediation.

### WI-5 — UI and API
- `GET /api/policy` — return the current active policy set.
- `POST /api/policy` — update the policy set (admin scope required).
- `GET /settings/policy` — HTML editor with toggle switches, numeric inputs, and multi-selects for each rule.
- Policy persisted in `kv_store` as JSON; env vars override GUI values (existing convention).
- `GET /api/reports/policy-violations` — export violations as CSV/JSON for compliance reporting.

### WI-6 — Default behavior
- The default policy set is **equivalent** to today's posture grading: no new failures unless the operator explicitly tightens rules.
- This preserves backward compatibility; the policy engine is opt-in tightening.

## Acceptance

- A cert with RSA 1024 is flagged by `key_size_rsa` as `critical` and the overall grade is `F`.
- A cert with validity 400 days is flagged by `validity_max_days` as `warning` when `max_days=398`.
- A cert from an issuer not in the allowlist is flagged when `issuer_allowlist` is enabled.
- Disabling a rule removes its violations from future evaluations.
- The policy editor in settings can enable/disable rules and edit parameters.
- The existing posture grade for a default-config policy is identical to the current hard-coded posture grade.
- 0 lint errors; unit tests cover each rule, severity override, and UI/API round-trip; full suite passes.

## Non-goals

- Custom Python rule plugins (arbitrary code execution in policy rules is a security risk; stick to the built-in library).
- Per-host policy overrides (all hosts share the global policy in v1; per-host policies are a follow-up).
- Policy-as-code (YAML/JSON files on disk); the kv_store is the source of truth.
