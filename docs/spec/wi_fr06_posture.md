# Interface Specification: FR-06 TLS Posture Grading

## Dependencies

- `interface_ref`: `certificate_model`
- `interface_ref`: `cert_chain_library`
- `interface_ref`: `tls_scan`

## AC-01: Posture Evaluation

`evaluate_posture(cert, chain, tls_version, hsts_present, verify_requested, db_path) -> PostureResult` must grade a certificate as:

- **A+**: TLS 1.3 + HSTS present + all other checks pass
- **A**: All checks pass (no SHA-1, strong key, complete chain, TLS ≥ 1.2, reasonable validity, HSTS or OCSP must-staple)
- **B**: Minor issues (e.g., RSA 2048 key, no HSTS on non-443)
- **C**: Moderate issues (e.g., RSA 1024 key, self-signed, validity > 397 days)
- **F**: Critical issues (SHA-1, key < 1024, TLS 1.0/1.1, incomplete chain)

## AC-02: Key Size Check

- RSA: require ≥ 2048 bits (A+), 1024 bits = C, < 1024 = F
- ECDSA: require curve P-256 or stronger (P-384, P-521); non-standard curves = C
- EdDSA: acceptable for A+
- DSA: reject (F)

## AC-03: Signature Algorithm Check

- SHA-1 in any certificate (leaf or chain) = F
- SHA-256 or stronger required for A/A+
- MD5/MD2 = F

## AC-04: Chain Completeness

- A verified chain from leaf to a trust anchor must be present.
- Missing intermediate = C
- Self-signed leaf without uploaded trust anchor = C
- `chain_incomplete` flag stored in `scan_posture` when scan degradation occurs.

## AC-05: TLS Version Check

- TLS 1.3 = A+ requirement
- TLS 1.2 = acceptable for A
- TLS 1.0 or 1.1 = F
- `tls_version_meets_1_2()` shared helper used by both posture grade and compliance metric.

## AC-06: Validity Length Check

- Certificate validity > 397 days = C (baseline requirement)
- Exception: self-signed/internal CA certificates are exempt from validity-length penalty

## AC-07: HSTS Check

- HSTS header present on port 443 = A+ requirement
- `_probe_hsts()` checks the HSTS header using the pinned IP + correct SNI
- HSTS not applicable on non-443 ports (no penalty)

## AC-08: OCSP Must-Staple

- OCSP must-staple extension present = positive signal (counts toward A+)
- `CERT_WATCH_CHECK_REVOCATION=1` enables OCSP/CRL reachability checks (findings are warnings, not grade penalties)
- OCSP/CRL probes route through `http_client.ssrf_safe_urlopen` with SSRF validation
- Blocked endpoints emit "blocked by SSRF policy" findings, not failures

## AC-09: Posture Storage

- `scan_posture` table stores: `grade`, `findings` (JSON), `tls_version`, `chain_status`, `caa_present`, `caa_records`, `verify_requested`
- `verify_requested` stores the operator config flag (renamed from `tls_verified` in BC-125)
- Posture recomputed on every scan; historical posture visible in certificate detail page

## AC-10: Drift Detection

- `CERT_WATCH_DRIFT_ALERTS=1` (default) fires when:
  - Issuer changes
  - Key size drops
  - SHA-1 downgrade
  - Posture grade drops
  - TLS version downgrades
- Drift alerts are `pending` alerts with `type=drift_*` and appear in the alerts UI
