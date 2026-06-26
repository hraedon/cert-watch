"""Policy engine — configurable rules for certificate compliance."""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cert_watch.certificate_model import Certificate
from cert_watch.database.kv_store import kv_get, kv_set
from cert_watch.posture import GRADE_WORST_ORDER, Finding

logger = logging.getLogger("cert_watch.policy")

_POLICY_KV_KEY = "policy_set"

_ALLOWED_EC_CURVES = ["secp256r1", "secp384r1", "secp521r1"]

_ALLOWED_SEVERITIES = {"critical", "warning", "info"}

# Mapping from policy rule_id → posture Finding.check name for checks that
# overlap.  When posture already flagged the issue (status != "pass"), the
# policy violation is redundant (WI-014: avoid double-penalization).
_POLICY_TO_POSTURE_CHECK: dict[str, str] = {
    "key_size_rsa": "rsa_key_size",
    "key_size_ec": "ecdsa_curve",
    "hash_algorithm": "sha1_signature",
    "chain_completeness": "chain_completeness",
    "tls_version": "tls_version",
    "self_signed": "self_signed",
    "ocsp_must_staple": "ocsp_must_staple",
    "hsts_required": "hsts",
    "validity_max_days": "long_validity",
}

# Module-level lock for serialising policy writes (WI-017).
_policy_lock = threading.RLock()


@dataclass
class PolicyRule:
    rule_id: str
    category: str
    severity: str
    enabled: bool
    parameters: dict = field(default_factory=dict)


@dataclass
class PolicySet:
    rules: list[PolicyRule] = field(default_factory=list)
    default_severity: str = "warning"
    name: str = ""
    version: str = ""


@dataclass
class PolicyViolation:
    rule_id: str
    severity: str
    message: str
    remediation: str
    grade_affecting: bool = True


def default_policy_set() -> PolicySet:
    return PolicySet(
        rules=[
            PolicyRule("key_size_rsa", "key", "critical", False, {"min_rsa": 2048}),
            PolicyRule(
                "key_size_ec", "key", "critical", False,
                {"allowed_curves": list(_ALLOWED_EC_CURVES)},
            ),
            PolicyRule("hash_algorithm", "hash", "critical", False, {}),
            PolicyRule("chain_completeness", "chain", "warning", False, {}),
            PolicyRule("tls_version", "tls", "warning", False, {"min_tls": "1.2"}),
            PolicyRule("validity_max_days", "validity", "warning", False, {"max_days": 398}),
            PolicyRule("self_signed", "issuer", "warning", False, {}),
            PolicyRule(
                "issuer_allowlist", "issuer", "critical", False,
                {"allowed_issuers": []},
            ),
            PolicyRule("sans_required", "custom", "warning", False, {}),
            PolicyRule("ocsp_must_staple", "tls", "info", False, {}),
            PolicyRule("hsts_required", "tls", "info", False, {}),
        ],
        default_severity="warning",
    )


def _extract_cn_from_name(x509_name: Any) -> str:
    from cryptography.x509.oid import NameOID

    try:
        cns = x509_name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            return cns[0].value
    except (ValueError, TypeError, AttributeError):
        pass
    return str(x509_name)


def _tls_meets_min(protocol_version: str, min_tls: str) -> bool:
    from cert_watch.posture import tls_version_meets_1_2

    p = protocol_version.strip().lower()
    min_norm = min_tls.lower()
    if min_norm.startswith("tlsv"):
        min_norm = min_norm[len("tlsv"):]
    if min_norm == "1.3":
        return p == "tlsv1.3"
    if min_norm == "1.2":
        return tls_version_meets_1_2(protocol_version)
    return False


def _evaluate_rule(
    rule: PolicyRule,
    cert: Certificate,
    x509_cert: Any,
    chain_status: str | None,
    chain_incomplete: bool,
    protocol_version: str | None,
    hsts: bool | None,
    ocsp_stapling: bool | None,
) -> list[PolicyViolation]:
    from cryptography import x509 as _x509_mod
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

    rid = rule.rule_id
    sev = rule.severity
    params = rule.parameters

    if rid == "key_size_rsa":
        try:
            key = x509_cert.public_key()
            if isinstance(key, rsa.RSAPublicKey):
                min_rsa = params.get("min_rsa", 2048)
                if key.key_size < min_rsa:
                    return [PolicyViolation(
                        rid, sev,
                        f"RSA key size {key.key_size} < {min_rsa} bits",
                        f"Replace certificate with RSA key of at least {min_rsa} bits",
                    )]
        except (ValueError, TypeError, UnsupportedAlgorithm):  # crypto key access
            pass
        return []

    if rid == "key_size_ec":
        try:
            key = x509_cert.public_key()
            if isinstance(key, ec.EllipticCurvePublicKey):
                allowed = params.get("allowed_curves", list(_ALLOWED_EC_CURVES))
                if key.curve.name not in allowed:
                    return [PolicyViolation(
                        rid, sev,
                        f"ECDSA curve {key.curve.name} not in allowed list",
                        f"Replace certificate with an allowed curve: {', '.join(allowed)}",
                    )]
        except (ValueError, TypeError, UnsupportedAlgorithm):  # crypto key access
            pass
        return []

    if rid == "hash_algorithm":
        try:
            sig_oid = x509_cert.signature_algorithm_oid
            sha1_oids = (
                SignatureAlgorithmOID.RSA_WITH_SHA1,
                SignatureAlgorithmOID.ECDSA_WITH_SHA1,
            )
            if sig_oid in sha1_oids:
                return [PolicyViolation(
                    rid, sev,
                    "SHA-1 signature algorithm",
                    "Reissue certificate with SHA-256 or stronger signature",
                )]
            try:
                sig_hash = x509_cert.signature_hash_algorithm
                if isinstance(sig_hash, hashes.MD5):
                    return [PolicyViolation(
                        rid, sev,
                        "MD5 signature algorithm",
                        "Reissue certificate with SHA-256 or stronger signature",
                    )]
            except (ValueError, TypeError):  # crypto hash access
                pass
        except (ValueError, TypeError):  # crypto sig access
            pass
        return []

    if rid == "chain_completeness":
        if chain_incomplete or chain_status == "incomplete":
            return [PolicyViolation(
                rid, sev,
                "Incomplete certificate chain",
                "Configure server to serve full chain including intermediates",
            )]
        if chain_status == "invalid":
            return [PolicyViolation(
                rid, sev,
                "Certificate chain validation failed",
                "Fix chain configuration or replace invalid intermediates",
            )]
        return []

    if rid == "tls_version":
        if protocol_version:
            min_tls = params.get("min_tls", "1.2")
            if not _tls_meets_min(protocol_version, min_tls):
                return [PolicyViolation(
                    rid, sev,
                    f"TLS {protocol_version} below minimum {min_tls}",
                    f"Disable TLS versions below {min_tls}",
                )]
        return []

    if rid == "validity_max_days":
        validity_days = (cert.not_after - cert.not_before).days
        max_days = params.get("max_days", 398)
        if validity_days > max_days:
            return [PolicyViolation(
                rid, sev,
                f"Certificate validity {validity_days} days exceeds {max_days}-day limit",
                f"Reissue certificate with validity period of {max_days} days or less",
            )]
        return []

    if rid == "self_signed":
        try:
            is_self_signed = x509_cert.subject == x509_cert.issuer
        except (ValueError, TypeError):  # x509 name comparison
            is_self_signed = cert.subject == cert.issuer
        if is_self_signed:
            return [PolicyViolation(
                rid, sev,
                "Self-signed certificate in production position",
                "Replace with a certificate from a trusted CA",
            )]
        return []

    if rid == "issuer_allowlist":
        allowed = params.get("allowed_issuers", [])
        if allowed:
            issuer_cn = _extract_cn_from_name(x509_cert.issuer)
            if issuer_cn not in allowed:
                return [PolicyViolation(
                    rid, sev,
                    f"Issuer '{issuer_cn}' not in allowlist",
                    f"Use a certificate from an allowed issuer: {', '.join(allowed)}",
                )]
        return []

    if rid == "sans_required":
        if not cert.san_dns_names:
            return [PolicyViolation(
                rid, sev,
                "No Subject Alternative Names present",
                "Reissue certificate with SAN extension including DNS names",
            )]
        return []

    if rid == "ocsp_must_staple":
        try:
            ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
            must_staple = any(feature.value == 5 for feature in ext.value)
        except (_x509_mod.ExtensionNotFound, ValueError, TypeError):  # must-staple extension
            must_staple = False
        if not must_staple:
            return [PolicyViolation(
                rid, sev,
                "OCSP Must-Staple not configured",
                "Request certificate with OCSP Must-Staple extension",
            )]
        return []

    if rid == "hsts_required":
        if hsts is not True:
            return [PolicyViolation(
                rid, sev,
                "HSTS header not detected",
                "Enable HSTS on the web server (Strict-Transport-Security header)",
            )]
        return []

    if rid.startswith("sc081_validity_"):
        if chain_status != "public":
            return []
        milestone_date_str = params.get("milestone_date", "")
        max_days = params.get("max_days", 0)
        if not milestone_date_str:
            return []
        try:
            milestone_date = datetime.fromisoformat(milestone_date_str)
        except (ValueError, TypeError):
            return []
        nb = cert.not_before
        if nb.tzinfo is not None and milestone_date.tzinfo is None:
            milestone_date = milestone_date.replace(tzinfo=UTC)
        elif nb.tzinfo is None and milestone_date.tzinfo is not None:
            milestone_date = milestone_date.replace(tzinfo=None)
        if nb < milestone_date:
            return []
        validity_days = (cert.not_after - cert.not_before).days
        if validity_days > max_days:
            return [PolicyViolation(
                rid, sev,
                f"SC-081: Certificate validity {validity_days} days exceeds "
                f"{max_days}-day limit for certs issued after {milestone_date_str}",
                f"Reissue certificate with validity period of {max_days} days or less",
                grade_affecting=False,
            )]
        return []

    return []


def evaluate_policy(
    cert: Certificate,
    chain_status: str | None,
    chain_incomplete: bool,
    protocol_version: str | None,
    hsts: bool | None,
    ocsp_stapling: bool | None,
    ruleset: PolicySet,
    posture_findings: list[Finding] | None = None,
) -> list[PolicyViolation]:
    violations: list[PolicyViolation] = []

    if not cert.raw_der:
        return [PolicyViolation(
            "no_data", "critical",
            "No certificate data available for policy evaluation",
            "Rescan the host or re-upload the certificate",
        )]

    from cryptography import x509

    try:
        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
    except (ValueError, TypeError):  # x509 DER parse
        logger.warning("Failed to parse certificate DER for policy evaluation")
        return [PolicyViolation(
            "no_data", "critical",
            "Certificate data could not be parsed",
            "Rescan the host or re-upload the certificate",
        )]

    # Build a set of posture check names that already flagged a problem,
    # so we can skip the corresponding policy rule (WI-014).
    # Only suppress on "warn" or "fail" — "info" findings are informational
    # and should not block a policy rule from firing.
    already_flagged: set[str] = set()
    if posture_findings:
        for f in posture_findings:
            if f.status in ("warn", "fail"):
                already_flagged.add(f.check)

    for rule in ruleset.rules:
        if not rule.enabled:
            continue
        # Skip rule if posture already covers the same check (WI-014).
        posture_check = _POLICY_TO_POSTURE_CHECK.get(rule.rule_id)
        if posture_check and posture_check in already_flagged:
            continue
        vs = _evaluate_rule(
            rule, cert, x509_cert,
            chain_status, chain_incomplete,
            protocol_version, hsts, ocsp_stapling,
        )
        violations.extend(vs)

    return violations


_C_GRADE_ORDINAL = GRADE_WORST_ORDER["C"]
_F_GRADE_ORDINAL = GRADE_WORST_ORDER["F"]


def apply_policy_overrides(grade: str, violations: list[PolicyViolation]) -> str:
    grade_vs = [v for v in violations if v.grade_affecting]
    if any(v.severity == "critical" for v in grade_vs):
        return "F"
    if any(v.severity == "warning" for v in grade_vs):
        current = GRADE_WORST_ORDER.get(grade, _F_GRADE_ORDINAL)
        if current < _C_GRADE_ORDINAL:
            return "C"
    return grade


def _serialize_policy_set(ruleset: PolicySet) -> str:
    data: dict[str, Any] = {
        "default_severity": ruleset.default_severity,
        "rules": [
            {
                "rule_id": r.rule_id,
                "category": r.category,
                "severity": r.severity,
                "enabled": r.enabled,
                "parameters": r.parameters,
            }
            for r in ruleset.rules
        ],
    }
    if ruleset.name:
        data["name"] = ruleset.name
    if ruleset.version:
        data["version"] = ruleset.version
    return json.dumps(data)


def _deserialize_policy_set(raw: str) -> PolicySet:
    data = json.loads(raw)
    rules_data = data.get("rules", [])
    default_sev = data.get("default_severity", "warning")
    if default_sev not in _ALLOWED_SEVERITIES:
        default_sev = "warning"
    name = data.get("name", "")
    version = data.get("version", "")
    rules: list[PolicyRule] = []
    for r in rules_data:
        if not isinstance(r, dict):
            continue
        rule_id = r.get("rule_id", "unknown")
        category = r.get("category", "custom")
        sev = r.get("severity", "")
        if sev not in _ALLOWED_SEVERITIES:
            sev = default_sev
        enabled = r.get("enabled", False)
        params = r.get("parameters", {})
        if not isinstance(params, dict):
            params = {}
        rules.append(PolicyRule(
            rule_id=rule_id,
            category=category,
            severity=sev,
            enabled=bool(enabled),
            parameters=params,
        ))
    return PolicySet(rules=rules, default_severity=default_sev, name=name, version=version)


def load_policy_set(db_path: str) -> PolicySet:
    stored = kv_get(db_path, _POLICY_KV_KEY)
    if stored is None:
        return default_policy_set()
    try:
        return _deserialize_policy_set(stored)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        logger.warning("Malformed policy data in kv_store, falling back to defaults")
        return default_policy_set()


def save_policy_set(db_path: str, ruleset: PolicySet) -> None:
    with _policy_lock:
        kv_set(db_path, _POLICY_KV_KEY, _serialize_policy_set(ruleset))


def save_policy_set_locked(db_path: str, ruleset: PolicySet) -> None:
    """Save a policy set while holding the write lock.

    Use this when the caller needs to guarantee that the save is serialised
    with other locked writes (e.g. the PUT handler's read-modify-write).
    The lock is already held by the caller via :func:`acquire_policy_lock`.
    """
    kv_set(db_path, _POLICY_KV_KEY, _serialize_policy_set(ruleset))


class acquire_policy_lock:
    """Context manager that holds the policy write lock (WI-017).

    Usage::

        with acquire_policy_lock():
            current = load_policy_set(db)
            # ... merge / modify ...
            save_policy_set_locked(db, updated)
    """

    def __enter__(self) -> None:
        _policy_lock.acquire()

    def __exit__(self, *exc: Any) -> None:
        _policy_lock.release()