"""Policy engine — configurable rules for certificate compliance."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from cert_watch.certificate_model import Certificate
from cert_watch.database.kv_store import kv_get, kv_set
from cert_watch.posture import GRADE_WORST_ORDER

logger = logging.getLogger("cert_watch.policy")

_POLICY_KV_KEY = "policy_set"

_ALLOWED_EC_CURVES = ["secp256r1", "secp384r1", "secp521r1"]

_ALLOWED_SEVERITIES = {"critical", "warning", "info"}


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


@dataclass
class PolicyViolation:
    rule_id: str
    severity: str
    message: str
    remediation: str


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
    except Exception:
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
        except Exception:
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
        except Exception:
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
            except Exception:
                pass
        except Exception:
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
        except Exception:
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
        except Exception:
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

    return []


def evaluate_policy(
    cert: Certificate,
    chain_status: str | None,
    chain_incomplete: bool,
    protocol_version: str | None,
    hsts: bool | None,
    ocsp_stapling: bool | None,
    ruleset: PolicySet,
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
    except Exception:
        logger.warning("Failed to parse certificate DER for policy evaluation")
        return [PolicyViolation(
            "no_data", "critical",
            "Certificate data could not be parsed",
            "Rescan the host or re-upload the certificate",
        )]

    for rule in ruleset.rules:
        if not rule.enabled:
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
    if any(v.severity == "critical" for v in violations):
        return "F"
    if any(v.severity == "warning" for v in violations):
        current = GRADE_WORST_ORDER.get(grade, _F_GRADE_ORDINAL)
        if current < _C_GRADE_ORDINAL:
            return "C"
    return grade


def _serialize_policy_set(ruleset: PolicySet) -> str:
    data = {
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
    return json.dumps(data)


def _deserialize_policy_set(raw: str) -> PolicySet:
    data = json.loads(raw)
    rules_data = data.get("rules", [])
    default_sev = data.get("default_severity", "warning")
    if default_sev not in _ALLOWED_SEVERITIES:
        default_sev = "warning"
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
    return PolicySet(rules=rules, default_severity=default_sev)


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
    kv_set(db_path, _POLICY_KV_KEY, _serialize_policy_set(ruleset))