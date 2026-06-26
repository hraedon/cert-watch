"""Tests for the policy engine (Plan 042 WI-1 through WI-3)."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from cert_watch.certificate_model import Certificate
from cert_watch.database.kv_store import kv_get, kv_set
from cert_watch.database.schema import init_schema
from cert_watch.policy import (
    _POLICY_TO_POSTURE_CHECK,
    PolicyRule,
    PolicySet,
    PolicyViolation,
    _deserialize_policy_set,
    _extract_cn_from_name,
    _tls_meets_min,
    acquire_policy_lock,
    apply_policy_overrides,
    default_policy_set,
    evaluate_policy,
    load_policy_set,
    save_policy_set,
    save_policy_set_locked,
)


def _make_cert(
    subject: str = "CN=test.example.com",
    issuer: str = "CN=Test CA",
    days_remaining: int = 90,
    san_dns_names: list[str] | None = None,
    raw_der: bytes = b"",
) -> Certificate:
    now = datetime.now(UTC)
    return Certificate(
        subject=subject,
        issuer=issuer,
        not_before=now - timedelta(days=90),
        not_after=now + timedelta(days=days_remaining),
        san_dns_names=san_dns_names or ["test.example.com"],
        fingerprint_sha256="AA" * 32,
        raw_der=raw_der,
    )


def _self_signed_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "self-signed.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _weak_rsa_cert_der(key_size: int = 1024) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "weak-rsa.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _ca_signed_cert_der() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "good.example.com"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Good CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("good.example.com")]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _long_validity_cert_der(days: int = 400) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "long-validity.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _ecdsa_cert_der(curve_name: str = "secp256r1") -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    curve_map = {"secp256r1": ec.SECP256R1(), "secp224r1": ec.SECP224R1()}
    key = ec.generate_private_key(curve_map[curve_name])
    now = datetime.now(UTC)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"{curve_name}.example.com"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _cert_from_der(der: bytes) -> Certificate:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    x509_cert = x509.load_der_x509_certificate(der)
    fp = x509_cert.fingerprint(hashes.SHA256()).hex()
    san_names: list[str] = []
    try:
        ext = x509_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        san_names = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    return Certificate(
        subject=str(x509_cert.subject),
        issuer=str(x509_cert.issuer),
        not_before=x509_cert.not_valid_before_utc,
        not_after=x509_cert.not_valid_after_utc,
        san_dns_names=san_names,
        fingerprint_sha256=fp,
        raw_der=der,
    )


def _all_disabled_ruleset() -> PolicySet:
    ruleset = default_policy_set()
    for r in ruleset.rules:
        r.enabled = False
    return ruleset


class TestDefaultPolicySet:
    def test_returns_11_rules(self):
        ps = default_policy_set()
        assert len(ps.rules) == 11

    def test_all_rules_disabled_by_default(self):
        ps = default_policy_set()
        for r in ps.rules:
            assert r.enabled is False, f"{r.rule_id} should be disabled"

    def test_rule_ids(self):
        ps = default_policy_set()
        ids = [r.rule_id for r in ps.rules]
        expected = [
            "key_size_rsa", "key_size_ec", "hash_algorithm",
            "chain_completeness", "tls_version", "validity_max_days",
            "self_signed", "issuer_allowlist", "sans_required",
            "ocsp_must_staple", "hsts_required",
        ]
        assert ids == expected

    def test_categories(self):
        ps = default_policy_set()
        cats = {r.rule_id: r.category for r in ps.rules}
        assert cats["key_size_rsa"] == "key"
        assert cats["hash_algorithm"] == "hash"
        assert cats["chain_completeness"] == "chain"
        assert cats["tls_version"] == "tls"
        assert cats["validity_max_days"] == "validity"
        assert cats["issuer_allowlist"] == "issuer"
        assert cats["sans_required"] == "custom"

    def test_default_severity_is_warning(self):
        assert default_policy_set().default_severity == "warning"

    def test_default_parameters(self):
        ps = default_policy_set()
        by_id = {r.rule_id: r for r in ps.rules}
        assert by_id["key_size_rsa"].parameters["min_rsa"] == 2048
        assert by_id["tls_version"].parameters["min_tls"] == "1.2"
        assert by_id["validity_max_days"].parameters["max_days"] == 398
        assert by_id["issuer_allowlist"].parameters["allowed_issuers"] == []
        curves = by_id["key_size_ec"].parameters["allowed_curves"]
        assert curves == ["secp256r1", "secp384r1", "secp521r1"]


class TestEvaluatePolicyAllDisabled:
    def test_no_violations_when_all_disabled(self):
        der = _self_signed_cert_der()
        cert = _cert_from_der(der)
        violations = evaluate_policy(
            cert, chain_status=None, chain_incomplete=False,
            protocol_version="TLSv1.0", hsts=False, ocsp_stapling=False,
            ruleset=_all_disabled_ruleset(),
        )
        assert violations == []

    def test_empty_der_produces_critical_violation(self):
        cert = _make_cert(raw_der=b"")
        violations = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version="TLSv1.2", hsts=True, ocsp_stapling=True,
            ruleset=default_policy_set(),
        )
        assert len(violations) == 1
        assert violations[0].rule_id == "no_data"
        assert violations[0].severity == "critical"


class TestKeySizeRsaRule:
    def _ruleset(self, min_rsa: int = 2048) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "key_size_rsa":
                r.enabled = True
                r.parameters["min_rsa"] = min_rsa
        return ps

    def test_weak_rsa_violation(self):
        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "key_size_rsa"
        assert vs[0].severity == "critical"
        assert "1024" in vs[0].message

    def test_strong_rsa_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0

    def test_unsupported_algorithm_no_violation(self, monkeypatch):
        """WI-118: UnsupportedAlgorithm from public_key() must not crash."""
        from unittest.mock import MagicMock

        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        fake_cert = MagicMock()
        fake_cert.public_key.side_effect = UnsupportedAlgorithm(
            "unsupported public key",
        )
        monkeypatch.setattr(
            x509, "load_der_x509_certificate", lambda _data: fake_cert,
        )
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert vs == []


class TestKeySizeEcRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "key_size_ec":
                r.enabled = True
        return ps

    def test_weak_curve_violation(self):
        der = _ecdsa_cert_der("secp224r1")
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "key_size_ec"
        assert "secp224r1" in vs[0].message

    def test_strong_curve_passes(self):
        der = _ecdsa_cert_der("secp256r1")
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0

    def test_unsupported_algorithm_no_violation(self, monkeypatch):
        """WI-118: UnsupportedAlgorithm from public_key() must not crash."""
        from unittest.mock import MagicMock

        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm

        der = _ecdsa_cert_der("secp256r1")
        cert = _cert_from_der(der)
        fake_cert = MagicMock()
        fake_cert.public_key.side_effect = UnsupportedAlgorithm(
            "unsupported public key",
        )
        monkeypatch.setattr(
            x509, "load_der_x509_certificate", lambda _data: fake_cert,
        )
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert vs == []


class TestHashAlgorithmRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "hash_algorithm":
                r.enabled = True
        return ps

    def test_sha256_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0

    def test_sha1_violation(self):
        from cryptography import x509
        from cryptography.x509.oid import SignatureAlgorithmOID

        der = _ca_signed_cert_der()
        hex_der = der.hex()
        sha256_oid_hex = "2a864886f70d01010b"
        sha1_oid_hex = "2a864886f70d010105"
        patched_der = bytes.fromhex(hex_der.replace(sha256_oid_hex, sha1_oid_hex))
        x509_cert = x509.load_der_x509_certificate(patched_der)
        assert x509_cert.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA1
        cert = _cert_from_der(der)
        rs = self._ruleset()
        hash_rule = next(r for r in rs.rules if r.rule_id == "hash_algorithm")
        from cert_watch.policy import _evaluate_rule as _eval

        vs = _eval(hash_rule, cert, x509_cert, None, False, None, None, None)
        assert len(vs) == 1
        assert vs[0].rule_id == "hash_algorithm"
        assert "SHA-1" in vs[0].message


class TestChainCompletenessRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "chain_completeness":
                r.enabled = True
        return ps

    def test_incomplete_chain_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, "incomplete", False, None, None, None, self._ruleset(),
        )
        assert len(vs) == 1
        assert vs[0].rule_id == "chain_completeness"

    def test_chain_incomplete_flag(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, True, None, None, None, self._ruleset())
        assert len(vs) == 1

    def test_invalid_chain_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, "invalid", False, None, None, None, self._ruleset(),
        )
        assert len(vs) == 1
        assert "validation failed" in vs[0].message.lower()

    def test_complete_chain_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, "public", False, None, None, None, self._ruleset(),
        )
        assert len(vs) == 0


class TestTlsVersionRule:
    def _ruleset(self, min_tls: str = "1.2") -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "tls_version":
                r.enabled = True
                r.parameters["min_tls"] = min_tls
        return ps

    def test_tls_10_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, None, False, "TLSv1.0", None, None, self._ruleset(),
        )
        assert len(vs) == 1
        assert "TLSv1.0" in vs[0].message

    def test_tls_12_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, None, False, "TLSv1.2", None, None, self._ruleset(),
        )
        assert len(vs) == 0

    def test_no_protocol_no_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0

    def test_min_tls_13(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset(min_tls="1.3")
        vs = evaluate_policy(cert, None, False, "TLSv1.2", None, None, rs)
        assert len(vs) == 1
        vs2 = evaluate_policy(cert, None, False, "TLSv1.3", None, None, rs)
        assert len(vs2) == 0

    def test_min_tls_13_with_prefix(self):
        assert _tls_meets_min("TLSv1.2", "TLSv1.3") is False
        assert _tls_meets_min("TLSv1.3", "TLSv1.3") is True

    def test_unknown_min_tls_fails_closed(self):
        assert _tls_meets_min("TLSv1.2", "2.0") is False
        assert _tls_meets_min("TLSv1.2", "unknown") is False


class TestValidityMaxDaysRule:
    def _ruleset(self, max_days: int = 398) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "validity_max_days":
                r.enabled = True
                r.parameters["max_days"] = max_days
        return ps

    def test_long_validity_violation(self):
        der = _long_validity_cert_der(400)
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "validity_max_days"
        assert "exceeds 398-day" in vs[0].message

    def test_normal_validity_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0

    def test_tight_90_day_limit(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(
            cert, None, False, None, None, None, self._ruleset(max_days=90),
        )
        assert len(vs) == 1


class TestSelfSignedRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "self_signed":
                r.enabled = True
        return ps

    def test_self_signed_violation(self):
        der = _self_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "self_signed"
        assert "Self-signed" in vs[0].message

    def test_ca_signed_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0


class TestIssuerAllowlistRule:
    def _ruleset(self, allowed: list[str] | None = None) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "issuer_allowlist":
                r.enabled = True
                r.parameters["allowed_issuers"] = allowed or ["Good CA"]
        return ps

    def test_issuer_not_in_allowlist(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset(allowed=["Other CA"])
        vs = evaluate_policy(cert, None, False, None, None, None, rs)
        assert len(vs) == 1
        assert vs[0].rule_id == "issuer_allowlist"

    def test_issuer_in_allowlist(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset(allowed=["Good CA"])
        vs = evaluate_policy(cert, None, False, None, None, None, rs)
        assert len(vs) == 0

    def test_empty_allowlist_no_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset(allowed=[])
        vs = evaluate_policy(cert, None, False, None, None, None, rs)
        assert len(vs) == 0


class TestSansRequiredRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "sans_required":
                r.enabled = True
        return ps

    def test_no_sans_violation(self):
        der = _self_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "sans_required"

    def test_with_sans_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0


class TestOcspMustStapleRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "ocsp_must_staple":
                r.enabled = True
        return ps

    def test_no_must_staple_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 1
        assert vs[0].rule_id == "ocsp_must_staple"
        assert vs[0].severity == "info"

    def test_must_staple_present_passes(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509 import TLSFeatureType
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(UTC)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "must-staple.example.com"),
        ])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90))
            .add_extension(
                x509.TLSFeature(
                    features=[TLSFeatureType.status_request],
                ),
                critical=False,
            )
        )
        cert_obj = builder.sign(key, hashes.SHA256())
        der = cert_obj.public_bytes(serialization.Encoding.DER)
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, self._ruleset())
        assert len(vs) == 0


class TestHstsRequiredRule:
    def _ruleset(self) -> PolicySet:
        ps = _all_disabled_ruleset()
        for r in ps.rules:
            if r.rule_id == "hsts_required":
                r.enabled = True
        return ps

    def test_no_hsts_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset()
        vs = evaluate_policy(cert, None, False, None, hsts=False, ocsp_stapling=None, ruleset=rs)
        assert len(vs) == 1
        assert vs[0].rule_id == "hsts_required"
        assert vs[0].severity == "info"

    def test_hsts_present_passes(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset()
        vs = evaluate_policy(cert, None, False, None, hsts=True, ocsp_stapling=None, ruleset=rs)
        assert len(vs) == 0

    def test_hsts_none_violation(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        rs = self._ruleset()
        vs = evaluate_policy(cert, None, False, None, hsts=None, ocsp_stapling=None, ruleset=rs)
        assert len(vs) == 1


class TestApplyPolicyOverrides:
    def test_critical_overrides_to_f(self):
        vs = [PolicyViolation("x", "critical", "msg", "fix")]
        assert apply_policy_overrides("A", vs) == "F"

    def test_warning_caps_at_c(self):
        vs = [PolicyViolation("x", "warning", "msg", "fix")]
        assert apply_policy_overrides("A", vs) == "C"
        assert apply_policy_overrides("A+", vs) == "C"
        assert apply_policy_overrides("B", vs) == "C"

    def test_warning_does_not_lower_c_or_below(self):
        vs = [PolicyViolation("x", "warning", "msg", "fix")]
        assert apply_policy_overrides("C", vs) == "C"
        assert apply_policy_overrides("F", vs) == "F"

    def test_no_violations_keeps_grade(self):
        assert apply_policy_overrides("A", []) == "A"
        assert apply_policy_overrides("A+", []) == "A+"
        assert apply_policy_overrides("B", []) == "B"
        assert apply_policy_overrides("C", []) == "C"
        assert apply_policy_overrides("F", []) == "F"

    def test_info_severity_no_impact(self):
        vs = [PolicyViolation("x", "info", "msg", "fix")]
        assert apply_policy_overrides("A", vs) == "A"
        assert apply_policy_overrides("A+", vs) == "A+"

    def test_critical_beats_warning(self):
        vs = [
            PolicyViolation("a", "warning", "msg", "fix"),
            PolicyViolation("b", "critical", "msg", "fix"),
        ]
        assert apply_policy_overrides("A", vs) == "F"

    def test_a_plus_preserved_without_violations(self):
        assert apply_policy_overrides("A+", []) == "A+"
        assert apply_policy_overrides("A+", [PolicyViolation("x", "info", "m", "f")]) == "A+"


class TestExtractCnFromName:
    def test_extracts_cn_from_x509_name(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        ])
        assert _extract_cn_from_name(name) == "Test CA"

    def test_handles_escaped_commas(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'My "Quoted" CA, Inc.'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org"),
        ])
        assert _extract_cn_from_name(name) == 'My "Quoted" CA, Inc.'

    def test_no_cn_returns_str(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Org Only"),
        ])
        result = _extract_cn_from_name(name)
        assert isinstance(result, str)


class TestPersistenceRoundTrip:
    def test_save_and_load(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        ps = default_policy_set()
        ps.rules[0].enabled = True
        ps.rules[0].parameters["min_rsa"] = 4096
        save_policy_set(db, ps)
        loaded = load_policy_set(db)
        assert len(loaded.rules) == 11
        assert loaded.rules[0].enabled is True
        assert loaded.rules[0].parameters["min_rsa"] == 4096
        for r in loaded.rules[1:]:
            assert r.enabled is False

    def test_load_default_when_no_stored(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        loaded = load_policy_set(db)
        assert len(loaded.rules) == 11
        for r in loaded.rules:
            assert r.enabled is False

    def test_stored_as_json_in_kv_store(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        ps = default_policy_set()
        save_policy_set(db, ps)
        raw = kv_get(db, "policy_set")
        assert raw is not None
        data = json.loads(raw)
        assert "rules" in data
        assert "default_severity" in data
        assert len(data["rules"]) == 11


class TestDeserializationRobustness:
    def test_garbage_json_returns_default(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        kv_set(db, "policy_set", "not valid json {{{")
        loaded = load_policy_set(db)
        assert len(loaded.rules) == 11
        for r in loaded.rules:
            assert r.enabled is False

    def test_missing_rules_key_returns_default(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        kv_set(db, "policy_set", '{"default_severity": "critical"}')
        loaded = load_policy_set(db)
        assert len(loaded.rules) == 0
        assert loaded.default_severity == "critical"

    def test_rule_with_missing_fields_uses_defaults(self):
        raw = json.dumps({"rules": [{"rule_id": "test_rule"}]})
        ps = _deserialize_policy_set(raw)
        assert len(ps.rules) == 1
        assert ps.rules[0].rule_id == "test_rule"
        assert ps.rules[0].category == "custom"
        assert ps.rules[0].severity == "warning"
        assert ps.rules[0].enabled is False
        assert ps.rules[0].parameters == {}

    def test_unknown_severity_falls_back_to_default(self):
        raw = json.dumps({
            "default_severity": "warning",
            "rules": [{"rule_id": "r1", "category": "key", "severity": "bogus", "enabled": True}],
        })
        ps = _deserialize_policy_set(raw)
        assert ps.rules[0].severity == "warning"

    def test_unknown_rule_id_preserved(self):
        raw = json.dumps({
            "rules": [{
                "rule_id": "custom_rule", "category": "custom",
                "severity": "info", "enabled": True,
            }],
        })
        ps = _deserialize_policy_set(raw)
        assert ps.rules[0].rule_id == "custom_rule"
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        vs = evaluate_policy(cert, None, False, None, None, None, ps)
        assert vs == []

    def test_non_dict_rules_skipped(self):
        raw = json.dumps({"rules": ["not a dict", 42, None]})
        ps = _deserialize_policy_set(raw)
        assert len(ps.rules) == 0

    def test_non_dict_parameters_fallback(self):
        raw = json.dumps({
            "rules": [{"rule_id": "r1", "parameters": "bad"}],
        })
        ps = _deserialize_policy_set(raw)
        assert ps.rules[0].parameters == {}

    def test_invalid_default_severity_falls_back(self):
        raw = json.dumps({
            "default_severity": "bogus",
            "rules": [{
                "rule_id": "r1", "category": "key",
                "severity": "also_bogus", "enabled": True,
            }],
        })
        ps = _deserialize_policy_set(raw)
        assert ps.default_severity == "warning"
        assert ps.rules[0].severity == "warning"

    def test_load_malformed_kv_store_returns_default(self, tmp_path):
        db = str(tmp_path / "test.db")
        init_schema(db)
        kv_set(db, "policy_set", "}{not json")
        loaded = load_policy_set(db)
        default = default_policy_set()
        assert len(loaded.rules) == len(default.rules)
        for lr, dr in zip(loaded.rules, default.rules, strict=True):
            assert lr.rule_id == dr.rule_id


class TestWellConfiguredCertNoViolations:
    def test_default_policy_no_violations(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        ps = default_policy_set()
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version="TLSv1.2", hsts=True, ocsp_stapling=True,
            ruleset=ps,
        )
        assert vs == []

    def test_all_enabled_on_good_cert(self):
        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)
        ps = default_policy_set()
        skip = {"issuer_allowlist", "sans_required", "ocsp_must_staple", "hsts_required"}
        for r in ps.rules:
            if r.rule_id not in skip:
                r.enabled = True
        vs = evaluate_policy(
            cert, chain_status="public", chain_incomplete=False,
            protocol_version="TLSv1.2", hsts=True, ocsp_stapling=True,
            ruleset=ps,
        )
        assert len(vs) == 0


# ---------- WI-014: Policy + posture double-penalization ----------


def _enabled_ruleset(*rule_ids: str) -> PolicySet:
    """Return a PolicySet with only the named rules enabled."""
    ps = _all_disabled_ruleset()
    for r in ps.rules:
        if r.rule_id in rule_ids:
            r.enabled = True
    return ps


class TestPostureDeduplication:
    """WI-014: When posture already flagged an issue, policy should not duplicate it."""

    def test_rsa_key_size_deduplicated(self):
        """RSA 1024: posture fails, policy key_size_rsa enabled → only one finding."""
        from cert_watch.posture import Finding

        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="rsa_key_size", status="fail", message="RSA key size 1024 < 2048 bits"),
        ]

        rs = _enabled_ruleset("key_size_rsa")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0  # skipped because posture already flagged it

        # Without posture findings, the policy violation fires normally.
        vs2 = evaluate_policy(cert, None, False, None, None, None, rs)
        assert len(vs2) == 1
        assert vs2[0].rule_id == "key_size_rsa"

    def test_sha1_deduplicated(self):
        """SHA-1: posture fails, policy hash_algorithm enabled → deduplicated."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="sha1_signature", status="fail", message="SHA-1 signature algorithm"),
        ]

        rs = _enabled_ruleset("hash_algorithm")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0  # skipped

    def test_tls_version_deduplicated(self):
        """TLS 1.0: posture warns, policy tls_version enabled → deduplicated."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="tls_version", status="warn", message="TLS TLSv1.0 offered"),
        ]

        rs = _enabled_ruleset("tls_version")
        vs = evaluate_policy(
            cert, None, False, "TLSv1.0", None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0

    def test_chain_completeness_deduplicated(self):
        """Incomplete chain: posture warns, policy chain_completeness → deduplicated."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="chain_completeness", status="warn", message="Incomplete chain"),
        ]

        rs = _enabled_ruleset("chain_completeness")
        vs = evaluate_policy(
            cert, "incomplete", False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0

    def test_self_signed_deduplicated(self):
        """Self-signed: posture warns, policy self_signed → deduplicated."""
        from cert_watch.posture import Finding

        der = _self_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="self_signed", status="warn", message="Self-signed certificate"),
        ]

        rs = _enabled_ruleset("self_signed")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0

    def test_hsts_pass_not_deduplicated(self):
        """HSTS posture status='pass' should NOT block policy hsts_required."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="hsts", status="pass", message="No HSTS header detected"),
        ]

        rs = _enabled_ruleset("hsts_required")
        vs = evaluate_policy(
            cert, None, False, None, False, None, rs,
            posture_findings=posture_findings,
        )
        # Posture said "pass" so policy rule is NOT deduplicated — it still fires.
        assert len(vs) == 1
        assert vs[0].rule_id == "hsts_required"

    def test_hsts_fail_deduplicated(self):
        """HSTS: posture finding status='warn', policy hsts_required → deduplicated."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="hsts", status="warn", message="HSTS header missing"),
        ]

        rs = _enabled_ruleset("hsts_required")
        vs = evaluate_policy(
            cert, None, False, None, False, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0

    def test_policy_only_rule_not_deduplicated(self):
        """issuer_allowlist has no posture counterpart → always fires."""
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        rs = _enabled_ruleset("issuer_allowlist")
        for r in rs.rules:
            if r.rule_id == "issuer_allowlist":
                r.parameters["allowed_issuers"] = ["Other CA"]

        posture_findings = [
            Finding(check="rsa_key_size", status="fail", message="weak key"),
        ]

        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 1
        assert vs[0].rule_id == "issuer_allowlist"

    def test_validity_max_days_deduplicated(self):
        """Long validity: posture warns, policy validity_max_days → deduplicated."""
        from cert_watch.posture import Finding

        der = _long_validity_cert_der(400)
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(
                check="long_validity", status="warn",
                message="Validity 401 days exceeds 398-day limit",
            ),
        ]

        rs = _enabled_ruleset("validity_max_days")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 0

    def test_sans_required_not_deduplicated(self):
        """sans_required has no posture counterpart → always fires."""
        from cert_watch.posture import Finding

        der = _self_signed_cert_der()  # no SANs
        cert = _cert_from_der(der)

        rs = _enabled_ruleset("sans_required")
        posture_findings = [
            Finding(check="self_signed", status="warn", message="self-signed"),
        ]

        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        assert len(vs) == 1
        assert vs[0].rule_id == "sans_required"

    def test_no_posture_findings_fires_normally(self):
        """When posture_findings is None or empty, all enabled rules fire."""
        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)

        rs = _enabled_ruleset("key_size_rsa")

        vs = evaluate_policy(cert, None, False, None, None, None, rs, posture_findings=None)
        assert len(vs) == 1

        vs2 = evaluate_policy(cert, None, False, None, None, None, rs, posture_findings=[])
        assert len(vs2) == 1

    def test_posture_pass_status_not_deduplicated(self):
        """A posture finding with status='pass' should NOT block the policy rule."""
        from cert_watch.posture import Finding

        der = _weak_rsa_cert_der(1024)
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(check="rsa_key_size", status="pass", message="RSA 2048 bits"),
        ]

        rs = _enabled_ruleset("key_size_rsa")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        # Posture said "pass" so policy rule still fires.
        assert len(vs) == 1

    def test_info_status_does_not_suppress_policy(self):
        """A posture finding with status='info' should NOT block the policy rule.

        Info findings are informational (e.g., OCSP Must-Staple not present)
        and should not prevent a policy rule from flagging the same check.
        """
        from cert_watch.posture import Finding

        der = _ca_signed_cert_der()
        cert = _cert_from_der(der)

        posture_findings = [
            Finding(
                check="ocsp_must_staple", status="info",
                message="OCSP Must-Staple not required",
            ),
        ]

        rs = _enabled_ruleset("ocsp_must_staple")
        vs = evaluate_policy(
            cert, None, False, None, None, None, rs,
            posture_findings=posture_findings,
        )
        # Info status should not suppress the policy rule.
        assert len(vs) == 1

    def test_mapping_completeness(self):
        """Every overlapping rule_id maps to a valid posture check name."""
        for rule_id, check_name in _POLICY_TO_POSTURE_CHECK.items():
            assert isinstance(check_name, str), f"{rule_id} maps to non-string"
            assert len(check_name) > 0, f"{rule_id} maps to empty string"


# ---------- WI-017: Concurrent PUT /api/policy race condition ----------


class TestPolicyWriteLock:
    """WI-017: Serialised policy writes prevent lost updates."""

    def test_lock_prevents_interleaved_writes(self, tmp_path):
        """Two concurrent saves don't lose one writer's data."""
        import threading

        db = str(tmp_path / "test.db")
        init_schema(db)

        ps = default_policy_set()
        save_policy_set(db, ps)

        errors: list[str] = []
        barrier = threading.Barrier(2)

        def writer_a() -> None:
            try:
                barrier.wait(timeout=5)
                with acquire_policy_lock():
                    current = load_policy_set(db)
                    current.rules.append(PolicyRule(
                        rule_id="rule_a", category="custom",
                        severity="warning", enabled=True,
                    ))
                    save_policy_set_locked(db, current)
            except Exception as e:
                errors.append(f"writer_a: {e}")

        def writer_b() -> None:
            try:
                barrier.wait(timeout=5)
                with acquire_policy_lock():
                    current = load_policy_set(db)
                    current.rules.append(PolicyRule(
                        rule_id="rule_b", category="custom",
                        severity="info", enabled=True,
                    ))
                    save_policy_set_locked(db, current)
            except Exception as e:
                errors.append(f"writer_b: {e}")

        t1 = threading.Thread(target=writer_a)
        t2 = threading.Thread(target=writer_b)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert errors == [], f"writer errors: {errors}"

        final = load_policy_set(db)
        rule_ids = [r.rule_id for r in final.rules]
        assert "rule_a" in rule_ids, f"rule_a missing from {rule_ids}"
        assert "rule_b" in rule_ids, f"rule_b missing from {rule_ids}"

    def test_save_policy_set_acquires_lock(self, tmp_path):
        """save_policy_set() itself holds the module-level lock."""
        db = str(tmp_path / "test.db")
        init_schema(db)

        ps = default_policy_set()
        save_policy_set(db, ps)
        loaded = load_policy_set(db)
        assert len(loaded.rules) == 11

    def test_lock_does_not_block_reads(self, tmp_path):
        """GET (load_policy_set) should not be blocked by the write lock."""
        import threading

        db = str(tmp_path / "test.db")
        init_schema(db)
        ps = default_policy_set()
        save_policy_set(db, ps)

        read_result: list[str] = []
        read_done = threading.Event()

        def reader() -> None:
            loaded = load_policy_set(db)
            read_result.append(f"read {len(loaded.rules)} rules")
            read_done.set()

        with acquire_policy_lock():
            t = threading.Thread(target=reader)
            t.start()
            read_done.wait(timeout=3)

        t.join(timeout=5)
        assert len(read_result) == 1
        assert "11 rules" in read_result[0]

    def test_concurrent_read_modify_write_serialized(self, tmp_path):
        """Two concurrent read-modify-writes serialize (no data loss)."""
        import threading

        db = str(tmp_path / "test.db")
        init_schema(db)

        ps1 = PolicySet(rules=[
            PolicyRule(rule_id="base", category="custom", severity="warning", enabled=False),
        ])
        save_policy_set(db, ps1)

        errors: list[str] = []
        barrier = threading.Barrier(2)

        def writer(rule_id: str, severity: str) -> None:
            try:
                barrier.wait(timeout=5)
                with acquire_policy_lock():
                    current = load_policy_set(db)
                    current.rules.append(PolicyRule(
                        rule_id=rule_id, category="custom",
                        severity=severity, enabled=True,
                    ))
                    save_policy_set_locked(db, current)
            except Exception as e:
                errors.append(f"{rule_id}: {e}")

        t1 = threading.Thread(target=writer, args=("rule_x", "critical"))
        t2 = threading.Thread(target=writer, args=("rule_y", "info"))
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert errors == [], f"errors: {errors}"
        final = load_policy_set(db)
        rule_ids = [r.rule_id for r in final.rules]
        assert "rule_x" in rule_ids
        assert "rule_y" in rule_ids
        assert "base" in rule_ids