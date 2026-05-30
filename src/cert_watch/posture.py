"""TLS posture evaluation — policy lint and grade computation."""

from __future__ import annotations

from dataclasses import dataclass, field

from cert_watch.certificate_model import Certificate


@dataclass
class Finding:
    check: str
    status: str   # "pass", "warn", "fail"
    message: str


@dataclass
class PostureResult:
    grade: str                # "A+", "A", "B", "C", "F"
    findings: list[Finding] = field(default_factory=list)
    protocol_version: str = ""
    ocsp_stapling: bool | None = None
    hsts: bool | None = None
    must_staple: bool = False


def evaluate_posture(
    cert: Certificate,
    protocol_version: str | None = None,
    ocsp_stapling: bool | None = None,
    hsts: bool | None = None,
    chain_status: str | None = None,
) -> PostureResult:
    """Evaluate TLS posture grade and lint findings from certificate data.

    Policy lint (data-driven from Certificate object, no network calls):
    - SHA-1 signature algorithm
    - RSA key < 2048 bits / ECDSA < P-256
    - Validity > 398 days (CA/B forum limit)
    - Self-signed leaf
    - Missing intermediate (chain_status incomplete)
    - OCSP must-staple without stapling
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

    findings: list[Finding] = []
    grade_penalty = 0

    try:
        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
    except Exception:
        return PostureResult(
            grade="F",
            findings=[Finding(check="parse", status="fail", message="Cannot parse certificate")],
        )

    try:
        key = x509_cert.public_key()
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048:
                findings.append(Finding(
                    check="rsa_key_size", status="fail",
                    message=f"RSA key size {key.key_size} < 2048 bits",
                ))
                grade_penalty += 2
            else:
                findings.append(Finding(
                    check="rsa_key_size", status="pass",
                    message=f"RSA {key.key_size} bits",
                ))
        elif isinstance(key, ec.EllipticCurvePublicKey):
            curve_name = key.curve.name
            if curve_name in ("secp224r1", "secp192r1"):
                findings.append(Finding(
                    check="ecdsa_curve", status="fail",
                    message=f"Weak ECDSA curve {curve_name}",
                ))
                grade_penalty += 2
            else:
                findings.append(Finding(
                    check="ecdsa_curve", status="pass",
                    message=f"ECDSA {curve_name}",
                ))
        else:
            findings.append(Finding(
                check="key_type", status="pass",
                message=type(key).__name__,
            ))
    except Exception:
        findings.append(Finding(
            check="key_type", status="warn",
            message="Cannot determine key type",
        ))

    try:
        sig_oid = x509_cert.signature_algorithm_oid
        if sig_oid in (
            SignatureAlgorithmOID.RSA_WITH_SHA1,
            SignatureAlgorithmOID.ECDSA_WITH_SHA1,
        ):
            findings.append(Finding(
                check="sha1_signature", status="fail",
                message="SHA-1 signature algorithm",
            ))
            grade_penalty += 2
        else:
            findings.append(Finding(
                check="sha1_signature", status="pass",
                message="No SHA-1 signature",
            ))
    except Exception:
        findings.append(Finding(
            check="sha1_signature", status="warn",
            message="Cannot determine signature algorithm",
        ))

    validity_days = (cert.not_after - cert.not_before).days
    if validity_days > 398:
        findings.append(Finding(
            check="long_validity", status="warn",
            message=f"Validity {validity_days} days exceeds 398-day CA/B limit",
        ))
    else:
        findings.append(Finding(
            check="long_validity", status="pass",
            message=f"Validity {validity_days} days within limit",
        ))

    if cert.subject == cert.issuer:
        findings.append(Finding(
            check="self_signed", status="warn",
            message="Self-signed certificate in production position",
        ))
    else:
        findings.append(Finding(
            check="self_signed", status="pass",
            message="Not self-signed",
        ))

    try:
        ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
        must_staple = any(feature.value == 5 for feature in ext.value)
    except (x509.ExtensionNotFound, Exception):
        must_staple = False
    if must_staple:
        if ocsp_stapling is False:
            findings.append(Finding(
                check="ocsp_must_staple", status="warn",
                message="OCSP Must-Staple but no stapling observed",
            ))
        else:
            findings.append(Finding(
                check="ocsp_must_staple", status="pass",
                message="OCSP Must-Staple configured",
            ))
    else:
        findings.append(Finding(
            check="ocsp_must_staple", status="pass",
            message="OCSP Must-Staple not required",
        ))

    if chain_status == "incomplete":
        findings.append(Finding(
            check="chain_completeness", status="warn",
            message="Incomplete chain - server missing intermediate(s)",
        ))
        grade_penalty += 1
    elif chain_status == "invalid":
        findings.append(Finding(
            check="chain_completeness", status="fail",
            message="Chain validation failed",
        ))
        grade_penalty += 2
    else:
        findings.append(Finding(
            check="chain_completeness", status="pass",
            message="Chain complete",
        ))

    if protocol_version:
        proto_lower = protocol_version.lower()
        if "1.0" in proto_lower or "1.1" in proto_lower:
            findings.append(Finding(
                check="tls_version", status="warn",
                message=f"TLS {protocol_version} offered - consider disabling",
            ))
            grade_penalty += 1
        else:
            findings.append(Finding(
                check="tls_version", status="pass",
                message=f"TLS {protocol_version}",
            ))

    if hsts is False:
        findings.append(Finding(
            check="hsts", status="pass",
            message="No HSTS header detected (informational)",
        ))
    elif hsts is True:
        findings.append(Finding(
            check="hsts", status="pass",
            message="HSTS header present",
        ))

    if grade_penalty == 0:
        grade = "A"
    elif grade_penalty == 1:
        grade = "B"
    elif grade_penalty == 2:
        grade = "C"
    else:
        grade = "F"

    return PostureResult(
        grade=grade,
        findings=findings,
        protocol_version=protocol_version or "",
        ocsp_stapling=ocsp_stapling,
        hsts=hsts,
        must_staple=must_staple,
    )
