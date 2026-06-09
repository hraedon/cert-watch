"""TLS posture evaluation — policy lint and grade computation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cert_watch.certificate_model import Certificate
from cert_watch.http_client import SSRFBlockedError, ssrf_safe_urlopen

logger = logging.getLogger("cert_watch.posture")


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


# Worst-grade ordering: higher value = worse grade.
# Used for grade-drop detection and worst-grade aggregation.
GRADE_WORST_ORDER: dict[str, int] = {"A+": 0, "A": 0, "B": 1, "C": 2, "F": 3}


def tls_version_meets_1_2(protocol_version: str | None) -> bool:
    """Return True if *protocol_version* is TLS 1.2 or newer.

    Handles the strings both scan paths actually produce: ``ssl.version()`` and
    openssl ``s_client`` both report TLS 1.0 as the bare ``"TLSv1"`` (not
    ``"TLSv1.0"``), so a naive ``"1.0" in proto`` / ``startswith("TLSv1.0")``
    check misses it. SSLv2/SSLv3 and TLS 1.0/1.1 are all sub-1.2; TLS 1.2/1.3
    (and any future TLS 1.4+) pass.
    """
    if not protocol_version:
        return False
    p = protocol_version.strip().lower()
    return p in ("tlsv1.2", "tlsv1.3") or (
        p.startswith("tlsv1.") and p not in ("tlsv1.0", "tlsv1.1")
    )


# ---------- Revocation endpoint health (Plan 017 A1) ----------


def _extract_ocsp_url(cert_der: bytes) -> str | None:
    """Extract the first OCSP responder URL from the AIA extension."""
    from cryptography import x509
    from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

    try:
        x509_cert = x509.load_der_x509_certificate(cert_der)
        aia = x509_cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        for access_desc in aia.value:  # type: ignore[attr-defined]
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                return access_desc.access_location.value
    except (x509.ExtensionNotFound, ValueError, TypeError):
        pass
    return None


def _extract_crl_urls(cert_der: bytes) -> list[str]:
    """Extract CRL distribution point URLs from the certificate."""
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    urls: list[str] = []
    try:
        x509_cert = x509.load_der_x509_certificate(cert_der)
        cdp = x509_cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        for dp in cdp.value:  # type: ignore[attr-defined]
            if dp.full_name:
                for name in dp.full_name:
                    if hasattr(name, "value") and isinstance(name.value, str):
                        urls.append(name.value)
    except (x509.ExtensionNotFound, ValueError, TypeError):
        pass
    return urls


def _check_ocsp_reachable(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """Check if an OCSP responder URL is reachable (HTTP HEAD).

    Returns (reachable, message). When blocked by SSRF policy, returns
    (False, "endpoint blocked by SSRF policy").
    """
    try:
        resp = ssrf_safe_urlopen(
            url,
            timeout=timeout,
            method="HEAD",
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
        )
        with resp:
            return 200 <= resp.status < 500, ""
    except SSRFBlockedError:
        return False, "endpoint blocked by SSRF policy"
    except Exception:
        return False, ""


def _check_crl_reachable(
    url: str,
    timeout: int = 5,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> tuple[bool, str]:
    """Check if a CRL distribution point URL is reachable (HTTP GET, minimal).

    Returns (reachable, message). When blocked by SSRF policy, returns
    (False, "endpoint blocked by SSRF policy").
    """
    try:
        resp = ssrf_safe_urlopen(
            url,
            timeout=timeout,
            method="GET",
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
        )
        with resp:
            return 200 <= resp.status < 500, ""
    except SSRFBlockedError:
        return False, "endpoint blocked by SSRF policy"
    except Exception:
        return False, ""


def check_revocation_endpoints(
    cert_der: bytes,
    timeout: int = 5,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> list[Finding]:
    """Check reachability of OCSP and CRL endpoints for a certificate.

    Returns a list of Finding objects for each endpoint checked.
    When an endpoint is blocked by SSRF policy, the finding carries
    a clear message rather than a generic "unreachable".
    """
    findings: list[Finding] = []

    ocsp_url = _extract_ocsp_url(cert_der)
    if ocsp_url:
        reachable, block_msg = _check_ocsp_reachable(
            ocsp_url, timeout=timeout,
            allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        if reachable:
            findings.append(Finding(
                check="ocsp_endpoint", status="pass",
                message=f"OCSP responder reachable at {ocsp_url}",
            ))
        elif block_msg:
            findings.append(Finding(
                check="ocsp_endpoint", status="warn",
                message=f"OCSP endpoint {ocsp_url} {block_msg}",
            ))
        else:
            findings.append(Finding(
                check="ocsp_endpoint", status="warn",
                message=f"OCSP responder unreachable at {ocsp_url}",
            ))
    else:
        findings.append(Finding(
            check="ocsp_endpoint", status="info",
            message="No OCSP responder URL in AIA extension",
        ))

    crl_urls = _extract_crl_urls(cert_der)
    if crl_urls:
        for url in crl_urls:
            reachable, block_msg = _check_crl_reachable(
                url, timeout=timeout,
                allow_private=allow_private, allowed_subnets=allowed_subnets,
            )
            if reachable:
                findings.append(Finding(
                    check="crl_endpoint", status="pass",
                    message=f"CRL endpoint reachable at {url}",
                ))
            elif block_msg:
                findings.append(Finding(
                    check="crl_endpoint", status="warn",
                    message=f"CRL endpoint {url} {block_msg}",
                ))
            else:
                findings.append(Finding(
                    check="crl_endpoint", status="warn",
                    message=f"CRL endpoint unreachable at {url}",
                ))
    else:
        findings.append(Finding(
            check="crl_endpoint", status="info",
            message="No CRL distribution points in certificate",
        ))

    return findings


def evaluate_posture(
    cert: Certificate,
    protocol_version: str | None = None,
    ocsp_stapling: bool | None = None,
    hsts: bool | None = None,
    chain_status: str | None = None,
    chain_incomplete: bool = False,
    check_revocation: bool = False,
    revocation_timeout: int = 5,
    port: int = 443,
    caa_present: bool | None = None,
    caa_records: list[str] | None = None,
    *,
    allow_private: bool = False,
    allowed_subnets: tuple[str, ...] = (),
) -> PostureResult:
    """Evaluate TLS posture grade and lint findings from certificate data.

    Policy lint (data-driven from Certificate object, no network calls):
    - SHA-1 signature algorithm
    - RSA key < 2048 bits / ECDSA < P-256
    - Validity > 398 days (CA/B forum limit)
    - Self-signed leaf
    - Missing intermediate (chain_status incomplete)
    - OCSP must-staple without stapling
    - CAA presence (stored per scan, BC-121)

    When ``check_revocation`` is True, OCSP and CRL endpoint reachability
    is checked (network calls).  Gated by ``CERT_WATCH_CHECK_REVOCATION``.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID

    findings: list[Finding] = []
    grade_severity = 0  # 0=A, 1=B, 2=C, else=F (most severe finding wins)

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
                grade_severity = max(grade_severity, 2)
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
                grade_severity = max(grade_severity, 2)
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
            grade_severity = max(grade_severity, 2)
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

    try:
        is_self_signed = x509_cert.subject == x509_cert.issuer
    except Exception:
        is_self_signed = cert.subject == cert.issuer
    if is_self_signed:
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
        must_staple = any(feature.value == 5 for feature in ext.value)  # type: ignore[attr-defined]
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
            check="ocsp_must_staple", status="info",
            message="OCSP Must-Staple not required",
        ))

    if chain_incomplete:
        findings.append(Finding(
            check="chain_completeness", status="warn",
            message=(
                "Incomplete chain — scan ran with degraded extraction (leaf only)."
                " Consider upgrading to Python 3.13 or ensuring openssl is available."
            ),
        ))
        grade_severity = max(grade_severity, 1)
    elif chain_status == "incomplete":
        findings.append(Finding(
            check="chain_completeness", status="warn",
            message="Incomplete chain — server missing intermediate(s)",
        ))
        grade_severity = max(grade_severity, 1)
    elif chain_status == "invalid":
        findings.append(Finding(
            check="chain_completeness", status="fail",
            message="Chain validation failed",
        ))
        grade_severity = max(grade_severity, 2)
    else:
        findings.append(Finding(
            check="chain_completeness", status="pass",
            message="Chain complete",
        ))

    if protocol_version:
        if not tls_version_meets_1_2(protocol_version):
            findings.append(Finding(
                check="tls_version", status="warn",
                message=f"TLS {protocol_version} offered - consider disabling",
            ))
            grade_severity = max(grade_severity, 1)
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

    # CAA presence (BC-121)
    if caa_present is True:
        recs = caa_records or []
        recs_str = "; ".join(recs) if recs else "records present"
        findings.append(Finding(
            check="caa", status="pass",
            message=f"CAA present — {recs_str}",
        ))
    elif caa_present is False:
        findings.append(Finding(
            check="caa", status="info",
            message="No CAA records found (issuance implicitly allowed)",
        ))

    # Revocation endpoint health (opt-in, Plan 017 A1)
    if check_revocation and cert.raw_der:
        revocation_findings = check_revocation_endpoints(
            cert.raw_der, timeout=revocation_timeout,
            allow_private=allow_private, allowed_subnets=allowed_subnets,
        )
        findings.extend(revocation_findings)
        # Unreachable OCSP/CRL is a warning, not a grade penalty
        # (the cert itself may be fine; the responder may be down)

    if grade_severity == 0:
        grade = "A"
    elif grade_severity == 1:
        grade = "B"
    elif grade_severity == 2:
        grade = "C"
    else:
        grade = "F"

    # A+ requires TLS 1.3 + HSTS on port 443.  HSTS is a 443/HTTP concept,
    # so well-configured TLS services on non-443 ports can still earn A+.
    if (
        grade == "A"
        and protocol_version
        and "1.3" in protocol_version
        and (hsts is True or port != 443)
    ):
        grade = "A+"

    return PostureResult(
        grade=grade,
        findings=findings,
        protocol_version=protocol_version or "",
        ocsp_stapling=ocsp_stapling,
        hsts=hsts,
        must_staple=must_staple,
    )
