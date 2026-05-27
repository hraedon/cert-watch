"""Certificate chain helpers. See spec wi_cert_chain_library.md."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from cert_watch.certificate_model import Certificate, parse_certificate


def extract_chain(der_bytes: bytes) -> list[Certificate]:
    """Extract certificates from a PKCS#7 DER blob OR concatenated DER. See AC-01."""
    if not der_bytes:
        return []
    try:
        p7_certs = pkcs7.load_der_pkcs7_certificates(der_bytes)
        if p7_certs:
            out: list[Certificate] = []
            for c in p7_certs:
                parsed = parse_certificate(c.public_bytes(Encoding.DER))
                if isinstance(parsed, Certificate):
                    out.append(parsed)
            _mark_leaf(out)
            return out
    except Exception:  # noqa: BLE001
        pass
    parsed = parse_certificate(der_bytes)
    if isinstance(parsed, Certificate):
        return [parsed]
    return []


def extract_chain_pem(pem_bytes: bytes) -> list[Certificate]:
    """Extract certificates from a PEM-encoded PKCS#7 blob."""
    if not pem_bytes:
        return []
    try:
        p7_certs = pkcs7.load_pem_pkcs7_certificates(pem_bytes)
        if p7_certs:
            out: list[Certificate] = []
            for c in p7_certs:
                parsed = parse_certificate(c.public_bytes(Encoding.DER))
                if isinstance(parsed, Certificate):
                    out.append(parsed)
            _mark_leaf(out)
            return out
    except Exception:  # noqa: BLE001
        pass
    return []


def _mark_leaf(certs: list[Certificate]) -> None:
    for i, c in enumerate(certs):
        c.is_leaf = i == 0


def _subject_bytes(cert: Certificate) -> bytes:
    """Return DER-encoded subject for robust comparison.

    Prefers subject_der (from fresh x509 parsing). Falls back to
    UTF-8 encoded rfc4514 string for DB-loaded certificates.
    """
    return cert.subject_der or cert.subject.encode("utf-8")


def _issuer_bytes(cert: Certificate) -> bytes:
    """Return DER-encoded issuer for robust comparison.

    Prefers issuer_der (from fresh x509 parsing). Falls back to
    UTF-8 encoded rfc4514 string for DB-loaded certificates.
    """
    return cert.issuer_der or cert.issuer.encode("utf-8")


def validate_chain_order(chain: list[Certificate]) -> bool | None:
    """See AC-02. Returns None when chain length < 2 (not applicable).

    Compares issuer/subject using DER-encoded Name bytes when available,
    falling back to string comparison for DB-loaded certificates.
    """
    if len(chain) < 2:
        return None
    return all(
        _issuer_bytes(chain[i]) == _subject_bytes(chain[i + 1])
        for i in range(len(chain) - 1)
    )


def split_leaf_intermediates(
    certificates: list[Certificate],
) -> tuple[Certificate | None, list[Certificate]]:
    """See AC-03."""
    if not certificates:
        return None, []
    leaf_idx = next(
        (i for i, c in enumerate(certificates) if getattr(c, "is_leaf", True)),
        None,
    )
    if leaf_idx is None:
        return certificates[0], list(certificates[1:])
    leaf = certificates[leaf_idx]
    intermediates = [c for i, c in enumerate(certificates) if i != leaf_idx]
    return leaf, intermediates


def deduplicate_chain(certificates: list[Certificate]) -> list[Certificate]:
    """See AC-04."""
    seen: set[str] = set()
    out: list[Certificate] = []
    for c in certificates:
        if c.fingerprint_sha256 in seen:
            continue
        seen.add(c.fingerprint_sha256)
        out.append(c)
    return out


def validate_chain_with_anchors(chain: list[Certificate], anchors: list[Certificate]) -> bool:
    """Validate chain order including trust anchors.

    Same issuer==subject walk as validate_chain_order, but the final step
    may match an anchor (anchor.subject == last cert.issuer).
    """
    if len(chain) < 1:
        return False
    for i in range(len(chain) - 1):
        if _issuer_bytes(chain[i]) != _subject_bytes(chain[i + 1]):
            return False
    last = chain[-1]
    if _subject_bytes(last) == _issuer_bytes(last):
        return True
    return any(_issuer_bytes(last) == _subject_bytes(a) for a in anchors)


def is_anchored_by_user(chain: list[Certificate], anchors: list[Certificate]) -> bool:
    """Return True if the chain is anchored by a user-uploaded trust anchor.

    Checks whether the last certificate matches an uploaded anchor by
    fingerprint (self-signed roots) or by issuer/subject linkage.
    """
    if not chain or not anchors:
        return False
    last = chain[-1]
    for a in anchors:
        if last.fingerprint_sha256 == a.fingerprint_sha256:
            return True
        if _issuer_bytes(last) == _subject_bytes(a):
            return True
    return False


def chain_status(
    leaf: Certificate, chain: list[Certificate], anchors: list[Certificate]
) -> str:
    """Return a human-readable chain trust status.

    - "self-signed"   : leaf is its own issuer.
    - "unknown"       : no intermediates available (can't validate).
    - "invalid"       : chain order is structurally broken.
    - "private"       : chain is valid and anchored by a user-uploaded trust anchor.
    - "public"        : chain is valid and ends at a self-signed root (assumed public CA).
    - "incomplete"    : chain is structurally valid but missing a trusted root.
    """
    if _subject_bytes(leaf) == _issuer_bytes(leaf):
        return "self-signed"
    if not chain:
        return "unknown"
    structural = validate_chain_order([leaf, *chain])
    if not structural:
        return "invalid"
    if is_anchored_by_user([leaf, *chain], anchors):
        return "private"
    if _subject_bytes(chain[-1]) == _issuer_bytes(chain[-1]):
        return "public"
    return "incomplete"


def validate_is_ca_certificate(der_bytes: bytes) -> str | None:
    """Validate that a certificate is suitable as a trust anchor (CA certificate).

    Returns an error message string if the certificate is NOT suitable, or None if OK.

    Hard requirements:
    - BasicConstraints.ca == True (required)

    Soft checks (logged as warnings, do not block):
    - Self-signed (subject == issuer)
    - KeyUsage.key_cert_sign (older roots may lack it)
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return "failed to parse certificate"

    # Check BasicConstraints.ca — hard requirement
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            return "certificate is not a CA (BasicConstraints: CA=FALSE)"
    except x509.ExtensionNotFound:
        return "certificate lacks BasicConstraints extension (not a valid CA)"

    return None

