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


def validate_chain_order(chain: list[Certificate]) -> bool | None:
    """See AC-02. Returns None when chain length < 2 (not applicable)."""
    if len(chain) < 2:
        return None
    return all(
        chain[i].issuer == chain[i + 1].subject for i in range(len(chain) - 1)
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
        if chain[i].issuer != chain[i + 1].subject:
            return False
    last = chain[-1]
    if last.subject == last.issuer:
        return True
    for a in anchors:
        if last.issuer == a.subject:
            return True
    return False


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
        if last.issuer == a.subject:
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
    if leaf.subject == leaf.issuer:
        return "self-signed"
    if not chain:
        return "unknown"
    structural = validate_chain_order([leaf, *chain])
    if not structural:
        return "invalid"
    if is_anchored_by_user([leaf, *chain], anchors):
        return "private"
    if chain[-1].subject == chain[-1].issuer:
        return "public"
    return "incomplete"


# x509 import kept for potential future use of x509.load_der_x509_certificate.
_ = x509

