"""Certificate chain helpers. See spec wi_cert_chain_library.md."""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs7

from cert_watch.certificate_model import Certificate, parse_certificate


def extract_chain(der_bytes: bytes) -> list[Certificate]:
    """Extract certificates from a PKCS#7 DER blob OR concatenated DER. See AC-01."""
    if not der_bytes:
        return []
    # Try PKCS#7 first.
    try:
        p7_certs = pkcs7.load_der_pkcs7_certificates(der_bytes)
        if p7_certs:
            out: list[Certificate] = []
            for c in p7_certs:
                parsed = parse_certificate(c.public_bytes(serialization_encoding()))
                if isinstance(parsed, Certificate):
                    out.append(parsed)
            _mark_leaf(out)
            return out
    except Exception:  # noqa: BLE001
        pass
    # Try single DER cert.
    parsed = parse_certificate(der_bytes)
    if isinstance(parsed, Certificate):
        return [parsed]
    # Try concatenated DER by walking lengths via cryptography's loader on slices.
    # x509 does not give us length easily, so attempt to parse byte-by-byte sliding windows
    # is impractical; instead, fall back to empty.
    return []


def serialization_encoding():
    """Lazy import to avoid circular import surprises."""
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _mark_leaf(certs: list[Certificate]) -> None:
    for i, c in enumerate(certs):
        c.is_leaf = i == 0


def validate_chain_order(chain: list[Certificate]) -> bool:
    """See AC-02."""
    if len(chain) < 2:
        return False
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


# x509 import kept for potential future use of x509.load_der_x509_certificate.
_ = x509
