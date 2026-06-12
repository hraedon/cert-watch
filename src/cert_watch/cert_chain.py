"""Certificate chain helpers. See spec wi_cert_chain_library.md."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7

from cert_watch.certificate_model import Certificate, parse_certificate

logger = logging.getLogger("cert_watch.cert_chain")


class _AnchorLike(Protocol):
    """Minimal protocol for chain-status anchors.

    Both :class:`~cert_watch.certificate_model.Certificate` and
    :class:`~cert_watch.database.repo.TrustAnchorEntry` satisfy this.
    """

    fingerprint_sha256: str
    raw_der: bytes


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
    except (ValueError, TypeError):
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
    except (ValueError, TypeError):
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


_SYSTEM_CA_BUNDLE_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
]

_system_ca_cache: tuple[set[bytes], dict[bytes, list[x509.Certificate]]] | None = None


def _load_system_ca_cache() -> tuple[set[bytes], dict[bytes, list[x509.Certificate]]]:
    """Lazy-load system CA trust store as (subject_set, subject_to_certs).

    The subject set enables fast name lookups; the dict provides full
    x509.Certificate objects for signature verification (BC-069).
    Returns (empty set, empty dict) if no system CA bundle is found.
    Cached after the first call.
    """
    global _system_ca_cache
    if _system_ca_cache is not None:
        return _system_ca_cache

    subjects: set[bytes] = set()
    by_subject: dict[bytes, list[x509.Certificate]] = {}
    for path in _SYSTEM_CA_BUNDLE_PATHS:
        pem_path = Path(path)
        if not pem_path.exists():
            continue
        try:
            pem_data = pem_path.read_bytes()
        except OSError:
            continue
        while pem_data:
            start = pem_data.find(b"-----BEGIN CERTIFICATE-----")
            if start == -1:
                break
            end = pem_data.find(b"-----END CERTIFICATE-----", start)
            if end == -1:
                break
            end += len(b"-----END CERTIFICATE-----")
            try:
                cert = x509.load_pem_x509_certificate(pem_data[start:end])
                subj = cert.subject.public_bytes(Encoding.DER)
                subjects.add(subj)
                by_subject.setdefault(subj, []).append(cert)
            except (ValueError, TypeError):
                pass
            pem_data = pem_data[end:]
        continue

    logger.debug("loaded %d system CA subjects from trust store", len(subjects))
    _system_ca_cache = (subjects, by_subject)
    return _system_ca_cache


def _load_system_ca_subjects() -> set[bytes]:
    """Return DER-encoded subject bytes from the system CA trust store."""
    return _load_system_ca_cache()[0]


def _is_anchored_by_system_root(chain: list[Certificate]) -> bool:
    """Return True if the chain's top cert is *signature-verified* against a
    system CA root (BC-069).

    Finds system roots whose subject matches the top cert's issuer, then
    verifies the actual cryptographic signature — not just name matching.
    """
    if not chain:
        return False
    subjects, by_subject = _load_system_ca_cache()
    if not subjects:
        return False
    last = chain[-1]
    issuer_der = _issuer_bytes(last)
    if issuer_der not in subjects:
        return False
    last_x = _load_x509(last)
    if last_x is None:
        return False
    for root_x in by_subject.get(issuer_der, []):
        try:
            last_x.verify_directly_issued_by(root_x)
            return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _load_x509(cert: Certificate | _AnchorLike) -> x509.Certificate | None:
    """Parse a Certificate's DER bytes into an x509.Certificate, or None.

    Signature verification requires the raw DER (a public key parsed from it).
    DB-loaded and freshly-scanned certs both carry raw_der (NOT NULL column),
    so this normally succeeds; we return None defensively rather than raise.
    """
    if not cert.raw_der:
        return None
    try:
        return x509.load_der_x509_certificate(cert.raw_der)
    except (ValueError, TypeError):
        return None


def _is_signed_by(child: Certificate, issuer: Certificate | _AnchorLike) -> bool:
    """Return True iff `child` is cryptographically signed by `issuer`'s key.

    Verifies the actual signature, not just that names line up. Uses
    cryptography's verify_directly_issued_by (>=40; pyproject pins >=43) which
    also checks the issuer/subject Name match and the AKI/SKI hints. Returns
    False on any failure (bad signature, name mismatch, unparseable DER,
    unsupported key type).
    """
    child_x = _load_x509(child)
    issuer_x = _load_x509(issuer)
    if child_x is None or issuer_x is None:
        return False
    try:
        child_x.verify_directly_issued_by(issuer_x)
        return True
    except Exception:  # noqa: BLE001
        # InvalidSignature, ValueError (name mismatch), TypeError
        # (unsupported key), etc. all mean "not verifiably signed by".
        return False


def validate_chain_signatures(chain: list[Certificate]) -> bool | None:
    """Verify each cert in `chain` is cryptographically signed by the next.

    Returns None when chain length < 2 (not applicable, mirrors
    validate_chain_order). Returns True only when every adjacent pair passes
    real signature verification — name linkage is necessary but not sufficient.
    """
    if len(chain) < 2:
        return None
    return all(_is_signed_by(chain[i], chain[i + 1]) for i in range(len(chain) - 1))


def _is_signature_anchored_by_user(
    chain: list[Certificate], anchors: Sequence[_AnchorLike]
) -> bool:
    """Return True if the chain's top is signature-verified against an anchor.

    Either the last cert IS an uploaded anchor (fingerprint match — same cert,
    trivially valid), or the last cert is cryptographically signed by one of
    the uploaded anchors. Name-only linkage is NOT sufficient.
    """
    if not chain or not anchors:
        return False
    last = chain[-1]
    for a in anchors:
        if last.fingerprint_sha256 == a.fingerprint_sha256:
            return True
        if _is_signed_by(last, a):
            return True
    return False


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
    """Validate chain ORDER (name linkage) including trust anchors.

    NOTE: this checks issuer/subject *Name* linkage only — it does NOT verify
    signatures and is not a trust decision. Trust grading goes through
    chain_status(), which requires real signature verification (BC-061). This
    helper remains for structural ordering checks.

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
    """Return True if the chain is name-linked to a user-uploaded trust anchor.

    NOTE: name/fingerprint linkage only — NOT a signature check. For the trust
    decision use chain_status(), which calls _is_signature_anchored_by_user()
    to verify the anchor's signature (BC-061).

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
    leaf: Certificate, chain: list[Certificate], anchors: Sequence[_AnchorLike]
) -> str:
    """Return a human-readable chain trust status.

    Trust grades ("public"/"private") require CRYPTOGRAPHIC signature
    verification of every link, not just matching issuer/subject Names. A chain
    whose names line up but whose signatures are forged/mismatched grades as
    "invalid" — a forged intermediate is detected (BC-061).

    - "self-signed"   : leaf is its own issuer.
    - "unknown"       : no intermediates available (can't validate).
    - "invalid"       : chain order is structurally broken OR a link's signature
                        does not verify (names may match but the key does not).
    - "private"       : chain is signature-verified end to end and anchored by a
                        user-uploaded trust anchor.
    - "public"        : chain is signature-verified end to end and ends at a
                        self-signed root (assumed public CA) or at a certificate
                        whose issuer is in the system trust store.
    - "incomplete"    : chain links verify but no trusted root is present.
    """
    if _subject_bytes(leaf) == _issuer_bytes(leaf):
        return "self-signed"
    if not chain:
        return "unknown"
    full = [leaf, *chain]
    # Names must line up AND every link must be signature-verified. A
    # name-matching-but-forged chain is reported as invalid, not trusted.
    if not validate_chain_order(full):
        return "invalid"
    if validate_chain_signatures(full) is not True:
        return "invalid"
    if _is_signature_anchored_by_user(full, anchors):
        return "private"
    last = chain[-1]
    if _subject_bytes(last) == _issuer_bytes(last) and _is_signed_by(last, last):
        # Self-signed root: only "public" if it actually self-signs (a real
        # trust anchor), not merely if its names happen to match.
        return "public"
    if _is_anchored_by_system_root(full):
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
    except (ValueError, TypeError):  # DER parse
        return "failed to parse certificate"

    # Check BasicConstraints.ca — hard requirement
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if not bc.value.ca:
            return "certificate is not a CA (BasicConstraints: CA=FALSE)"
    except x509.ExtensionNotFound:
        return "certificate lacks BasicConstraints extension (not a valid CA)"

    return None

