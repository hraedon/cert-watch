"""Fleet crypto inventory & agility lens (informational; never grade-affecting).

Two honest jobs, both read-only over certs cert-watch already stores:

1. **Hygiene inventory** (actionable today): aggregate the genuinely-weak
   primitives across the whole estate — SHA-1 signatures, RSA < 2048, weak EC
   curves. Per-cert posture already flags these; this answers the *fleet*
   question ("how many SHA-1 certs do we still depend on, and which?").
2. **Crypto-agility inventory** (forward-looking): the distribution of key
   algorithms / sizes / signature hashes you depend on, so when post-quantum CA
   hierarchies arrive there is an inventory to plan migration against. This is
   the same "get ahead of the predictable mandate" posture as the SC-081
   readiness report — not a grade.

Deliberately **not** a grade: classical RSA and ECDSA are both fine today and
both eventually need PQC migration, so a "modern vs legacy" verdict would
mislead. We report the inventory and flag only what is weak *now*.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("cert_watch.crypto_posture")


# Signature-hash labels keyed off the OID dotted string, so we don't depend on
# every SignatureAlgorithmOID name existing across cryptography versions.
_SIG_HASH_BY_OID: dict[str, str] = {
    "1.2.840.113549.1.1.5": "SHA-1",      # RSA w/ SHA-1
    "1.2.840.10045.4.1": "SHA-1",          # ECDSA w/ SHA-1
    "1.2.840.113549.1.1.4": "MD5",         # RSA w/ MD5
    "1.2.840.113549.1.1.11": "SHA-256",    # RSA w/ SHA-256
    "1.2.840.113549.1.1.12": "SHA-384",    # RSA w/ SHA-384
    "1.2.840.113549.1.1.13": "SHA-512",    # RSA w/ SHA-512
    "1.2.840.10045.4.3.2": "SHA-256",      # ECDSA w/ SHA-256
    "1.2.840.10045.4.3.3": "SHA-384",      # ECDSA w/ SHA-384
    "1.2.840.10045.4.3.4": "SHA-512",      # ECDSA w/ SHA-512
    "1.3.101.112": "Ed25519",              # Ed25519 (PureEdDSA)
    "1.3.101.113": "Ed448",                # Ed448
}

_WEAK_HASHES = frozenset({"SHA-1", "MD5"})
_WEAK_CURVES = frozenset({"secp192r1", "secp224r1"})
# EC curve common name → marketing label + approximate strength bits.
_EC_CURVE_LABEL = {
    "secp256r1": ("P-256", 256),
    "prime256v1": ("P-256", 256),
    "secp384r1": ("P-384", 384),
    "secp521r1": ("P-521", 521),
    "secp224r1": ("P-224", 224),
    "secp192r1": ("P-192", 192),
}


@dataclass
class CertCrypto:
    """Crypto primitives of a single certificate."""

    key_family: str  # "RSA" | "EC" | "Ed25519" | "Ed448" | "other"
    key_label: str   # "RSA-2048" | "EC-P256" | "Ed25519" | ...
    sig_hash: str    # "SHA-256" | "SHA-1" | "Ed25519" | "unknown"
    is_weak: bool    # genuinely weak *today* (sub-2048 RSA / weak curve / SHA-1)
    weak_reason: str = ""


@dataclass
class CryptoPosture:
    """Fleet-level crypto inventory over leaf certificates."""

    total: int = 0
    key_algorithms: dict[str, int] = field(default_factory=dict)  # label -> count
    sig_hashes: dict[str, int] = field(default_factory=dict)
    families: dict[str, int] = field(default_factory=dict)        # RSA/EC/EdDSA -> count
    weak_count: int = 0
    weak_certs: list[dict[str, Any]] = field(default_factory=list)          # addressable offenders
    pqc_note: str = ""


def classify_cert_crypto(raw_der: bytes) -> CertCrypto | None:
    """Classify one cert's key + signature primitives from its DER bytes.

    Returns ``None`` if the cert can't be parsed (callers skip it).
    """
    if not raw_der:
        return None
    try:
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

        cert = x509.load_der_x509_certificate(raw_der)
    except (ValueError, TypeError):
        return None

    weak = False
    reason = ""

    try:
        key = cert.public_key()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return CertCrypto(
            key_family="other", key_label="unknown", sig_hash="unknown",
            is_weak=False,
        )

    if isinstance(key, rsa.RSAPublicKey):
        family = "RSA"
        bits = key.key_size
        label = f"RSA-{bits}"
        if bits < 2048:
            weak, reason = True, f"RSA key {bits} bits < 2048"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        family = "EC"
        curve = key.curve.name
        marketing, _bits = _EC_CURVE_LABEL.get(curve, (curve, 0))
        label = f"EC-{marketing}"
        if curve in _WEAK_CURVES:
            weak, reason = True, f"weak EC curve {curve}"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        family, label = "EdDSA", "Ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        family, label = "EdDSA", "Ed448"
    else:
        family, label = "other", type(key).__name__

    import contextlib

    sig_oid = ""
    with contextlib.suppress(ValueError, AttributeError):
        sig_oid = cert.signature_algorithm_oid.dotted_string
    sig_hash = _SIG_HASH_BY_OID.get(sig_oid, "unknown")
    if sig_hash in _WEAK_HASHES:
        weak = True
        reason = reason or f"{sig_hash} signature"

    return CertCrypto(
        key_family=family, key_label=label, sig_hash=sig_hash,
        is_weak=weak, weak_reason=reason,
    )


def analyze_fleet_crypto(db_path: str | Path) -> CryptoPosture:
    """Aggregate the crypto inventory across all leaf certificates."""
    from cert_watch.database import _connect

    posture = CryptoPosture()
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, subject, hostname, port, raw_der "
            "FROM certificates WHERE is_leaf = 1"
        ).fetchall()

    for r in rows:
        info = classify_cert_crypto(r["raw_der"])
        if info is None:
            continue
        posture.total += 1
        posture.key_algorithms[info.key_label] = (
            posture.key_algorithms.get(info.key_label, 0) + 1
        )
        posture.sig_hashes[info.sig_hash] = (
            posture.sig_hashes.get(info.sig_hash, 0) + 1
        )
        posture.families[info.key_family] = (
            posture.families.get(info.key_family, 0) + 1
        )
        if info.is_weak:
            posture.weak_count += 1
            posture.weak_certs.append({
                "cert_id": r["id"],
                "hostname": r["hostname"] or "",
                "port": r["port"],
                "subject": r["subject"] or "",
                "key_label": info.key_label,
                "reason": info.weak_reason,
            })

    posture.weak_certs.sort(key=lambda c: (c["hostname"], c["subject"]))
    # Honest forward-looking note: production TLS certs do not use PQC primitives
    # yet, so this is inventory-for-migration, not PQC detection.
    posture.pqc_note = (
        "No post-quantum signature/key primitives are in use yet (none are "
        "generally available for public-trust TLS). This inventory is the basis "
        "for planning PQC migration once PQC CA hierarchies arrive."
    )
    return posture


def crypto_posture_to_dict(posture: CryptoPosture) -> dict[str, Any]:
    """Serialize for templates / JSON, with distributions ordered by count desc."""
    def _ranked(d: dict[str, int]) -> list[dict[str, Any]]:
        return [
            {"label": k, "count": v}
            for k, v in sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))
        ]

    return {
        "total": posture.total,
        "key_algorithms": _ranked(posture.key_algorithms),
        "sig_hashes": _ranked(posture.sig_hashes),
        "families": _ranked(posture.families),
        "weak_count": posture.weak_count,
        "weak_certs": posture.weak_certs,
        "pqc_note": posture.pqc_note,
    }
