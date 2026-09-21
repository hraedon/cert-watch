"""Pure presentation logic for certificate identity and chain details."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

from cert_watch.cert_chain import ACTIONABLE_CHAIN_STATUSES, display_urgency
from cert_watch.certificate_model import Certificate
from cert_watch.filters import compute_urgency, friendly_issuer, issuer_cn, subject_cn


@dataclass(frozen=True)
class ChainCertificateView:
    id: str
    subject: str
    issuer: str
    not_after: str
    days_remaining: int
    subject_cn: str
    issuer_org: str
    key_type: str
    self_issued: bool


@dataclass(frozen=True)
class CertificateTechnicalView:
    key_type: str
    sig_alg: str
    serial: str
    fingerprint: str
    chain: tuple[ChainCertificateView, ...]
    urgency: str
    days_remaining: int
    subject_cn: str
    issuer_org: str
    issuer_cn: str
    chain_issue: str | None

    def template_context(self) -> dict[str, Any]:
        """Expose the existing template keys while the route moves behind the seam."""
        context = asdict(self)
        context["chain"] = [asdict(cert) for cert in self.chain]
        return context


def _key_type(cert: Certificate) -> str:
    try:
        key = x509.load_der_x509_certificate(cert.raw_der).public_key()
        if isinstance(key, rsa.RSAPublicKey):
            return f"RSA {key.key_size}"
        if isinstance(key, ec.EllipticCurvePublicKey):
            return f"ECDSA {key.curve.name}"
        if isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519"
        if isinstance(key, ed448.Ed448PublicKey):
            return "Ed448"
        return type(key).__name__
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return "unknown"


def present_certificate_technical_details(
    cert: Certificate,
    chain: list[tuple[str, Certificate]],
    chain_status: str,
) -> CertificateTechnicalView:
    """Build certificate detail values without HTTP, database, or template concerns."""
    try:
        parsed = x509.load_der_x509_certificate(cert.raw_der)
        sig_alg = parsed.signature_algorithm_oid._name
        serial_hex = format(parsed.serial_number, "X")
        serial = ":".join(serial_hex[i : i + 2] for i in range(0, len(serial_hex), 2))
    except (ValueError, TypeError, UnsupportedAlgorithm):
        sig_alg = "unknown"
        serial = "unknown"

    fingerprint = cert.fingerprint_sha256
    if ":" not in fingerprint and len(fingerprint) == 64:
        fingerprint = ":".join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        ).upper()

    presented_chain = tuple(
        ChainCertificateView(
            id=cert_id,
            subject=item.subject,
            issuer=item.issuer,
            not_after=item.not_after.isoformat(),
            days_remaining=item.days_until_expiry(),
            subject_cn=subject_cn(item.subject),
            issuer_org=friendly_issuer(item.issuer),
            key_type=_key_type(item),
            self_issued=item.subject == item.issuer,
        )
        for cert_id, item in chain
    )
    leaf_days = cert.days_until_expiry()
    worst_days = min(
        (leaf_days, *(item.days_remaining for item in presented_chain)),
    )

    return CertificateTechnicalView(
        key_type=_key_type(cert),
        sig_alg=sig_alg,
        serial=serial,
        fingerprint=fingerprint,
        chain=presented_chain,
        urgency=display_urgency(compute_urgency(worst_days), chain_status),
        days_remaining=leaf_days,
        subject_cn=subject_cn(cert.subject),
        issuer_org=friendly_issuer(cert.issuer),
        issuer_cn=issuer_cn(cert.issuer),
        chain_issue=(
            chain_status if chain_status in ACTIONABLE_CHAIN_STATUSES else None
        ),
    )
