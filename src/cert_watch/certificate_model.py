"""Certificate parsing primitives. See spec wi_certificate_model.md."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID


@dataclass
class MalformedCertificateError:
    """Returned (not raised) when a certificate cannot be parsed. See AC-04/AC-06."""

    message: str


@dataclass
class Certificate:
    """Parsed X.509 leaf certificate. See AC-01."""

    subject: str
    issuer: str
    not_before: datetime
    not_after: datetime
    san_dns_names: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    raw_der: bytes = b""
    is_leaf: bool = True
    notes: str = ""

    def days_until_expiry(self) -> int:
        """Whole days between now (UTC) and not_after (floor semantics). See AC-02.

        Uses floor (truncation): a cert expiring in 1d23h returns 1, not 2.
        This matches the alert threshold semantics — the 1-day alert fires
        when there are fewer than 2 full days remaining, which is correct:
        you have at most 1 complete day left. The trade-off is that a
        threshold boundary can fire up to ~23h before the nominal expiry
        day; this is acceptable because thresholds are calendar-day aligned.
        """
        now = datetime.now(UTC)
        not_after = self.not_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)
        delta = not_after - now
        return delta.days

    @property
    def display_name(self) -> str:
        """See AC-08."""
        if self.subject:
            return self.subject
        if self.san_dns_names:
            return self.san_dns_names[0]
        return "unknown"


def _from_x509(cert: x509.Certificate) -> Certificate:
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dns = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san_dns = []

    fp = cert.fingerprint(hashes.SHA256()).hex()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    return Certificate(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=not_before,
        not_after=not_after,
        san_dns_names=san_dns,
        fingerprint_sha256=fp,
        raw_der=cert.public_bytes(Encoding.DER),
        is_leaf=True,
    )


def parse_certificate(der_bytes: bytes) -> Certificate | MalformedCertificateError:
    """Parse a DER-encoded X.509 certificate. See AC-03/AC-04."""
    if not der_bytes:
        return MalformedCertificateError(message="empty DER input")
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:  # noqa: BLE001
        return MalformedCertificateError(message=f"failed to parse DER: {exc}")
    return _from_x509(cert)


def parse_pem_certificate(pem_text: str) -> Certificate | MalformedCertificateError:
    """Parse a PEM-encoded X.509 certificate. See AC-05."""
    if not pem_text or "-----BEGIN CERTIFICATE-----" not in pem_text:
        return MalformedCertificateError(message="no PEM certificate block found")
    try:
        cert = x509.load_pem_x509_certificate(pem_text.encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return MalformedCertificateError(message=f"failed to parse PEM: {exc}")
    return _from_x509(cert)


_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def extract_chain_from_pem(pem_text: str) -> list[Certificate]:
    """Extract all certificates from a multi-cert PEM file. See AC-09."""
    out: list[Certificate] = []
    if not pem_text:
        return out
    for block in _PEM_CERT_RE.findall(pem_text):
        parsed = parse_pem_certificate(block)
        if isinstance(parsed, Certificate):
            out.append(parsed)
    for i, c in enumerate(out):
        c.is_leaf = i == 0
    return out
