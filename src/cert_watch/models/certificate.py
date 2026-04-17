"""Certificate data models."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Optional


class CertificateType(Enum):
    """Type of certificate entry."""

    LEAF = auto()
    INTERMEDIATE = auto()
    ROOT = auto()


class CertificateSource(Enum):
    """Source of certificate entry."""

    SCANNED = auto()  # Extracted via TLS handshake
    UPLOADED = auto()  # Uploaded from file


@dataclass
class Certificate:
    """Certificate model representing a monitored certificate."""

    # Identification
    id: Optional[int] = None
    certificate_type: CertificateType = CertificateType.LEAF
    source: CertificateSource = CertificateSource.SCANNED

    # Location/Label
    hostname: Optional[str] = None  # For scanned entries
    port: Optional[int] = None  # For scanned entries
    label: Optional[str] = None  # User-defined label

    # Certificate fields
    subject: str = ""
    issuer: str = ""
    not_before: datetime = field(default_factory=datetime.utcnow)
    not_after: datetime = field(default_factory=datetime.utcnow)
    fingerprint: str = ""  # SHA-256 thumbprint
    serial_number: str = ""

    # Chain relationship
    chain_fingerprint: Optional[str] = None  # Fingerprint of parent chain cert
    chain_position: int = 0  # Position in chain (0 = leaf)

    # Storage
    pem_data: Optional[bytes] = None  # PEM-encoded certificate

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_scanned_at: Optional[datetime] = None

    # Source tracking
    source_hostname: Optional[str] = None  # For chain certs - where they came from
    source_port: Optional[int] = None

    @property
    def is_expired(self) -> bool:
        """Check if certificate has expired."""
        return datetime.utcnow() > self.not_after

    @property
    def days_remaining(self) -> int:
        """Compute days remaining until expiry."""
        from ..core.formatters import compute_days_remaining

        return compute_days_remaining(self.not_after)

    @property
    def status_color(self) -> str:
        """Get status color based on days remaining."""
        from ..core.formatters import get_status_color

        return get_status_color(self.days_remaining)

    @property
    def display_name(self) -> str:
        """Get display name for this certificate."""
        if self.label:
            return self.label
        if self.hostname:
            if self.port and self.port != 443:
                return f"{self.hostname}:{self.port}"
            return self.hostname
        return self.subject

    @property
    def is_leaf(self) -> bool:
        """Check if this is a leaf certificate."""
        return self.certificate_type == CertificateType.LEAF

    @property
    def is_chain(self) -> bool:
        """Check if this is a chain certificate."""
        return self.certificate_type in (
            CertificateType.INTERMEDIATE,
            CertificateType.ROOT,
        )
