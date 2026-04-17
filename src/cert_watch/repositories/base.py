"""Repository abstract base classes.

All database access MUST go through these repository interfaces.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..models.certificate import Certificate
from ..models.alert import Alert
from ..models.scan_history import ScanHistory


class CertificateRepository(ABC):
    """Repository for certificate CRUD operations."""

    @abstractmethod
    async def get_by_id(self, cert_id: int) -> Optional[Certificate]:
        """Get certificate by ID."""
        pass

    @abstractmethod
    async def get_by_fingerprint(self, fingerprint: str) -> Optional[Certificate]:
        """Get certificate by fingerprint."""
        pass

    @abstractmethod
    async def get_all(self, limit: int = 1000) -> list[Certificate]:
        """Get all certificates, sorted by urgency (days remaining ascending)."""
        pass

    @abstractmethod
    async def get_by_hostname(self, hostname: str, port: Optional[int] = None) -> list[Certificate]:
        """Get certificates by hostname."""
        pass

    @abstractmethod
    async def create(self, cert: Certificate) -> Certificate:
        """Create new certificate entry."""
        pass

    @abstractmethod
    async def update(self, cert: Certificate) -> Certificate:
        """Update existing certificate."""
        pass

    @abstractmethod
    async def delete(self, cert_id: int) -> bool:
        """Delete certificate by ID."""
        pass

    @abstractmethod
    async def get_chain_for_leaf(self, leaf_fingerprint: str) -> list[Certificate]:
        """Get chain certificates for a given leaf."""
        pass


class AlertRepository(ABC):
    """Repository for alert CRUD operations."""

    @abstractmethod
    async def get_by_id(self, alert_id: int) -> Optional[Alert]:
        """Get alert by ID."""
        pass

    @abstractmethod
    async def get_pending(self) -> list[Alert]:
        """Get all pending alerts."""
        pass

    @abstractmethod
    async def get_for_certificate(self, cert_id: int, limit: int = 100) -> list[Alert]:
        """Get alerts for a specific certificate."""
        pass

    @abstractmethod
    async def create(self, alert: Alert) -> Alert:
        """Create new alert."""
        pass

    @abstractmethod
    async def mark_sent(self, alert_id: int) -> bool:
        """Mark alert as sent."""
        pass

    @abstractmethod
    async def mark_failed(self, alert_id: int, error: str) -> bool:
        """Mark alert as failed with error message."""
        pass


class ScanHistoryRepository(ABC):
    """Repository for scan history operations."""

    @abstractmethod
    async def get_by_id(self, scan_id: int) -> Optional[ScanHistory]:
        """Get scan history by ID."""
        pass

    @abstractmethod
    async def get_recent(self, limit: int = 100) -> list[ScanHistory]:
        """Get recent scan history entries."""
        pass

    @abstractmethod
    async def create(self, scan: ScanHistory) -> ScanHistory:
        """Create new scan history entry."""
        pass

    @abstractmethod
    async def complete(self, scan_id: int, status: ScanStatus, **kwargs) -> bool:
        """Mark scan as complete with status and results."""
        pass
