"""Service abstract base classes.

Services contain business logic and orchestrate repositories.
"""

from abc import ABC, abstractmethod
from typing import Optional

from ..models.certificate import Certificate


class CertificateService(ABC):
    """Service for certificate business logic."""

    @abstractmethod
    async def scan_host(
        self, hostname: str, port: int = 443
    ) -> tuple[Certificate, list[Certificate]]:
        """Scan host for certificates via TLS handshake.

        Returns:
            Tuple of (leaf certificate, chain certificates)
        """
        pass

    @abstractmethod
    async def upload_certificate(self, data: bytes, label: Optional[str] = None) -> Certificate:
        """Upload and parse certificate file.

        Args:
            data: Raw certificate file bytes
            label: Optional user-defined label

        Returns:
            Created certificate entry
        """
        pass


class AlertService(ABC):
    """Service for alert business logic."""

    @abstractmethod
    async def evaluate_alerts(self) -> list[int]:
        """Evaluate all certificates and create pending alerts.

        Returns:
            List of created alert IDs
        """
        pass

    @abstractmethod
    async def send_pending_alerts(self) -> tuple[int, int]:
        """Send all pending alerts.

        Returns:
            Tuple of (sent count, failed count)
        """
        pass


class ScanSchedulerService(ABC):
    """Service for scheduled scanning."""

    @abstractmethod
    async def run_daily_scan(self) -> None:
        """Run the daily scan cycle."""
        pass

    @abstractmethod
    def start_scheduler(self) -> None:
        """Start the background scheduler."""
        pass

    @abstractmethod
    def stop_scheduler(self) -> None:
        """Stop the background scheduler."""
        pass
