"""Service abstract base classes.

Services contain business logic and orchestrate repositories.
"""

from abc import ABC, abstractmethod

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
    async def upload_certificate(self, data: bytes, label: str | None = None) -> Certificate:
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


# =============================================================================
# Stub Implementations for Parallel Development
# =============================================================================


class CertificateServiceStub(CertificateService):
    """Stub implementation of CertificateService for parallel development.

    This stub allows other agents to import and reference the service
    while the actual implementation is being developed.
    """

    async def scan_host(
        self, hostname: str, port: int = 443
    ) -> tuple[Certificate, list[Certificate]]:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("CertificateServiceStub.scan_host is not yet implemented")

    async def upload_certificate(self, data: bytes, label: str | None = None) -> Certificate:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError(
            "CertificateServiceStub.upload_certificate is not yet implemented"
        )


class AlertServiceStub(AlertService):
    """Stub implementation of AlertService for parallel development.

    This stub allows other agents to import and reference the service
    while the actual implementation is being developed.
    """

    async def evaluate_alerts(self) -> list[int]:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("AlertServiceStub.evaluate_alerts is not yet implemented")

    async def send_pending_alerts(self) -> tuple[int, int]:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("AlertServiceStub.send_pending_alerts is not yet implemented")


class ScanSchedulerServiceStub(ScanSchedulerService):
    """Stub implementation of ScanSchedulerService for parallel development.

    This stub allows other agents to import and reference the service
    while the actual implementation is being developed.
    """

    async def run_daily_scan(self) -> None:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("ScanSchedulerServiceStub.run_daily_scan is not yet implemented")

    def start_scheduler(self) -> None:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("ScanSchedulerServiceStub.start_scheduler is not yet implemented")

    def stop_scheduler(self) -> None:
        """Stub - raises NotImplementedError."""
        raise NotImplementedError("ScanSchedulerServiceStub.stop_scheduler is not yet implemented")
