"""cert-watch services package."""

from .base import (
    AlertService,
    # Stub implementations for parallel development
    AlertServiceStub,
    CertificateService,
    CertificateServiceStub,
    ScanSchedulerService,
    ScanSchedulerServiceStub,
)

# Import concrete implementations if available
try:
    from .alert_service_impl import AlertServiceImpl
except ImportError:
    AlertServiceImpl = None  # type: ignore

__all__ = [
    # ABCs
    "AlertService",
    "CertificateService",
    "ScanSchedulerService",
    # Stub implementations
    "AlertServiceStub",
    "CertificateServiceStub",
    "ScanSchedulerServiceStub",
    # Concrete implementations
    "AlertServiceImpl",
]
