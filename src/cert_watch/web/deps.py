"""FastAPI dependencies for dependency injection.

This module provides canonical database and repository dependencies.
Implementing agents MUST use these dependencies rather than importing
sqlite3 or creating connections directly.

Usage in route files:
    from ..deps import get_repo
    from ...repositories import CertificateRepository

    @router.get("/")
    async def handler(repo: CertificateRepository = Depends(get_repo())):
        pass
"""

from collections.abc import AsyncGenerator
from functools import lru_cache
from pathlib import Path

from fastapi import Request

from ..core.config import Settings
from ..repositories.base import AlertRepository, CertificateRepository, ScanHistoryRepository
from ..repositories.sqlite import (
    SQLiteAlertRepository,
    SQLiteCertificateRepository,
    SQLiteConnectionPool,
    SQLiteScanHistoryRepository,
)

# Service implementations for parallel development
# Each service is imported separately so they can be available independently

# AlertService (FR-04)
try:
    from ..services.alert_service_impl import AlertServiceImpl
    from ..services.base import AlertService

    ALERT_SERVICE_AVAILABLE = True
except ImportError:
    ALERT_SERVICE_AVAILABLE = False
    AlertService = None  # type: ignore
    AlertServiceImpl = None  # type: ignore

# ScanSchedulerService (FR-05)
try:
    from ..services.base import ScanSchedulerService
    from ..services.scheduler_impl import ScanSchedulerImpl

    SCHEDULER_SERVICE_AVAILABLE = True
except ImportError:
    SCHEDULER_SERVICE_AVAILABLE = False
    ScanSchedulerService = None  # type: ignore
    ScanSchedulerImpl = None  # type: ignore


@lru_cache(maxsize=128)
def _get_connection_pool(db_path: str) -> SQLiteConnectionPool:
    """Get the connection pool for a specific database path.

    The pool is cached per database path to support both production
    and testing scenarios where different databases are used.
    """
    path = Path(db_path)
    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteConnectionPool(path)


def _clear_connection_pool_cache():
    """Clear the connection pool cache.

    This is used primarily for testing to ensure database isolation
    between test cases.
    """
    _get_connection_pool.cache_clear()


def _clear_settings_cache():
    """Clear the Settings singleton cache.

    This is used primarily for testing to ensure settings can be
    reconfigured between test cases.
    """
    from ..core.config import _get_cached_settings

    _get_cached_settings.cache_clear()


async def get_db(request: Request) -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Get database connection pool dependency.

    Yields the connection pool for use in route handlers.
    """
    settings = getattr(request.app.state, "settings", None) or Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
    try:
        yield pool
    finally:
        # Connection cleanup handled by pool
        pass


def get_repo(request: Request) -> CertificateRepository:
    """Create repository dependency.

    Usage: repo: CertificateRepository = Depends(get_repo)
    """
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        pool = _get_connection_pool(str(settings.database_path))
    else:
        pool = _get_connection_pool(str(Settings.get().database_path))
    return SQLiteCertificateRepository(pool)


def get_alert_repo(request: Request) -> AlertRepository:
    """Get AlertRepository dependency."""
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        pool = _get_connection_pool(str(settings.database_path))
    else:
        pool = _get_connection_pool(str(Settings.get().database_path))
    return SQLiteAlertRepository(pool)


def get_scan_repo(request: Request) -> ScanHistoryRepository:
    """Get ScanHistoryRepository dependency."""
    settings = getattr(request.app.state, "settings", None)
    if settings is not None:
        pool = _get_connection_pool(str(settings.database_path))
    else:
        pool = _get_connection_pool(str(Settings.get().database_path))
    return SQLiteScanHistoryRepository(pool)


# =============================================================================
# Service Dependencies (for FR-04, FR-05)
# =============================================================================


def get_alert_service() -> "AlertService":
    """Get AlertService implementation.

    Returns the concrete AlertService implementation for sending email alerts.
    """
    if not ALERT_SERVICE_AVAILABLE:
        raise NotImplementedError("AlertService not yet implemented")
    return AlertServiceImpl()


def get_scheduler_service() -> "ScanSchedulerService":
    """Get ScanSchedulerService implementation.

    Returns the concrete ScanSchedulerService for daily scans.
    """
    if not SCHEDULER_SERVICE_AVAILABLE:
        raise NotImplementedError("ScanSchedulerService not yet implemented")
    return ScanSchedulerImpl()
