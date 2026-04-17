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

from functools import lru_cache
from typing import AsyncGenerator

from fastapi import Depends, Request

from ..core.config import Settings
from ..repositories.base import CertificateRepository, AlertRepository, ScanHistoryRepository
from ..repositories.sqlite import (
    SQLiteConnectionPool,
    SQLiteCertificateRepository,
    SQLiteAlertRepository,
    SQLiteScanHistoryRepository,
)


def _get_connection_pool(settings: Settings | None = None) -> SQLiteConnectionPool:
    """Get the connection pool for the given settings."""
    settings = Settings.get(settings)
    return SQLiteConnectionPool(settings.database_path)


async def get_db() -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Get database connection pool dependency.

    Yields the connection pool for use in route handlers.
    """
    pool = _get_connection_pool()
    try:
        yield pool
    finally:
        # Connection cleanup handled by pool
        pass


def get_repo():
    """Create repository dependency factory.

    Returns a dependency function that provides the requested repository type.
    Usage: Depends(get_repo()) provides CertificateRepository
    """

    def _get_repo(request: Request) -> CertificateRepository:
        # Try to get settings from app state (set during testing)
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteCertificateRepository(pool)

    return _get_repo


def get_alert_repo():
    """Get AlertRepository dependency."""

    def _get_alert_repo(request: Request) -> AlertRepository:
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteAlertRepository(pool)

    return _get_alert_repo


def get_scan_repo():
    """Get ScanHistoryRepository dependency."""

    def _get_scan_repo(request: Request) -> ScanHistoryRepository:
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteScanHistoryRepository(pool)

    return _get_scan_repo
