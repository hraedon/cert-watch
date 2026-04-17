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


def _get_connection_pool(request: Request) -> SQLiteConnectionPool:
    """Get the connection pool using settings from the request app state.

    This ensures tests use the test-specific database path instead of
    the default Settings.get() path.
    """
    settings: Settings = request.app.state.settings
    return SQLiteConnectionPool(settings.database_path)


async def get_db(request: Request) -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Get database connection pool dependency.

    Yields the connection pool for use in route handlers.
    """
    pool = _get_connection_pool(request)
    try:
        yield pool
    finally:
        # Connection cleanup handled by pool
        pass


def get_repo(request: Request) -> CertificateRepository:
    """Create repository dependency.

    Usage: repo: CertificateRepository = Depends(get_repo)
    """
    pool = _get_connection_pool(request)
    return SQLiteCertificateRepository(pool)


def get_alert_repo(request: Request) -> AlertRepository:
    """Get AlertRepository dependency."""
    pool = _get_connection_pool(request)
    return SQLiteAlertRepository(pool)


def get_scan_repo(request: Request) -> ScanHistoryRepository:
    """Get ScanHistoryRepository dependency."""
    pool = _get_connection_pool(request)
    return SQLiteScanHistoryRepository(pool)
