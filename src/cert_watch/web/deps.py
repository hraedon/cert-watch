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


@lru_cache(maxsize=128)
def _get_connection_pool(db_path: str) -> SQLiteConnectionPool:
    """Get the connection pool for a specific database path.

    The pool is cached per database path to support both production
    and testing scenarios where different databases are used.
    """
    from pathlib import Path

    return SQLiteConnectionPool(Path(db_path))


def _clear_connection_pool_cache():
    """Clear the connection pool cache.

    This is used primarily for testing to ensure database isolation
    between test cases.
    """
    _get_connection_pool.cache_clear()


async def get_db() -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Get database connection pool dependency.

    Yields the connection pool for use in route handlers.
    """
    settings = Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
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
    settings = Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
    return SQLiteCertificateRepository(pool)


def get_alert_repo():
    """Get AlertRepository dependency."""
    settings = Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
    return SQLiteAlertRepository(pool)


def get_scan_repo():
    """Get ScanHistoryRepository dependency."""
    settings = Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
    return SQLiteScanHistoryRepository(pool)
