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


_current_db_path: str | None = None


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


def _clear_settings_cache():
    """Clear the Settings singleton cache.

    This is used primarily for testing to ensure settings can be
    reconfigured between test cases.
    """
    Settings.get.cache_clear()


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
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    # Check if database path has changed (for testing scenarios)
    if _current_db_path is not None and _current_db_path != db_path:
        # Clear caches to ensure we use the new database
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    return SQLiteCertificateRepository(pool)


def get_alert_repo():
    """Get AlertRepository dependency."""
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    if _current_db_path is not None and _current_db_path != db_path:
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    return SQLiteAlertRepository(pool)


def get_scan_repo():
    """Get ScanHistoryRepository dependency."""
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    if _current_db_path is not None and _current_db_path != db_path:
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    return SQLiteScanHistoryRepository(pool)
