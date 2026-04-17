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

from fastapi import Request

from ..core.config import Settings
from ..repositories.base import AlertRepository, CertificateRepository, ScanHistoryRepository
from functools import lru_cache

from ..core.config import Settings

from ..core.config import Settings
from ..repositories.base import AlertRepository, CertificateRepository, ScanHistoryRepository
from ..repositories.sqlite import (
    SQLiteAlertRepository,
    SQLiteCertificateRepository,
    SQLiteConnectionPool,
    SQLiteScanHistoryRepository,
)

_current_db_path: str | None = None

def _get_connection_pool(settings: Settings | None = None) -> SQLiteConnectionPool:
    """Get the connection pool for the given settings."""
    settings = Settings.get(settings)
def _get_connection_pool(request: Request) -> SQLiteConnectionPool:
    """Get the connection pool using settings from the request app state.

    This ensures tests use the test-specific database path instead of
    the default Settings.get() path.
    """
    settings: Settings = request.app.state.settings
    return SQLiteConnectionPool(settings.database_path)

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


async def get_db(request: Request) -> AsyncGenerator[SQLiteConnectionPool, None]:
    """Get database connection pool dependency.

    Yields the connection pool for use in route handlers.
    """
    settings = Settings.get()
    pool = _get_connection_pool(str(settings.database_path))
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

    def _get_repo(request: Request) -> CertificateRepository:
        # Try to get settings from app state (set during testing)
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteCertificateRepository(pool)

    return _get_repo
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    # Check if database path has changed (for testing scenarios)
    if _current_db_path is not None and _current_db_path != db_path:
        # Clear caches to ensure we use the new database
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    pool = _get_connection_pool(request)
    return SQLiteCertificateRepository(pool)


def get_alert_repo(request: Request) -> AlertRepository:
    """Get AlertRepository dependency."""

    def _get_alert_repo(request: Request) -> AlertRepository:
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteAlertRepository(pool)

    return _get_alert_repo
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    if _current_db_path is not None and _current_db_path != db_path:
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    pool = _get_connection_pool(request)
    return SQLiteAlertRepository(pool)


def get_scan_repo(request: Request) -> ScanHistoryRepository:
    """Get ScanHistoryRepository dependency."""

    def _get_scan_repo(request: Request) -> ScanHistoryRepository:
        settings = getattr(request.app.state, "settings", None)
        pool = _get_connection_pool(settings)
        return SQLiteScanHistoryRepository(pool)

    return _get_scan_repo
    global _current_db_path
    settings = Settings.get()
    db_path = str(settings.database_path)

    if _current_db_path is not None and _current_db_path != db_path:
        _clear_connection_pool_cache()
    _current_db_path = db_path

    pool = _get_connection_pool(db_path)
    pool = _get_connection_pool(request)
    return SQLiteScanHistoryRepository(pool)
