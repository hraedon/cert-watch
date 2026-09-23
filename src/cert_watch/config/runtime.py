"""Process-local publication and fallback cache for resolved settings snapshots."""

from __future__ import annotations

import threading
from pathlib import Path

from cert_watch.config.settings import Settings

_lock = threading.RLock()
_published: dict[Path, Settings] = {}
_standalone: dict[tuple[Path, str | None], Settings] = {}


def _key(db_path: str | Path) -> Path:
    return Path(db_path).resolve()


def publish_settings(settings: Settings) -> None:
    """Publish the application's immutable current snapshot for hot-path reads."""
    db_key = _key(settings.db_path)
    with _lock:
        _published[db_key] = settings
        for cache_key in tuple(_standalone):
            if cache_key[0] == db_key:
                del _standalone[cache_key]


def current_settings(
    db_path: str | Path, *, encryption_key: str | None = None
) -> Settings:
    """Return the published snapshot, resolving once for standalone callers."""
    db_key = _key(db_path)
    cache_key = (db_key, encryption_key)
    with _lock:
        published = _published.get(db_key)
        if published is not None:
            return published
        cached = _standalone.get(cache_key)
        if cached is None:
            cached = Settings.from_env_with_kv(db_key, encryption_key)
            _standalone[cache_key] = cached
        return cached


def invalidate_settings(db_path: str | Path) -> None:
    """Forget snapshots after a persisted settings mutation."""
    db_key = _key(db_path)
    with _lock:
        _published.pop(db_key, None)
        for cache_key in tuple(_standalone):
            if cache_key[0] == db_key:
                del _standalone[cache_key]
