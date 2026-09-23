"""Process-local publication and fallback cache for resolved settings snapshots."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

from cert_watch.config.settings import Settings

_lock = threading.RLock()
_published: dict[Path, Settings] = {}
_standalone: dict[tuple[Path, str | None], Settings] = {}
_generations: dict[Path, int] = {}


def _key(db_path: str | Path) -> Path:
    return Path(db_path).resolve()


def settings_generation(db_path: str | Path) -> int:
    """Return the current process-local mutation generation for *db_path*."""
    db_key = _key(db_path)
    with _lock:
        return _generations.get(db_key, 0)


def publish_settings(
    settings: Settings, *, expected_generation: int | None = None
) -> bool:
    """Publish a snapshot if it was resolved at the current generation.

    Callers rebuilding from persistent configuration pass the generation they
    captured before resolving.  A concurrent save increments the generation,
    causing this publication to be refused instead of reviving stale values.
    """
    db_key = _key(settings.db_path)
    with _lock:
        if (
            expected_generation is not None
            and _generations.get(db_key, 0) != expected_generation
        ):
            return False
        _published[db_key] = settings
        for cache_key in tuple(_standalone):
            if cache_key[0] == db_key:
                del _standalone[cache_key]
        return True


def resolve_and_publish_settings(
    db_path: str | Path,
    *,
    encryption_key: str | None = None,
    apply: Callable[[Settings], None] | None = None,
) -> Settings:
    """Resolve, publish, and apply a snapshot, retrying across concurrent saves."""
    db_key = _key(db_path)
    while True:
        generation = settings_generation(db_key)
        settings = Settings.from_env_with_kv(db_key, encryption_key)
        if not publish_settings(settings, expected_generation=generation):
            continue
        if apply is not None:
            apply(settings)
        # Applying to app/scheduler state happens outside the publication lock.
        # If a save raced that step, rebuild again so those consumers also end
        # on the newest generation.
        if settings_generation(db_key) == generation:
            return settings


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
    """Advance the mutation generation and forget all cached snapshots."""
    db_key = _key(db_path)
    with _lock:
        _generations[db_key] = _generations.get(db_key, 0) + 1
        _published.pop(db_key, None)
        for cache_key in tuple(_standalone):
            if cache_key[0] == db_key:
                del _standalone[cache_key]
