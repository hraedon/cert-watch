"""Rate limiting: a SQLite-backed sliding window shared across workers
(BC-049), sharded in-memory fallback, proxy-aware client-IP extraction, the
per-route dependency factory and the ``/api/*`` limit middleware."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from starlette.responses import Response

logger = logging.getLogger("cert_watch.middleware")

# ---------- Rate limiting (SQLite-backed sliding window, BC-049) ----------

_RATE_SHARDS = 256
_rate_db_init_lock = threading.Lock()
_rate_db_path: Path | None = None
_rate_db_initialized = False
# In-memory cache for reduced DB I/O (per-key, synced to SQLite). Sharded to
# avoid a single global lock serialising unrelated keys under concurrent load.
_rate_locks: tuple[threading.Lock, ...] = tuple(threading.Lock() for _ in range(_RATE_SHARDS))
_rate_caches: list[dict[str, list[float]]] = [{} for _ in range(_RATE_SHARDS)]
_RATE_CACHE_TTL = 10.0  # seconds before cache entry is considered stale
_RATE_STALE_TTL = 600.0  # evict rows stale for 10 minutes
# Guards the DB-backed rate_limits table against unbounded growth: cleanup is
# throttled to once per _RATE_CACHE_TTL (not on every request), so the DELETE
# query doesn't become part of the hot per-request path.
_last_rate_cleanup = 0.0


def _rate_shard(key: str) -> int:
    return hash(key) % _RATE_SHARDS


def _clear_rate_caches() -> None:
    """Clear all in-memory rate-limit cache shards (test helper)."""
    for cache in _rate_caches:
        cache.clear()

_TRUST_PROXY = os.environ.get("CERT_WATCH_TRUST_PROXY", "") == "1"
_TRUSTED_PROXIES = frozenset(
    p.strip() for p in os.environ.get("CERT_WATCH_TRUSTED_PROXIES", "").split(",") if p.strip()
)


def _extract_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting proxy headers when configured.

    When ``TRUST_PROXY=1`` and ``TRUSTED_PROXIES`` is empty, we use the **rightmost**
    XFF entry (the hop the trusted proxy appended) rather than the leftmost
    (client-controlled) entry, which is spoofable. This is the correct behavior
    for a single trusted proxy; multi-proxy chains should use ``TRUSTED_PROXIES``.

    L10 hardening: when ``TRUSTED_PROXIES`` is empty AND there is only one XFF
    entry, that entry is entirely client-controlled (no proxy rewrote it), so
    we fall back to ``request.client.host`` (the TCP peer) instead.

    X-Real-IP is only trusted when ``TRUSTED_PROXIES`` is configured (the
    proxy is explicitly trusted to have set it correctly). Without
    ``TRUSTED_PROXIES``, X-Real-IP is client-controlled and must not be
    used for rate limiting. When trusted, the value is validated as a
    well-formed IP address to prevent garbage injection.
    """
    peer = request.client.host if request.client else "unknown"
    if not _TRUST_PROXY:
        return peer

    # A configured allowlist describes which immediate TCP peers may supply
    # forwarding headers. Without this check, merely setting TRUSTED_PROXIES
    # caused headers from every peer to be trusted (WI-144).
    if _TRUSTED_PROXIES and peer not in _TRUSTED_PROXIES:
        return peer

    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        parts = [p.strip() for p in xff.split(",")]
        if _TRUSTED_PROXIES:
            for part in reversed(parts):
                try:
                    ipaddress.ip_address(part)
                except ValueError:
                    return peer
                if part not in _TRUSTED_PROXIES:
                    return part
        elif len(parts) > 1:
            return parts[-1]
    if _TRUSTED_PROXIES:
        real_ip = request.headers.get("x-real-ip", "")
        if real_ip:
            try:
                ipaddress.ip_address(real_ip)
            except ValueError:
                pass
            else:
                return real_ip
    return peer


def _init_rate_db(db_path: Path | str) -> None:
    """Initialize the rate limit database path. Called at app startup."""
    global _rate_db_path
    _rate_db_path = Path(db_path)


def _load_timestamps(conn: sqlite3.Connection, key: str, cutoff: float) -> list[float]:
    """Load and filter timestamps for a rate limit key from SQLite."""
    row = conn.execute(
        "SELECT timestamps FROM rate_limits WHERE key = ?", (key,)
    ).fetchone()
    if not row:
        return []
    try:
        all_ts = json.loads(row[0])
    except (json.JSONDecodeError, TypeError):
        return []
    return [t for t in all_ts if t >= cutoff]


def _save_timestamps(conn: sqlite3.Connection, key: str, timestamps: list[float]) -> None:
    """Save timestamps for a rate limit key to SQLite."""
    now_iso = datetime.now(UTC).isoformat()
    ts_json = json.dumps(timestamps)
    conn.execute(
        "INSERT OR REPLACE INTO rate_limits (key, timestamps, updated_at) "
        "VALUES (?, ?, ?)",
        (key, ts_json, now_iso),
    )


def _cleanup_stale(conn: sqlite3.Connection) -> None:
    """Remove rate limit entries that haven't been updated recently."""
    stale_before = (
        datetime.now(UTC).timestamp() - _RATE_STALE_TTL
    )
    stale_iso = datetime.fromtimestamp(stale_before, tz=UTC).isoformat()
    conn.execute(
        "DELETE FROM rate_limits WHERE updated_at < ?", (stale_iso,)
    )


def _apply_memory_limit(
    cache: dict[str, list[float]], key: str, cutoff: float, max_requests: int, now: float
) -> bool:
    """Apply sliding-window rate limit in-memory for a single cache shard."""
    ts = [t for t in cache.get(key, []) if t >= cutoff]
    if len(ts) >= max_requests:
        cache[key] = ts
        return False
    ts.append(now)
    cache[key] = ts
    # Evict stale keys to prevent unbounded growth; per-shard threshold keeps
    # total cache bounded without a global lock.
    if len(cache) > max(16, 256 // _RATE_SHARDS):
        stale = [k for k, v in cache.items() if not v or max(v) < cutoff]
        for k in stale:
            del cache[k]
    return True


def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited.

    Uses SQLite for persistence so rate limits are shared across workers (BC-049).
    Falls back to in-memory mode when no database is configured.
    """
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds

    global _last_rate_cleanup

    shard = _rate_shard(key)
    lock = _rate_locks[shard]
    cache = _rate_caches[shard]

    if _rate_db_path is None:
        # Fallback: in-memory only (single-worker mode)
        with lock:
            return _apply_memory_limit(cache, key, cutoff, max_requests, now)

    with lock:
        try:
            from cert_watch.database.connection import _connect
            from cert_watch.database.schema import init_schema

            global _rate_db_initialized
            if not _rate_db_initialized:
                with _rate_db_init_lock:
                    if not _rate_db_initialized:
                        init_schema(_rate_db_path)
                        _rate_db_initialized = True
            with _connect(_rate_db_path) as conn:
                # Periodic cleanup of stale entries (rows are keyed by client
                # IP and never otherwise evicted — without this, the table
                # grows without bound under rotating IPs / spoofed XFF).
                if _last_rate_cleanup + _RATE_CACHE_TTL < now:
                    _cleanup_stale(conn)
                    conn.commit()
                    _last_rate_cleanup = now

                # Evict stale in-memory cache entries periodically. The cache now
                # only mirrors state for get_rate_remaining() and the in-memory
                # fallback path — the allow/deny decision always reads SQLite.
                if len(cache) > max(16, 256 // _RATE_SHARDS):
                    stale = [k for k, v in cache.items() if not v or max(v) < cutoff]
                    for k in stale:
                        del cache[k]

                # Serialize the read-modify-write across workers/processes so
                # concurrent increments on the same key can't be lost, and always
                # read the authoritative count from SQLite. Two correctness bugs
                # this closes:
                #  1. The per-process cache was served for up to _RATE_CACHE_TTL
                #     without consulting SQLite, so under `uvicorn --workers N`
                #     each worker counted independently → N×max_requests.
                #  2. A deferred (default) transaction only locks at first write,
                #     letting two workers read the same count and the later write
                #     drop the earlier's append. BEGIN IMMEDIATE acquires the
                #     write lock up front; busy_timeout makes contending workers
                #     wait rather than collide.
                try:
                    # If a prior cleanup commit failed mid-transaction, the
                    # cached connection could still hold an open txn; clear it
                    # before acquiring the write lock so BEGIN IMMEDIATE can't
                    # fail with "cannot start a transaction within a transaction"
                    # (which would degrade this thread to fail-open in-memory).
                    if conn.in_transaction:
                        conn.rollback()
                    conn.execute("BEGIN IMMEDIATE")
                    ts = _load_timestamps(conn, key, cutoff)
                    if len(ts) >= max_requests:
                        cache[key] = ts
                        _save_timestamps(conn, key, ts)
                        conn.commit()
                        return False

                    ts.append(now)
                    cache[key] = ts
                    _save_timestamps(conn, key, ts)
                    conn.commit()
                    return True
                except sqlite3.Error:
                    # Roll back so the cached connection is left clean (an open
                    # txn here would make the next BEGIN IMMEDIATE fail).
                    with contextlib.suppress(sqlite3.Error):
                        conn.rollback()
                    raise
        except (sqlite3.Error, OSError):
            # WARNING, not DEBUG (BC-078): a silent DB-error fallback degrades
            # rate limiting to per-process counters without anyone noticing.
            # This is fail-open (degraded rather than denied) — crashing the
            # whole app over a rate-limit DB error is worse than temporarily
            # losing cross-worker limit enforcement. Monitor for this log
            # line: sustained fallback means rate limiting is ineffective in
            # multi-worker deployments.
            logger.error(
                "RATE_LIMIT_DEGRADED: rate limit DB error, falling back to "
                "per-process in-memory limiting. Cross-worker rate limiting "
                "is INEFFECTIVE until the DB recovers. Monitor and alert on "
                "this message pattern.",
                exc_info=True,
            )
            # Fallback to in-memory on DB errors
            return _apply_memory_limit(cache, key, cutoff, max_requests, now)


def get_rate_remaining(key: str, max_requests: int, window_seconds: int) -> tuple[int, int]:
    """Return (remaining, retry_after_seconds) for the given rate limit window."""
    now = datetime.now(UTC).timestamp()
    cutoff = now - window_seconds
    shard = _rate_shard(key)
    cache = _rate_caches[shard]

    if _rate_db_path is not None:
        try:
            from cert_watch.database.connection import _connect

            with _connect(_rate_db_path) as conn:
                ts = _load_timestamps(conn, key, cutoff)
        except (sqlite3.Error, OSError):
            with _rate_locks[shard]:
                ts = [t for t in cache.get(key, []) if t >= cutoff]
    else:
        with _rate_locks[shard]:
            ts = [t for t in cache.get(key, []) if t >= cutoff]

    count = len(ts)
    remaining = max(0, max_requests - count)
    oldest = min(ts, default=now)
    retry_after = max(0, int(window_seconds - (now - oldest)))
    return remaining, retry_after



def rate_limit(key_prefix: str, max_requests: int, window_seconds: int) -> Any:
    """FastAPI dependency factory for per-client-IP rate limiting (Plan 020 S2).

    Usage: ``deps=[Depends(rate_limit("ct", 10, 60))]`` (or a parameter
    ``_rl: None = Depends(rate_limit("ct", 10, 60))``). Raises
    ``HTTPException(429)`` when the limit is exceeded, and always uses
    ``_extract_client_ip()`` so proxy-aware identification is automatic — a
    new API route can't forget it.

    This is for JSON/API routes. Routes that return a ``RedirectResponse`` on
    limit (form POSTs like ``/hosts`` and ``/login``) must keep a manual
    ``check_rate_limit`` call, because a dependency can only raise, not return
    a redirect.
    """

    async def _dep(request: Request) -> None:
        client_ip = _extract_client_ip(request)
        if not check_rate_limit(f"{key_prefix}:{client_ip}", max_requests, window_seconds):
            raise HTTPException(status_code=429, detail="rate limited")

    return _dep


async def rate_limit_headers_middleware(
    request: Request, call_next: RequestResponseEndpoint
) -> Response:
    """Enforce rate limits on API routes and add X-RateLimit headers."""
    if not request.url.path.startswith("/api/"):
        return await call_next(request)
    # Health checks are polled frequently (UI banner, k8s probes) — exempt.
    if request.url.path == "/api/health":
        return await call_next(request)
    client = _extract_client_ip(request)
    key = f"api:{client}"
    if not check_rate_limit(key, 60, 60):
        remaining, retry_after = get_rate_remaining(key, 60, 60)
        response: Response = JSONResponse(
            content={"error": "rate limited"},
            status_code=429,
        )
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Limit"] = "60"
        response.headers["Retry-After"] = str(retry_after)
        return response
    response = await call_next(request)
    remaining, _ = get_rate_remaining(key, 60, 60)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Limit"] = "60"
    return response

