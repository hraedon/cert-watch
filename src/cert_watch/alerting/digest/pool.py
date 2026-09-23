"""The digest thread pool: renewal-digest webhooks and the orphan notice run here.

Plan 058 PR 5 makes digest delivery synchronous and deletes this module.
"""

from __future__ import annotations

import concurrent.futures
import logging
import threading
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("cert_watch.digest")


_digest_pool: concurrent.futures.ThreadPoolExecutor | None = concurrent.futures.ThreadPoolExecutor(
    max_workers=2, thread_name_prefix="cw-digest",
)
_digest_pool_lock = threading.Lock()


def _flush_digest_pool() -> None:
    """Drain pending tasks and explicitly reset the pool (test helper)."""
    global _digest_pool
    with _digest_pool_lock:
        pool = _digest_pool
        _digest_pool = None
    if pool is not None:
        pool.shutdown(wait=True)
    start_digest_pool()


def start_digest_pool() -> None:
    """Enable digest task submission for an explicit scheduler startup."""
    global _digest_pool
    with _digest_pool_lock:
        if _digest_pool is None:
            _digest_pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="cw-digest",
            )


def shutdown_digest_pool() -> None:
    """Terminally stop digest submissions until ``start_digest_pool``."""
    pool = _detach_digest_pool()
    if pool is not None:
        pool.shutdown(wait=True)


def _detach_digest_pool() -> concurrent.futures.ThreadPoolExecutor | None:
    """Close the submission gate immediately and return the pool to drain."""
    global _digest_pool
    with _digest_pool_lock:
        pool = _digest_pool
        _digest_pool = None
    return pool


def _handle_digest_task_completion(
    future: concurrent.futures.Future[Any],
    *,
    task_name: str,
    failure_callback: Callable[[bool], None] | None,
) -> None:
    try:
        future.result()
    except Exception:
        logger.exception("%s task failed", task_name)
        if failure_callback is not None:
            try:
                failure_callback(False)
            except Exception:
                logger.exception("digest delivery completion callback failed")


def _submit_digest_task(
    fn: Callable[..., Any],
    *args: Any,
    task_name: str = "digest",
    failure_callback: Callable[[bool], None] | None = None,
) -> bool:
    """Submit only while the pool is accepting work; never revive it implicitly."""
    with _digest_pool_lock:
        if _digest_pool is None:
            return False
        future = _digest_pool.submit(fn, *args)
        future.add_done_callback(
            lambda completed: _handle_digest_task_completion(
                completed,
                task_name=task_name,
                failure_callback=failure_callback,
            )
        )
    return True
