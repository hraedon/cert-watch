"""Reusable retry/backoff utilities."""

from __future__ import annotations

import logging
import time
from collections.abc import Generator
from typing import Literal

logger = logging.getLogger("cert_watch.retry")


def backoff_range(
    max_retries: int,
    base_delay: float,
    *,
    strategy: Literal["exponential", "linear"] = "exponential",
) -> Generator[int]:
    """Yield attempt numbers 0..max_retries, sleeping between attempts.

    Yields 0 first (no initial sleep). Sleeps ``base_delay * 2**attempt``
    (exponential) or ``base_delay * (attempt + 1)`` (linear) between retries.

    Usage::

        for attempt in backoff_range(3, 1.0):
            result = try_thing()
            if result is not None:
                break
    """
    for attempt in range(max_retries + 1):
        yield attempt
        if attempt < max_retries:
            if strategy == "exponential":
                delay = base_delay * (2 ** attempt)
            else:
                delay = base_delay * (attempt + 1)
            logger.debug("retry %d/%d, sleeping %.1fs", attempt + 1, max_retries, delay)
            time.sleep(delay)
