"""Tests for the retry backoff helper."""

from __future__ import annotations

import time
from unittest.mock import patch

# Capture this during collection, before the autouse retry fixture runs.
_STDLIB_SLEEP = time.sleep


def test_retry_sleep_overrides_leave_other_threads_sleeping(monkeypatch):
    """Skipping retry delays must preserve the process-wide scheduling primitive."""
    from cert_watch import retry

    assert time.sleep is _STDLIB_SLEEP
    slept: list[float] = []
    monkeypatch.setattr(retry.time, "sleep", slept.append)
    monkeypatch.setattr(retry.random, "uniform", lambda _low, _high: 0.0)

    assert list(retry.backoff_range(2, 1.0)) == [0, 1, 2]
    assert slept == [1.0, 2.0]
    assert time.sleep is _STDLIB_SLEEP


def test_backoff_yields_attempt_numbers():
    """backoff_range yields 0..max_retries inclusive."""
    from cert_watch.retry import backoff_range

    with patch("cert_watch.retry.time.sleep"):  # neutralize real sleeps
        attempts = list(backoff_range(3, 0.001))
    assert attempts == [0, 1, 2, 3]


def test_backoff_includes_jitter():
    """backoff_range must call random.uniform for jitter (not a fixed delay)."""
    from cert_watch.retry import backoff_range

    jitter_calls: list[float] = []
    original_uniform = __import__("random").uniform

    def _spy_uniform(lo, hi):
        val = original_uniform(lo, hi)
        jitter_calls.append(val)
        return val

    with patch("cert_watch.retry.time.sleep"), \
         patch("cert_watch.retry.random.uniform", side_effect=_spy_uniform):
        list(backoff_range(3, 1.0, strategy="exponential"))

    assert len(jitter_calls) == 3  # one per inter-attempt sleep
    assert all(v >= 0 for v in jitter_calls)
    assert all(v <= 1.0 * 0.5 * (2 ** i) for i, v in enumerate(jitter_calls))
