"""Tests for the retry backoff helper."""

from __future__ import annotations

from unittest.mock import patch


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
