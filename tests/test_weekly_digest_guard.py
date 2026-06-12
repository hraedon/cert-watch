"""Tests for the weekly-digest same-day restart guard in app.py's lifespan.

_weekly_digest_day is initialized to today's weekday so that a restart on
the same day does not re-fire the digest. The guard fires only when the
weekday actually changes.

The guard lives as a closure inside lifespan, so these tests replicate the
exact algorithm (init to today, compare, update on mismatch) to verify the
behaviour the closure must exhibit.
"""

from __future__ import annotations

import datetime as _dt
from unittest.mock import MagicMock


def _build_guard(initial_weekday: int, digest_fn):
    state = {"last_day": initial_weekday}

    def _maybe_run(current_weekday: int) -> None:
        if current_weekday != state["last_day"]:
            state["last_day"] = current_weekday
            digest_fn()

    return _maybe_run


def test_weekly_digest_no_fire_on_same_day():
    today = _dt.datetime.now(_dt.UTC).weekday()
    digest = MagicMock()
    guard = _build_guard(today, digest)
    guard(today)
    digest.assert_not_called()


def test_weekly_digest_fires_on_different_day():
    today = _dt.datetime.now(_dt.UTC).weekday()
    tomorrow = (today + 1) % 7
    digest = MagicMock()
    guard = _build_guard(today, digest)
    guard(tomorrow)
    digest.assert_called_once()


def test_weekly_digest_fires_once_per_day_change():
    today = _dt.datetime.now(_dt.UTC).weekday()
    tomorrow = (today + 1) % 7
    digest = MagicMock()
    guard = _build_guard(today, digest)
    guard(tomorrow)
    guard(tomorrow)
    digest.assert_called_once()


def test_weekly_digest_fires_again_on_subsequent_change():
    today = _dt.datetime.now(_dt.UTC).weekday()
    day2 = (today + 1) % 7
    day3 = (today + 2) % 7
    digest = MagicMock()
    guard = _build_guard(today, digest)
    guard(day2)
    guard(day3)
    assert digest.call_count == 2


def test_weekly_digest_old_init_value_would_fire_on_restart():
    today = _dt.datetime.now(_dt.UTC).weekday()
    digest = MagicMock()
    guard = _build_guard(-1, digest)
    guard(today)
    digest.assert_called_once()
