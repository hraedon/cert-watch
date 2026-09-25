"""The one certificate status rule, for Python and for SQL (#113).

Every surface that shows or counts a status (Home, Browse and its group
views, the group-expansion API, the compliance report, ``/metrics``) uses
this rule, documented in docs/operations.md ("What the numbers mean"):

- **Effective days**: whole days until the soonest expiry among the leaf and
  the chain certificates stored with it. An expired intermediate makes a
  99-day leaf's effective days negative.
- **Status**: ``expired`` below 0 effective days, ``critical`` below 7,
  ``warning`` below 30, else ``healthy``; a ``healthy`` certificate whose
  chain is not verified (self-signed, incomplete, invalid, unknown) is shown
  as ``warning`` (:func:`cert_watch.cert_chain.display_urgency`). A row with no
  certificate yet (a pending endpoint) is ``gray``.

The Python presenter builds rows with :func:`effective_days` and
:func:`effective_urgency`. SQL aggregates with :func:`effective_days_sql` and
:func:`urgency_sql`, which call the *same* two functions through the SQLite
functions registered by :func:`register_sql_functions` -- so a count and the
rows it counts cannot disagree about a threshold, a day boundary or the chain
floor. The chain status SQL reads is the ``certificates.chain_status`` cache
(:mod:`cert_watch.database.chain_status_cache`), used only while it is
current; a missing or stale entry reads as ``unverified``, which the floor
treats like any unverified chain, so the cache can never make a certificate
look healthier than the rows do.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime

CRITICAL_DAYS = 7
WARNING_DAYS = 30

URGENCIES = ("expired", "critical", "warning", "healthy")
URGENCY_RANK = {u: i for i, u in enumerate(URGENCIES)}

# Separates chain ``not_after`` values in the ``group_concat`` handed to SQL.
_SEP = "\x1f"


def _as_datetime(value: str | datetime) -> datetime:
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(value)
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def days_until(not_after: str | datetime, now: datetime) -> int:
    """Whole days from *now* until *not_after*, negative once it has passed."""
    return (_as_datetime(not_after) - now).days


def expiry_urgency(days: int | None) -> str:
    """Status from a day count alone (``gray`` when there is no certificate)."""
    if days is None:
        return "gray"
    if days < 0:
        return "expired"
    if days < CRITICAL_DAYS:
        return "critical"
    if days < WARNING_DAYS:
        return "warning"
    return "healthy"


def effective_days(
    leaf_not_after: str | datetime,
    chain_not_afters: Iterable[str | datetime],
    now: datetime,
) -> int:
    """Days until the soonest expiry among the leaf and its stored chain."""
    return min(
        [days_until(leaf_not_after, now), *(days_until(n, now) for n in chain_not_afters)]
    )


def effective_urgency(eff_days: int | None, chain_status: str | None) -> str:
    """The row status: expiry status of *eff_days*, with the chain floor."""
    from cert_watch.cert_chain import display_urgency

    if eff_days is None:
        return "gray"
    return display_urgency(expiry_urgency(eff_days), chain_status)


# --- SQL ---------------------------------------------------------------------


def _sql_effective_days(leaf_not_after: str | None, chain: str | None, now: str) -> int | None:
    if not leaf_not_after:
        return None
    chain_values = [v for v in (chain or "").split(_SEP) if v]
    try:
        return effective_days(leaf_not_after, chain_values, _as_datetime(now))
    except (ValueError, TypeError, OverflowError):
        # An unreadable date must not fail every status query in the estate.
        return None


def _sql_urgency(eff_days: int | None, chain_status: str | None) -> str:
    return effective_urgency(eff_days, chain_status)


def register_sql_functions(conn: sqlite3.Connection) -> None:
    """Expose the rule to SQL: ``cw_effective_days``, ``cw_urgency`` and helpers."""
    from cert_watch.database.chain_status_cache import register_sql_functions as _cache
    from cert_watch.filters import subject_cn

    conn.create_function("cw_effective_days", 3, _sql_effective_days, deterministic=True)
    conn.create_function("cw_urgency", 2, _sql_urgency, deterministic=True)
    conn.create_function(
        "cw_subject_cn", 1, lambda s: subject_cn(s or ""), deterministic=True
    )
    _cache(conn)


def effective_days_sql(alias: str = "c") -> str:
    """SQL for the effective days of leaf row *alias*; binds one ``?`` (now).

    Bind :attr:`cert_watch.database.chain_status_cache.StatusContext.sql_now`.
    """
    return (
        f"cw_effective_days({alias}.not_after, (SELECT group_concat(ch.not_after, char(31))"
        f" FROM certificates ch WHERE ch.parent_cert_id = {alias}.id), ?)"
    )


def urgency_sql(alias: str = "c") -> str:
    """SQL for the status of leaf row *alias*; binds ``?`` now, then ``?`` trust digest.

    The chain status is the cached one only while it is current, otherwise
    ``unverified`` (never Healthy): see
    :func:`cert_watch.database.chain_status_cache.verified_chain_status_sql`.
    """
    from cert_watch.database.chain_status_cache import verified_chain_status_sql

    return f"cw_urgency({effective_days_sql(alias)}, {verified_chain_status_sql(alias)})"


def urgency_rank_sql(expr: str) -> str:
    """SQL ranking an urgency expression (``expired`` = 0 ... ``healthy`` = 3)."""
    whens = " ".join(f"WHEN '{u}' THEN {i}" for u, i in URGENCY_RANK.items())
    return f"(CASE {expr} {whens} ELSE 4 END)"
