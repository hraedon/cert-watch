"""Reduce stored scan evidence into renewal-attempt verification state."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cert_watch.alerting.model import (
    RENEWAL_VERIFY_EARLY_CHECK_HOURS,
    RENEWAL_VERIFY_EARLY_DAYS,
    RENEWAL_VERIFY_EXPIRED_CHECK_MINUTES,
    RENEWAL_VERIFY_MID_CHECK_HOURS,
    RENEWAL_VERIFY_MID_RAISE_HOURS,
    RENEWAL_VERIFY_URGENT_CHECK_HOURS,
    RENEWAL_VERIFY_URGENT_DAYS,
)
from cert_watch.config import Settings
from cert_watch.database import get_write_lock
from cert_watch.database.connection import _connect, begin_immediate


@dataclass(frozen=True)
class VerificationResult:
    state: str
    next_check_at: str | None
    reason: str | None


def _verification_reason(attempt: sqlite3.Row, leaf_fingerprint: str | None) -> str | None:
    """Return the one scan-evidence decision shared by every verification path."""
    if leaf_fingerprint is None:
        return None
    leaf = leaf_fingerprint.lower()
    baseline = (
        str(attempt["baseline_fingerprint"]).lower()
        if attempt["baseline_fingerprint"]
        else None
    )
    expected = (
        str(attempt["new_fingerprint"]).lower() if attempt["new_fingerprint"] else None
    )
    if expected is not None:
        if leaf == expected and (baseline is None or leaf != baseline):
            return "reported_fingerprint"
        return None
    if baseline is not None and leaf != baseline:
        return "observed_successor"
    return None


def observe_failure_successor_on(
    conn: sqlite3.Connection,
    hostname: str,
    port: int,
    leaf_fingerprint: str,
    *,
    observed_at: datetime,
) -> bool:
    """Clear a carried failure when an atomic scan stores a new leaf."""
    attempt = conn.execute(
        """SELECT a.* FROM renewal_attempts a
           JOIN hosts h ON h.id=a.host_id
           WHERE h.hostname=? AND h.port=? AND a.is_current=1
             AND a.failure_reported_at IS NOT NULL
             AND a.failure_cleared_at IS NULL""",
        (hostname, port),
    ).fetchone()
    if attempt is None:
        return False
    leaf = leaf_fingerprint.lower()
    reason = _verification_reason(attempt, leaf)
    if reason is None:
        return False
    instant = observed_at.astimezone(UTC).isoformat()
    origin = str(attempt["failure_attempt_id"] or attempt["attempt_id"])
    conn.execute(
        """UPDATE renewal_attempts
           SET state='verified',suppresses_stalled=0,
               verification_reason=?,next_check_at=NULL,
               closed_reason=?,verified_fingerprint=?,
               failure_cleared_at=COALESCE(failure_cleared_at,?),rule_due_at=?
           WHERE attempt_id=?""",
        (reason, reason, leaf, instant, instant, attempt["attempt_id"]),
    )
    conn.execute(
        """UPDATE renewal_attempts
           SET failure_cleared_at=COALESCE(failure_cleared_at,?),rule_due_at=?
           WHERE host_id=? AND COALESCE(failure_attempt_id,attempt_id)=?""",
        (instant, instant, attempt["host_id"], origin),
    )
    return True


def _instant(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _band(attempt: sqlite3.Row, now: datetime) -> str:
    not_after = _instant(attempt["baseline_not_after"])
    if not_after is None:
        return "urgent"
    remaining = not_after - now
    if remaining.total_seconds() < 0:
        return "expired"
    if remaining >= timedelta(days=RENEWAL_VERIFY_EARLY_DAYS):
        return "early"
    if remaining >= timedelta(days=RENEWAL_VERIFY_URGENT_DAYS):
        return "mid"
    return "urgent"


def _grace_at(attempt: sqlite3.Row, settings: Settings) -> datetime:
    succeeded = _instant(attempt["success_received_at"]) or _instant(
        attempt["received_at"]
    )
    assert succeeded is not None
    return succeeded + timedelta(minutes=settings.renewal_verify_grace_minutes)


def _success_at(attempt: sqlite3.Row) -> datetime:
    succeeded = _instant(attempt["success_received_at"]) or _instant(
        attempt["received_at"]
    )
    assert succeeded is not None
    return succeeded


def _following_check(
    attempt: sqlite3.Row, now: datetime, settings: Settings
) -> datetime:
    band = _band(attempt, now)
    grace = _grace_at(attempt, settings)
    if now < grace and band in {"urgent", "expired"}:
        return grace
    if band == "early":
        deadline = _success_at(attempt) + timedelta(hours=RENEWAL_VERIFY_EARLY_CHECK_HOURS)
        if now < deadline:
            return deadline
        return now + timedelta(hours=RENEWAL_VERIFY_EARLY_CHECK_HOURS)
    if band == "mid":
        return now + timedelta(hours=RENEWAL_VERIFY_MID_CHECK_HOURS)
    if band == "expired":
        return now + timedelta(minutes=RENEWAL_VERIFY_EXPIRED_CHECK_MINUTES)
    # Unknown expiry follows a stable hourly grid rooted at the grace anchor.
    if _instant(attempt["baseline_not_after"]) is None:
        elapsed = max(timedelta(), now - grace)
        periods = int(elapsed / timedelta(hours=RENEWAL_VERIFY_URGENT_CHECK_HOURS)) + 1
        return grace + periods * timedelta(hours=RENEWAL_VERIFY_URGENT_CHECK_HOURS)
    return now + timedelta(hours=RENEWAL_VERIFY_URGENT_CHECK_HOURS)


def _qualifies(attempt: sqlite3.Row, started_at: datetime, settings: Settings) -> bool:
    return started_at >= _grace_at(attempt, settings)


def _raise_due(attempt: sqlite3.Row, started_at: datetime, settings: Settings) -> bool:
    if not _qualifies(attempt, started_at, settings):
        return False
    band = _band(attempt, started_at)
    if band == "early":
        return started_at >= _success_at(attempt) + timedelta(
            hours=RENEWAL_VERIFY_EARLY_CHECK_HOURS
        )
    if band == "mid":
        return started_at >= _success_at(attempt) + timedelta(
            hours=RENEWAL_VERIFY_MID_RAISE_HOURS
        )
    return True


def evaluate_evidence_on(
    conn: sqlite3.Connection,
    attempt: sqlite3.Row,
    leaf_fingerprint: str | None,
    *,
    started_at: datetime,
    settings: Settings,
    count_check: bool,
) -> VerificationResult:
    """Apply one successful stored observation using the caller's transaction."""
    state = str(attempt["state"])
    failure_open = bool(
        attempt["failure_reported_at"] and not attempt["failure_cleared_at"]
    )
    if state not in {"open", "verifying", "not_deployed"} and not failure_open:
        return VerificationResult(state, attempt["next_check_at"], attempt["verification_reason"])
    leaf = leaf_fingerprint.lower() if leaf_fingerprint else None
    baseline = (
        str(attempt["baseline_fingerprint"]).lower()
        if attempt["baseline_fingerprint"]
        else None
    )
    expected = (
        str(attempt["new_fingerprint"]).lower() if attempt["new_fingerprint"] else None
    )
    last_check = _instant(attempt["last_check_at"])
    spaced_check = count_check and (
        last_check is None or started_at >= last_check + timedelta(minutes=5)
    )
    updates: dict[str, Any] = {"verification_blocked_at": None}
    if spaced_check:
        updates["checks_done"] = int(attempt["checks_done"] or 0) + 1
        updates["last_check_at"] = started_at.isoformat()
        if _qualifies(attempt, started_at, settings) and not attempt["first_qualifying_check_at"]:
            updates["first_qualifying_check_at"] = started_at.isoformat()

    reason: str | None = None
    next_check: datetime | None = None
    verification_reason = _verification_reason(attempt, leaf)
    if verification_reason is not None:
        state, reason = "verified", verification_reason
    elif failure_open and state not in {"open", "verifying", "not_deployed"}:
        # Failure-only states have no verification scan cadence.  An ordinary
        # stored scan may still prove the successor and close the condition,
        # but a baseline observation never changes their state.
        return VerificationResult(state, attempt["next_check_at"], None)
    elif not count_check:
        # Acceptance may recognize successor evidence already stored by a
        # completed scan, but it never turns an old observation into a raise
        # or displaces the one immediate post-report check.
        return VerificationResult(state, attempt["next_check_at"], None)
    elif (
        leaf is not None
        and expected is not None
        and leaf != expected
        and leaf != baseline
    ):
        if spaced_check and _raise_due(attempt, started_at, settings):
            state, reason = "not_deployed", "mismatch"
            # With no baseline, the first deadline decides the claim. Further
            # scans return to the endpoint's ordinary cadence.
            next_check = (
                None if baseline is None else _following_check(attempt, started_at, settings)
            )
        else:
            # Once raised, only observed successor evidence can close the
            # condition. Reports and non-qualifying checks cannot demote it.
            state = "not_deployed" if state == "not_deployed" else "verifying"
            if state == "not_deployed":
                reason = str(attempt["verification_reason"] or "") or None
            next_check = _following_check(attempt, started_at, settings)
            if not spaced_check and last_check is not None:
                next_check = max(next_check, last_check + timedelta(minutes=5))
    elif state == "open":
        # An open attempt changes only when the scan proves a successor.
        return VerificationResult(state, attempt["next_check_at"], None)
    elif spaced_check and leaf == baseline and _raise_due(attempt, started_at, settings):
        state, reason = "not_deployed", "baseline_still_served"
        next_check = _following_check(attempt, started_at, settings)
    elif not spaced_check:
        existing_next = _instant(attempt["next_check_at"])
        spacing_floor = last_check + timedelta(minutes=5) if last_check else started_at
        next_check = max(existing_next or spacing_floor, spacing_floor)
        reason = str(attempt["verification_reason"] or "") or None
    else:
        next_check = _following_check(attempt, started_at, settings)
        reason = str(attempt["verification_reason"] or "") or None

    updates.update(
        state=state,
        suppresses_stalled=0,
        verification_reason=reason,
        next_check_at=next_check.isoformat() if next_check else None,
    )
    if state == "verified":
        updates["closed_reason"] = reason
        updates["verified_fingerprint"] = leaf
        if failure_open:
            updates["failure_cleared_at"] = started_at.isoformat()
            updates["rule_due_at"] = started_at.isoformat()
    elif state == "not_deployed" and not attempt["raised_at"]:
        updates["raised_at"] = started_at.isoformat()
    assignments = ",".join(f"{name}=?" for name in updates)
    conn.execute(
        f"UPDATE renewal_attempts SET {assignments} WHERE attempt_id=?",
        (*updates.values(), attempt["attempt_id"]),
    )
    if state == "verified" and failure_open:
        failure_attempt_id = str(
            attempt["failure_attempt_id"] or attempt["attempt_id"]
        )
        conn.execute(
            """UPDATE renewal_attempts
               SET failure_cleared_at=COALESCE(failure_cleared_at,?),rule_due_at=?
               WHERE host_id=?
                 AND COALESCE(failure_attempt_id,attempt_id)=?""",
            (
                started_at.isoformat(),
                started_at.isoformat(),
                attempt["host_id"],
                failure_attempt_id,
            ),
        )
    return VerificationResult(
        state, next_check.isoformat() if next_check else None, reason
    )


def evaluate_after_scan(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf_fingerprint: str,
    *,
    started_at: datetime,
    settings: Settings,
) -> VerificationResult | None:
    """Evaluate a successfully stored scan in its own short transaction."""
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            attempt = conn.execute(
                """SELECT a.* FROM renewal_attempts a
                   JOIN hosts h ON h.id=a.host_id
                   WHERE h.hostname=? AND h.port=? AND a.is_current=1""",
                (hostname, port),
            ).fetchone()
            if attempt is None:
                conn.rollback()
                return None
            result = evaluate_evidence_on(
                conn,
                attempt,
                leaf_fingerprint,
                started_at=started_at.astimezone(UTC),
                settings=settings,
                count_check=True,
            )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise


def mark_verification_blocked(
    db_path: str | Path,
    hostname: str,
    port: int,
    *,
    started_at: datetime,
    settings: Settings,
) -> None:
    """Record missing evidence without treating a failed scan/store as a check."""
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            attempt = conn.execute(
                """SELECT a.* FROM renewal_attempts a
                   JOIN hosts h ON h.id=a.host_id
                   WHERE h.hostname=? AND h.port=? AND a.is_current=1
                     AND a.state IN ('verifying','not_deployed')""",
                (hostname, port),
            ).fetchone()
            if attempt is not None:
                next_check = _following_check(attempt, started_at.astimezone(UTC), settings)
                conn.execute(
                    """UPDATE renewal_attempts
                       SET verification_blocked_at=?,next_check_at=?
                       WHERE attempt_id=?""",
                    (started_at.astimezone(UTC).isoformat(), next_check.isoformat(),
                     attempt["attempt_id"]),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def mark_verification_evaluation_error(
    db_path: str | Path,
    hostname: str,
    port: int,
    *,
    started_at: datetime,
    settings: Settings,
) -> None:
    """Back off a stored-scan evaluation error without treating it as evidence."""
    failed_at = started_at.astimezone(UTC)
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            attempt = conn.execute(
                """SELECT a.* FROM renewal_attempts a
                   JOIN hosts h ON h.id=a.host_id
                   WHERE h.hostname=? AND h.port=? AND a.is_current=1
                     AND a.state IN ('verifying','not_deployed')""",
                (hostname, port),
            ).fetchone()
            if attempt is not None:
                band_delay = _following_check(attempt, failed_at, settings) - failed_at
                floor = timedelta(minutes=5)
                cap = max(floor, band_delay)
                prior_failed = _instant(attempt["verification_blocked_at"])
                prior_next = _instant(attempt["next_check_at"])
                delay = floor
                if prior_failed is not None and prior_next is not None:
                    prior_delay = max(floor, prior_next - prior_failed)
                    delay = min(cap, prior_delay * 2)
                next_check = failed_at + min(delay, cap)
                conn.execute(
                    """UPDATE renewal_attempts
                       SET verification_blocked_at=?,next_check_at=?
                       WHERE attempt_id=?""",
                    (failed_at.isoformat(), next_check.isoformat(), attempt["attempt_id"]),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
