"""Endpoint scan evidence and the cadence policy shared with the scheduler."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database.connection import _connect
from cert_watch.database.dashboard_helpers import _add_effective_tag_filter


def cadence_due_at(last_success: datetime, interval_hours: int | None,
                   hour: int, minute: int) -> datetime:
    """Next successful observation due after this success, ignoring retry backoff."""
    if interval_hours is not None and interval_hours > 0:
        return last_success + timedelta(hours=interval_hours)
    boundary = last_success.replace(hour=hour, minute=minute, second=0, microsecond=0)
    return boundary + timedelta(days=1) if boundary <= last_success else boundary


def _timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return None


@dataclass(frozen=True)
class ScanEvidence:
    host_id: str
    last_success: datetime | None
    last_attempt: datetime | None
    attempt_status: str | None
    due_at: datetime | None
    next_attempt_at: datetime | None
    state: str

    @property
    def label(self) -> str:
        return {"current": "Current scan", "overdue": "Scan overdue",
                "unobserved": "No successful scan", "failed": "Latest scan incomplete",
                "unknown": "Scan timing unknown"}[self.state]


def load_scan_evidence(
    db_path: str | Path, *, hour: int = 6, minute: int = 0,
    now: datetime | None = None, scope_tags: list[str] | tuple[str, ...] | None = None,
    host_id: str | None = None,
) -> dict[str, ScanEvidence]:
    """Read registered endpoints once; uploads cannot establish scan freshness.

    Visibility follows Home/Browse's effective host/scanned-certificate tags.
    Failed/partial attempts never move the cadence deadline or count as current.
    """
    from cert_watch.scheduler import FAST_RETRY_INTERVAL

    now = now or datetime.now(UTC)
    sql = """
        SELECT DISTINCT h.id, h.scan_interval_hours,
            (SELECT MAX(scanned_at) FROM scan_history s
             WHERE s.hostname = h.hostname AND s.port = h.port
               AND s.status = 'success') AS last_success,
            (SELECT scanned_at FROM scan_history s
             WHERE s.hostname = h.hostname AND s.port = h.port
             ORDER BY scanned_at DESC, id DESC LIMIT 1) AS last_attempt,
            (SELECT status FROM scan_history s
             WHERE s.hostname = h.hostname AND s.port = h.port
             ORDER BY scanned_at DESC, id DESC LIMIT 1) AS attempt_status
        FROM hosts h LEFT JOIN certificates c
          ON c.hostname = h.hostname AND c.port = h.port
          AND c.is_leaf = 1 AND c.source = 'scanned'
        WHERE 1 = 1
    """
    sql, params = _add_effective_tag_filter(sql, [], scope_tags or ())
    if host_id is not None:
        sql += " AND h.id = ?"
        params.append(host_id)
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    result = {}
    for row in rows:
        last = _timestamp(row["last_success"])
        attempt = _timestamp(row["last_attempt"])
        due = retry = None
        invalid = (bool(row["last_success"]) and last is None
                   or bool(row["last_attempt"]) and attempt is None
                   or last is not None and last > now
                   or attempt is not None and attempt > now)
        try:
            due = (cadence_due_at(last, row["scan_interval_hours"], hour, minute)
                   if last else None)
            retry = due
            if attempt is not None and (last is None or attempt > last):
                retry = max(due or attempt, attempt + timedelta(seconds=FAST_RETRY_INTERVAL))
        except (OverflowError, TypeError, ValueError):
            invalid = True
        if invalid:
            state = "unknown"
            due = retry = None
        elif last is None:
            state = "unobserved"
        elif due is not None and due <= now:
            state = "overdue"
        elif row["attempt_status"] != "success":
            state = "failed"
        else:
            state = "current"
        result[row["id"]] = ScanEvidence(row["id"], last, attempt, row["attempt_status"],
                                         due, retry, state)
    return result


def summarize_scan_evidence(evidence: dict[str, ScanEvidence]) -> dict[str, int]:
    counts = dict.fromkeys(("current", "overdue", "unobserved", "failed", "unknown"), 0)
    for item in evidence.values():
        counts[item.state] += 1
    return {"total": len(evidence), **counts}
