"""Team dashboard query helpers."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cert_watch.database.connection import _connect, _parse_iso
from cert_watch.filters import compute_urgency_with_chain, subject_cn

_COUNT_SQL = (
    "SELECT COUNT(*) FROM certificates c "
    "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
    "WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?)"
)

_PAGE_SQL = (
    "SELECT c.id, c.subject, c.issuer, c.not_after, "
    "c.hostname, c.port, c.source, "
    "h.owner_email, "
    "(SELECT MIN(julianday(ch.not_after) - julianday('now')) "
    " FROM certificates ch WHERE ch.parent_cert_id = c.id) AS min_chain_days, "
    "(SELECT sp.chain_status FROM scan_posture sp "
    " WHERE sp.cert_id = c.id "
    " ORDER BY sp.scanned_at DESC, sp.id DESC LIMIT 1) AS chain_status "
    "FROM certificates c "
    "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
    "WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?) "
    "ORDER BY c.not_after ASC "
    "LIMIT ? OFFSET ?"
)

_STATS_SQL = (
    "SELECT c.not_after, "
    "(SELECT MIN(julianday(ch.not_after) - julianday('now')) "
    " FROM certificates ch WHERE ch.parent_cert_id = c.id) AS min_chain_days, "
    "(SELECT sp.chain_status FROM scan_posture sp "
    " WHERE sp.cert_id = c.id "
    " ORDER BY sp.scanned_at DESC, sp.id DESC LIMIT 1) AS chain_status "
    "FROM certificates c "
    "LEFT JOIN hosts h ON c.hostname = h.hostname AND c.port = h.port "
    "WHERE c.is_leaf = 1 AND LOWER(h.owner_email) = LOWER(?)"
)


def team_dashboard_data(
    db_path: str | Path,
    owner_email: str,
    *,
    page: int = 1,
    per_page: int = 25,
) -> dict[str, Any]:
    """Return team dashboard data: paginated entries + stats + total count.

    Returns: {
        "entries": list[dict],
        "stats": dict[str, int],
        "total": int,
        "total_pages": int,
        "page": int,
    }
    """
    with _connect(db_path) as conn:
        total_row = conn.execute(_COUNT_SQL, (owner_email,)).fetchone()
        total = total_row[0] if total_row else 0
        total_pages = max((total + per_page - 1) // per_page, 1)
        page = max(1, min(page, total_pages))
        offset = (page - 1) * per_page

        rows = conn.execute(
            _PAGE_SQL, (owner_email, per_page, offset)
        ).fetchall()

        stat_rows = conn.execute(_STATS_SQL, (owner_email,)).fetchall()

    stats = {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}
    for r in stat_rows:
        na = _parse_iso(r["not_after"])
        leaf_days = (na - datetime.now(UTC)).days
        u = compute_urgency_with_chain(leaf_days, r["min_chain_days"], r["chain_status"])
        stats[u] += 1

    entries: list[dict[str, Any]] = []
    for r in rows:
        na = _parse_iso(r["not_after"])
        leaf_days = (na - datetime.now(UTC)).days
        u = compute_urgency_with_chain(leaf_days, r["min_chain_days"], r["chain_status"])
        host = f"{r['hostname']}:{r['port']}" if r["hostname"] else ""
        entries.append({
            "id": r["id"],
            "name": subject_cn(r["subject"]),
            "subject": r["subject"],
            "issuer": r["issuer"],
            "not_after": r["not_after"],
            "days_remaining": leaf_days,
            "urgency": u,
            "host": host,
            "source": r["source"],
        })

    return {
        "entries": entries,
        "stats": stats,
        "total": total,
        "total_pages": total_pages,
        "page": page,
    }
