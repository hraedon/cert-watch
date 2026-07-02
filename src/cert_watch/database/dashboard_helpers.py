"""Shared constants and helper functions for dashboard queries."""
from __future__ import annotations

from typing import Any

_URGENCY_ORDER = ("expired", "critical", "warning", "healthy", "gray")

_SORT_COLUMNS_BARE = frozenset({
    "subject", "not_before", "not_after", "created_at",
})

_SORT_COLUMNS_ALIAS = frozenset({
    "sort_name", "sort_issue", "sort_scan", "sort_expiry",
})

_SORT_COLUMNS_GROUPED = frozenset({
    "LOWER(COALESCE(c.subject, c.hostname || ':' || c.port))",
    "c.not_before",
    "COALESCE(last_scan_at, '0000-01-01T00:00:00')",
    "c.not_after",
})

_SQL_DIRS = frozenset({"ASC", "DESC"})


def _add_effective_tag_filter(
    sql: str,
    params: list[Any],
    scope_tags: list[str] | tuple[str, ...],
    col_cert: str | None = "c.tags",
    col_host: str = "h.tags",
) -> tuple[str, list[Any]]:
    """Append effective-tag (cert ∪ host) filter clauses to *sql*.

    For each scope tag, adds LIKE conditions on the cert and/or host tag
    columns. Passing *col_cert=None* omits the cert-tag condition (e.g. for
    pending hosts that have no certificate row yet). Tags that are empty or
    whitespace are ignored.  LIKE wildcards in tags are escaped (BC-051).
    """
    if not scope_tags:
        return sql, params
    conditions: list[str] = []
    new_params: list[Any] = []
    seen: set[str] = set()
    for tag in scope_tags:
        tag = tag.strip()
        if not tag or tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        like = f"%,{_escape_like(tag)},%"
        if col_cert:
            conditions.append(
                f"cw_casefold(',' || COALESCE({col_cert}, '') || ',')"
                " LIKE cw_casefold(?) ESCAPE '\\'"
            )
            new_params.append(like)
        conditions.append(
            f"cw_casefold(',' || COALESCE({col_host}, '') || ',')"
            " LIKE cw_casefold(?) ESCAPE '\\'"
        )
        new_params.append(like)
    if not conditions:
        return sql, params
    return f"{sql} AND ({' OR '.join(conditions)})", params + new_params


def _add_grouped_effective_tag_filter(
    sql: str,
    params: list[Any],
    scope_tags: list[str] | tuple[str, ...],
) -> tuple[str, list[Any]]:
    """Append effective-tag filter for grouped fingerprint rows (WI-051).

    A fingerprint group is kept when at least one of its scanned leaf certs
    has a matching cert tag or its host has a matching host tag.  LIKE
    wildcards in tags are escaped (BC-051).
    """
    if not scope_tags:
        return sql, params
    conditions: list[str] = []
    new_params: list[Any] = []
    seen: set[str] = set()
    for tag in scope_tags:
        tag = tag.strip()
        if not tag or tag.casefold() in seen:
            continue
        seen.add(tag.casefold())
        like = f"%,{_escape_like(tag)},%"
        conditions.append(
            "EXISTS ("
            "SELECT 1 FROM certificates c2 "
            "LEFT JOIN hosts h ON h.hostname = c2.hostname AND h.port = c2.port "
            "WHERE c2.fingerprint_sha256 = c.fingerprint_sha256 "
            "AND c2.is_leaf = 1 AND c2.source = 'scanned' "
            "AND (cw_casefold(',' || COALESCE(c2.tags, '') || ',') LIKE cw_casefold(?) ESCAPE '\\' "
            "OR cw_casefold(',' || COALESCE(h.tags, '') || ',') LIKE cw_casefold(?) ESCAPE '\\'))"
        )
        new_params.extend([like, like])
    if not conditions:
        return sql, params
    return f"{sql} AND ({' OR '.join(conditions)})", params + new_params


def _safe_col(col: str, allowed: frozenset[str]) -> str:
    if col not in allowed:
        raise ValueError(f"Invalid sort column: {col!r}")
    return col


def _safe_dir(direction: str) -> str:
    if direction not in _SQL_DIRS:
        raise ValueError(f"Invalid sort direction: {direction!r}")
    return direction


def _escape_like(s: str) -> str:
    """Escape ``%``, ``_`` and ``\\`` so they are treated as literals in a LIKE pattern."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _clamp_page(page: int, total: int, per_page: int) -> int:
    """Clamp a 1-based page index into the valid range for ``total`` rows."""
    if per_page <= 0:
        return 1
    total_pages = max((total + per_page - 1) // per_page, 1)
    return max(1, min(page, total_pages))


def _reorder_by_candidates(
    entries: list[dict[str, Any]], ordered: list[Any],
) -> list[dict[str, Any]]:
    """Reorder built entries to match the SQL candidate ordering by id."""
    by_id: dict[str, dict[str, Any]] = {e["id"]: e for e in entries}
    result: list[dict[str, Any]] = []
    for r in ordered:
        e = by_id.get(r["ekey"])
        if e is not None:
            result.append(e)
    return result


def _matches_q(e: dict[str, Any], ql: str) -> bool:
    """Python text match used by the dashboard filter (case-insensitive)."""
    fields = [e.get("name"), e.get("subject"), e.get("issuer"), e.get("host"),
              e.get("tags")]
    if e.get("kind") == "grouped":
        for h in e.get("hosts", []):
            fields.extend([h.get("host"), h.get("name")])
    return any(ql in (f or "").lower() for f in fields)


def _filter_unified(
    entries: list[dict[str, Any]],
    *,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
) -> list[dict[str, Any]]:
    """Apply the dashboard q/urgency/source filters to built unified entries.

    This mirrors the filter semantics used by the dashboard route exactly so
    grouped and ungrouped paths stay identical.
    """
    if q:
        ql = q.lower()
        entries = [e for e in entries if _matches_q(e, ql)]
    if urgency:
        entries = [e for e in entries if e.get("urgency") == urgency]
    if source:
        if source == "scanned":
            entries = [
                e for e in entries
                if e.get("kind") in ("scanned", "pending", "grouped")
            ]
        else:
            entries = [e for e in entries if e.get("source") == source]
    return entries


_UNIFIED_SORT_KEYS = {
    "name": lambda e: (e.get("name") or "").lower(),
    "issue_date": lambda e: e.get("not_before") or "9999-12-31T23:59:59",
    "last_scan": lambda e: e.get("last_scanned_at") or "0000-01-01T00:00:00",
    "expiry": lambda e: e.get("not_after") or "9999-12-31T23:59:59",
    "days": lambda e: (
        e["days_remaining"] if e.get("days_remaining") is not None else 9999
    ),
}


def _sort_unified(
    entries: list[dict[str, Any]], *, sort_by: str = "days", sort_order: str = "asc"
) -> list[dict[str, Any]]:
    """Sort built unified entries with the dashboard's sort semantics."""
    key_fn = _UNIFIED_SORT_KEYS.get(sort_by, _UNIFIED_SORT_KEYS["days"])
    entries.sort(key=key_fn, reverse=(sort_order == "desc"))
    return entries


def _entry_matches_scope_tag(
    entry: dict[str, Any],
    scope_tags: list[str] | tuple[str, ...],
) -> bool:
    """Return True when *entry*'s tags intersect *scope_tags*.

    Used for Python-level filtering of uploaded/pending rows in the grouped
    dashboard path, where the per-row effective tags have already been
    materialised.
    """
    if not scope_tags:
        return True
    entry_tags = entry.get("tags", "")
    entry_set = set(t.strip().casefold() for t in entry_tags.split(",") if t.strip())
    return any(t.strip().casefold() in entry_set for t in scope_tags)
