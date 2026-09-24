"""Attention queue — the home page's data assembly (redesign/attention-home).

First-principles IA: the landing page answers "what needs a human, and when?",
not "show me an inventory table". Each work item is one concrete problem on
one endpoint, ranked by severity and time-to-impact. The configured renewal
method breaks ties between otherwise equally urgent items; it does not prove
that automation is working.

Renewal confidence comes from the per-host renewal method
(``acme``/``cert-manager`` ⇒ automated, ``manual`` ⇒ manual, unset ⇒
unknown). Renewal-stall detection shares the alert pipeline's current
certificate/host predicate and requires a monitored endpoint. Static uploads
receive expiry guidance. Sending a notification does not resolve the underlying
condition on a monitored endpoint.

Scope tags (RBAC) are honored by ranking only the scoped inventory rows.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from cert_watch.scan_freshness import ScanEvidence

_AUTO_METHODS = {"acme", "cert-manager"}

_SEV_RANK = {"expired": 0, "stalled": 1, "critical": 2, "failing": 3, "warning": 4, "info": 5}


def renewal_confidence(renewal_method: str) -> str:
    """Map a host renewal_method to a queue confidence label."""
    if renewal_method in _AUTO_METHODS:
        return "auto"
    if renewal_method == "manual":
        return "manual"
    return "unknown"


def _conf_label(conf: str) -> str:
    return {
        "auto": "automation configured",
        "manual": "manual renewal",
        "unknown": "renewal unknown",
    }[conf]


# Home shows this many items; the panel says how many there are in all.
HOME_QUEUE_LIMIT = 50

_TRUST_ISSUES = {
    "invalid": ("chain_invalid", "chain validation failed"),
    "incomplete": ("chain_incomplete", "chain incomplete"),
    "unknown": ("chain_unknown", "issuer certificate is not available"),
    "self-signed": ("chain_self_signed", "certificate is self-signed and untrusted"),
    "unverified": ("chain_unverified", "chain not verified yet"),
}
_AUTO_SQL = ", ".join(f"'{m}'" for m in sorted(_AUTO_METHODS))
_TRUST_SQL = ", ".join(f"'{s}'" for s in sorted(_TRUST_ISSUES))


def _ranked_sql(inv_sql: str) -> str:
    """Rank inventory rows by their most urgent queue item, in SQL.

    Mirrors :func:`_items_for` exactly: the severity ranks of ``_SEV_RANK``
    from the row's effective days (the one status rule), renewal stall,
    trust issue, failing scan and stale scan evidence. ``best`` is the rank of
    the row's most urgent item (99 when it has none) and ``items`` how many
    items it yields, so the queue can be counted and cut without building a
    row. Binds, after *inv_sql*'s parameters: the stale-evidence host ids
    (a JSON array), then :func:`renewal_window_sql`'s three.
    """
    from cert_watch.alerting.rules.renewal import renewal_window_sql

    r = _SEV_RANK
    return f"""
        WITH inv AS ({inv_sql}),
        a AS (
            SELECT inv.etype, inv.ekey, inv.eff_days, inv.chain_status, inv.host_id,
                   inv.grp_method,
                   COALESCE(inv.hostname || ':' || inv.port,
                            NULLIF(cw_subject_cn(inv.subject), ''), '—') AS endpoint,
                   CASE WHEN inv.host_id IS NOT NULL AND (
                       SELECT s.status FROM scan_history s
                       WHERE s.hostname = inv.hostname AND s.port = inv.port
                       ORDER BY s.scanned_at DESC LIMIT 1) = 'failure'
                   THEN 1 ELSE 0 END AS failing,
                   CASE WHEN inv.host_id IN (SELECT value FROM json_each(?))
                   THEN 1 ELSE 0 END AS stale_evidence,
                   CASE WHEN inv.etype = 'leaf' AND inv.host_id IS NOT NULL AND EXISTS (
                       SELECT 1 FROM certificates sc
                       WHERE sc.id = inv.ekey AND {renewal_window_sql("sc")})
                   THEN 1 ELSE 0 END AS stalled
            FROM inv
        ),
        e AS (
            SELECT a.*,
                   CASE WHEN etype = 'pending' THEN NULL
                        WHEN eff_days < 0 THEN {r["expired"]}
                        WHEN stalled = 1 THEN {r["stalled"]}
                        WHEN eff_days < 7 THEN {r["critical"]}
                        WHEN eff_days < 30 THEN {r["warning"]}
                        WHEN chain_status IN ({_TRUST_SQL}) THEN {r["warning"]}
                   END AS expiry_rank
            FROM a
        ),
        k AS (
            SELECT e.*,
                   CASE WHEN etype = 'pending'
                        THEN CASE WHEN failing = 1 THEN {r["failing"]} ELSE {r["info"]} END
                        ELSE MIN(COALESCE(expiry_rank, 99),
                                 CASE WHEN failing = 1 THEN {r["failing"]} ELSE 99 END,
                                 CASE WHEN stale_evidence = 1 AND failing = 0
                                           AND expiry_rank IS NULL
                                      THEN {r["warning"]} ELSE 99 END)
                   END AS best,
                   CASE WHEN etype = 'pending' THEN 1
                        ELSE (expiry_rank IS NOT NULL) + failing
                             + (stale_evidence = 1 AND failing = 0 AND expiry_rank IS NULL)
                   END AS items
            FROM e
        )
        SELECT * FROM k WHERE best < 99
    """


def _chain_note(entry: dict[str, Any], days: int) -> str:
    """Who expires first: '' for the leaf itself, else the chain certificate."""
    from cert_watch.filters import subject_cn

    if entry.get("days_remaining") is None or days >= entry["days_remaining"]:
        return ""
    first = min(entry.get("chain") or [], key=lambda c: c["days_remaining"], default=None)
    if first is None:
        return ""
    return f"chain certificate {subject_cn(first.get('subject') or '') or 'in the chain'} "


def _items_for(
    e: dict[str, Any], *, stalled: bool, evidence: ScanEvidence | None
) -> list[dict[str, Any]]:
    """The queue items one inventory row yields (see :func:`_ranked_sql`)."""
    kind = e.get("kind")
    days = e.get("effective_days")
    failing = e.get("scan_status") == "failure"
    conf = renewal_confidence(e.get("renewal_method") or "")
    cert_id = e.get("id")
    host = e.get("host") or ""
    endpoint = host if e.get("host_id") and host else e.get("name") or host or "—"
    confidence_label = (
        "upload replacement certificate"
        if not e.get("host_id") and kind != "pending"
        else _conf_label(conf)
    )
    base = {
        "cert_id": cert_id,
        "detail_url": f"/certificates/{cert_id}" if cert_id else None,
        "endpoint": endpoint,
        "host": host,
        "host_id": e.get("host_id"),
        "days_remaining": days,
        "owner_name": e.get("owner_name") or "",
        "confidence": conf,
        "confidence_label": confidence_label,
        "host_count": 1,
    }
    items: list[dict[str, Any]] = []

    if kind == "pending" or days is None:
        if failing:
            err = e.get("scan_error") or "no certificate retrieved"
            items.append({**base, "severity": "failing", "kind": "scan_failing",
                          "reasons": [f"scan failing: {err}"]})
        else:
            items.append({**base, "severity": "info", "kind": "never_scanned",
                          "reasons": ["added but never successfully scanned"]})
        return items

    reasons: list[str] = []
    severity: str | None = None
    item_kind = "expiry"
    who = _chain_note(e, days)
    if days < 0:
        severity, item_kind = "expired", "expired"
        reasons.append(f"{who}expired {-days} day{'s' if -days != 1 else ''} ago")
    elif e.get("host_id") and stalled:
        severity, item_kind = "stalled", "renewal_stalled"
        reasons.append("inside its renewal window with no successor cert yet")
    elif days < 7:
        severity = "critical"
        reasons.append(f"{who}expires in {days} day{'s' if days != 1 else ''}")
    elif days < 30:
        severity = "warning"
        reasons.append(f"{who}expires in {days} days")
    trust_issue = _TRUST_ISSUES.get(str(e.get("chain_status") or ""))
    if trust_issue:
        trust_kind, trust_reason = trust_issue
        reasons.append(trust_reason)
        if severity is None:
            severity, item_kind = "warning", trust_kind

    if severity is not None:
        if item_kind in {"expiry", "expired", "renewal_stalled"}:
            reasons.append(confidence_label)
        items.append({**base, "severity": severity, "kind": item_kind, "reasons": reasons})

    if failing:
        items.append({**base, "severity": "failing", "kind": "scan_failing", "reasons": [
            f"scan failing: {e.get('scan_error') or 'no certificate retrieved'}",
            "inventory data on this row may be stale",
        ]})

    if evidence and evidence.state != "current" and not failing:
        if severity is not None:
            reasons.append(evidence.label)
        else:
            items.append({**base, "severity": "warning", "kind": "scan_evidence",
                          "reasons": [evidence.label,
                                      "scan again to confirm the certificate currently served"]})
    return items


def _item_key(item: dict[str, Any]) -> tuple[int, int, int, str]:
    conf_boost = 0 if item["confidence"] != "auto" else 1
    return (
        _SEV_RANK[item["severity"]],
        item["days_remaining"] if item["days_remaining"] is not None else 9999,
        conf_boost,
        item["endpoint"],
    )


def attention_queue_page(
    db_path: str | Path,
    *,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    window_days: int = 30,
    scan_evidence: dict[str, ScanEvidence] | None = None,
    limit: int | None = HOME_QUEUE_LIMIT,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], int]:
    """The *limit* most urgent attention items, and how many there are in all.

    Each item: ``severity``, ``kind``, ``cert_id``/``detail_url``, ``endpoint``
    (display name), ``host``, ``host_id``, ``days_remaining`` (effective
    days: the soonest expiry in the stored chain, the one status rule),
    ``reasons`` (human-readable evidence), ``owner_name``, ``confidence``
    (auto/manual/unknown), ``host_count``.

    Sorted by (severity rank, days remaining, confidence, endpoint name). A
    warning-tier expiry with automated renewal sorts after the same item with
    manual or unknown renewal.

    The rows are ranked and counted in SQL (:func:`_ranked_sql`) and only the
    rows behind the items shown are built, so Home costs its page, not the
    estate (#113 review: Home rebuilt every certificate to rank the queue).
    ``limit=None`` returns every item.
    """
    import json

    from cert_watch.database.chain_status_cache import prepare_status
    from cert_watch.database.connection import _connect
    from cert_watch.database.dashboard_page import (
        build_inventory_entries,
        inventory_candidates_sql,
    )
    from cert_watch.database.schema import init_schema

    init_schema(db_path)
    status = prepare_status(db_path, now)
    candidates = inventory_candidates_sql(scope_tags=scope_tags, status=status)
    if candidates is None:
        return [], 0
    inv_sql, inv_params = candidates
    evidence = scan_evidence or {}
    stale_hosts = json.dumps(sorted(h for h, ev in evidence.items() if ev.state != "current"))
    ranked = _ranked_sql(inv_sql)
    params = [*inv_params, stale_hosts, window_days, status.sql_now, window_days]
    order = (
        f"ORDER BY best, COALESCE(eff_days, 9999), (grp_method IN ({_AUTO_SQL})), endpoint"
    )
    # One pass: the window total is taken over every ranked row before the
    # LIMIT applies.
    page_sql = (
        f"SELECT etype, ekey, stalled, SUM(items) OVER () AS total_items"
        f" FROM ({ranked}) {order}"
    )
    page_params = list(params)
    if limit is not None:
        # Every item among the first *limit* comes from a row whose most
        # urgent item ranks no lower, so *limit* rows always suffice.
        page_sql += " LIMIT ?"
        page_params.append(limit)
    with _connect(db_path) as conn:
        rows = conn.execute(page_sql, page_params).fetchall()
        entries = build_inventory_entries(conn, rows, now=status.now)
    total = rows[0]["total_items"] if rows else 0
    stalled = {r["ekey"] for r in rows if r["stalled"]}
    items: list[dict[str, Any]] = []
    for entry in entries:
        items += _items_for(
            entry,
            stalled=entry.get("id") in stalled,
            evidence=evidence.get(entry.get("host_id") or ""),
        )
    items.sort(key=_item_key)
    return (items if limit is None else items[:limit]), int(total)


def build_attention_queue(
    db_path: str | Path,
    *,
    scope_tags: list[str] | tuple[str, ...] | None = None,
    window_days: int = 30,
    scan_evidence: dict[str, ScanEvidence] | None = None,
) -> list[dict[str, Any]]:
    """Every attention item, ranked (see :func:`attention_queue_page`)."""
    items, _ = attention_queue_page(
        db_path, scope_tags=scope_tags, window_days=window_days,
        scan_evidence=scan_evidence, limit=None,
    )
    return items
