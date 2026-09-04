"""Attention queue — the home page's data assembly (redesign/attention-home).

First-principles IA: the landing page answers "what needs a human, and when?",
not "show me an inventory table". Each work item is one concrete problem on
one endpoint, ranked by time-to-impact, with renewal confidence adjusting the
rank: an expiring cert with working automation outranks nothing, while the
same cert with manual/unknown renewal is a genuine to-do.

Renewal confidence comes from the per-host renewal method
(``acme``/``cert-manager`` ⇒ automated, ``manual`` ⇒ manual, unset ⇒
unknown). Renewal-stall detection reuses the alert pipeline's own signal
(pending ``renewal_stalled`` alerts) so the queue cannot disagree with what
alerting would fire.

Scope tags (RBAC) are honored by feeding scoped grouped-page entries and the
scoped pending-alert list into assembly.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

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
    return {"auto": "auto-renews", "manual": "manual renewal", "unknown": "renewal unknown"}[conf]


def _entry_hosts(entry: dict[str, Any]) -> list[dict[str, Any]]:
    """Per-host sub-rows for an entry (grouped entries carry them; plain
    scanned/pending entries represent exactly one host)."""
    hosts = entry.get("hosts") or []
    if hosts:
        return hosts
    if entry.get("host_id"):
        return [entry]
    return []


def build_attention_queue(
    db_path: str | Path,
    *,
    scope_tags: list[str] | tuple[str, ...] | None = None,
) -> list[dict[str, Any]]:
    """Assemble the ranked attention queue over the whole (scoped) estate.

    Each item: ``severity``, ``kind``, ``cert_id``/``detail_url``, ``endpoint``
    (display name), ``host``, ``host_id``, ``days_remaining``, ``reasons``
    (human-readable evidence), ``owner_name``, ``confidence``
    (auto/manual/unknown), ``host_count`` (grouped deployments).

    Sorted by (severity rank, days remaining, endpoint name). A warning-tier
    expiry with automated renewal sorts after the same item with manual or
    unknown renewal.
    """
    from cert_watch.database import list_dashboard_grouped_page
    from cert_watch.database.repo import SqliteAlertRepository

    entries, _total = list_dashboard_grouped_page(
        db_path, per_page=100_000, scope_tags=scope_tags
    )
    stalled_ids = {
        a.cert_id
        for a in SqliteAlertRepository(db_path).list_pending_scoped(scope_tags or [])
        if a.alert_type == "renewal_stalled"
    }

    items: list[dict[str, Any]] = []
    for e in entries:
        kind = e.get("kind")
        days = e.get("days_remaining")
        hosts = _entry_hosts(e)
        failing = [h for h in hosts if h.get("scan_status") == "failure"]
        conf = renewal_confidence(e.get("renewal_method") or "")
        base = {
            "cert_id": e.get("id"),
            "detail_url": f"/certificates/{e['id']}" if e.get("id") else None,
            "endpoint": e.get("name") or e.get("host") or "—",
            "host": e.get("host") or "",
            "host_id": e.get("host_id"),
            "days_remaining": days,
            "owner_name": e.get("owner_name") or "",
            "confidence": conf,
            "confidence_label": _conf_label(conf),
            "host_count": e.get("host_count") or 1,
        }

        if kind == "pending" or e.get("source") == "scanned" and days is None:
            if failing:
                err = failing[0].get("scan_error") or "no certificate retrieved"
                items.append({
                    **base, "severity": "failing", "kind": "scan_failing",
                    "reasons": [f"scan failing: {err}"],
                })
            else:
                items.append({
                    **base, "severity": "info", "kind": "never_scanned",
                    "reasons": ["added but never successfully scanned"],
                })
            continue

        reasons: list[str] = []
        severity: str | None = None
        item_kind = "expiry"
        if days is not None:
            if days < 0:
                severity, item_kind = "expired", "expired"
                reasons.append(f"expired {-days} day{'s' if -days != 1 else ''} ago")
            elif e.get("id") in stalled_ids:
                severity, item_kind = "stalled", "renewal_stalled"
                reasons.append("inside its renewal window with no successor cert yet")
            elif days < 7:
                severity = "critical"
                reasons.append(f"expires in {days} day{'s' if days != 1 else ''}")
            elif days < 30:
                severity = "warning"
                reasons.append(f"expires in {days} days")
        chain_status = e.get("chain_status")
        if chain_status == "invalid":
            reasons.append("chain validation failed")
            severity = severity or "warning"
        elif chain_status == "incomplete":
            reasons.append("chain incomplete")
            severity = severity or "warning"

        if severity is not None:
            reasons.append(_conf_label(conf))
            items.append({**base, "severity": severity, "kind": item_kind, "reasons": reasons})

        if failing and days is not None:
            items.append({
                **base, "severity": "failing", "kind": "scan_failing",
                "reasons": [
                    f"scan failing on {failing[0].get('host') or 'a host'}: "
                    f"{failing[0].get('scan_error') or 'no certificate retrieved'}",
                    "inventory data on this row may be stale",
                ],
            })

    def _key(item: dict[str, Any]) -> tuple[int, int, int, str]:
        conf_boost = 0 if item["confidence"] != "auto" else 1
        return (
            _SEV_RANK[item["severity"]],
            item["days_remaining"] if item["days_remaining"] is not None else 9999,
            conf_boost,
            item["endpoint"],
        )

    return sorted(items, key=_key)
