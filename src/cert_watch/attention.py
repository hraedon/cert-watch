"""Attention queue — the home page's data assembly (redesign/attention-home).

First-principles IA: the landing page answers "what needs a human, and when?",
not "show me an inventory table". Each work item is one concrete problem on
one endpoint, ranked by severity and time-to-impact. The configured renewal
method breaks ties between otherwise equally urgent items; it does not prove
that automation is working.

Renewal confidence comes from the per-host renewal method
(``acme``/``cert-manager`` ⇒ automated, ``manual`` ⇒ manual, unset ⇒
unknown). Renewal-stall detection shares the alert pipeline's current
certificate/host predicate. Sending a notification does not resolve the
underlying condition.

Scope tags (RBAC) are honored by assembling only scoped grouped-page entries.
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
    return {
        "auto": "automation configured",
        "manual": "manual renewal",
        "unknown": "renewal unknown",
    }[conf]


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
    window_days: int = 30,
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
    from cert_watch.alerts import renewal_window_candidates
    from cert_watch.database import list_dashboard_grouped_page

    entries, _total = list_dashboard_grouped_page(db_path, per_page=100_000, scope_tags=scope_tags)
    stalled_ids = {candidate["id"] for candidate in renewal_window_candidates(db_path, window_days)}

    items: list[dict[str, Any]] = []
    for grouped_entry in entries:
        deployments = _entry_hosts(grouped_entry) or [grouped_entry]
        for e in deployments:
            kind = e.get("kind") or grouped_entry.get("kind")
            days = e.get("days_remaining")
            failing = e.get("scan_status") == "failure"
            conf = renewal_confidence(e.get("renewal_method") or "")
            cert_id = e.get("id")
            host = e.get("host") or ""
            endpoint = (
                host
                if e.get("host_id") and host
                else e.get("name") or grouped_entry.get("name") or host or "—"
            )
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

            if kind == "pending" or e.get("source") == "scanned" and days is None:
                if failing:
                    err = e.get("scan_error") or "no certificate retrieved"
                    items.append(
                        {
                            **base,
                            "severity": "failing",
                            "kind": "scan_failing",
                            "reasons": [f"scan failing: {err}"],
                        }
                    )
                else:
                    items.append(
                        {
                            **base,
                            "severity": "info",
                            "kind": "never_scanned",
                            "reasons": ["added but never successfully scanned"],
                        }
                    )
                continue

            reasons: list[str] = []
            severity: str | None = None
            item_kind = "expiry"
            if days is not None:
                if days < 0:
                    severity, item_kind = "expired", "expired"
                    reasons.append(f"expired {-days} day{'s' if -days != 1 else ''} ago")
                elif cert_id in stalled_ids:
                    severity, item_kind = "stalled", "renewal_stalled"
                    reasons.append("inside its renewal window with no successor cert yet")
                elif days < 7:
                    severity = "critical"
                    reasons.append(f"expires in {days} day{'s' if days != 1 else ''}")
                elif days < 30:
                    severity = "warning"
                    reasons.append(f"expires in {days} days")
            chain_status = str(e.get("chain_status") or "")
            trust_issue = {
                "invalid": ("chain_invalid", "chain validation failed"),
                "incomplete": ("chain_incomplete", "chain incomplete"),
                "unknown": ("chain_unknown", "issuer certificate is not available"),
                "self-signed": ("chain_self_signed", "certificate is self-signed and untrusted"),
            }.get(chain_status)
            if trust_issue:
                trust_kind, trust_reason = trust_issue
                reasons.append(trust_reason)
                if severity is None:
                    severity, item_kind = "warning", trust_kind

            if severity is not None:
                if item_kind in {"expiry", "expired", "renewal_stalled"}:
                    reasons.append(confidence_label)
                items.append({**base, "severity": severity, "kind": item_kind, "reasons": reasons})

            if failing and days is not None:
                items.append(
                    {
                        **base,
                        "severity": "failing",
                        "kind": "scan_failing",
                        "reasons": [
                            f"scan failing: {e.get('scan_error') or 'no certificate retrieved'}",
                            "inventory data on this row may be stale",
                        ],
                    }
                )

    def _key(item: dict[str, Any]) -> tuple[int, int, int, str]:
        conf_boost = 0 if item["confidence"] != "auto" else 1
        return (
            _SEV_RANK[item["severity"]],
            item["days_remaining"] if item["days_remaining"] is not None else 9999,
            conf_boost,
            item["endpoint"],
        )

    return sorted(items, key=_key)
