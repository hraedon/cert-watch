"""Scheduled Certificate Transparency monitoring.

Compares CT log entries against known certificates and alerts on
unauthorized issuance. See spec FEAT-007.

Phase 3 adds CT reconciliation: inventory gap analysis that compares
CT log hostnames against tracked hosts to surface coverage gaps.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from cert_watch.ct_lookup import query_ct_log
from cert_watch.database import _connect, init_schema

logger = logging.getLogger("cert_watch.ct_monitor")

# Short-TTL cache for CT reconciliation results (BC-029 H)
_CT_RECON_CACHE: dict[str, tuple[float, ReconciliationResult]] = {}
_CT_RECON_CACHE_TTL = 300  # 5 minutes


@dataclass
class ReconciliationResult:
    domain: str
    tracked_hostnames: list[str] = field(default_factory=list)
    ct_hostnames: list[str] = field(default_factory=list)
    ct_only_hostnames: list[str] = field(default_factory=list)
    tracked_only_hostnames: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0
    error: str = ""


def ct_reconciliation(db_path: str | Path, domain: str) -> ReconciliationResult:
    """Compare CT log entries against tracked certificates for a domain.

    Returns a ReconciliationResult showing:
    - tracked_hostnames: hostnames we're actively scanning
    - ct_hostnames: hostnames found in CT logs
    - ct_only_hostnames: hostnames in CT but not tracked (gaps)
    - tracked_only_hostnames: hostnames tracked but not in CT (may be stale)
    - coverage_pct: percentage of CT hostnames that are tracked
    """
    cache_key = f"{db_path}:{domain}"
    now = time.monotonic()
    cached = _CT_RECON_CACHE.get(cache_key)
    if cached and (now - cached[0]) < _CT_RECON_CACHE_TTL:
        return cached[1]

    init_schema(db_path)
    with _connect(db_path) as conn:
        tracked = {
            r["hostname"]
            for r in conn.execute(
                "SELECT DISTINCT hostname FROM hosts WHERE hostname IS NOT NULL"
            ).fetchall()
        }

    tracked_hostnames = sorted(
        h for h in tracked if h == domain or h.endswith("." + domain)
    )

    result = query_ct_log(domain)
    if isinstance(result, str):
        recon = ReconciliationResult(
            domain=domain,
            tracked_hostnames=tracked_hostnames,
            error=result,
        )
        _CT_RECON_CACHE[cache_key] = (now, recon)
        return recon

    ct_hostnames: set[str] = set()
    for entry in result:
        ct_hostnames.add(entry.common_name)
        for name in entry.name_value.split("\n"):
            name = name.strip()
            if name:
                ct_hostnames.add(name)

    ct_hostnames_filtered = sorted(
        h for h in ct_hostnames
        if h == domain or h.endswith("." + domain)
    )

    tracked_set = set(tracked_hostnames)
    ct_set = set(ct_hostnames_filtered)
    ct_only = sorted(ct_set - tracked_set)
    tracked_only = sorted(tracked_set - ct_set)

    total_ct = len(ct_set)
    covered = len(ct_set & tracked_set)
    coverage = (covered / total_ct * 100) if total_ct > 0 else 100.0

    recon = ReconciliationResult(
        domain=domain,
        tracked_hostnames=tracked_hostnames,
        ct_hostnames=ct_hostnames_filtered,
        ct_only_hostnames=ct_only,
        tracked_only_hostnames=tracked_only,
        coverage_pct=round(coverage, 1),
    )
    _CT_RECON_CACHE[cache_key] = (now, recon)
    return recon


def run_ct_monitor(db_path: str | Path) -> dict[str, int]:
    """Query CT logs for all tracked host domains and report new findings.

    Returns {"checked": N, "new": M, "errors": E}.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT hostname FROM hosts WHERE hostname IS NOT NULL"
        ).fetchall()

    checked = 0
    new = 0
    errors = 0
    known_serial_issuer: set[tuple[str, str]] = set()
    for row in rows:
        hostname = row["hostname"]
        checked += 1
        result = query_ct_log(hostname)
        if isinstance(result, str):
            logger.warning("CT monitor error for %s: %s", hostname, result)
            errors += 1
            continue
        for entry in result:
            dedup_key = (entry.serial_number, entry.issuer_name)
            if dedup_key not in known_serial_issuer:
                known_serial_issuer.add(dedup_key)
                new += 1
                logger.info(
                    "CT monitor: new certificate found for %s — CN=%s issuer=%s serial=%s",
                    hostname, entry.common_name, entry.issuer_name, entry.serial_number,
                )
    if new > 0:
        logger.info(
            "CT monitor complete: %d checked, %d new certificates, %d errors",
            checked, new, errors,
        )
    return {"checked": checked, "new": new, "errors": errors}
