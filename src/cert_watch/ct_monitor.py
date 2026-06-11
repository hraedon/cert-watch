"""Scheduled Certificate Transparency monitoring.

Compares CT log entries against known certificates and alerts on
unauthorized issuance. See spec FEAT-007.

Phase 3 adds CT reconciliation: inventory gap analysis that compares
CT log hostnames against tracked hosts to surface coverage gaps.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from cert_watch.ct_lookup import query_ct_log
from cert_watch.database import _connect, init_schema
from cert_watch.database.connection import close_connections

logger = logging.getLogger("cert_watch.ct_monitor")

# Short-TTL cache for CT reconciliation results (BC-029 H)
_CT_RECON_CACHE: dict[str, tuple[float, ReconciliationResult]] = {}
_CT_RECON_CACHE_TTL = 300  # 5 minutes
_CT_RECON_CACHE_MAX = 512  # evict oldest entries when exceeded


def _evict_ct_cache(now: float) -> None:
    """Evict stale and overflow entries from _CT_RECON_CACHE."""
    stale_keys = [k for k, (ts, _) in _CT_RECON_CACHE.items() if now - ts > _CT_RECON_CACHE_TTL * 2]
    for k in stale_keys:
        del _CT_RECON_CACHE[k]
    if len(_CT_RECON_CACHE) > _CT_RECON_CACHE_MAX:
        sorted_keys = sorted(_CT_RECON_CACHE, key=lambda k: _CT_RECON_CACHE[k][0])
        for k in sorted_keys[: len(_CT_RECON_CACHE) - _CT_RECON_CACHE_MAX]:
            del _CT_RECON_CACHE[k]


def invalidate_ct_cache() -> None:
    """Clear the CT reconciliation cache.

    Called when expected_issuers or other configuration changes should
    take effect immediately rather than waiting for the 5-min TTL.
    """
    _CT_RECON_CACHE.clear()

# Background-refresh bookkeeping (BC-097): the Discover page must never block on
# live crt.sh calls in the request path, so stale/missing domains are warmed off
# the request thread.
_CT_REFRESH_LOCK = threading.Lock()
_CT_REFRESH_INFLIGHT: set[str] = set()


def peek_reconciliation(
    db_path: str | Path, domain: str
) -> tuple[ReconciliationResult | None, float | None]:
    """Return ``(cached result | None, age_seconds | None)`` doing **no** I/O.

    Used by the Discover page to render from cache without ever calling crt.sh in
    the request path (BC-097). Returns the cached result regardless of TTL so a
    stale-but-usable view renders instantly while a refresh runs in the
    background.
    """
    cached = _CT_RECON_CACHE.get(f"{db_path}:{domain}")
    if cached is None:
        return None, None
    return cached[1], time.monotonic() - cached[0]


def _refresh_worker(db_path: str | Path, domains: list[str]) -> None:
    try:
        for d in domains:
            try:
                ct_reconciliation(db_path, d)  # populates _CT_RECON_CACHE
            except Exception:
                logger.warning("CT reconciliation refresh failed for %s", d, exc_info=True)
            finally:
                with _CT_REFRESH_LOCK:
                    _CT_REFRESH_INFLIGHT.discard(f"{db_path}:{d}")
    finally:
        # WI-024: this thread is short-lived — release its cached connection
        # (and the -wal/-shm handles) instead of stranding it until GC.
        close_connections()


def start_reconciliation_refresh(db_path: str | Path, domains: list[str]) -> bool:
    """Warm the reconciliation cache for stale/missing *domains* off-thread.

    Idempotent: a domain already fresh, or already being refreshed, is skipped.
    Returns ``True`` if any refresh is in flight (so the caller can show a
    "reconciling…" indicator). Never blocks on network I/O.
    """
    now = time.monotonic()
    to_start: list[str] = []
    with _CT_REFRESH_LOCK:
        for d in domains:
            key = f"{db_path}:{d}"
            cached = _CT_RECON_CACHE.get(key)
            fresh = cached is not None and (now - cached[0]) < _CT_RECON_CACHE_TTL
            if fresh or key in _CT_REFRESH_INFLIGHT:
                continue
            _CT_REFRESH_INFLIGHT.add(key)
            to_start.append(d)
        any_inflight = bool(_CT_REFRESH_INFLIGHT)
    if to_start:
        threading.Thread(
            target=_refresh_worker, args=(db_path, to_start), daemon=True
        ).start()
    return any_inflight


@dataclass
class ReconciliationResult:
    domain: str
    tracked_hostnames: list[str] = field(default_factory=list)
    ct_hostnames: list[str] = field(default_factory=list)
    ct_only_hostnames: list[str] = field(default_factory=list)
    tracked_only_hostnames: list[str] = field(default_factory=list)
    coverage_pct: float = 0.0
    error: str = ""
    # BC-151: mis-issued hostnames (CT shows a cert with different issuer/serial)
    misissued: list[dict] = field(default_factory=list)
    # BC-151: first-seen dates for issuers found in CT
    first_seen_by_issuer: dict[str, str] = field(default_factory=dict)


def _get_scanned_issuer(db_path: str | Path, hostname: str) -> str | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT c.issuer FROM certificates c
            WHERE c.hostname = ? AND c.is_leaf = 1 AND c.source = 'scanned'
            ORDER BY c.updated_at DESC LIMIT 1""",
            (hostname,),
        ).fetchone()
    return row["issuer"] if row else None


def _extract_cn(dn: str) -> str:
    """Extract the CN value from an X.509 distinguished name string.

    Handles both slash-separated (``/CN=R3/O=Let's Encrypt``) and
    comma-separated (``CN=R3, O=Let's Encrypt, C=US``) DN formats.
    Returns the full *dn* unchanged if no CN is found.
    """
    if not dn:
        return ""
    # Slash-separated format (OpenSSL default): /CN=.../O=...
    # Detect by leading slash
    if dn.startswith("/"):
        for part in dn.split("/"):
            part = part.strip()
            if part.upper().startswith("CN="):
                return part[3:].strip()
    # Comma-separated format: CN=..., O=..., C=...
    for part in dn.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:].strip()
    return dn


def _get_expected_issuers(db_path: str | Path, hostname: str) -> list[str]:
    """Return the expected-issuer CN allowlist for *hostname*'s host record.

    The allowlist is stored as CSV in the ``hosts.expected_issuers`` column.
    An empty list means no allowlist is configured (fall back to strict match).
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT expected_issuers FROM hosts WHERE hostname = ? LIMIT 1",
            (hostname,),
        ).fetchone()
    if not row:
        return []
    raw = row["expected_issuers"] or ""
    return [i.strip() for i in raw.split(",") if i.strip()]


def _issuer_matches(ct_issuer: str, scanned_issuer: str, expected_issuers: list[str]) -> bool:
    """Return True if *ct_issuer* is an acceptable issuer for this host.

    Acceptance rules (WI-007):
    1. If *expected_issuers* is non-empty, match *ct_issuer* CN against it (case-insensitive).
    2. Otherwise, fall back to strict equality with *scanned_issuer* (case-insensitive).
    """
    if expected_issuers:
        ct_cn = _extract_cn(ct_issuer).strip().lower()
        allowed = {a.strip().lower() for a in expected_issuers}
        return ct_cn in allowed
    # Fallback: compare CNs (not raw DNs) to avoid false-positives when
    # OpenSSL stores slash-separated DNs but CT returns comma-separated.
    return _extract_cn(ct_issuer).strip().lower() == _extract_cn(scanned_issuer).strip().lower()


def _record_ct_issuer_first_seen(db_path: str | Path, issuer_name: str) -> str | None:
    """Record first-seen date for an issuer if not already known."""
    from datetime import UTC, datetime

    from cert_watch.database.connection import _iso

    with _connect(db_path) as conn:
        now_str = _iso(datetime.now(UTC))
        conn.execute(
            "INSERT INTO ct_issuer_first_seen (issuer_name, first_seen_at) "
            "VALUES (?, ?) ON CONFLICT (issuer_name) DO NOTHING",
            (issuer_name, now_str),
        )
        conn.commit()
        row = conn.execute(
            "SELECT first_seen_at FROM ct_issuer_first_seen WHERE issuer_name = ?",
            (issuer_name,),
        ).fetchone()
        return row["first_seen_at"] if row else None


def ct_reconciliation(db_path: str | Path, domain: str) -> ReconciliationResult:
    """Compare CT log entries against tracked certificates for a domain.

    Returns a ReconciliationResult showing:
    - tracked_hostnames: hostnames we're actively scanning
    - ct_hostnames: hostnames found in CT logs
    - ct_only_hostnames: hostnames in CT but not tracked (gaps)
    - tracked_only_hostnames: hostnames tracked but not in CT (may be stale)
    - coverage_pct: percentage of CT hostnames that are tracked
    - misissued: hostnames where CT shows a cert with different issuer/serial
    - first_seen_by_issuer: {issuer_name: first_seen_at} for issuers in CT
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
        _evict_ct_cache(now)
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

    # BC-151: mis-issuance detection + first-seen capture
    misissued: list[dict] = []
    first_seen_by_issuer: dict[str, str] = {}
    ct_issuers_by_host: dict[str, set[str]] = {}
    for entry in result:
        for name in entry.name_value.split("\n"):
            name = name.strip()
            if name and (name == domain or name.endswith("." + domain)):
                ct_issuers_by_host.setdefault(name, set()).add(entry.issuer_name)
        cn = entry.common_name
        if cn and (cn == domain or cn.endswith("." + domain)):
            ct_issuers_by_host.setdefault(cn, set()).add(entry.issuer_name)

    for host in tracked_hostnames:
        scanned_issuer = _get_scanned_issuer(db_path, host)
        expected_issuers = _get_expected_issuers(db_path, host)
        ct_issuers = ct_issuers_by_host.get(host, set())
        if scanned_issuer and ct_issuers:
            for ct_issuer in ct_issuers:
                if not _issuer_matches(ct_issuer, scanned_issuer, expected_issuers):
                    misissued.append({
                        "host": host,
                        "scanned_issuer": scanned_issuer,
                        "ct_issuer": ct_issuer,
                    })
                if ct_issuer not in first_seen_by_issuer:
                    first_seen = _record_ct_issuer_first_seen(db_path, ct_issuer)
                    if first_seen:
                        first_seen_by_issuer[ct_issuer] = first_seen

    recon = ReconciliationResult(
        domain=domain,
        tracked_hostnames=tracked_hostnames,
        ct_hostnames=ct_hostnames_filtered,
        ct_only_hostnames=ct_only,
        tracked_only_hostnames=tracked_only,
        coverage_pct=round(coverage, 1),
        misissued=misissued,
        first_seen_by_issuer=first_seen_by_issuer,
    )
    _CT_RECON_CACHE[cache_key] = (now, recon)
    _evict_ct_cache(now)
    return recon


def _extract_parent_domains(hostnames: list[str]) -> set[str]:
    domains: set[str] = set()
    for h in hostnames:
        parts = h.split(".")
        if len(parts) >= 2:
            domains.add(".".join(parts[-2:]))
    return domains


def _get_scanned_cert_id(db_path: str | Path, hostname: str) -> str:
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT id FROM certificates
               WHERE hostname = ? AND is_leaf = 1 AND source = 'scanned'
               ORDER BY updated_at DESC LIMIT 1""",
            (hostname,),
        ).fetchone()
    return row["id"] if row else ""


def _has_pending_misissuance_alert(db_path: str | Path, cert_id: str) -> bool:
    if not cert_id:
        return False
    with _connect(db_path) as conn:
        row = conn.execute(
            """SELECT 1 FROM alerts
               WHERE cert_id = ? AND alert_type = 'mis_issuance'
                 AND status = 'pending' LIMIT 1""",
            (cert_id,),
        ).fetchone()
    return row is not None


def create_ct_misissuance_alert(
    db_path: str | Path,
    misissued_entry: dict,
    domain: str,
) -> str | None:
    from cert_watch.database.repo import Alert, SqliteAlertRepository

    host = misissued_entry["host"]
    scanned_issuer = misissued_entry["scanned_issuer"]
    ct_issuer = misissued_entry["ct_issuer"]

    cert_id = _get_scanned_cert_id(db_path, host)
    if _has_pending_misissuance_alert(db_path, cert_id):
        return None

    message = (
        f"{host} — CT mis-issuance detected: expected issuer '{scanned_issuer}', "
        f"found '{ct_issuer}' in CT logs (domain={domain})"
    )

    subject = ""
    with _connect(db_path) as conn:
        row = conn.execute("SELECT subject FROM certificates WHERE id = ?", (cert_id,)).fetchone()
        if row:
            subject = row["subject"] or ""

    alert = Alert(
        cert_id=cert_id,
        alert_type="mis_issuance",
        status="pending",
        message=message,
        hostname=host,
        subject=subject,
    )
    alert_repo = SqliteAlertRepository(db_path)
    return alert_repo.create(alert)


def run_ct_monitor(db_path: str | Path) -> dict[str, int]:
    """Query CT logs for all tracked host domains and report new findings.

    Also runs CT reconciliation per parent domain to detect mis-issuance
    and creates alerts for any mismatched issuers.

    Returns {"checked": N, "new": M, "errors": E, "misissued": M, "alerts_created": A}.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT hostname FROM hosts WHERE hostname IS NOT NULL"
        ).fetchall()

    hostnames = [row["hostname"] for row in rows]

    checked = 0
    new = 0
    errors = 0
    known_serial_issuer: set[tuple[str, str]] = set()
    for hostname in hostnames:
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

    misissued_count = 0
    alerts_created = 0
    domains = _extract_parent_domains(hostnames)
    for domain in sorted(domains):
        try:
            recon = ct_reconciliation(db_path, domain)
        except Exception:
            logger.warning("CT reconciliation failed for %s", domain, exc_info=True)
            continue
        for mi in recon.misissued:
            misissued_count += 1
            alert_id = create_ct_misissuance_alert(db_path, mi, domain)
            if alert_id:
                alerts_created += 1
                logger.warning(
                    "CT mis-issuance alert: %s — expected issuer '%s', found '%s' (domain=%s)",
                    mi["host"], mi["scanned_issuer"], mi["ct_issuer"], domain,
                )

    if new > 0 or alerts_created > 0:
        logger.info(
            "CT monitor complete: %d checked, %d new, %d errors, "
            "%d misissued, %d alerts created",
            checked, new, errors, misissued_count, alerts_created,
        )
    return {
        "checked": checked, "new": new, "errors": errors,
        "misissued": misissued_count, "alerts_created": alerts_created,
    }
