"""Scheduled Certificate Transparency monitoring.

Compares CT log entries against known certificates and alerts on
unauthorized issuance. See spec FEAT-007.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cert_watch.ct_lookup import query_ct_log
from cert_watch.database import _connect, init_schema

logger = logging.getLogger("cert_watch.ct_monitor")


def run_ct_monitor(db_path: str | Path) -> dict[str, int]:
    """Query CT logs for all tracked host domains and report new findings.

    Returns {"checked": N, "new": M, "errors": E}.
    """
    init_schema(db_path)
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT hostname FROM hosts WHERE hostname IS NOT NULL"
        ).fetchall()
        # Collect known fingerprints for dedup against stored certificates.
        # Note: crt.sh provides serial_number, not SHA256 fingerprints,
        # so we also track (serial, issuer) pairs seen in CT results.
        known_fps = {
            r["fingerprint_sha256"]
            for r in conn.execute(
                "SELECT fingerprint_sha256 FROM certificates"
            ).fetchall()
        }
        known_serial_issuer: set[tuple[str, str]] = set()

    checked = 0
    new = 0
    errors = 0
    for row in rows:
        hostname = row["hostname"]
        checked += 1
        result = query_ct_log(hostname)
        if isinstance(result, str):
            logger.warning("CT monitor error for %s: %s", hostname, result)
            errors += 1
            continue
        for entry in result:
            # Use (serial, issuer) as composite key — serial numbers alone
            # are not unique across CAs.
            dedup_key = (entry.serial_number, entry.issuer_name)
            if dedup_key not in known_fps and dedup_key not in known_serial_issuer:
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
