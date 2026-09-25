"""Migration 0043 — persist the canonical endpoint renewal classification."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0043"
DESCRIPTION = "persist canonical endpoint renewal analytics"


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS endpoint_renewal_analytics (
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            classification TEXT NOT NULL
                CHECK (classification IN ('unknown', 'manual', 'likely-automated')),
            evidence_json TEXT NOT NULL,
            observed_lifetimes_json TEXT NOT NULL,
            lifetime_trend TEXT NOT NULL,
            renewal_lead_times_json TEXT NOT NULL,
            median_lead_time REAL,
            median_cadence_days REAL,
            deployment_count INTEGER NOT NULL,
            basis_history_count INTEGER NOT NULL,
            basis_latest_history_id TEXT,
            basis_latest_fingerprint TEXT,
            calculated_at TEXT NOT NULL,
            PRIMARY KEY (hostname, port)
        )"""
    )

    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if "cert_history" not in tables:
        return

    # Any writer that bypasses the sanctioned helpers cannot leave a plausible
    # but stale result behind.  It invalidates the endpoint row, so reads fail
    # closed to ``unknown`` until an in-transaction refresh supplies a new row.
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS invalidate_renewal_analytics_insert
           AFTER INSERT ON cert_history
           WHEN NEW.hostname IS NOT NULL AND NEW.port IS NOT NULL
           BEGIN
             DELETE FROM endpoint_renewal_analytics
             WHERE hostname = NEW.hostname AND port = NEW.port;
           END"""
    )
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS invalidate_renewal_analytics_delete
           AFTER DELETE ON cert_history
           WHEN OLD.hostname IS NOT NULL AND OLD.port IS NOT NULL
           BEGIN
             DELETE FROM endpoint_renewal_analytics
             WHERE hostname = OLD.hostname AND port = OLD.port;
           END"""
    )
    conn.execute(
        """CREATE TRIGGER IF NOT EXISTS invalidate_renewal_analytics_update
           AFTER UPDATE ON cert_history
           BEGIN
             DELETE FROM endpoint_renewal_analytics
             WHERE (hostname = OLD.hostname AND port = OLD.port)
                OR (hostname = NEW.hostname AND port = NEW.port);
           END"""
    )

    from cert_watch.renewal_analytics import refresh_endpoint_analytics

    endpoints = conn.execute(
        """SELECT hostname, port FROM hosts
           UNION
           SELECT hostname, port FROM cert_history
           WHERE hostname IS NOT NULL AND port IS NOT NULL
           ORDER BY hostname, port"""
    ).fetchall()
    for hostname, port in endpoints:
        refresh_endpoint_analytics(conn, str(hostname), int(port))
