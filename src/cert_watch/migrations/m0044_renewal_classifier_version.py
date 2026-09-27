"""Migration 0044 — version persisted renewal classifications."""

from __future__ import annotations

import sqlite3

MIGRATION_ID = "0044"
DESCRIPTION = "version persisted renewal classifications"


# This predicate proves that NEW is a chronological append to the current
# fingerprint period and cannot recover missing validity for that period.
_HARMLESS_APPEND = """
    NOT EXISTS (
      SELECT 1 FROM cert_history newer
      WHERE newer.hostname = NEW.hostname AND newer.port = NEW.port
        AND newer.id != NEW.id
        AND (newer.scanned_at > NEW.scanned_at
             OR (newer.scanned_at = NEW.scanned_at AND newer.id > NEW.id))
    )
    AND (
      SELECT previous.fingerprint_sha256 FROM cert_history previous
      WHERE previous.hostname = NEW.hostname AND previous.port = NEW.port
        AND previous.id != NEW.id
      ORDER BY previous.scanned_at DESC, previous.id DESC LIMIT 1
    ) = NEW.fingerprint_sha256
    AND (
      NEW.not_before IS NULL OR NEW.not_after IS NULL OR COALESCE((
        SELECT
          typeof(previous.not_before) = 'text'
          AND (
            previous.not_before GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9]'
            OR previous.not_before GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9][-+][0-2][0-9]:[0-5][0-9]'
            OR previous.not_before GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][-+][0-2][0-9]:[0-5][0-9]'
          )
          AND substr(previous.not_before, 1, 4) >= '0001'
          AND date(substr(previous.not_before, 1, 19)) =
              substr(previous.not_before, 1, 10)
          AND time(substr(previous.not_before, 1, 19)) =
              substr(previous.not_before, 12, 8)
          AND typeof(previous.not_after) = 'text'
          AND (
            previous.not_after GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9]'
            OR previous.not_after GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9][-+][0-2][0-9]:[0-5][0-9]'
            OR previous.not_after GLOB
              '[0-9][0-9][0-9][0-9]-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-6][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][-+][0-2][0-9]:[0-5][0-9]'
          )
          AND substr(previous.not_after, 1, 4) >= '0001'
          AND date(substr(previous.not_after, 1, 19)) =
              substr(previous.not_after, 1, 10)
          AND time(substr(previous.not_after, 1, 19)) =
              substr(previous.not_after, 12, 8)
          AND julianday(previous.not_after) > julianday(previous.not_before)
        FROM cert_history previous
        WHERE previous.hostname = NEW.hostname AND previous.port = NEW.port
          AND previous.id != NEW.id
        ORDER BY previous.scanned_at DESC, previous.id DESC LIMIT 1
      ), 0) = 1
    )
"""


def upgrade(conn: sqlite3.Connection) -> None:
    from cert_watch.renewal_analytics import (
        CLASSIFIER_VERSION,
        refresh_endpoint_analytics,
    )

    columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(endpoint_renewal_analytics)")
    }
    if "classifier_version" not in columns:
        conn.execute(
            "ALTER TABLE endpoint_renewal_analytics "
            "ADD COLUMN classifier_version INTEGER NOT NULL DEFAULT 0"
        )

    tables = {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    if "cert_history" not in tables:
        return

    conn.execute("DROP TRIGGER IF EXISTS invalidate_renewal_analytics_insert")
    conn.execute("DROP TRIGGER IF EXISTS maintain_renewal_analytics_insert")
    conn.execute("DROP TRIGGER IF EXISTS invalidate_renewal_analytics_replace")
    conn.execute(
        """CREATE TRIGGER invalidate_renewal_analytics_replace
           BEFORE INSERT ON cert_history
           WHEN EXISTS (SELECT 1 FROM cert_history WHERE id = NEW.id)
           BEGIN
             DELETE FROM endpoint_renewal_analytics
             WHERE (hostname, port) IN (
                       SELECT hostname, port FROM cert_history WHERE id = NEW.id
                   )
                OR (hostname = NEW.hostname AND port = NEW.port);
           END"""
    )
    conn.execute(
        f"""CREATE TRIGGER invalidate_renewal_analytics_insert
            AFTER INSERT ON cert_history
            WHEN NEW.hostname IS NOT NULL AND NEW.port IS NOT NULL
             AND NOT ({_HARMLESS_APPEND})
            BEGIN
              DELETE FROM endpoint_renewal_analytics
              WHERE hostname = NEW.hostname AND port = NEW.port;
            END"""
    )
    conn.execute(
        f"""CREATE TRIGGER maintain_renewal_analytics_insert
            AFTER INSERT ON cert_history
            WHEN NEW.hostname IS NOT NULL AND NEW.port IS NOT NULL
             AND ({_HARMLESS_APPEND})
            BEGIN
              UPDATE endpoint_renewal_analytics
              SET basis_history_count = basis_history_count + 1,
                  basis_latest_history_id = NEW.id,
                  basis_latest_fingerprint = NEW.fingerprint_sha256
              WHERE hostname = NEW.hostname AND port = NEW.port;
            END"""
    )

    endpoints = conn.execute(
        """SELECT hostname, port FROM endpoint_renewal_analytics
           WHERE classifier_version != ? ORDER BY hostname, port""",
        (CLASSIFIER_VERSION,),
    ).fetchall()
    for hostname, port in endpoints:
        refresh_endpoint_analytics(conn, str(hostname), int(port))
