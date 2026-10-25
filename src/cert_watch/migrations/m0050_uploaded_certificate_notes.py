"""Restore notes for uploaded certificates, including preserved legacy notes."""

from __future__ import annotations

import sqlite3


def upgrade(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS uploaded_certificate_notes ("
        "cert_id TEXT PRIMARY KEY REFERENCES certificates(id) ON DELETE CASCADE, "
        "notes TEXT NOT NULL DEFAULT '')"
    )
    columns = {row[1] for row in conn.execute("PRAGMA table_info(certificates)")}
    if "notes" in columns:
        # 0031 retained this column when a note had no matching host. Never
        # overwrite a subsequently edited note when reconciling old schemas.
        conn.execute(
            "INSERT INTO uploaded_certificate_notes (cert_id, notes) "
            "SELECT id, notes FROM certificates "
            "WHERE source = 'uploaded' AND notes IS NOT NULL AND notes != '' "
            "ON CONFLICT(cert_id) DO NOTHING"
        )
    # Unmatched legacy endpoint metadata must not attach an upload to a new
    # team's host when that address is later added. Existing associations stay
    # intact until that host is explicitly removed.
    conn.execute(
        "UPDATE certificates SET hostname = '', port = 0 "
        "WHERE source = 'uploaded' AND COALESCE(hostname, '') != '' "
        "AND NOT EXISTS (SELECT 1 FROM hosts h "
        "WHERE h.hostname = certificates.hostname AND h.port = certificates.port)"
    )
