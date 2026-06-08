"""Test helpers for seeding database state without raw SQL.

BC-123: Test helpers for seeding fleets should use repository or upload
helpers, not raw SQL.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteCertificateRepository, SqliteHostRepository
from cert_watch.database.schema import init_schema
from cert_watch.scan import ScannedEntry, store_scanned


def seed_host(db_path: str | Path, hostname: str, port: int = 443) -> None:
    """Add a host row using the repository helper."""
    init_schema(db_path)
    SqliteHostRepository(db_path).add(hostname, port)


def seed_certificate(
    db_path: str | Path,
    cert: Certificate,
    *,
    cert_id: str | None = None,
    source: str = "scanned",
    hostname: str | None = None,
    port: int | None = None,
    chain_valid: bool | None = None,
    replaces_cert_id: str | None = None,
    tags: str = "",
) -> str:
    """Insert a certificate row using the repository helper.

    Returns the generated certificate id.
    """
    from cert_watch.database.connection import _connect, _iso

    init_schema(db_path)
    if cert_id is None:
        repo = SqliteCertificateRepository(
            db_path,
            source=source,
            hostname=hostname,
            port=port,
            chain_valid=chain_valid,
            replaces_cert_id=replaces_cert_id,
        )
        return repo.add(cert)

    # Deterministic id path for tests that need specific ids.
    now = _iso(datetime.now(UTC))
    cv: int | None = (
        None if chain_valid is None else (1 if chain_valid else 0)
    )
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO certificates
            (id, subject, issuer, not_before, not_after, san_dns_names,
             fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
             parent_cert_id, chain_valid, replaces_cert_id, notes, tags,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id,
                cert.subject,
                cert.issuer,
                _iso(cert.not_before),
                _iso(cert.not_after),
                json.dumps(cert.san_dns_names),
                cert.fingerprint_sha256,
                cert.raw_der,
                source,
                hostname,
                port,
                1 if cert.is_leaf else 0,
                None,
                cv,
                replaces_cert_id,
                cert.notes,
                tags,
                now,
                now,
            ),
        )
        conn.commit()
    return cert_id


def seed_scanned(
    db_path: str | Path,
    hostname: str,
    port: int,
    leaf: Certificate,
    chain: list[Certificate] | None = None,
) -> str:
    """Insert a scanned leaf + chain via store_scanned.

    Returns the leaf certificate id.
    """
    init_schema(db_path)
    entry = ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf,
        chain=chain or [],
    )
    return store_scanned(entry, db_path)
