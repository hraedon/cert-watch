"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import contextlib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.cert_chain import validate_chain_order
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import SqliteCertificateRepository, init_schema
from cert_watch.database import _connect as _connect_db

DEFAULT_TIMEOUT = 10.0


@dataclass
class ScanError:
    hostname: str
    port: int
    error_message: str


@dataclass
class ScannedEntry:
    host: str
    port: int
    leaf: Certificate
    chain: list[Certificate] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _open_tls_connection(hostname: str, port: int, timeout: float):
    """Open a TLS connection and return the SSLSocket. Separated so tests can monkeypatch."""
    ctx = ssl.create_default_context()
    # We want the cert chain regardless of validity (this is monitoring, not enforcement).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((hostname, port), timeout=timeout)
    return ctx.wrap_socket(sock, server_hostname=hostname)


def _get_chain_der(ssl_sock) -> list[bytes]:
    """
    Return DER bytes for every certificate the peer presented.
    Uses SSLSocket.getpeercert(True) for the leaf and (when available)
    getpeercert_chain() for intermediates. Older Pythons lack the latter; fall
    back to just the leaf.
    """
    leaf = ssl_sock.getpeercert(binary_form=True)
    chain: list[bytes] = []
    if leaf:
        chain.append(leaf)
    # Python 3.13+ exposes get_verified_chain / get_unverified_chain. Try both.
    for method in ("get_unverified_chain", "get_verified_chain"):
        getter = getattr(ssl_sock, method, None)
        if getter:
            try:
                items = getter()
            except Exception:  # noqa: BLE001
                continue
            chain = []
            for c in items:
                # Newer cryptography returns _Certificate-like with public_bytes,
                # cpython returns bytes-like via .public_bytes() on Certificate objects
                try:
                    der = c.public_bytes(_der_enc())
                except AttributeError:
                    der = bytes(c)
                chain.append(der)
            break
    return chain


def _der_enc():
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def scan_host(
    hostname: str, port: int = 443, *, timeout: float = DEFAULT_TIMEOUT
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06."""
    try:
        ssl_sock = _open_tls_connection(hostname, port, timeout)
    except TimeoutError as exc:
        return ScanError(hostname=hostname, port=port, error_message=f"timeout: {exc}")
    except OSError as exc:
        return ScanError(hostname=hostname, port=port, error_message=str(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=str(exc))

    try:
        der_chain = _get_chain_der(ssl_sock)
    finally:
        with contextlib.suppress(Exception):
            ssl_sock.close()

    if not der_chain:
        return ScanError(
            hostname=hostname, port=port, error_message="no certificate presented"
        )

    leaf_parsed = parse_certificate(der_chain[0])
    if not isinstance(leaf_parsed, Certificate):
        return ScanError(
            hostname=hostname, port=port, error_message=leaf_parsed.message
        )

    chain_certs: list[Certificate] = []
    for der in der_chain[1:]:
        cp = parse_certificate(der)
        if isinstance(cp, Certificate):
            cp.is_leaf = False
            chain_certs.append(cp)

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=chain_certs,
        scanned_at=datetime.now(UTC),
    )


def store_scanned(entry: ScannedEntry, repo_path_or_repo) -> str:
    """
    Persist leaf + chain. Accepts either an existing CertificateRepository OR a path
    (so callers can pass the db path directly and we wire up source/hostname/port).
    Removes any previous leaf + chain certs for the same (hostname, port) first to
    avoid accumulation on repeated scans. See AC-07.
    """
    if isinstance(repo_path_or_repo, str | Path):
        init_schema(repo_path_or_repo)
        chain_valid = validate_chain_order([entry.leaf, *entry.chain])
        with _connect_db(repo_path_or_repo) as conn:
            old_leaves = [
                row["id"]
                for row in conn.execute(
                    "SELECT id FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
                    (entry.host, entry.port),
                ).fetchall()
            ]
            for old_id in old_leaves:
                conn.execute(
                    "DELETE FROM certificates WHERE parent_cert_id = ?", (old_id,)
                )
            conn.execute(
                "DELETE FROM certificates WHERE hostname = ? AND port = ? AND is_leaf = 1",
                (entry.host, entry.port),
            )
            conn.commit()
        leaf_repo = SqliteCertificateRepository(
            repo_path_or_repo,
            source="scanned",
            hostname=entry.host,
            port=entry.port,
            chain_valid=chain_valid,
        )
        leaf_id = leaf_repo.add(entry.leaf)
        for chain_cert in entry.chain:
            chain_repo = SqliteCertificateRepository(
                repo_path_or_repo,
                source="scanned",
                hostname=entry.host,
                port=entry.port,
                parent_cert_id=leaf_id,
            )
            chain_repo.add(chain_cert)
        return leaf_id

    repo = repo_path_or_repo
    leaf_id = repo.add(entry.leaf)
    for chain_cert in entry.chain:
        repo.add(chain_cert)
    return leaf_id
