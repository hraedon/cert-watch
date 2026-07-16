"""Certificate file upload (PEM/DER/CER/CRT + PKCS#12 .pfx). See spec wi_fr03_upload.md.

PKCS#12 support extends the original spec per the MVP requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, pkcs12

from cert_watch.cert_chain import extract_chain, extract_chain_pem, validate_chain_order
from cert_watch.certificate_model import (
    Certificate,
    extract_chain_from_pem,
    parse_certificate,
)
from cert_watch.database import init_schema


@dataclass
class ParseError:
    error_message: str


@dataclass
class UploadedEntry:
    file_name: str
    leaf: Certificate
    chain: list[Certificate] = field(default_factory=list)
    uploaded_at: datetime = field(default_factory=lambda: datetime.now(UTC))


_PEM_EXT = {".pem", ".crt", ".cer"}
_DER_EXT = {".der"}
_PKCS12_EXT = {".pfx", ".p12"}
_PKCS7_EXT = {".p7b", ".p7c"}


def upload_certificate(
    file_path: Path,
    *,
    password: bytes | None = None,
) -> UploadedEntry | ParseError:
    """Parse a file by extension. Returns UploadedEntry or ParseError."""
    path = Path(file_path)
    if not path.exists():
        return ParseError(error_message=f"file not found: {path}")
    ext = path.suffix.lower()

    try:
        data = path.read_bytes()
    except OSError as exc:
        return ParseError(error_message=f"could not read file: {exc}")

    if ext in _PKCS12_EXT:
        return _parse_pkcs12(path.name, data, password)
    if ext in _PKCS7_EXT:
        return _parse_pkcs7(path.name, data)
    if ext in _PEM_EXT:
        return _parse_pem_or_der(path.name, data)
    if ext in _DER_EXT:
        return _parse_der(path.name, data)
    # Unknown extension: best-effort attempt PEM then DER.
    try_pem = _parse_pem_or_der(path.name, data)
    if isinstance(try_pem, UploadedEntry):
        return try_pem
    try_der = _parse_der(path.name, data)
    if isinstance(try_der, UploadedEntry):
        return try_der
    return ParseError(error_message=f"unsupported file extension: {ext}")


def _parse_pem_or_der(name: str, data: bytes) -> UploadedEntry | ParseError:
    text = data.decode("utf-8", errors="ignore")
    if "-----BEGIN CERTIFICATE-----" in text:
        try:
            certs = extract_chain_from_pem(text)
        except ValueError as exc:
            return ParseError(error_message=str(exc))
        if not certs:
            return ParseError(error_message="no valid PEM certificates found")
        return UploadedEntry(file_name=name, leaf=certs[0], chain=certs[1:])
    # Maybe DER masquerading as .pem extension.
    return _parse_der(name, data)


def _parse_der(name: str, data: bytes) -> UploadedEntry | ParseError:
    parsed = parse_certificate(data)
    if not isinstance(parsed, Certificate):
        return ParseError(error_message=parsed.message)
    return UploadedEntry(file_name=name, leaf=parsed, chain=[])


def _parse_pkcs12(
    name: str, data: bytes, password: bytes | None
) -> UploadedEntry | ParseError:
    try:
        _key, cert, additional = pkcs12.load_key_and_certificates(data, password)
    except Exception:  # noqa: BLE001 — cryptography raises various Errors
        return ParseError(
            error_message="could not parse PKCS#12: invalid password or corrupted file"
        )
    if cert is None:
        return ParseError(error_message="PKCS#12 contains no certificate")
    leaf_parsed = parse_certificate(cert.public_bytes(Encoding.DER))
    if not isinstance(leaf_parsed, Certificate):
        return ParseError(error_message=leaf_parsed.message)
    chain: list[Certificate] = []
    for c in additional or []:
        cp = parse_certificate(c.public_bytes(Encoding.DER))
        if isinstance(cp, Certificate):
            cp.is_leaf = False
            chain.append(cp)
    if len(chain) > 50:
        return ParseError(
            error_message=(
                f"PKCS#12 contains too many additional certificates"
                f" ({len(chain)}), max 50"
            )
        )
    return UploadedEntry(file_name=name, leaf=leaf_parsed, chain=chain)


def _parse_pkcs7(name: str, data: bytes) -> UploadedEntry | ParseError:
    certs = extract_chain(data)
    if not certs:
        certs = extract_chain_pem(data)
    if not certs:
        return ParseError(error_message="could not parse PKCS#7: no certificates found")
    if len(certs) > 100:
        return ParseError(
            error_message=(
                f"PKCS#7 bundle contains too many certificates"
                f" ({len(certs)}), max 100"
            )
        )
    leaf = certs[0]
    leaf.is_leaf = True
    chain_certs = certs[1:]
    for c in chain_certs:
        c.is_leaf = False
    return UploadedEntry(file_name=name, leaf=leaf, chain=chain_certs)


def store_uploaded(
    entry: UploadedEntry,
    repo_path: Path | str,
    *,
    tags: str = "",
) -> str:
    """Persist leaf + chain in a single transaction to avoid partial uploads.

    *tags* are stored on the uploaded leaf certificate (WI-052).
    """
    import json
    import uuid

    from cert_watch.database.connection import _connect, _iso

    init_schema(repo_path)
    chain_valid = validate_chain_order([entry.leaf, *entry.chain])
    cv: int | None = None if chain_valid is None else (1 if chain_valid else 0)
    leaf_id = str(uuid.uuid4())
    now = _iso(datetime.now(UTC))

    with _connect(repo_path) as conn:
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
                leaf_id,
                entry.leaf.subject,
                entry.leaf.issuer,
                _iso(entry.leaf.not_before),
                _iso(entry.leaf.not_after),
                json.dumps(entry.leaf.san_dns_names),
                entry.leaf.fingerprint_sha256,
                entry.leaf.raw_der,
                "uploaded",
                "",
                0,
                1,
                None,
                cv,
                None,
                "",
                tags,
                now,
                now,
            ),
        )
        for chain_cert in entry.chain:
            chain_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO certificates
                (id, subject, issuer, not_before, not_after, san_dns_names,
                 fingerprint_sha256, raw_der, source, hostname, port, is_leaf,
                 parent_cert_id, chain_valid, replaces_cert_id, notes,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_id,
                    chain_cert.subject,
                    chain_cert.issuer,
                    _iso(chain_cert.not_before),
                    _iso(chain_cert.not_after),
                    json.dumps(chain_cert.san_dns_names),
                    chain_cert.fingerprint_sha256,
                    chain_cert.raw_der,
                    "uploaded",
                    "",
                    0,
                    0,
                    leaf_id,
                    None,
                    None,
                    "",
                    now,
                    now,
                ),
            )
        conn.commit()
    try:
        from cert_watch.events import Event, emit_event

        emit_event(
            Event(
                event_type="cert_added",
                timestamp=datetime.now(UTC),
                payload={"cert_id": leaf_id, "source": "upload"},
                source="upload",
            ),
            repo_path,
        )
    except Exception:  # noqa: BLE001
        pass
    return leaf_id
