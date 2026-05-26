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
from cert_watch.database import SqliteCertificateRepository, init_schema


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
    return ParseError(error_message=f"unsupported file extension: {ext}")


def _parse_pem_or_der(name: str, data: bytes) -> UploadedEntry | ParseError:
    text = data.decode("utf-8", errors="ignore")
    if "-----BEGIN CERTIFICATE-----" in text:
        certs = extract_chain_from_pem(text)
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
    except Exception as exc:  # noqa: BLE001 — cryptography raises various Errors
        return ParseError(error_message=f"could not parse PKCS#12: {exc}")
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
    return UploadedEntry(file_name=name, leaf=leaf_parsed, chain=chain)


def _parse_pkcs7(name: str, data: bytes) -> UploadedEntry | ParseError:
    certs = extract_chain(data)
    if not certs:
        certs = extract_chain_pem(data)
    if not certs:
        return ParseError(error_message="could not parse PKCS#7: no certificates found")
    leaf = certs[0]
    leaf.is_leaf = True
    chain_certs = certs[1:]
    for c in chain_certs:
        c.is_leaf = False
    return UploadedEntry(file_name=name, leaf=leaf, chain=chain_certs)


def store_uploaded(entry: UploadedEntry, repo_path: Path | str) -> str:
    """Persist leaf + chain via dedicated repos so parent_cert_id is wired correctly."""
    init_schema(repo_path)
    chain_valid = validate_chain_order([entry.leaf, *entry.chain])
    leaf_repo = SqliteCertificateRepository(
        repo_path, source="uploaded", chain_valid=chain_valid
    )
    leaf_id = leaf_repo.add(entry.leaf)
    for chain_cert in entry.chain:
        chain_repo = SqliteCertificateRepository(
            repo_path, source="uploaded", parent_cert_id=leaf_id
        )
        chain_repo.add(chain_cert)
    return leaf_id
