"""Application services for uploaded certificates and trust anchors."""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cert_watch.audit import record_audit
from cert_watch.auth.scope import (
    ensure_new_tags_in_scope,
    ensure_write_scope,
    require_auth_context,
)
from cert_watch.cert_chain import validate_is_ca_certificate
from cert_watch.database import (
    SqliteTrustAnchorRepository,
    delete_certificate_cascade,
    get_write_lock,
)
from cert_watch.tags import format_tags, merge_tags
from cert_watch.upload import ParseError, UploadedEntry, store_uploaded, upload_certificate

logger = logging.getLogger("cert_watch.services.certificate_management")

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
CERTIFICATE_SUFFIXES = frozenset({".pem", ".crt", ".cer", ".der", ".pfx", ".p12", ".p7b", ".p7c"})
ANCHOR_SUFFIXES = frozenset({".pem", ".crt", ".cer", ".der"})


class CertificateValidationError(ValueError):
    """An uploaded certificate or trust anchor is invalid."""


class CertificateNotFoundError(LookupError):
    """A certificate or trust anchor does not exist."""


@dataclass(frozen=True)
class UploadResult:
    id: str
    filename: str


def _parse_upload(
    content: bytes,
    filename: str,
    password: str | None,
    suffixes: frozenset[str],
) -> UploadedEntry:
    if len(content) > MAX_UPLOAD_BYTES:
        raise CertificateValidationError("file too large (max 10 MB)")
    suffix = Path(filename or "uploaded").suffix.lower()
    suffix = suffix if suffix in suffixes else ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        result = upload_certificate(tmp_path, password=password.encode() if password else None)
    finally:
        tmp_path.unlink(missing_ok=True)
    if isinstance(result, ParseError):
        raise CertificateValidationError(result.error_message)
    result.file_name = filename or result.file_name
    return result


def upload_certificate_bytes(
    db_path: str | Path,
    content: bytes,
    filename: str,
    password: str | None = None,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    tags: str = "",
) -> UploadResult:
    require_auth_context(auth)
    scope = getattr(auth, "scope_tag", "") if auth is not None else ""
    tags = format_tags(merge_tags(tags, scope or ""))
    ensure_new_tags_in_scope(auth, tags)
    try:
        entry = _parse_upload(content, filename, password, CERTIFICATE_SUFFIXES)
    except CertificateValidationError as exc:
        logger.warning("certificate upload parsing failed for %r: %s", filename, exc)
        message = str(exc)
        if message.startswith(("failed to parse DER:", "failed to parse PEM:")):
            message = "could not parse certificate file"
        raise CertificateValidationError(message) from None
    with get_write_lock():
        cert_id = store_uploaded(entry, db_path, tags=tags)
    record_audit(
        db_path,
        actor=actor,
        action="cert.upload",
        target_type="certificate",
        target_id="upload",
        detail={"filename": filename or "unknown"},
        source_ip=source_ip,
    )
    return UploadResult(cert_id, filename or "unknown")


def delete_certificate(
    db_path: str | Path,
    cert_id: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> bool:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, cert_id=cert_id)
        deleted = delete_certificate_cascade(db_path, cert_id)
    record_audit(
        db_path,
        actor=actor,
        action="cert.delete",
        target_type="certificate",
        target_id=cert_id,
        source_ip=source_ip,
    )
    return deleted


def add_trust_anchor(
    db_path: str | Path,
    content: bytes,
    filename: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> UploadResult:
    require_auth_context(auth)
    if auth is not None and not getattr(auth, "is_admin", False):
        raise PermissionError("admin required")
    entry = _parse_upload(content, filename, None, ANCHOR_SUFFIXES)
    bundle = [entry.leaf, *entry.chain]
    anchor = next(
        (cert for cert in reversed(bundle) if validate_is_ca_certificate(cert.raw_der) is None),
        entry.leaf,
    )
    error = validate_is_ca_certificate(anchor.raw_der)
    if error:
        raise CertificateValidationError("Invalid trust anchor: " + error)
    with get_write_lock():
        anchor_id = SqliteTrustAnchorRepository(db_path).add(anchor)
    record_audit(
        db_path,
        actor=actor,
        action="trust_anchor.add",
        target_type="trust_anchor",
        target_id=anchor_id,
        detail={"subject": anchor.subject},
        source_ip=source_ip,
    )
    return UploadResult(anchor_id, filename or "unknown")


def delete_trust_anchor(
    db_path: str | Path,
    anchor_id: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> bool:
    require_auth_context(auth)
    if auth is not None and not getattr(auth, "is_admin", False):
        raise PermissionError("admin required")
    with get_write_lock():
        deleted = SqliteTrustAnchorRepository(db_path).delete(anchor_id)
    record_audit(
        db_path,
        actor=actor,
        action="trust_anchor.delete",
        target_type="trust_anchor",
        target_id=anchor_id,
        source_ip=source_ip,
    )
    return deleted
