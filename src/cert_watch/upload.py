"""Certificate file upload (PEM/DER/CER/CRT + PKCS#12 .pfx). See spec wi_fr03_upload.md.

PKCS#12 support extends the original spec per the MVP requirements.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, pkcs12

from cert_watch.cert_chain import (
    _AnchorLike,
    _is_anchored_by_system_root,
    _is_signature_anchored_by_user,
    _issuer_bytes,
    _load_x509,
    _subject_bytes,
    deduplicate_chain,
    extract_chain,
    extract_chain_pem,
    validate_chain_order,
)
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
    anchors: Sequence[_AnchorLike] = (),
) -> UploadedEntry | ParseError:
    """Parse a file by extension. Returns UploadedEntry or ParseError.

    *anchors* are the user's trust anchors; a PKCS#7 bag with cross-signed
    issuers prefers a chain they anchor.
    """
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
        return _parse_pkcs7(path.name, data, anchors)
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


def _parse_pkcs12(name: str, data: bytes, password: bytes | None) -> UploadedEntry | ParseError:
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
                f"PKCS#12 contains too many additional certificates ({len(chain)}), max 50"
            )
        )
    return UploadedEntry(file_name=name, leaf=leaf_parsed, chain=chain)


def _parse_pkcs7(
    name: str, data: bytes, anchors: Sequence[_AnchorLike] = (),
) -> UploadedEntry | ParseError:
    certs = extract_chain(data)
    if not certs:
        certs = extract_chain_pem(data)
    if not certs:
        return ParseError(error_message="could not parse PKCS#7: no certificates found")
    if len(certs) > 100:
        return ParseError(
            error_message=(f"PKCS#7 bundle contains too many certificates ({len(certs)}), max 100")
        )
    ordered = _order_pkcs7_chain(certs, anchors)
    if ordered is None:
        return ParseError(
            error_message=(
                "PKCS#7 must contain one unambiguous certificate chain; "
                "upload a leaf-first PEM chain instead"
            )
        )
    leaf = ordered[0]
    leaf.is_leaf = True
    chain_certs = ordered[1:]
    for c in chain_certs:
        c.is_leaf = False
    return UploadedEntry(file_name=name, leaf=leaf, chain=chain_certs)


# Bounds the search over cross-signed alternatives in one 100-certificate bag.
_PKCS7_PATH_STEPS = 10_000


def _public_key_der(certificate: Certificate) -> bytes | None:
    parsed = _load_x509(certificate)
    if parsed is None:
        return None
    try:
        return parsed.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    except (ValueError, TypeError):  # unsupported key type
        return None


def _order_pkcs7_chain(
    certs: list[Certificate],
    anchors: Sequence[_AnchorLike] = (),
    *,
    now: datetime | None = None,
) -> list[Certificate] | None:
    """Order a certificate bag structurally, without asserting signature or trust.

    PKCS#7 CertificateSet is unordered (RFC 5652 section 10.2.3). Exactly one
    certificate may issue nothing else in the bag: that is the leaf. Every
    certificate must be reachable from the leaf through its issuers, and at
    least one path must end at a self-issued certificate or at one whose
    issuer is absent. A branch that only loops back onto its own path is
    dropped, so its certificates are reachable but not stored.

    Public CA bundles often carry cross-signs: copies of one CA certificate,
    with the same name and key, signed by different issuers. Any copy can
    issue the certificate below it, so a choice between them is not
    ambiguous. A choice between same-named issuers with different keys is,
    and so are unrelated chains and pure cycles; those need an explicit
    leaf-first PEM upload instead.

    Of the candidate paths, the stored chain prefers, in order: every issuer
    valid now; a top anchored by one of the user's trust anchors or the system
    trust store; ending at a self-signed root in the bag; issuers that stay
    valid longest; fewer certificates. Validity comes first because the
    earliest expiry across the stored chain is the upload's effective expiry:
    an expired cross-sign must not make a valid upload read as expired. The
    alternative copies are not stored.
    """
    current_time = now or datetime.now(UTC)
    unique = deduplicate_chain(certs)
    count = len(unique)
    parents: list[set[int]] = []
    for child, certificate in enumerate(unique):
        if _is_self_signed(certificate):
            parents.append(set())  # a root, or self-issued: the path ends here
            continue
        parents.append({
            parent
            for parent, issuer in enumerate(unique)
            if parent != child and validate_chain_order([certificate, issuer])
        })
    for candidates in parents:
        if len(candidates) > 1:
            keys = {_public_key_der(unique[index]) for index in candidates}
            if len(keys) != 1 or None in keys:
                return None
    issuers = {parent for candidates in parents for parent in candidates}
    leaves = set(range(count)) - issuers
    if len(leaves) != 1:
        return None
    leaf = leaves.pop()

    paths: list[list[int]] = []
    visited: set[int] = set()
    steps = 0

    def walk(path: list[int]) -> bool:
        nonlocal steps
        steps += 1
        if steps > _PKCS7_PATH_STEPS:
            return False
        current = path[-1]
        visited.add(current)
        if not parents[current]:
            paths.append(list(path))
            return True
        # A parent already on the path is a cycle; that branch has no end.
        for parent in sorted(parents[current] - set(path)):
            path.append(parent)
            if not walk(path):
                return False
            path.pop()
        return True

    if not walk([leaf]) or not paths or len(visited) != count:
        return None

    def preference(path: list[int]) -> tuple[bool, bool, bool, datetime, int, list[str]]:
        chain = [unique[index] for index in path]
        issuers = chain[1:]
        valid_now = all(
            _utc(cert.not_before) <= current_time < _utc(cert.not_after) for cert in issuers
        )
        anchored = bool(issuers) and (
            _is_signature_anchored_by_user(chain, anchors) or _is_anchored_by_system_root(chain)
        )
        complete = bool(issuers) and _is_self_signed(chain[-1])
        issued_until = min(
            (_utc(cert.not_after) for cert in issuers),
            default=datetime.max.replace(tzinfo=UTC),
        )
        return (
            valid_now, anchored, complete, issued_until, -len(path),
            [cert.fingerprint_sha256 for cert in chain],
        )

    best = max(paths, key=preference)
    return [unique[index] for index in best]


def _is_self_signed(certificate: Certificate) -> bool:
    return _issuer_bytes(certificate) == _subject_bytes(certificate)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


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
             parent_cert_id, chain_valid, replaces_cert_id, tags,
             created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                 parent_cert_id, chain_valid, replaces_cert_id,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
