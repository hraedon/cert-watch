"""Certificate detail, delete, notes, upload, and trust anchor routes."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.cert_chain import validate_is_ca_certificate
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteTrustAnchorRepository,
    _connect,
    _row_to_cert,
    delete_certificate_cascade,
)
from cert_watch.filters import (
    compute_urgency,
    friendly_issuer,
    issuer_cn,
    register_filters,
    subject_cn,
)
from cert_watch.middleware import check_csrf, check_rate_limit, get_csrf_context
from cert_watch.upload import ParseError, store_uploaded, upload_certificate

logger = logging.getLogger("cert_watch.routes.certificates")

router = APIRouter()

BASE_DIR = Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_filters(templates)

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


@router.get("/certificates/{cert_id}", response_class=HTMLResponse)
def certificate_detail(request: Request, cert_id: str) -> HTMLResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    # Parse key type and signature algorithm from raw DER
    try:
        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        key_info = x509_cert.public_key()
        key_type_str = type(key_info).__name__
        try:
            if isinstance(key_info, rsa.RSAPublicKey):
                key_type_str = f"RSA {key_info.key_size}"
            elif isinstance(key_info, ec.EllipticCurvePublicKey):
                key_type_str = f"ECDSA {key_info.curve.name}"
            elif isinstance(key_info, ed25519.Ed25519PublicKey):
                key_type_str = "Ed25519"
            elif isinstance(key_info, ed448.Ed448PublicKey):
                key_type_str = "Ed448"
        except Exception:
            pass
        sig_alg = x509_cert.signature_algorithm_oid._name
        serial = format(x509_cert.serial_number, 'X')
        serial = ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))
    except Exception:
        key_type_str = "unknown"
        sig_alg = "unknown"
        serial = "unknown"

    fp_hex = cert.fingerprint_sha256
    if ":" not in fp_hex and len(fp_hex) == 64:
        fp_hex = ':'.join(fp_hex[i:i+2] for i in range(0, len(fp_hex), 2)).upper()

    # Get chain (non-leaf certs with this cert as parent)
    with _connect(db) as conn:
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ? AND is_leaf = 0",
            (cert_id,),
        ).fetchall()

    chain_certs = []
    for cr in chain_rows:
        c = _row_to_cert(cr)
        chain_days = c.days_until_expiry()
        # Determine key type from raw DER
        kt = "unknown"
        try:
            x509_chain = x509.load_der_x509_certificate(c.raw_der)
            k = x509_chain.public_key()
            kt = type(k).__name__
            if isinstance(k, rsa.RSAPublicKey):
                kt = f"RSA {k.key_size}"
            elif isinstance(k, ec.EllipticCurvePublicKey):
                kt = f"ECDSA {k.curve.name}"
            elif isinstance(k, ed25519.Ed25519PublicKey):
                kt = "Ed25519"
            elif isinstance(k, ed448.Ed448PublicKey):
                kt = "Ed448"
        except Exception:
            pass
        chain_certs.append({
            "id": cr["id"],
            "subject": c.subject,
            "issuer": c.issuer,
            "not_after": c.not_after.isoformat(),
            "days_remaining": chain_days,
            "subject_cn": subject_cn(c.subject),
            "issuer_org": friendly_issuer(c.issuer),
            "key_type": kt,
        })

    # Determine chain status
    from cert_watch.cert_chain import chain_status as _chain_status
    anchors = SqliteTrustAnchorRepository(db).list_entries()
    chain_certs_objects = [_row_to_cert(cr) for cr in chain_rows]
    cs = _chain_status(cert, chain_certs_objects, anchors)

    # Compute urgency from the cert and chain
    leaf_days = cert.days_until_expiry()
    all_chain_days = [c["days_remaining"] for c in chain_certs]
    worst_days = min([leaf_days] + all_chain_days) if all_chain_days else leaf_days
    urgency = compute_urgency(worst_days)

    # Get host info if scanned
    hostname = ""
    port = 443
    with _connect(db) as conn:
        host_row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        if host_row:
            hostname = host_row["hostname"] or ""
            port = host_row["port"] or 443

    # Get last scan time
    last_scan = None
    if hostname:
        with _connect(db) as conn:
            scan_row = conn.execute(
                "SELECT scanned_at FROM scan_history "
                "WHERE hostname = ? AND port = ? "
                "ORDER BY scanned_at DESC LIMIT 1",
                (hostname, port),
            ).fetchone()
            if scan_row:
                last_scan = scan_row["scanned_at"]

    ctx = get_csrf_context(request)
    from datetime import UTC, datetime

    return templates.TemplateResponse(
        request=request,
        name="certificate_detail.html",
        context={
            "cert": cert,
            "cert_id": cert_id,
            "version": __version__,
            "auth_user": request.scope.get("auth_user", ""),
            "active_page": "dashboard",
            "key_type": key_type_str,
            "sig_alg": sig_alg,
            "serial": serial,
            "fingerprint": fp_hex,
            "chain": chain_certs,
            "chain_status": cs,
            "urgency": urgency,
            "days_remaining": leaf_days,
            "subject_cn": subject_cn(cert.subject),
            "issuer_org": friendly_issuer(cert.issuer),
            "issuer_cn": issuer_cn(cert.issuer),
            "hostname": hostname,
            "port": port,
            "last_scan": last_scan,
            "source": cert.san_dns_names,
            "now": datetime.now(UTC),
            **ctx,
        },
    )


@router.post("/certificates/{cert_id}/delete")
async def delete_certificate(request: Request, cert_id: str) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    db = _db_path(request)
    delete_certificate_cascade(db, cert_id)
    logger.info("deleted certificate %s (cascade)", cert_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/certificates/{cert_id}/notes")
async def update_certificate_notes(
    request: Request, cert_id: str, notes: str = Form(...)
) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if len(notes) > 10000:
        return RedirectResponse(
            url=f"/?error={quote('notes too long (max 10000)')}", status_code=303
        )
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    if repo.get_by_id(cert_id) is None:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    repo.update_notes(cert_id, notes)
    logger.info("updated notes for certificate %s", cert_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),  # noqa: B008
) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not check_rate_limit(f"upload:{request.client.host}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)
    allowed_suffixes = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12", ".p7b", ".p7c"}
    raw_suffix = Path(file.filename or "uploaded").suffix.lower()
    suffix = raw_suffix if raw_suffix in allowed_suffixes else ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            return RedirectResponse(
                url=f"/?error={quote('file too large (max 10 MB)')}", status_code=303
            )
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        pw_bytes = password.encode("utf-8") if password else None
        entry = upload_certificate(tmp_path, password=pw_bytes)
        if isinstance(entry, ParseError):
            return RedirectResponse(
                url=f"/?error={quote(entry.error_message)}", status_code=303
            )
        entry.file_name = file.filename or entry.file_name
        store_uploaded(entry, db)
        logger.info("uploaded certificate: %s", file.filename or "unknown")
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors")
async def add_trust_anchor(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    db = _db_path(request)
    allowed_suffixes = {".pem", ".crt", ".cer", ".der"}
    raw_suffix = Path(file.filename or "uploaded").suffix.lower()
    suffix = raw_suffix if raw_suffix in allowed_suffixes else ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            return RedirectResponse(
                url=f"/?error={quote('file too large (max 10 MB)')}", status_code=303
            )
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        entry = upload_certificate(tmp_path)
        if isinstance(entry, ParseError):
            return RedirectResponse(
                url=f"/?error={quote(entry.error_message)}", status_code=303
            )
        # Validate that the certificate is suitable as a CA trust anchor
        ca_err = validate_is_ca_certificate(entry.leaf.raw_der)
        if ca_err:
            return RedirectResponse(
                url=f"/?error={quote('Invalid trust anchor: ' + ca_err)}", status_code=303
            )
        # Store as a trust anchor (not a certificate for monitoring)
        repo = SqliteTrustAnchorRepository(db)
        repo.add(entry.leaf)
        logger.info("uploaded trust anchor: %s", entry.leaf.subject)
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors/{anchor_id}/delete")
async def delete_trust_anchor(request: Request, anchor_id: str) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    db = _db_path(request)
    repo = SqliteTrustAnchorRepository(db)
    repo.delete(anchor_id)
    logger.info("deleted trust anchor %s", anchor_id)
    return RedirectResponse(url="/", status_code=303)
