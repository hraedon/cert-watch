"""Certificate API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import (
    admin_write_guard,
    json_write_guard,
    require_auth,
    write_guard,
)
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.database import (
    SqliteCertificateRepository,
    list_cert_history,
    list_dashboard_page,
)
from cert_watch.posture import check_revocation_endpoints
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth
from cert_watch.routes._scoped import scope_read_denied, scope_tags_from_auth
from cert_watch.routes.api._shared import (
    JsonBodyError,
    _normalize_pagination,
    _pagination_links,
    tags_from_json_body,
)
from cert_watch.security.ratelimit import rate_limit
from cert_watch.services.certificate_management import (
    MAX_UPLOAD_BYTES,
    CertificateValidationError,
    add_trust_anchor,
    delete_certificate,
    delete_trust_anchor,
    upload_certificate_bytes,
)
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    ResourceMetadataValidationError,
    update_certificate_tags,
)
from cert_watch.tags import parse_tags

logger = logging.getLogger("cert_watch.routes.api.certificates")

router = APIRouter()


@router.post("/api/certificates/upload")
async def api_upload_certificate(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    password: str | None = Form(None),
    _auth: str = Depends(write_guard),
    _rl: None = Depends(rate_limit("upload", 10, 60)),
) -> JSONResponse:
    try:
        result = upload_certificate_bytes(
            _db_path(request),
            await file.read(MAX_UPLOAD_BYTES + 1),
            file.filename or "uploaded",
            password,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except (CertificateValidationError, ScopeDeniedError) as exc:
        status = 403 if isinstance(exc, ScopeDeniedError) else 400
        return JSONResponse(status_code=status, content={"error": str(exc)})
    return JSONResponse(status_code=201, content={"id": result.id, "filename": result.filename})


@router.post("/api/trust-anchors")
async def api_add_trust_anchor(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    _auth: str = Depends(admin_write_guard),
) -> JSONResponse:
    try:
        result = add_trust_anchor(
            _db_path(request),
            await file.read(MAX_UPLOAD_BYTES + 1),
            file.filename or "uploaded",
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except CertificateValidationError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "admin required"})
    return JSONResponse(status_code=201, content={"id": result.id, "filename": result.filename})


@router.delete("/api/trust-anchors/{anchor_id}")
async def api_delete_trust_anchor(
    anchor_id: IdParam,
    request: Request,
    _auth: str = Depends(admin_write_guard),
) -> JSONResponse:
    try:
        deleted = delete_trust_anchor(
            _db_path(request),
            anchor_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except PermissionError:
        return JSONResponse(status_code=403, content={"error": "admin required"})
    if not deleted:
        return JSONResponse(status_code=404, content={"error": "trust anchor not found"})
    return JSONResponse(content={"status": "deleted", "id": anchor_id})


@router.get("/api/certificates")
def api_list_certificates(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    # Clamp limit to [1,200] BEFORE querying so the SQL LIMIT is bounded — a
    # raw client-supplied limit would otherwise materialize the entire
    # inventory into memory (BC-047 style inventory-in-RAM regression).
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    rows, total = list_dashboard_page(
        db,
        page=page, per_page=limit,
        scope_tags=scope_tags,
    )
    page, limit, pages, _offset = _normalize_pagination(page, limit, total)
    # Re-normalize against the scoped total that came back from the query.
    return JSONResponse(
        content={
            "certificates": rows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": pages,
                **_pagination_links(request, "/api/certificates", page, limit, total),
            },
        }
    )


@router.get("/api/certificates/{cert_id}")
def api_get_certificate(
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(
        content={
            "id": cert_id,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "not_before": cert.not_before.isoformat(),
            "not_after": cert.not_after.isoformat(),
            "san_dns_names": cert.san_dns_names,
            "fingerprint_sha256": cert.fingerprint_sha256,
            "is_leaf": cert.is_leaf,
            "days_until_expiry": cert.days_until_expiry(),
            "tags": parse_tags(repo.get_tags(cert_id)),
            "effective_tags": repo.effective_tags(cert_id),
        }
    )


@router.get("/api/certificates/{cert_id}/posture", response_model=None)
def api_certificate_posture(
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)
) -> dict[str, object]:
    """Return the latest posture evaluation for a certificate as JSON."""
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return {"error": "not found", "cert_id": cert_id}
    from cert_watch.database import get_posture_for_cert

    posture = get_posture_for_cert(db, cert_id)
    if posture is None:
        return {"error": "no posture data", "cert_id": cert_id}
    return {
        "cert_id": cert_id,
        "grade": posture["grade"],
        "findings": posture["findings"],
        "protocol_version": posture.get("protocol_version", ""),
        "ocsp_stapling": posture.get("ocsp_stapling"),
        "hsts": posture.get("hsts"),
        "must_staple": posture.get("must_staple", False),
        "scanned_at": posture.get("scanned_at", ""),
    }


@router.delete("/api/certificates/{cert_id}")
async def api_delete_certificate(
    cert_id: IdParam, request: Request, _auth: str = Depends(write_guard)
) -> JSONResponse:
    try:
        deleted = delete_certificate(
            _db_path(request),
            cert_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    if not deleted:
        return JSONResponse(status_code=404, content={"error": "certificate not found"})
    return JSONResponse(content={"status": "deleted", "id": cert_id})


@router.get("/api/certificates/{cert_id}/pem")
def api_download_pem(
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return PlainTextResponse("not found", status_code=404)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return PlainTextResponse("not found", status_code=404)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        pem = x509_cert.public_bytes(Encoding.PEM)
    except (ValueError, TypeError):  # x509 encode
        return PlainTextResponse("cannot encode certificate", status_code=500)
    filename = f"cert-{cert_id[:8]}.pem"
    return PlainTextResponse(
        pem.decode(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Note: PATCH /api/certificates/{id}/notes was removed (UI-INVENTORY V1).
# Notes are host-scoped now: PATCH /api/hosts/{id}/notes is the JSON write path.

@router.get("/api/certificates/{cert_id}/history")
def api_cert_history(
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth), limit: int = 365
) -> JSONResponse:
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
    if row is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    history = list_cert_history(db, row["hostname"], row["port"], limit=min(max(limit, 1), 1000))
    return JSONResponse(content={"cert_id": cert_id, "history": history})


@router.get("/api/certificates/{cert_id}/revocation")
def api_check_revocation(
    request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Check OCSP/CRL endpoint reachability for a certificate on demand."""
    db = _db_path(request)
    denied = scope_read_denied(request, db, cert_id=cert_id)
    if denied:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    s = _get_settings(request)
    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    if not cert.raw_der:
        return JSONResponse(content={"error": "certificate has no raw data"}, status_code=400)
    findings = check_revocation_endpoints(
        cert.raw_der,
        allow_private=s.allow_private,
        allowed_subnets=s.allowed_subnets,
    )
    return JSONResponse(
        content={
            "cert_id": cert_id,
            "findings": [
                {"check": f.check, "status": f.status, "message": f.message}
                for f in findings
            ],
        }
    )


# ---------- Tags ----------


@router.get("/api/tags")
def api_list_tags(request: Request, _auth: str = Depends(require_auth)) -> JSONResponse:
    from cert_watch.database import distinct_tags

    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    return JSONResponse(content={"tags": distinct_tags(_db_path(request), scope_tags=scope_tags)})


@router.put("/api/certificates/{cert_id}/tags")
async def api_set_cert_tags(
    cert_id: IdParam, request: Request, _auth: str = Depends(json_write_guard)
) -> JSONResponse:
    db = _db_path(request)
    raw = await request.body()
    try:
        result = update_certificate_tags(
            db,
            cert_id,
            lambda: tags_from_json_body(raw),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    except (JsonBodyError, ResourceMetadataValidationError) as exc:
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except ResourceMetadataNotFoundError:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(
        content={
            "id": cert_id,
            "tags": list(result.tags),
            "effective_tags": list(result.effective_tags),
        }
    )
