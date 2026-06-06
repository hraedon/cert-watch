"""Certificate API endpoints."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import (
    SqliteCertificateRepository,
    count_dashboard_leaves,
    list_cert_history,
    list_dashboard_rows,
)
from cert_watch.middleware import require_auth, require_write
from cert_watch.posture import check_revocation_endpoints
from cert_watch.routes._deps import _db_path, _get_settings
from cert_watch.routes.api._shared import (
    _normalize_pagination,
    _pagination_links,
    _tags_from_body,
)
from cert_watch.tags import parse_tags

logger = logging.getLogger("cert_watch.routes.api.certificates")

router = APIRouter()


@router.get("/api/certificates")
def api_list_certificates(
    request: Request, _auth: str = Depends(require_auth), page: int = 1, limit: int = 50
) -> JSONResponse:
    db = _db_path(request)
    total = count_dashboard_leaves(db)
    page, limit, pages, _offset = _normalize_pagination(page, limit, total)
    rows = list_dashboard_rows(db, page=page, per_page=limit)
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
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    db = _db_path(request)

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
            "notes": cert.notes,
            "tags": parse_tags(repo.get_tags(cert_id)),
            "effective_tags": repo.effective_tags(cert_id),
        }
    )


@router.get("/api/certificates/{cert_id}/pem")
def api_download_pem(
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> PlainTextResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return PlainTextResponse("not found", status_code=404)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding

        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        pem = x509_cert.public_bytes(Encoding.PEM)
    except Exception:
        return PlainTextResponse("cannot encode certificate", status_code=500)
    filename = f"cert-{cert_id[:8]}.pem"
    return PlainTextResponse(
        pem.decode(),
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.patch("/api/certificates/{cert_id}/notes")
async def api_update_notes(
    cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    notes = body.get("notes", "")
    if not isinstance(notes, str):
        return JSONResponse(content={"error": "notes must be a string"}, status_code=400)
    if len(notes) > 10000:
        return JSONResponse(content={"error": "notes too long (max 10000)"}, status_code=400)
    repo.update_notes(cert_id, notes)
    record_audit(
        _db_path(request),
        actor=resolve_actor(request),
        action="cert.update_notes",
        target_type="certificate",
        target_id=cert_id,
        detail={"notes_length": len(notes)},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(content={"id": cert_id, "notes": notes})


@router.get("/api/certificates/{cert_id}/history")
def api_cert_history(
    request: Request, cert_id: str, _auth: str = Depends(require_auth), limit: int = 365
) -> JSONResponse:
    db = _db_path(request)
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
    request: Request, cert_id: str, _auth: str = Depends(require_auth)
) -> JSONResponse:
    """Check OCSP/CRL endpoint reachability for a certificate on demand."""
    db = _db_path(request)
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

    return JSONResponse(content={"tags": distinct_tags(_db_path(request))})


@router.put("/api/certificates/{cert_id}/tags")
async def api_set_cert_tags(
    cert_id: str, request: Request, _auth: str = Depends(require_write)
) -> JSONResponse:
    db = _db_path(request)
    repo = SqliteCertificateRepository(db)
    if repo.get_by_id(cert_id) is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    tags = _tags_from_body(body)
    if tags is None:
        return JSONResponse(
            content={"error": "tags must be a string or list of strings"}, status_code=400
        )
    repo.set_tags(cert_id, tags)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="cert.set_tags",
        target_type="certificate",
        target_id=cert_id,
        detail={"tags": tags},
        source_ip=resolve_source_ip(request),
    )
    return JSONResponse(
        content={
            "id": cert_id,
            "tags": parse_tags(tags),
            "effective_tags": repo.effective_tags(cert_id),
        }
    )
