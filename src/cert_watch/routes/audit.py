"""Audit log read surface — HTML and JSON."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import count_audit, list_audit
from cert_watch.middleware import get_auth_context, require_auth
from cert_watch.routes._deps import _db_path, get_templates

logger = logging.getLogger("cert_watch.routes.audit")

router = APIRouter()

templates = get_templates()


@router.get("/audit", response_class=HTMLResponse)
def audit_page(
    request: Request,
    target_type: str = "",
    actor: str = "",
    page: int = 1,
) -> HTMLResponse:
    db = _db_path(request)
    limit = 50
    rows = list_audit(
        db,
        target_type=target_type or None,
        actor=actor or None,
        page=page,
        limit=limit,
    )
    total = count_audit(db, target_type=target_type or None, actor=actor or None)
    total_pages = max((total + limit - 1) // limit, 1)
    return templates.TemplateResponse(
        request=request,
        name="audit.html",
        context={
            "rows": rows,
            "version": __version__,
            "commit": __commit__,
            **get_auth_context(request),
            "active_page": "audit",
            "filter_target_type": target_type,
            "filter_actor": actor,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


@router.get("/api/audit")
def api_audit(
    request: Request,
    _auth: str = Depends(require_auth),
    target_type: str = "",
    target_id: str = "",
    actor: str = "",
    page: int = 1,
    limit: int = 50,
) -> JSONResponse:
    db = _db_path(request)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    rows = list_audit(
        db,
        target_type=target_type or None,
        target_id=target_id or None,
        actor=actor or None,
        page=page,
        limit=limit,
    )
    total = count_audit(
        db,
        target_type=target_type or None,
        target_id=target_id or None,
        actor=actor or None,
    )
    return JSONResponse(
        content={
            "audit": rows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "pages": (total + limit - 1) // limit if limit else 0,
            },
        }
    )
