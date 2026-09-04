"""Audit log read surface — HTML and JSON."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import count_audit, list_audit
from cert_watch.middleware import get_auth_context, require_admin, require_admin_form
from cert_watch.routes._deps import _db_path, get_templates

logger = logging.getLogger("cert_watch.routes.audit")

router = APIRouter()

templates = get_templates()


# Admin-gated (plan 055 / C5): the audit log carries actor IPs and actions
# across the whole fleet, which a tag-scoped viewer must not see.
@router.get("/audit", response_class=HTMLResponse, response_model=None)
def audit_page(
    request: Request,
    target_type: str = "",
    actor: str = "",
    page: int = 1,
) -> HTMLResponse | RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err
    db = _db_path(request)
    limit = 50
    total = count_audit(db, target_type=target_type or None, actor=actor or None)
    total_pages = max((total + limit - 1) // limit, 1)
    page = max(1, min(page, total_pages))
    rows = list_audit(
        db,
        target_type=target_type or None,
        actor=actor or None,
        page=page,
        limit=limit,
    )
    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "rows": rows,
            "version": __version__,
            "commit": __commit__,
            **get_auth_context(request),
            "active_page": "activity",
            "tab": "audit",
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
    _auth: str = Depends(require_admin),
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
