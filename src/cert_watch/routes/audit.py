"""Audit log read surface — HTML and JSON."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import count_audit, list_audit
from cert_watch.auth.guards import (
    admin_page_guard,
    get_auth_context,
)
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
    _auth: str = Depends(admin_page_guard),
) -> HTMLResponse | RedirectResponse:
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
