"""Scan history and CAA check routes."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.auth.guards import get_auth_context, require_auth
from cert_watch.caa_check import (
    _DOMAIN_RE,
    _MAX_DOMAIN_LEN,
)
from cert_watch.database import list_scan_batches
from cert_watch.routes._deps import _db_path, get_templates
from cert_watch.routes._scoped import scope_tags_from_auth
from cert_watch.security.csrf import get_csrf_context
from cert_watch.security.ratelimit import rate_limit

logger = logging.getLogger("cert_watch.routes.scan_history")

router = APIRouter()

templates = get_templates()


@router.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    per_page = 20
    # Scope-filtered like the dashboard and alerts: a tag-scoped user must not
    # see other teams' hostnames or scan errors. Admins/unscoped get ().
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    rows, total = list_scan_batches(
        db, page=page, per_page=per_page, scope_tags=scope_tags,
    )
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    return templates.TemplateResponse(
        request=request,
        name="activity.html",
        context={
            "batches": rows,
            "version": __version__, "commit": __commit__,
            **get_auth_context(request),
            **get_csrf_context(request),
            "active_page": "activity",
            "notice": request.query_params.get("notice", ""),
            "tab": "scans",
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )


@router.get(
    "/caa-check/{domain}",
    dependencies=[Depends(require_auth), Depends(rate_limit("caa", 10, 60))],
)
def caa_check_view(request: Request, domain: str) -> dict[str, Any]:
    """FEAT-010: Return CAA records and issuance policy for a domain."""
    if not domain or len(domain) > _MAX_DOMAIN_LEN or not _DOMAIN_RE.match(domain):
        return {"domain": domain, "error": "invalid domain"}

    from cert_watch.caa_check import check_caa

    result = check_caa(domain)
    if result.error:
        return {"domain": domain, "error": result.error}
    return {
        "domain": domain,
        "records": result.records,
        "issue_allowed": result.issue_allowed,
        "issuewild_allowed": result.issuewild_allowed,
    }
