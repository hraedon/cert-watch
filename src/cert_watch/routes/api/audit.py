"""Audit-log JSON API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from cert_watch.audit import count_audit, list_audit
from cert_watch.auth.guards import require_admin
from cert_watch.routes._deps import _db_path

router = APIRouter()


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
    filters = {
        "target_type": target_type or None,
        "target_id": target_id or None,
        "actor": actor or None,
    }
    rows = list_audit(db, page=page, limit=limit, **filters)
    total = count_audit(db, **filters)
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
