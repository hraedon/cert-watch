"""Team dashboard route."""

from __future__ import annotations

import logging
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from cert_watch import __commit__, __version__
from cert_watch.database import team_dashboard_data
from cert_watch.database.users_roles import SqliteRoleRepository, SqliteUserRepository
from cert_watch.middleware import get_auth_context, get_csrf_context, require_auth
from cert_watch.routes._deps import _db_path, get_templates

logger = logging.getLogger("cert_watch.routes.team")

router = APIRouter()

templates = get_templates()


@router.get("/team", response_class=HTMLResponse, dependencies=[Depends(require_auth)])
def team_dashboard(request: Request, page: int = 1) -> HTMLResponse:
    db = _db_path(request)
    username = request.scope.get("auth_user", "")
    per_page = 25

    has_role = False
    role_name = ""
    role_email = ""

    try:
        user_repo = SqliteUserRepository(db)
        role_repo = SqliteRoleRepository(db)
        user = user_repo.get_by_username(username) if username else None
        role = role_repo.get(user.role_id) if user and user.role_id else None
        has_role = role is not None and bool(role.email)
        role_name = role.name if role else ""
        role_email = role.email if role else ""
    except (ImportError, sqlite3.Error):
        logger.warning("Team dashboard: user/role lookup failed", exc_info=True)
        has_role = False

    entries: list[dict[str, Any]] = []
    stats = {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}
    total_entries = 0
    total_pages = 1

    if has_role:
        data = team_dashboard_data(db, role_email, page=page, per_page=per_page)
        entries = data["entries"]
        stats = data["stats"]
        total_entries = data["total"]
        total_pages = data["total_pages"]
        page = data["page"]

    auth_ctx = get_auth_context(request)
    csrf_ctx = get_csrf_context(request)

    return templates.TemplateResponse(
        request=request,
        name="team_dashboard.html",
        context={
            "version": __version__, "commit": __commit__,
            **auth_ctx,
            **csrf_ctx,
            "active_page": "team",
            "has_role": has_role,
            "role_name": role_name,
            "role_email": role_email,
            "entries": entries,
            "stats": stats,
            "total_entries": total_entries,
            "page": page,
            "total_pages": total_pages,
            "has_prev": page > 1,
            "has_next": page < total_pages,
        },
    )
