"""Role and local user management routes."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch.auth import _scrypt_hash
from cert_watch.auth.rbac import PERMISSION_TIERS
from cert_watch.database import (
    Role,
    SqliteRoleRepository,
    SqliteUserRepository,
    User,
    bump_session_version,
)
from cert_watch.middleware import check_csrf, require_admin_form
from cert_watch.routes._deps import IdParam, _db_path, get_templates
from cert_watch.routes.settings.render import _settings_context

templates = get_templates()

router = APIRouter()


def _normalize_permission_tier(tier: str) -> str:
    tier = (tier or "").strip().lower()
    return tier if tier in PERMISSION_TIERS else "viewer"


def _normalize_scope_tag(tag: str) -> str:
    from cert_watch.tags import format_tags, parse_tags

    return format_tags(parse_tags(tag))


def _normalize_alert_group_id(value: str) -> str | None:
    """Normalize the alert_group_id form field: empty string → None."""
    value = (value or "").strip()
    return value or None


# ---------- Role management ----------


@router.get("/settings/roles", response_class=HTMLResponse, response_model=None)
def roles_page(request: Request) -> HTMLResponse | RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    db = _db_path(request)
    roles = SqliteRoleRepository(db).list_all()
    ctx = _settings_context(request, tab="roles")
    ctx["roles"] = roles
    ctx["users"] = []
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=ctx,
    )


@router.post("/settings/roles")
async def create_role(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=roles&error={csrf_err}", status_code=303)

    form = await request.form()
    name = str(form.get("name") or "").strip()
    email = str(form.get("email") or "").strip()
    description = str(form.get("description") or "").strip()
    permission_tier = _normalize_permission_tier(str(form.get("permission_tier") or ""))
    scope_tag = _normalize_scope_tag(str(form.get("scope_tag") or ""))
    alert_group_id = _normalize_alert_group_id(str(form.get("alert_group_id") or ""))
    if not name:
        return RedirectResponse(url="/settings?tab=roles&error=role+name+required", status_code=303)

    role = Role(
        name=name, email=email, description=description,
        permission_tier=permission_tier, scope_tag=scope_tag,
        alert_group_id=alert_group_id,
    )
    SqliteRoleRepository(_db_path(request)).add(role)
    return RedirectResponse(url="/settings?tab=roles&saved=1", status_code=303)


@router.post("/settings/roles/{role_id}")
async def update_role(role_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=roles&error={csrf_err}", status_code=303)

    repo = SqliteRoleRepository(_db_path(request))
    role = repo.get(role_id)
    if role is None:
        return RedirectResponse(url="/settings?tab=roles&error=role+not+found", status_code=303)

    form = await request.form()
    name = str(form.get("name") or "").strip()
    if not name:
        return RedirectResponse(url="/settings?tab=roles&error=role+name+required", status_code=303)
    role.name = name
    role.email = str(form.get("email") or "").strip()
    role.description = str(form.get("description") or "").strip()
    role.permission_tier = _normalize_permission_tier(str(form.get("permission_tier") or ""))
    role.scope_tag = _normalize_scope_tag(str(form.get("scope_tag") or ""))
    role.alert_group_id = _normalize_alert_group_id(str(form.get("alert_group_id") or ""))
    repo.update(role)
    # Invalidate active sessions for all users with this role — a permission
    # tier or scope change must take effect immediately, not at TTL expiry.
    db = _db_path(request)
    for username in SqliteUserRepository(db).list_usernames_by_role_id(role_id):
        bump_session_version(db, username)
    return RedirectResponse(url="/settings?tab=roles&saved=1", status_code=303)


@router.post("/settings/roles/{role_id}/delete")
async def delete_role(role_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=roles&error={csrf_err}", status_code=303)

    db = _db_path(request)
    # Invalidate active sessions for all users with this role before the role
    # is deleted (delete() clears their role_id).
    for username in SqliteUserRepository(db).list_usernames_by_role_id(role_id):
        bump_session_version(db, username)
    SqliteRoleRepository(db).delete(role_id)
    return RedirectResponse(url="/settings?tab=roles&saved=1", status_code=303)


# ---------- User management ----------


@router.get("/settings/users", response_class=HTMLResponse, response_model=None)
def users_page(request: Request) -> HTMLResponse | RedirectResponse:
    redirect_resp = require_admin_form(request)
    if redirect_resp:
        return redirect_resp
    db = _db_path(request)
    users = SqliteUserRepository(db).list_all()
    roles = SqliteRoleRepository(db).list_all()
    ctx = _settings_context(request, tab="users")
    ctx["users"] = users
    ctx["roles"] = roles
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context=ctx,
    )


@router.post("/settings/users")
async def create_user(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=users&error={csrf_err}", status_code=303)

    form = await request.form()
    username = str(form.get("username") or "").strip()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "").strip()
    role_id = str(form.get("role_id") or "").strip()
    if not username or not password:
        return RedirectResponse(
            url="/settings?tab=users&error=username+and+password+required", status_code=303
        )
    if ":" in username:
        return RedirectResponse(
            url="/settings?tab=users&error=username+must+not+contain+colons", status_code=303
        )
    if len(password) < 8:
        return RedirectResponse(
            url="/settings?tab=users&error=password+must+be+at+least+8+characters", status_code=303
        )

    user = User(
        username=username,
        email=email,
        password_hash=_scrypt_hash(password),
        role_id=role_id,
    )
    SqliteUserRepository(_db_path(request)).add(user)
    return RedirectResponse(url="/settings?tab=users&saved=1", status_code=303)


@router.post("/settings/users/{user_id}")
async def update_user(user_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=users&error={csrf_err}", status_code=303)

    repo = SqliteUserRepository(_db_path(request))
    user = repo.get(user_id)
    if user is None:
        return RedirectResponse(url="/settings?tab=users&error=user+not+found", status_code=303)

    form = await request.form()
    username = str(form.get("username") or "").strip()
    email = str(form.get("email") or "").strip()
    password = str(form.get("password") or "").strip()
    role_id = str(form.get("role_id") or "").strip()
    if not username:
        return RedirectResponse(
            url="/settings?tab=users&error=username+required", status_code=303
        )
    if ":" in username:
        return RedirectResponse(
            url="/settings?tab=users&error=username+must+not+contain+colons", status_code=303
        )
    user.username = username
    user.email = email
    user.role_id = role_id
    # Password is optional on edit: only re-hash when a new one is supplied,
    # otherwise the existing hash is kept.
    db = _db_path(request)
    if password:
        if len(password) < 8:
            return RedirectResponse(
                url="/settings?tab=users&error=password+must+be+at+least+8+characters",
                status_code=303,
            )
        user.password_hash = _scrypt_hash(password)
    repo.update(user)
    # Invalidate active sessions for this user — a password change or role
    # reassignment must take effect immediately, not at TTL expiry.
    bump_session_version(db, username)
    return RedirectResponse(url="/settings?tab=users&saved=1", status_code=303)


@router.post("/settings/users/{user_id}/delete")
async def delete_user(user_id: IdParam, request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=users&error={csrf_err}", status_code=303)

    db = _db_path(request)
    repo = SqliteUserRepository(db)
    user = repo.get(user_id)
    # Invalidate the user's active sessions BEFORE deleting the row — after
    # deletion there's no username to bump. A deleted user's cookie must not
    # keep working until TTL expiry.
    if user:
        bump_session_version(db, user.username)
    repo.delete(user_id)
    return RedirectResponse(url="/settings?tab=users&saved=1", status_code=303)
