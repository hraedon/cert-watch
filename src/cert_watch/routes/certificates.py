"""Certificate detail, delete, upload, and trust anchor routes."""

from __future__ import annotations

import logging
from pathlib import Path
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import (
    admin_form_guard,
    get_auth_context,
    write_form_guard,
)
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.database import resolve_current_certificate
from cert_watch.presenters.certificate_detail import present_certificate_detail
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth, get_templates
from cert_watch.routes._scoped import (
    scope_read_denied,
    scope_tags_from_auth,
    superseded_redirect,
    tags_with_scope,
)
from cert_watch.routes.hosts import endpoint_settings_writable
from cert_watch.security.csrf import get_csrf_context
from cert_watch.security.ratelimit import _extract_client_ip, check_rate_limit
from cert_watch.services.certificate_detail import (
    PendingHostDetailData,
    load_certificate_detail,
)
from cert_watch.services.certificate_identity import (
    CertificateNotFoundError,
    CertificateSupersededError,
)
from cert_watch.services.certificate_management import (
    CertificateValidationError,
    upload_certificate_bytes,
)
from cert_watch.services.certificate_management import (
    add_trust_anchor as add_trust_anchor_service,
)
from cert_watch.services.certificate_management import (
    delete_certificate as delete_certificate_service,
)
from cert_watch.services.certificate_management import (
    delete_trust_anchor as delete_trust_anchor_service,
)
from cert_watch.services.host_ownership import (
    HostNotFoundError,
    HostOwnershipTargetError,
    HostOwnershipUpdate,
    HostOwnershipValidationError,
    resolve_host_ownership_target,
    update_host_ownership,
)
from cert_watch.services.resource_metadata import (
    ResourceMetadataNotFoundError,
    ResourceMetadataValidationError,
)
from cert_watch.services.resource_metadata import (
    update_certificate_tags as persist_certificate_tags,
)
from cert_watch.status_model import AxisSettings

logger = logging.getLogger("cert_watch.routes.certificates")

router = APIRouter()

templates = get_templates()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


def _redirect_to_current_certificate(
    request: Request, db: Path, stale_id: str
) -> RedirectResponse | None:
    """Send a stale certificate id, or a host id, to the endpoint's current
    certificate (#113): ids change on renewal, and links must survive that.

    The target is authorized before its id is revealed; an out-of-scope
    target answers exactly like an unknown id.
    """
    ref = resolve_current_certificate(db, stale_id)
    if ref is None:
        return None
    if scope_read_denied(request, db, cert_id=ref.cert_id):
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    params = [
        (key, value)
        for key, value in request.query_params.multi_items()
        if key != "superseded"
    ]
    if ref.superseded:
        params.append(("superseded", "1"))
    query = f"?{urlencode(params)}" if params else ""
    return RedirectResponse(url=f"/certificates/{ref.cert_id}{query}", status_code=303)


@router.get("/certificates/{cert_id}", response_class=HTMLResponse, response_model=None)
def certificate_detail(request: Request, cert_id: IdParam) -> HTMLResponse | RedirectResponse:
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    settings = _get_settings(request)
    data = load_certificate_detail(
        db,
        cert_id,
        scope_tags=scope_tags,
        sched_hour=settings.sched_hour,
        sched_min=settings.sched_min,
        axis_settings=AxisSettings.from_settings(settings),
    )
    if data is None or isinstance(data, PendingHostDetailData):
        moved = _redirect_to_current_certificate(request, db, cert_id)
        if moved is not None:
            return moved
    if data is None:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    denied = (
        scope_read_denied(request, db, host_id=cert_id)
        if isinstance(data, PendingHostDetailData)
        else scope_read_denied(request, db, cert_id=cert_id)
    )
    if denied:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    host_id = data.host.id if data.host is not None else ""
    view = present_certificate_detail(
        data,
        settings_writable=(
            endpoint_settings_writable(request, db, host_id) if host_id else False
        ),
        slack_configured=settings.webhook_kind == "slack",
        endpoint_saved=bool(request.query_params.get("endpoint_saved")),
        endpoint_error=request.query_params.get("endpoint_error", ""),
        superseded=bool(request.query_params.get("superseded")),
        scanned=bool(request.query_params.get("scanned")),
        added=bool(request.query_params.get("added")),
    )
    return templates.TemplateResponse(
        request=request,
        name="certificate_detail.html",
        context={
            **view.template_context(),
            "version": __version__,
            "commit": __commit__,
            **get_auth_context(request),
            "active_page": "browse",
            # Flash messages from actions that return here (tags, owner,
            # Scan now); base.html renders them.
            "error": request.query_params.get("error", ""),
            "warning": request.query_params.get("warning", ""),
            **get_csrf_context(request),
        },
    )


@router.post("/certificates/{cert_id}/delete")
async def delete_certificate(
    request: Request, cert_id: IdParam, _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        deleted = delete_certificate_service(
            db,
            cert_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except CertificateSupersededError as exc:
        return superseded_redirect(exc)
    except CertificateNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    if not deleted:
        # It used to land Home with no message, as if it had deleted.
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    logger.info("deleted certificate %s (cascade)", cert_id)
    return RedirectResponse(url="/", status_code=303)


# Note: POST /certificates/{id}/notes was removed (UI-INVENTORY V1). Notes are
# a host-scoped concept now — the single write surface is POST /hosts/{id}/notes.

@router.post("/certificates/{cert_id}/tags")
async def update_certificate_tags(
    request: Request, cert_id: IdParam, tags: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        persist_certificate_tags(
            db,
            cert_id,
            tags,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except ResourceMetadataValidationError as exc:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(str(exc))}", status_code=303,
        )
    except ResourceMetadataNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    except CertificateSupersededError as exc:
        return superseded_redirect(exc)
    except CertificateNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    logger.info("updated tags for certificate %s", cert_id)
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=303)


@router.post("/certificates/{cert_id}/owner")
async def update_certificate_owner(
    request: Request,
    cert_id: IdParam,
    owner_name: str = Form(""),
    owner_email: str = Form(""),
    owner_slack: str = Form(""),
    renewal_method: str = Form(""),
    runbook_url: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"cert_owner:{_extract_client_ip(request)}", 30, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)

    try:
        target = resolve_host_ownership_target(db, cert_id, auth=acting_auth(request))
    except CertificateSupersededError as exc:
        return superseded_redirect(exc)
    except CertificateNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except HostOwnershipTargetError as exc:
        if exc.reason == "resource_not_found":
            return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
        message = (
            "no host associated" if exc.reason == "no_host_associated" else "host not found"
        )
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(message)}", status_code=303,
        )

    host_id = target.host_id
    try:
        update_host_ownership(
            db,
            target,
            HostOwnershipUpdate(
                owner_name=owner_name,
                owner_email=owner_email,
                owner_slack=owner_slack,
                renewal_method=renewal_method,
                runbook_url=runbook_url,
            ),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except HostOwnershipValidationError as exc:
        message = "invalid renewal method" if exc.field == "renewal_method" else str(exc)
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote(message)}", status_code=303,
        )
    except HostNotFoundError:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote('host not found')}", status_code=303,
        )
    except CertificateSupersededError as exc:
        return superseded_redirect(exc)
    except CertificateNotFoundError:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    except HostOwnershipTargetError:
        # Renewed away between resolving the target and the write, to a
        # certificate the caller can't see: the unknown-id answer.
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    logger.info("updated owner for host %s via certificate %s", host_id, cert_id)
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=303)


@router.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"upload:{_extract_client_ip(request)}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        upload_certificate_bytes(
            _db_path(request),
            content,
            file.filename or "uploaded",
            password,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            tags=tags_with_scope(request, ""),
        )
    except (CertificateValidationError, ScopeDeniedError) as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors")
async def add_trust_anchor(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    _auth: str = Depends(admin_form_guard),
) -> RedirectResponse:
    # #65: a trust anchor changes chain validation for the whole fleet, so it
    # is admin-only (like the /settings/trust-anchors page), not write-gated.
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    try:
        add_trust_anchor_service(
            _db_path(request),
            content,
            file.filename or "uploaded",
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except CertificateValidationError as exc:
        return RedirectResponse(
            url=f"/settings/trust-anchors?error={quote(str(exc))}", status_code=303,
        )
    return RedirectResponse(url="/settings/trust-anchors?saved=1", status_code=303)


@router.post("/trust-anchors/{anchor_id}/delete")
async def delete_trust_anchor(
    request: Request, anchor_id: IdParam,
    _auth: str = Depends(admin_form_guard),  # #65: admin-only
) -> RedirectResponse:
    delete_trust_anchor_service(
        _db_path(request),
        anchor_id,
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
    )
    logger.info("deleted trust anchor %s", anchor_id)
    return RedirectResponse(url="/settings/trust-anchors?saved=1", status_code=303)
