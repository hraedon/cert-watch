"""Host CRUD, import, and scan routes."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse

from cert_watch.alerting import WebhookConfig
from cert_watch.audit import resolve_actor, resolve_source_ip
from cert_watch.auth.guards import (
    admin_form_guard,
    form_write_error,
    write_form_guard,
)
from cert_watch.auth.scope import ScopeDeniedError
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository
from cert_watch.host_validation import hostname_is_valid
from cert_watch.routes._deps import IdParam, _db_path, _get_settings, acting_auth
from cert_watch.routes._scoped import scope_write_denied, tags_with_scope
from cert_watch.scan import (
    ScanError,
    resolve_and_validate_host,
    scan_host_async,
    store_scanned_async,
)
from cert_watch.scan_freshness import (
    MAX_SCAN_INTERVAL_HOURS,
    MIN_SCAN_INTERVAL_HOURS,
)
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.security.ratelimit import _extract_client_ip, check_rate_limit
from cert_watch.services.host_management import (
    HostNotFoundError as ManagedHostNotFoundError,
)
from cert_watch.services.host_management import (
    HostSettingsUpdate,
    HostValidationError,
    create_hosts,
)
from cert_watch.services.host_management import (
    delete_host as delete_host_service,
)
from cert_watch.services.host_management import (
    import_hosts_csv as import_hosts_csv_service,
)
from cert_watch.services.host_management import (
    scan_all_hosts as scan_all_hosts_service,
)
from cert_watch.services.host_management import (
    scan_host_now as scan_host_now_service,
)
from cert_watch.services.host_management import (
    update_expected_issuers as update_expected_issuers_service,
)
from cert_watch.services.host_management import (
    update_host_settings as update_host_settings_service,
)
from cert_watch.services.host_ownership import (
    HostNotFoundError as OwnershipHostNotFoundError,
)
from cert_watch.services.host_ownership import (
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
    update_host_notes as persist_host_notes,
)
from cert_watch.services.resource_metadata import (
    update_host_tags as persist_host_tags,
)

SCAN_INTERVAL_ERROR = (
    f"Scan interval must be between {MIN_SCAN_INTERVAL_HOURS} and "
    f"{MAX_SCAN_INTERVAL_HOURS} hours, or blank for daily."
)

logger = logging.getLogger("cert_watch.routes.hosts")


async def _scan_and_store(
    hostname: str,
    port: int,
    db: str | Path,
    settings: Settings,
    *,
    pinned_ip: str | None,
    starttls_mode: str,
    source: str,
    webhook_config: WebhookConfig | None = None,
    _store_error_types: tuple[type[BaseException], ...] = (Exception,),
) -> tuple[Literal["success", "scan_error", "store_error"], str | None]:
    result = await scan_host_async(
        hostname,
        port,
        verify=settings.tls_verify,
        timeout=settings.scan_timeout,
        retries=settings.scan_retries,
        allow_private=settings.allow_private,
        allowed_subnets=settings.allowed_subnets,
        dns_servers=settings.dns_servers,
        pinned_ip=pinned_ip,
        max_output_bytes=settings.scan_max_output_bytes,
        hsts_timeout=settings.hsts_timeout,
        starttls_mode=starttls_mode,
    )
    if isinstance(result, ScanError):
        record_scan_history(
            db,
            ScanHistory(
                hostname=hostname,
                port=port,
                status="failure",
                error_message=result.error_message,
            ),
        )
        try:
            from cert_watch.events import emit_scan_failed

            emit_scan_failed(db, hostname, port, result.error_message, source=source)
        except Exception:
            logger.debug("emit_scan_failed suppressed for %s:%d", hostname, port, exc_info=True)
        return "scan_error", result.error_message
    try:
        leaf_id = await store_scanned_async(
            result,
            db,
            drift_alerts=settings.drift_alerts,
            check_revocation=settings.check_revocation,
            allow_private=settings.allow_private,
            allowed_subnets=settings.allowed_subnets,
            webhook_config=webhook_config,
        )
    except _store_error_types as exc:
        logger.exception("store_scanned_async failed for %s:%d", hostname, port)
        record_scan_history(
            db,
            ScanHistory(
                hostname=hostname,
                port=port,
                status="failure",
                error_message=f"store failed: {exc}",
            ),
        )
        return "store_error", f"store failed: {exc}"
    if not leaf_id:
        # Defense in depth (WI-142): store_scanned now raises rather than
        # returning "" on a rolled-back transaction, so this branch should
        # be unreachable from the real store path. Kept as a safety net for
        # any future store_fn regression that silently returns empty.
        logger.warning(
            "store_scanned returned empty (transaction rolled back) for %s:%d",
            hostname,
            port,
        )
        record_scan_history(
            db,
            ScanHistory(
                hostname=hostname,
                port=port,
                status="failure",
                error_message="store failed: transaction rolled back",
            ),
        )
        return "store_error", "store failed: transaction rolled back"
    record_scan_history(db, ScanHistory(hostname=hostname, port=port, status="success"))
    return "success", None


router = APIRouter()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_CSV_ROWS = 500
# RFC 1035 caps a fully-qualified domain name at 253 octets; IPv6 literals
# are far shorter. Rejecting absurd-length hostnames at the route layer
# prevents a write-authorized user from bloating dashboard queries and
# audit rows with multi-MB hostname strings (B6).
COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)


def _hostname_within_octet_limit(hostname: str) -> bool:
    """Backward-compatible route-local alias for the shared validator."""
    return hostname_is_valid(hostname)


def endpoint_settings_writable(request: Request, db: str | Path, host_id: str) -> bool:
    """Ask exactly what ``update_host_settings`` will ask, in the same order.

    Both halves must match the POST or the form is a trap: it renders, takes
    the operator's input, and bounces to ``/?error=`` with the input gone.
    ``form_write_error`` is the POST's own gate, and ``scope_write_denied`` is
    the same per-resource check the POST runs immediately after it.
    """
    return (
        form_write_error(request) is None
        and scope_write_denied(request, db, host_id=host_id) is None
    )


@router.post("/hosts/{host_id}/owner")
async def update_host_owner(
    request: Request,
    host_id: IdParam,
    owner_name: str = Form(""),
    owner_email: str = Form(""),
    owner_slack: str = Form(""),
    renewal_method: str = Form(""),
    runbook_url: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    """Update host ownership through the host-namespaced UI adapter."""
    if not check_rate_limit(f"host_owner:{_extract_client_ip(request)}", 30, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)
    try:
        target = resolve_host_ownership_target(db, host_id)
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
    except (HostOwnershipTargetError, OwnershipHostNotFoundError):
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except HostOwnershipValidationError as exc:
        message = "invalid renewal method" if exc.field == "renewal_method" else str(exc)
        return RedirectResponse(
            url=f"/certificates/{host_id}?error={quote(message)}", status_code=303,
        )
    return RedirectResponse(url=f"/certificates/{host_id}", status_code=303)


@router.post("/hosts/{host_id}/settings")
async def update_host_settings(
    request: Request,
    host_id: IdParam,
    scan_interval_hours: str = Form(""),
    threshold_days: str = Form(""),
    renewal_status: str = Form("pending"),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    """Edit cadence, expiry thresholds, and the operator's renewal report."""
    db = _db_path(request)
    # Preserve the form's early-denial behavior (and avoid reflecting endpoint
    # state to an out-of-scope writer). The service repeats this check while
    # holding the write lock, which remains the authorization boundary.
    denied = scope_write_denied(request, db, host_id=host_id)
    if denied:
        return RedirectResponse(url=f"/?error={quote(denied)}", status_code=303)
    repo = SqliteHostRepository(db)
    host = repo.get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)

    from cert_watch.database.connection import _connect

    with _connect(db) as conn:
        leaf = conn.execute(
            "SELECT id FROM certificates WHERE hostname = ? AND port = ? "
            "AND source = 'scanned' AND is_leaf = 1 ORDER BY created_at DESC LIMIT 1",
            (host.hostname, host.port),
        ).fetchone()
    back = f"/certificates/{leaf['id'] if leaf else host_id}"

    def invalid(message: str) -> RedirectResponse:
        return RedirectResponse(
            url=f"{back}?endpoint_error={quote(message)}#endpoint-settings",
            status_code=303,
        )

    if not check_rate_limit(f"host_settings:{_extract_client_ip(request)}", 30, 60):
        return invalid("Too many requests; try again shortly.")
    form = await request.form()
    if not {"scan_interval_hours", "threshold_days", "renewal_status"}.issubset(form):
        return invalid("Submit all endpoint settings; use blank numeric fields for defaults.")
    try:
        interval = int(scan_interval_hours.strip()) if scan_interval_hours.strip() else None
    except ValueError:
        return invalid("Scan interval must be a whole number of hours, or blank for daily.")
    try:
        threshold = int(threshold_days.strip()) if threshold_days.strip() else None
    except ValueError:
        return invalid("Alert threshold must be a positive whole number of days, or blank.")
    try:
        update_host_settings_service(
            db,
            host_id,
            HostSettingsUpdate(interval, threshold, renewal_status),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
        from cert_watch.scheduler import wake_scheduler

        wake_scheduler(request.app.state.scheduler)
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except HostValidationError as exc:
        return invalid(str(exc))
    except ManagedHostNotFoundError:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    return RedirectResponse(url=f"{back}?endpoint_saved=1#endpoint-settings", status_code=303)


@router.post("/hosts")
async def add_host(
    request: Request,
    hostname: str = Form(...),
    port: int = Form(443),
    threshold_days: int | None = Form(None),
    tags: str = Form(""),
    scan_interval_hours: int | None = Form(None),
    common_ports: bool = Form(False),
    notes: str = Form(""),
    starttls_mode: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    # Once framework parsing and guards complete, both adapters charge the
    # shared budget before application validation, so malformed attempts count.
    if not check_rate_limit(f"add_host:{_extract_client_ip(request)}", 20, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    try:
        await create_hosts(
            _db_path(request),
            _get_settings(request),
            hostname=hostname,
            port=port,
            threshold_days=threshold_days,
            tags=tags_with_scope(request, tags),
            scan_interval_hours=scan_interval_hours,
            common_ports=common_ports,
            notes=notes,
            starttls_mode=starttls_mode,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            _resolve_fn=resolve_and_validate_host,
            _scan_fn=_scan_and_store,
        )
    except (HostValidationError, ScopeDeniedError) as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/import")
async def import_hosts(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"import_hosts:{_extract_client_ip(request)}", 5, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return RedirectResponse(
            url=f"/?error={quote('CSV file too large (max 10 MB)')}", status_code=303
        )
    try:
        result = await import_hosts_csv_service(
            _db_path(request),
            _get_settings(request),
            content,
            file.filename or "unknown",
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            _resolve_fn=resolve_and_validate_host,
            _scan_fn=_scan_and_store,
        )
    except HostValidationError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    errors = list(result.errors)
    imported = result.imported
    if errors and imported == 0:
        logger.warning("CSV import failed: %s", errors[:3])
        return RedirectResponse(
            url=f"/?error={quote('Import failed: ' + '; '.join(errors[:3]))}", status_code=303
        )
    if errors:
        # A partial import used to redirect to a bare "/": rows the operator
        # believed they had imported were dropped and nothing on the page said
        # so. Silence is affordable when a row is merely a duplicate; it is not
        # when the row was an endpoint somebody meant to start monitoring, and
        # bounding the cadence (#29) adds a reason to reject a row that was
        # previously accepted -- turning a silent bad value into a silent
        # missing host, which is worse.
        logger.info("CSV import partial: %d imported, %d errors", imported, len(errors))
        shown = "; ".join(errors[:3])
        if len(errors) > 3:
            shown += f"; and {len(errors) - 3} more"
        summary = f"Imported {imported} host(s); {len(errors)} row(s) rejected: {shown}"
        return RedirectResponse(url=f"/?warning={quote(summary)}", status_code=303)
    logger.info("CSV import complete: %d hosts imported", imported)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/{host_id}/notes")
async def update_host_notes(
    request: Request,
    host_id: IdParam,
    notes: str = Form(...),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        persist_host_notes(
            db,
            host_id,
            notes,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except ResourceMetadataValidationError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except ResourceMetadataNotFoundError:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    logger.info("updated notes for host %s", host_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/{host_id}/tags")
async def update_host_tags(
    request: Request,
    host_id: IdParam,
    tags: str = Form(""),
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        persist_host_tags(
            db,
            host_id,
            tags,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    except ResourceMetadataValidationError as exc:
        return RedirectResponse(
            url=f"/hosts/{host_id}?error={quote(str(exc))}",
            status_code=303,
        )
    except ResourceMetadataNotFoundError:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    logger.info("updated tags for host %s", host_id)
    return RedirectResponse(url=f"/hosts/{host_id}", status_code=303)


@router.post("/hosts/{host_id}/expected-issuers")
async def update_host_expected_issuers(
    request: Request,
    host_id: IdParam,
    expected_issuers: str = Form(""),
    _auth: str = Depends(admin_form_guard),
) -> RedirectResponse:
    """Update the CT expected-issuer allowlist for a host."""
    db = _db_path(request)

    try:
        update_expected_issuers_service(
            db,
            host_id,
            expected_issuers,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ManagedHostNotFoundError:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    except (HostValidationError, ScopeDeniedError) as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    logger.info("updated expected_issuers for host %s", host_id)
    return RedirectResponse(url="/?saved=1", status_code=303)


@router.post("/hosts/{host_id}/delete")
async def delete_host(
    request: Request,
    host_id: IdParam,
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    db = _db_path(request)
    try:
        delete_host_service(
            db,
            host_id,
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
        )
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    logger.info("deleted host %s", host_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/all/scan")
async def scan_all_hosts(
    request: Request,
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"scan_all:{_extract_client_ip(request)}", 3, 300):
        return RedirectResponse(
            url=f"/scan-history?error={quote('rate limited: too many scan-all requests')}",
            status_code=303,
        )
    scanned, failures = await scan_all_hosts_service(
        _db_path(request),
        _get_settings(request),
        auth=acting_auth(request),
        actor=resolve_actor(request),
        source_ip=resolve_source_ip(request),
        _scan_fn=_scan_and_store,
    )
    logger.info("scan_all: %d scanned, %d failures", scanned, failures)
    return RedirectResponse(url="/scan-history", status_code=303)


@router.post("/hosts/{host_id}/scan")
async def scan_host_now(
    request: Request,
    host_id: IdParam,
    _auth: str = Depends(write_form_guard),
) -> RedirectResponse:
    if not check_rate_limit(f"scan_host:{_extract_client_ip(request)}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many scan requests')}", status_code=303
        )
    db = _db_path(request)
    host = SqliteHostRepository(db).get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    try:
        result = await scan_host_now_service(
            db,
            host_id,
            _get_settings(request),
            auth=acting_auth(request),
            actor=resolve_actor(request),
            source_ip=resolve_source_ip(request),
            _scan_fn=_scan_and_store,
        )
    except ManagedHostNotFoundError:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    except ScopeDeniedError as exc:
        return RedirectResponse(url=f"/?error={quote(str(exc))}", status_code=303)
    if result.status == "success":
        return RedirectResponse(url="/", status_code=303)
    if result.status == "store_error":
        return RedirectResponse(
            url=f"/?warning={quote('scan succeeded but store failed')}", status_code=303
        )
    msg = f"scan failed for {host.hostname}:{host.port}: {result.error}"
    return RedirectResponse(url=f"/?warning={quote(msg)}", status_code=303)
