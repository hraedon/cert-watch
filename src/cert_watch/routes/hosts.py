"""Host CRUD, import, and scan routes."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse

from cert_watch.alerts import WebhookConfig
from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.config import Settings
from cert_watch.database import HostEntry, SqliteHostRepository, get_write_lock
from cert_watch.middleware import (
    _extract_client_ip,
    check_rate_limit,
    require_admin_write_form,
    require_auth,
    require_write_form,
)
from cert_watch.routes._deps import IdParam, _csv_safe, _db_path, _get_settings
from cert_watch.routes._scoped import scope_tags_from_auth, scope_write_denied, tags_with_scope
from cert_watch.scan import (
    STARTTLS_MODES,
    ScanError,
    resolve_and_validate_host,
    scan_host_async,
    store_scanned_async,
)
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.tags import parse_tags

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
        logger.warning(
            "store_scanned returned empty (transaction rolled back) for %s:%d",
            hostname, port,
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
COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)


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
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if not common_ports and not (1 <= port <= 65535):
        return RedirectResponse(
            url=f"/?error={quote('port must be between 1 and 65535')}", status_code=303
        )
    # STARTTLS only makes sense for a single explicit port; the common-ports
    # sweep targets standard wrapped-TLS ports, so ignore the mode there.
    starttls_mode = starttls_mode.strip().lower()
    if starttls_mode and starttls_mode not in STARTTLS_MODES:
        return RedirectResponse(
            url=f"/?error={quote(f'unsupported starttls mode: {starttls_mode}')}",
            status_code=303,
        )
    if common_ports:
        starttls_mode = ""
    if threshold_days is not None and threshold_days < 1:
        return RedirectResponse(
            url=f"/?error={quote('threshold_days must be at least 1')}", status_code=303
        )
    if not check_rate_limit(f"add_host:{_extract_client_ip(request)}", 20, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    s = _get_settings(request)
    ssrf_err, pinned_ip = resolve_and_validate_host(
        hostname,
        allow_private=s.allow_private,
        allowed_subnets=s.allowed_subnets,
        dns_servers=s.dns_servers,
    )
    if ssrf_err:
        return RedirectResponse(url=f"/?error={quote(ssrf_err)}", status_code=303)
    db = _db_path(request)
    host_repo = SqliteHostRepository(db)
    ports = COMMON_TLS_PORTS if common_ports else (port,)
    actor = resolve_actor(request)
    source_ip = resolve_source_ip(request)
    with get_write_lock():
        for p in ports:
            host_id = host_repo.add(
                hostname,
                p,
                threshold_days=threshold_days,
                tags=tags_with_scope(request, tags),
                scan_interval_hours=scan_interval_hours,
                notes=notes,
                starttls_mode=starttls_mode,
            )
            record_audit(
                db,
                actor=actor,
                action="host.add",
                target_type="host",
                target_id=host_id,
                detail={"hostname": hostname, "port": p},
                source_ip=source_ip,
            )

    async def _scan_one(p: int) -> bool:
        status, error = await _scan_and_store(
            hostname,
            p,
            db,
            s,
            pinned_ip=pinned_ip,
            starttls_mode=starttls_mode,
            source="scan",
            webhook_config=s.build_webhook_config(),
            _store_error_types=(Exception,),
        )
        if status == "success":
            logger.info("added and scanned host %s:%d", hostname, p)
            return True
        if status == "scan_error":
            logger.warning(
                "added host %s:%d but scan failed: %s",
                hostname, p, error,
            )
        return False

    results = await asyncio.gather(*[_scan_one(p) for p in ports])
    scanned = sum(1 for r in results if r)
    if common_ports:
        logger.info("common-ports scan for %s: %d/%d succeeded", hostname, scanned, len(ports))
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/import")
async def import_hosts(request: Request, file: UploadFile = File(...)) -> RedirectResponse:  # noqa: B008
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if not check_rate_limit(f"import_hosts:{_extract_client_ip(request)}", 5, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)
    host_repo = SqliteHostRepository(db)
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        return RedirectResponse(
            url=f"/?error={quote('CSV file too large (max 10 MB)')}", status_code=303
        )
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return RedirectResponse(
            url=f"/?error={quote('CSV must be UTF-8 encoded')}", status_code=303
        )
    reader = csv.DictReader(io.StringIO(text))

    s = _get_settings(request)
    # Parse and validate all rows first, collecting scan jobs
    errors: list[str] = []
    scan_jobs: list[tuple[str, int, int | None, str | None, str]] = []
    for i, row in enumerate(reader, start=2):
        if i - 1 > MAX_CSV_ROWS:
            return RedirectResponse(
                url=f"/?error={quote(f'CSV import limited to {MAX_CSV_ROWS} rows')}",
                status_code=303,
            )
        hostname = row.get("hostname", "").strip()
        if not hostname:
            errors.append(f"row {i}: missing hostname")
            continue
        port_str = row.get("port", "443").strip()
        try:
            port = int(port_str)
        except ValueError:
            errors.append(f"row {i}: invalid port '{port_str}'")
            continue
        if not (1 <= port <= 65535):
            errors.append(f"row {i}: port out of range")
            continue
        threshold_str = row.get("threshold_days", "").strip()
        threshold = None
        if threshold_str:
            try:
                threshold = int(threshold_str)
            except ValueError:
                errors.append(f"row {i}: invalid threshold_days '{threshold_str}'")
                continue
        ssrf_err, row_pinned_ip = resolve_and_validate_host(
            hostname,
            allow_private=s.allow_private,
            allowed_subnets=s.allowed_subnets,
            dns_servers=s.dns_servers,
        )
        if ssrf_err:
            errors.append(f"row {i}: {ssrf_err}")
            continue
        row_tags = row.get("tags", "").strip()
        row_notes = row.get("notes", "").strip()
        interval_str = row.get("scan_interval_hours", "").strip()
        interval_hours = None
        if interval_str:
            try:
                interval_hours = int(interval_str)
            except ValueError:
                errors.append(f"row {i}: invalid scan_interval_hours '{interval_str}'")
                continue
        row_starttls = row.get("starttls_mode", "").strip().lower()
        if row_starttls and row_starttls not in STARTTLS_MODES:
            errors.append(f"row {i}: unsupported starttls_mode '{row_starttls}'")
            continue
        with get_write_lock():
            host_repo.add(
                hostname,
                port,
                threshold_days=threshold,
                tags=tags_with_scope(request, row_tags),
                scan_interval_hours=interval_hours,
                notes=row_notes,
                starttls_mode=row_starttls,
            )
        scan_jobs.append((hostname, port, threshold, row_pinned_ip, row_starttls))

    actor = resolve_actor(request)
    source_ip = resolve_source_ip(request)
    record_audit(
        db,
        actor=actor,
        action="host.import",
        target_type="host",
        target_id="bulk",
        detail={"filename": file.filename, "rows": len(scan_jobs), "errors": len(errors)},
        source_ip=source_ip,
    )

    async def _scan_one(
        job: tuple[str, int, int | None, str | None, str],
    ) -> None:
        hostname, port, _, pinned, row_starttls = job
        async with _import_sem:
            await _scan_and_store(
                hostname,
                port,
                db,
                s,
                pinned_ip=pinned,
                starttls_mode=row_starttls,
                source="scan",
                webhook_config=s.build_webhook_config(),
            )

    _import_sem = asyncio.Semaphore(10)
    statuses = await asyncio.gather(*[_scan_one(j) for j in scan_jobs])
    imported = len(statuses)
    if errors and imported == 0:
        logger.warning("CSV import failed: %s", errors[:3])
        return RedirectResponse(
            url=f"/?error={quote('Import failed: ' + '; '.join(errors[:3]))}", status_code=303
        )
    if errors:
        logger.info("CSV import partial: %d imported, %d errors", imported, len(errors))
    else:
        logger.info("CSV import complete: %d hosts imported", imported)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/{host_id}/notes")
async def update_host_notes(
    request: Request, host_id: IdParam, notes: str = Form(...)
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if len(notes) > 10000:
        return RedirectResponse(
            url=f"/?error={quote('notes too long (max 10000)')}", status_code=303
        )
    db = _db_path(request)
    denied = scope_write_denied(request, db, host_id=host_id)
    if denied:
        return RedirectResponse(url=f"/?error={quote(denied)}", status_code=303)
    repo = SqliteHostRepository(db)
    with get_write_lock():
        updated = repo.update_notes(host_id, notes)
    if not updated:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.update_notes",
        target_type="host",
        target_id=host_id,
        detail={"notes_length": len(notes)},
        source_ip=resolve_source_ip(request),
    )
    logger.info("updated notes for host %s", host_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/{host_id}/tags")
async def update_host_tags(
    request: Request, host_id: IdParam, tags: str = Form("")
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if len(tags) > 2000:
        return RedirectResponse(
            url=f"/hosts/{host_id}?error={quote('tags too long (max 2000)')}",
            status_code=303,
        )
    db = _db_path(request)
    denied = scope_write_denied(request, db, host_id=host_id)
    if denied:
        return RedirectResponse(url=f"/?error={quote(denied)}", status_code=303)
    from cert_watch.tags import format_tags

    normalized = format_tags(parse_tags(tags))
    from cert_watch.routes._scoped import scope_new_tags_denied

    new_tags_denied = scope_new_tags_denied(request, normalized)
    if new_tags_denied:
        return RedirectResponse(url=f"/?error={quote(new_tags_denied)}", status_code=303)
    repo = SqliteHostRepository(db)
    with get_write_lock():
        updated = repo.set_tags(host_id, normalized)
    if not updated:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.update_tags",
        target_type="host",
        target_id=host_id,
        detail={"tags": normalized},
        source_ip=resolve_source_ip(request),
    )
    logger.info("updated tags for host %s", host_id)
    return RedirectResponse(url=f"/hosts/{host_id}", status_code=303)


@router.post("/hosts/{host_id}/expected-issuers")
async def update_host_expected_issuers(
    request: Request, host_id: IdParam, expected_issuers: str = Form(""),
) -> RedirectResponse:
    """Update the CT expected-issuer allowlist for a host."""
    write_err = await require_admin_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)

    repo = SqliteHostRepository(db)
    host = repo.get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    # Normalize: comma-separated, stripped
    normalized = ",".join(
        i.strip()
        for i in expected_issuers.split(",")
        if i.strip()
    )
    if len(normalized) > 2000:
        return RedirectResponse(url="/?error=expected+issuers+too+long", status_code=303)
    with get_write_lock():
        repo.set_expected_issuers(host_id, normalized)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.update_expected_issuers",
        target_type="host",
        target_id=host_id,
        detail={"hostname": host.hostname, "expected_issuers": normalized},
        source_ip=resolve_source_ip(request),
    )
    logger.info("updated expected_issuers for host %s", host_id)
    return RedirectResponse(url="/?saved=1", status_code=303)


@router.post("/hosts/{host_id}/delete")
async def delete_host(request: Request, host_id: IdParam) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)
    denied = scope_write_denied(request, db, host_id=host_id)
    if denied:
        return RedirectResponse(url=f"/?error={quote(denied)}", status_code=303)
    with get_write_lock():
        SqliteHostRepository(db).delete(host_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.delete",
        target_type="host",
        target_id=host_id,
        source_ip=resolve_source_ip(request),
    )
    logger.info("deleted host %s", host_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/all/scan")
async def scan_all_hosts(request: Request) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if not check_rate_limit(f"scan_all:{_extract_client_ip(request)}", 3, 300):
        return RedirectResponse(
            url=f"/scan-history?error={quote('rate limited: too many scan-all requests')}",
            status_code=303,
        )
    db = _db_path(request)
    s = _get_settings(request)

    # Tag-scoped access control (WI-078): a scoped user only scans hosts inside
    # their team scope; admins / unscoped users scan everything.
    auth_ctx = getattr(request.state, "auth_context", None)
    scope_tags = scope_tags_from_auth(auth_ctx)
    hosts = SqliteHostRepository(db).list_scoped(scope_tags)

    if not hosts:
        return RedirectResponse(url="/scan-history", status_code=303)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.scan_all",
        target_type="host",
        target_id="all",
        source_ip=resolve_source_ip(request),
    )
    scanned = 0
    failures = 0

    sem = asyncio.Semaphore(10)

    async def _limited_scan(
        h: HostEntry,
    ) -> tuple[HostEntry, tuple[Literal["success", "scan_error", "store_error"], str | None]]:
        async with sem:
            return h, await _scan_and_store(
                h.hostname,
                h.port,
                db,
                s,
                pinned_ip=None,
                starttls_mode=h.starttls_mode,
                source="scan",
                webhook_config=s.build_webhook_config(),
            )

    for h, (status, _) in await asyncio.gather(*[_limited_scan(h) for h in hosts]):
        try:
            if status == "success":
                scanned += 1
            else:
                failures += 1
        except Exception:
            logger.exception("scan_all: failed for %s:%d", h.hostname, h.port)
            failures += 1
    logger.info("scan_all: %d scanned, %d failures", scanned, failures)
    return RedirectResponse(url="/scan-history", status_code=303)


@router.post("/hosts/{host_id}/scan")
async def scan_host_now(request: Request, host_id: IdParam) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if not check_rate_limit(f"scan_host:{_extract_client_ip(request)}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many scan requests')}", status_code=303
        )
    db = _db_path(request)
    host = SqliteHostRepository(db).get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    denied = scope_write_denied(request, db, host_id=host_id)
    if denied:
        return RedirectResponse(url=f"/?error={quote(denied)}", status_code=303)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="host.scan",
        target_type="host",
        target_id=host_id,
        detail={"hostname": host.hostname, "port": host.port},
        source_ip=resolve_source_ip(request),
    )
    s = _get_settings(request)
    status, error = await _scan_and_store(
        host.hostname,
        host.port,
        db,
        s,
        pinned_ip=None,
        starttls_mode=host.starttls_mode,
        source="manual",
        webhook_config=s.build_webhook_config(),
    )
    if status == "success":
        logger.info("manual scan succeeded for %s:%d", host.hostname, host.port)
        return RedirectResponse(url="/", status_code=303)
    if status == "store_error":
        logger.error("manual scan store failed for %s:%d", host.hostname, host.port)
        return RedirectResponse(
            url=f"/?warning={quote('scan succeeded but store failed')}", status_code=303
        )
    assert status == "scan_error"
    msg = f"scan failed for {host.hostname}:{host.port}: {error}"
    logger.warning("manual scan failed for %s:%d: %s", host.hostname, host.port, error)
    return RedirectResponse(url=f"/?warning={quote(msg)}", status_code=303)


@router.get("/api/export/hosts.csv")
def api_export_hosts_csv(request: Request, _auth: str = Depends(require_auth)) -> PlainTextResponse:
    """Export all tracked hosts as CSV."""
    db = _db_path(request)
    scope_tags = scope_tags_from_auth(getattr(request.state, "auth_context", None))
    repo = SqliteHostRepository(db)
    hosts = repo.list_scoped(scope_tags) if scope_tags else repo.list_all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "hostname",
            "port",
            "threshold_days",
            "tags",
            "scan_interval_hours",
            "owner_name",
            "owner_email",
            "owner_slack",
            "renewal_status",
            "notes",
            "starttls_mode",
            "added_at",
        ]
    )
    for h in hosts:
        writer.writerow(
            [
                _csv_safe(h.hostname),
                _csv_safe(h.port),
                _csv_safe(h.threshold_days or ""),
                _csv_safe(h.tags),
                _csv_safe(h.scan_interval_hours or ""),
                _csv_safe(h.owner_name),
                _csv_safe(h.owner_email),
                _csv_safe(h.owner_slack),
                _csv_safe(h.renewal_status),
                _csv_safe(h.notes),
                _csv_safe(h.starttls_mode),
                _csv_safe(h.added_at.isoformat()),
            ]
        )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hosts.csv"},
    )
