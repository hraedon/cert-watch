"""Host CRUD, import, and scan routes."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.database import SqliteHostRepository
from cert_watch.middleware import (
    _extract_client_ip,
    check_rate_limit,
    require_auth,
    require_write_form,
)
from cert_watch.routes._deps import IdParam, _csv_safe, _db_path, _get_settings
from cert_watch.scan import (
    ScanError,
    ScannedEntry,
    resolve_and_validate_host,
    scan_host_async,
    store_scanned_async,
)
from cert_watch.scheduler import ScanHistory, record_scan_history

ScanResult = ScannedEntry | ScanError

logger = logging.getLogger("cert_watch.routes.hosts")

# Serialize concurrent store_scanned_async calls — SQLite WAL handles writers
# but concurrent writes beyond busy_timeout raise OperationalError.
_store_sem = asyncio.Semaphore(1)


router = APIRouter()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
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
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if not common_ports and not (1 <= port <= 65535):
        return RedirectResponse(
            url=f"/?error={quote('port must be between 1 and 65535')}", status_code=303
        )
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
    for p in ports:
        host_id = host_repo.add(
            hostname,
            p,
            threshold_days=threshold_days,
            tags=tags,
            scan_interval_hours=scan_interval_hours,
            notes=notes,
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

    async def _scan_and_store(p: int) -> bool:
        result = await scan_host_async(
            hostname,
            p,
            timeout=s.scan_timeout,
            retries=s.scan_retries,
            allow_private=s.allow_private,
            allowed_subnets=s.allowed_subnets,
            dns_servers=s.dns_servers,
            pinned_ip=pinned_ip,
        )
        if not isinstance(result, ScanError):
            async with _store_sem:
                try:
                    await store_scanned_async(
                        result, db,
                        check_revocation=s.check_revocation,
                        allow_private=s.allow_private,
                        allowed_subnets=s.allowed_subnets,
                        webhook_config=s.build_webhook_config(),
                    )
                except Exception:
                    logger.exception("store_scanned_async failed for %s:%d", hostname, p)
                    return False
            record_scan_history(db, ScanHistory(hostname=hostname, port=p, status="success"))
            logger.info("added and scanned host %s:%d", hostname, p)
            return True
        record_scan_history(
            db,
            ScanHistory(
                hostname=hostname, port=p, status="failure",
                error_message=result.error_message,
            ),
        )
        logger.warning(
            "added host %s:%d but scan failed: %s",
            hostname, p, result.error_message,
        )
        return False

    results = await asyncio.gather(*[_scan_and_store(p) for p in ports])
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
    scan_jobs: list[tuple[str, int, int | None, str | None]] = []
    for i, row in enumerate(reader, start=2):
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
        host_repo.add(
            hostname,
            port,
            threshold_days=threshold,
            tags=row_tags,
            scan_interval_hours=interval_hours,
            notes=row_notes,
        )
        scan_jobs.append((hostname, port, threshold, row_pinned_ip))

    allow_priv = s.allow_private
    allowed_nets = s.allowed_subnets
    dns_srv = s.dns_servers
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
        job: tuple[str, int, int | None, str | None],
    ) -> tuple[str, int, ScanResult]:
        hostname, port, _, pinned = job
        result = await scan_host_async(
            hostname,
            port,
            timeout=s.scan_timeout,
            retries=s.scan_retries,
            allow_private=allow_priv,
            allowed_subnets=allowed_nets,
            dns_servers=dns_srv,
            pinned_ip=pinned,
        )
        return hostname, port, result

    imported = 0
    for hostname, port, result in await asyncio.gather(*[_scan_one(j) for j in scan_jobs]):
        if not isinstance(result, ScanError):
            async with _store_sem:
                try:
                    await store_scanned_async(
                        result, db,
                        check_revocation=s.check_revocation,
                        allow_private=s.allow_private,
                        allowed_subnets=s.allowed_subnets,
                        webhook_config=s.build_webhook_config(),
                    )
                except Exception:
                    logger.exception("store_scanned_async failed for %s:%d", hostname, port)
                    record_scan_history(
                        db,
                        ScanHistory(
                            hostname=hostname, port=port,
                            status="failure", error_message="store failed",
                        ),
                    )
                    imported += 1
                    continue
            record_scan_history(db, ScanHistory(hostname=hostname, port=port, status="success"))
        else:
            record_scan_history(
                db,
                ScanHistory(
                    hostname=hostname,
                    port=port,
                    status="failure",
                    error_message=result.error_message,
                ),
            )
        imported += 1
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
    repo = SqliteHostRepository(db)
    if not repo.update_notes(host_id, notes):
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


@router.post("/hosts/{host_id}/delete")
async def delete_host(request: Request, host_id: IdParam) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)
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
    hosts = SqliteHostRepository(db).list_all()
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
    for h in hosts:
        try:
            result = await scan_host_async(
                h.hostname,
                h.port,
                timeout=s.scan_timeout,
                retries=s.scan_retries,
                allow_private=s.allow_private,
                allowed_subnets=s.allowed_subnets,
                dns_servers=s.dns_servers,
            )
            if isinstance(result, ScanError):
                record_scan_history(
                    db,
                    ScanHistory(
                        hostname=h.hostname, port=h.port,
                        status="failure", error_message=result.error_message,
                    ),
                )
                failures += 1
            else:
                async with _store_sem:
                    try:
                        await store_scanned_async(
                            result, db,
                            check_revocation=s.check_revocation,
                            allow_private=s.allow_private,
                            allowed_subnets=s.allowed_subnets,
                            webhook_config=s.build_webhook_config(),
                        )
                    except Exception:
                        logger.exception("store_scanned_async failed for %s:%d", h.hostname, h.port)
                        record_scan_history(
                            db,
                            ScanHistory(
                                hostname=h.hostname, port=h.port,
                                status="failure", error_message="store failed",
                            ),
                        )
                        failures += 1
                        continue
                record_scan_history(
                    db, ScanHistory(hostname=h.hostname, port=h.port, status="success")
                )
                scanned += 1
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
    result = await scan_host_async(
        host.hostname,
        host.port,
        timeout=s.scan_timeout,
        retries=s.scan_retries,
        allow_private=s.allow_private,
        allowed_subnets=s.allowed_subnets,
        dns_servers=s.dns_servers,
    )
    if not isinstance(result, ScanError):
        async with _store_sem:
            try:
                await store_scanned_async(
                    result, db,
                    check_revocation=s.check_revocation,
                    allow_private=s.allow_private,
                    allowed_subnets=s.allowed_subnets,
                    webhook_config=s.build_webhook_config(),
                )
            except Exception:
                logger.exception("store_scanned_async failed for %s:%d", host.hostname, host.port)
                record_scan_history(
                    db,
                    ScanHistory(
                        hostname=host.hostname, port=host.port,
                        status="failure", error_message="store failed",
                    ),
                )
                logger.error("manual scan store failed for %s:%d", host.hostname, host.port)
                return RedirectResponse(
                    url=f"/?warning={quote('scan succeeded but store failed')}", status_code=303
                )
        record_scan_history(
            db, ScanHistory(hostname=host.hostname, port=host.port, status="success")
        )
        logger.info("manual scan succeeded for %s:%d", host.hostname, host.port)
        return RedirectResponse(url="/", status_code=303)
    record_scan_history(
        db,
        ScanHistory(
            hostname=host.hostname,
            port=host.port,
            status="failure",
            error_message=result.error_message,
        ),
    )
    logger.warning(
        "manual scan failed for %s:%d: %s", host.hostname, host.port, result.error_message
    )
    msg = f"scan failed for {host.hostname}:{host.port}: {result.error_message}"
    return RedirectResponse(url=f"/?warning={quote(msg)}", status_code=303)


@router.get("/api/export/hosts.csv")
def api_export_hosts_csv(request: Request, _auth: str = Depends(require_auth)) -> PlainTextResponse:
    """Export all tracked hosts as CSV."""
    db = _db_path(request)
    hosts = SqliteHostRepository(db).list_all()
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
                _csv_safe(h.added_at.isoformat()),
            ]
        )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hosts.csv"},
    )
