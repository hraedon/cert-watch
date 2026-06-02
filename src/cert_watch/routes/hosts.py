"""Host CRUD, import, and scan routes."""

from __future__ import annotations

import concurrent.futures
import csv
import io
import logging
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import PlainTextResponse, RedirectResponse

from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository
from cert_watch.middleware import _extract_client_ip, check_csrf, check_rate_limit, require_auth
from cert_watch.scan import ScanError, scan_host, store_scanned
from cert_watch.scheduler import ScanHistory, record_scan_history

logger = logging.getLogger("cert_watch.routes.hosts")

_CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


def _csv_safe(value) -> str:
    s = str(value) if value is not None else ""
    if s and s[0] in _CSV_DANGEROUS_PREFIXES:
        return "'" + s
    return s


router = APIRouter()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)


def _get_settings(request: Request) -> Settings:
    return request.app.state.settings


def _db_path(request: Request) -> Path:
    return _get_settings(request).db_path


def _is_blocked_host_check(
    hostname: str,
    *,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
) -> tuple[str | None, str | None]:
    """SSRF pre-check for the add-host form.

    Returns (error_message_or_None, pinned_ip_or_None).
    When no error is found the pinned_ip is the first allowed address
    so the subsequent scan can connect to the same IP (prevents DNS rebinding).
    """
    import ipaddress

    from cert_watch.scan import _PRIVATE_NETWORKS, _is_blocked_ip, resolve_hostname

    infos = resolve_hostname(hostname, 0, dns_servers=dns_servers)
    if not infos:
        return None, None
    pinned_ip = None
    blocked_info = None
    for _family, sockaddr in infos:
        ip_str = sockaddr[0]
        if ip_str is None:
            continue
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(ip, allow_private=allow_private, allowed_subnets=allowed_subnets):
            check_ip = (
                ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
            )
            is_private = any(check_ip in net for net in _PRIVATE_NETWORKS)
            blocked_info = (ip, is_private)
            continue
        pinned_ip = ip_str
        break
    if pinned_ip is None:
        if blocked_info is not None:
            ip, is_private = blocked_info
            if is_private and allowed_subnets:
                return (
                    f"hostname resolves to private address {ip}, which is outside the "
                    f"configured CERT_WATCH_ALLOWED_SUBNETS. Add its range to scan it.",
                    None,
                )
            if is_private and not allow_private:
                return (
                    f"hostname resolves to blocked address {ip}. "
                    f"Set CERT_WATCH_ALLOW_PRIVATE_IPS=1 to allow scanning private IPs.",
                    None,
                )
            return f"hostname resolves to blocked address {ip}", None
        return None, None
    return None, pinned_ip


@router.post("/hosts")
async def add_host(
    request: Request,
    hostname: str = Form(...),
    port: int = Form(443),
    threshold_days: int | None = Form(None),
    tags: str = Form(""),
    scan_interval_hours: int | None = Form(None),
    common_ports: bool = Form(False),
) -> RedirectResponse:
    if not common_ports and not (1 <= port <= 65535):
        return RedirectResponse(
            url=f"/?error={quote('port must be between 1 and 65535')}", status_code=303
        )
    if threshold_days is not None and threshold_days < 1:
        return RedirectResponse(
            url=f"/?error={quote('threshold_days must be at least 1')}", status_code=303
        )
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not check_rate_limit(f"add_host:{_extract_client_ip(request)}", 20, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    s = _get_settings(request)
    ssrf_err, pinned_ip = _is_blocked_host_check(
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
    scanned = 0
    actor = resolve_actor(request)
    source_ip = resolve_source_ip(request)
    for p in ports:
        host_id = host_repo.add(
            hostname,
            p,
            threshold_days=threshold_days,
            tags=tags,
            scan_interval_hours=scan_interval_hours,
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
        result = scan_host(
            hostname,
            p,
            allow_private=s.allow_private,
            allowed_subnets=s.allowed_subnets,
            dns_servers=s.dns_servers,
            pinned_ip=pinned_ip,
        )
        if not isinstance(result, ScanError):
            store_scanned(result, db)
            scanned += 1
            record_scan_history(db, ScanHistory(hostname=hostname, port=p, status="success"))
            logger.info("added and scanned host %s:%d", hostname, p)
        else:
            record_scan_history(
                db,
                ScanHistory(
                    hostname=hostname,
                    port=p,
                    status="failure",
                    error_message=result.error_message,
                ),
            )
            logger.warning(
                "added host %s:%d but scan failed: %s",
                hostname,
                p,
                result.error_message,
            )
    if common_ports:
        logger.info("common-ports scan for %s: %d/%d succeeded", hostname, scanned, len(ports))
    return RedirectResponse(url="/", status_code=303)


@router.post("/hosts/import")
async def import_hosts(request: Request, file: UploadFile = File(...)) -> RedirectResponse:  # noqa: B008
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
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
        ssrf_err, row_pinned_ip = _is_blocked_host_check(
            hostname,
            allow_private=s.allow_private,
            allowed_subnets=s.allowed_subnets,
            dns_servers=s.dns_servers,
        )
        if ssrf_err:
            errors.append(f"row {i}: {ssrf_err}")
            continue
        row_tags = row.get("tags", "").strip()
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
        )
        scan_jobs.append((hostname, port, threshold, row_pinned_ip))

    # Scan hosts concurrently
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

    def _scan_one(job: tuple[str, int, int | None, str | None]) -> tuple[str, int, object]:
        hostname, port, _, pinned = job
        result = scan_host(
            hostname,
            port,
            allow_private=allow_priv,
            allowed_subnets=allowed_nets,
            dns_servers=dns_srv,
            pinned_ip=pinned,
        )
        return hostname, port, result

    imported = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for hostname, port, result in pool.map(_scan_one, scan_jobs):
            if not isinstance(result, ScanError):
                store_scanned(result, db)
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


@router.post("/hosts/{host_id}/delete")
async def delete_host(request: Request, host_id: str) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
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


@router.post("/hosts/{host_id}/scan")
async def scan_host_now(request: Request, host_id: str) -> RedirectResponse:
    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
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
    result = scan_host(
        host.hostname,
        host.port,
        allow_private=s.allow_private,
        allowed_subnets=s.allowed_subnets,
        dns_servers=s.dns_servers,
    )
    if not isinstance(result, ScanError):
        store_scanned(result, db)
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
                _csv_safe(h.added_at.isoformat()),
            ]
        )
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=hosts.csv"},
    )
