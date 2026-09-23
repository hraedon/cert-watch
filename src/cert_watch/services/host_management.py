"""Application services for host lifecycle, settings, issuers, and scans."""

from __future__ import annotations

import asyncio
import csv
import io
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from cert_watch import scheduler
from cert_watch.alerting import WebhookConfig
from cert_watch.audit import record_audit
from cert_watch.auth.scope import (
    ensure_new_tags_in_scope,
    ensure_write_scope,
    require_auth_context,
)
from cert_watch.config import Settings
from cert_watch.database import HostEntry, SqliteHostRepository, get_write_lock
from cert_watch.host_validation import hostname_is_valid
from cert_watch.scan import (
    STARTTLS_MODES,
    ScanError,
    resolve_and_validate_host,
    scan_host_async,
    store_scanned_async,
)
from cert_watch.scan_freshness import scan_interval_out_of_range
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.tags import format_tags, merge_tags, parse_tags

logger = logging.getLogger("cert_watch.services.host_management")

COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)
MAX_CSV_ROWS = 500
ScanStatus = Literal["success", "scan_error", "store_error"]
RouteScan = Callable[..., Awaitable[tuple[ScanStatus, str | None]]]


class HostValidationError(ValueError):
    """A host mutation contains invalid input."""


class HostNotFoundError(LookupError):
    """The requested host does not exist."""


@dataclass(frozen=True)
class HostSettingsUpdate:
    scan_interval_hours: int | None
    threshold_days: int | None
    renewal_status: str


@dataclass(frozen=True)
class ScanResult:
    status: ScanStatus
    error: str | None = None


@dataclass(frozen=True)
class HostCreateResult:
    host_ids: tuple[str, ...]
    scanned: int


@dataclass(frozen=True)
class HostImportResult:
    imported: int
    errors: tuple[str, ...]


def _scoped_tags(auth: Any, tags: str) -> str:
    scope = getattr(auth, "scope_tag", "") if auth is not None else ""
    return format_tags(merge_tags(tags, scope or ""))


async def _scan_and_store(
    hostname: str,
    port: int,
    db_path: str | Path,
    settings: Settings,
    *,
    pinned_ip: str | None,
    starttls_mode: str,
    source: str,
    webhook_config: WebhookConfig | None = None,
    _store_error_types: tuple[type[BaseException], ...] = (Exception,),
) -> ScanResult:
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
            db_path,
            ScanHistory(
                hostname=hostname,
                port=port,
                status="failure",
                error_message=result.error_message,
            ),
        )
        try:
            from cert_watch.events import emit_scan_failed

            emit_scan_failed(db_path, hostname, port, result.error_message, source=source)
        except Exception:
            logger.debug("emit_scan_failed suppressed for %s:%d", hostname, port, exc_info=True)
        return ScanResult("scan_error", result.error_message)
    try:
        leaf_id = await store_scanned_async(
            result,
            db_path,
            drift_alerts=settings.drift_alerts,
            check_revocation=settings.check_revocation,
            allow_private=settings.allow_private,
            allowed_subnets=settings.allowed_subnets,
            webhook_config=webhook_config,
        )
    except _store_error_types as exc:
        logger.exception("store_scanned_async failed for %s:%d", hostname, port)
        message = f"store failed: {exc}"
        record_scan_history(
            db_path,
            ScanHistory(hostname=hostname, port=port, status="failure", error_message=message),
        )
        return ScanResult("store_error", message)
    if not leaf_id:
        message = "store failed: transaction rolled back"
        record_scan_history(
            db_path,
            ScanHistory(hostname=hostname, port=port, status="failure", error_message=message),
        )
        return ScanResult("store_error", message)
    record_scan_history(db_path, ScanHistory(hostname=hostname, port=port, status="success"))
    return ScanResult("success")


async def create_hosts(
    db_path: str | Path,
    settings: Settings,
    *,
    hostname: str,
    port: int = 443,
    threshold_days: int | None = None,
    tags: str = "",
    scan_interval_hours: int | None = None,
    common_ports: bool = False,
    notes: str = "",
    starttls_mode: str = "",
    auth: Any,
    actor: str,
    source_ip: str | None,
    _resolve_fn: Callable[..., tuple[str | None, str | None]] = resolve_and_validate_host,
    _scan_fn: RouteScan | None = None,
) -> HostCreateResult:
    require_auth_context(auth)
    if not isinstance(hostname, str):
        raise HostValidationError("hostname must be a string")
    hostname = hostname.strip()
    if not hostname_is_valid(hostname):
        raise HostValidationError("hostname must be valid and at most 253 IDNA octets")
    if not common_ports and not 1 <= port <= 65535:
        raise HostValidationError("port must be between 1 and 65535")
    starttls_mode = starttls_mode.strip().lower()
    if starttls_mode and starttls_mode not in STARTTLS_MODES:
        raise HostValidationError(f"unsupported starttls mode: {starttls_mode}")
    if common_ports:
        starttls_mode = ""
    if threshold_days is not None and threshold_days < 1:
        raise HostValidationError("threshold_days must be at least 1")
    if scan_interval_out_of_range(scan_interval_hours):
        raise HostValidationError("scan interval must be between 1 and 8760 hours, or blank")
    normalized_tags = _scoped_tags(auth, tags)
    ensure_new_tags_in_scope(auth, normalized_tags)
    ssrf_error, pinned_ip = _resolve_fn(
        hostname,
        allow_private=settings.allow_private,
        allowed_subnets=settings.allowed_subnets,
        dns_servers=settings.dns_servers,
    )
    if ssrf_error:
        raise HostValidationError(ssrf_error)

    repo = SqliteHostRepository(db_path)
    ports = COMMON_TLS_PORTS if common_ports else (port,)
    added: list[tuple[str, int]] = []
    with get_write_lock():
        for candidate_port in ports:
            host_id = repo.add(
                hostname,
                candidate_port,
                threshold_days=threshold_days,
                tags=normalized_tags,
                scan_interval_hours=scan_interval_hours,
                notes=notes,
                starttls_mode=starttls_mode,
            )
            added.append((host_id, candidate_port))
    for host_id, candidate_port in added:
        record_audit(
            db_path,
            actor=actor,
            action="host.add",
            target_type="host",
            target_id=host_id,
            detail={"hostname": hostname, "port": candidate_port},
            source_ip=source_ip,
        )

    async def scan(candidate_port: int) -> bool:
        if _scan_fn is not None:
            status, _error = await _scan_fn(
                hostname,
                candidate_port,
                db_path,
                settings,
                pinned_ip=pinned_ip,
                starttls_mode=starttls_mode,
                source="scan",
                webhook_config=settings.build_webhook_config(),
                _store_error_types=(Exception,),
            )
            return status == "success"
        result = await _scan_and_store(
            hostname,
            candidate_port,
            db_path,
            settings,
            pinned_ip=pinned_ip,
            starttls_mode=starttls_mode,
            source="scan",
            webhook_config=settings.build_webhook_config(),
        )
        return result.status == "success"

    scans = await asyncio.gather(*(scan(candidate_port) for _, candidate_port in added))
    return HostCreateResult(tuple(host_id for host_id, _ in added), sum(scans))


async def import_hosts_csv(
    db_path: str | Path,
    settings: Settings,
    content: bytes,
    filename: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    _resolve_fn: Callable[..., tuple[str | None, str | None]] = resolve_and_validate_host,
    _scan_fn: RouteScan | None = None,
) -> HostImportResult:
    require_auth_context(auth)
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HostValidationError("CSV must be UTF-8 encoded") from None
    repo = SqliteHostRepository(db_path)
    errors: list[str] = []
    jobs: list[tuple[str, int, str | None, str]] = []
    for row_number, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
        if row_number - 1 > MAX_CSV_ROWS:
            raise HostValidationError(f"CSV import limited to {MAX_CSV_ROWS} rows")
        hostname = (row.get("hostname") or "").strip()
        if not hostname:
            errors.append(f"row {row_number}: missing hostname")
            continue
        if not hostname_is_valid(hostname):
            errors.append(f"row {row_number}: hostname is invalid or exceeds 253 IDNA octets")
            continue
        try:
            port = int((row.get("port") or "443").strip())
        except ValueError:
            errors.append(f"row {row_number}: invalid port '{row.get('port') or ''}'")
            continue
        if not 1 <= port <= 65535:
            errors.append(f"row {row_number}: port out of range")
            continue
        threshold: int | None = None
        threshold_raw = (row.get("threshold_days") or "").strip()
        if threshold_raw:
            try:
                threshold = int(threshold_raw)
            except ValueError:
                errors.append(f"row {row_number}: invalid threshold_days '{threshold_raw}'")
                continue
        interval: int | None = None
        interval_raw = (row.get("scan_interval_hours") or "").strip()
        if interval_raw:
            try:
                interval = int(interval_raw)
            except ValueError:
                errors.append(f"row {row_number}: invalid scan_interval_hours '{interval_raw}'")
                continue
            if scan_interval_out_of_range(interval):
                errors.append(
                    f"row {row_number}: scan_interval_hours must be between 1 and 8760, "
                    f"got '{interval_raw}'"
                )
                continue
        starttls_mode = (row.get("starttls_mode") or "").strip().lower()
        if starttls_mode and starttls_mode not in STARTTLS_MODES:
            errors.append(f"row {row_number}: unsupported starttls_mode '{starttls_mode}'")
            continue
        error, pinned_ip = _resolve_fn(
            hostname,
            allow_private=settings.allow_private,
            allowed_subnets=settings.allowed_subnets,
            dns_servers=settings.dns_servers,
        )
        if error:
            errors.append(f"row {row_number}: {error}")
            continue
        tags = _scoped_tags(auth, (row.get("tags") or "").strip())
        try:
            ensure_new_tags_in_scope(auth, tags)
        except PermissionError as exc:
            errors.append(f"row {row_number}: {exc}")
            continue
        with get_write_lock():
            repo.add(
                hostname,
                port,
                threshold_days=threshold,
                tags=tags,
                scan_interval_hours=interval,
                notes=(row.get("notes") or "").strip(),
                starttls_mode=starttls_mode,
            )
        jobs.append((hostname, port, pinned_ip, starttls_mode))

    record_audit(
        db_path,
        actor=actor,
        action="host.import",
        target_type="host",
        target_id="bulk",
        detail={"filename": filename, "rows": len(jobs), "errors": len(errors)},
        source_ip=source_ip,
    )
    semaphore = asyncio.Semaphore(10)

    async def scan(job: tuple[str, int, str | None, str]) -> None:
        hostname, port, pinned_ip, starttls_mode = job
        async with semaphore:
            if _scan_fn is not None:
                await _scan_fn(
                    hostname,
                    port,
                    db_path,
                    settings,
                    pinned_ip=pinned_ip,
                    starttls_mode=starttls_mode,
                    source="scan",
                    webhook_config=settings.build_webhook_config(),
                    _store_error_types=(Exception,),
                )
                return
            await _scan_and_store(
                hostname,
                port,
                db_path,
                settings,
                pinned_ip=pinned_ip,
                starttls_mode=starttls_mode,
                source="scan",
                webhook_config=settings.build_webhook_config(),
            )

    await asyncio.gather(*(scan(job) for job in jobs))
    return HostImportResult(len(jobs), tuple(errors))


async def scan_all_hosts(
    db_path: str | Path,
    settings: Settings,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    _scan_fn: RouteScan | None = None,
) -> tuple[int, int]:
    require_auth_context(auth)
    scope_tags: tuple[str, ...] = ()
    if auth is not None and not getattr(auth, "is_admin", False):
        scope_tags = tuple(parse_tags(getattr(auth, "scope_tag", "") or ""))
    hosts = SqliteHostRepository(db_path).list_scoped(scope_tags)
    if hosts:
        record_audit(
            db_path,
            actor=actor,
            action="host.scan_all",
            target_type="host",
            target_id="all",
            source_ip=source_ip,
        )
    semaphore = asyncio.Semaphore(10)

    async def scan(host: HostEntry) -> ScanResult:
        async with semaphore:
            if _scan_fn is not None:
                status, error = await _scan_fn(
                    host.hostname,
                    host.port,
                    db_path,
                    settings,
                    pinned_ip=None,
                    starttls_mode=host.starttls_mode,
                    source="scan",
                    webhook_config=settings.build_webhook_config(),
                    _store_error_types=(Exception,),
                )
                return ScanResult(status, error)
            return await _scan_and_store(
                host.hostname,
                host.port,
                db_path,
                settings,
                pinned_ip=None,
                starttls_mode=host.starttls_mode,
                source="scan",
                webhook_config=settings.build_webhook_config(),
            )

    results = await asyncio.gather(*(scan(host) for host in hosts))
    successes = sum(result.status == "success" for result in results)
    return successes, len(results) - successes


def update_host_settings(
    db_path: str | Path,
    host_id: str,
    update: HostSettingsUpdate,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> HostEntry:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        repo = SqliteHostRepository(db_path)
        host = repo.get(host_id)
        if host is None:
            raise HostNotFoundError("host not found")
        if update.scan_interval_hours != host.scan_interval_hours and scan_interval_out_of_range(
            update.scan_interval_hours
        ):
            raise HostValidationError(
                "Scan interval must be between 1 and 8760 hours, or blank for daily."
            )
        if update.threshold_days is not None and not 1 <= update.threshold_days <= 2**63 - 1:
            raise HostValidationError(
                "Alert threshold must be a positive whole number within the stored range."
            )
        if update.renewal_status not in {"pending", "in_progress", "renewed"}:
            raise HostValidationError("Choose a valid operator-reported renewal status.")
        if not repo.update_settings(
            host_id,
            scan_interval_hours=update.scan_interval_hours,
            threshold_days=update.threshold_days,
            renewal_status=update.renewal_status,
        ):
            raise HostNotFoundError("host not found")
        updated = repo.get(host_id)
    record_audit(
        db_path,
        actor=actor,
        action="host.update_settings",
        target_type="host",
        target_id=host_id,
        detail={
            "scan_interval_hours": update.scan_interval_hours,
            "threshold_days": update.threshold_days,
            "renewal_status": update.renewal_status,
        },
        source_ip=source_ip,
    )
    scheduler.wake_scheduler()
    assert updated is not None
    return updated


def update_expected_issuers(
    db_path: str | Path,
    host_id: str,
    issuers: str | list[str],
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    audit_action: str = "host.update_expected_issuers",
) -> tuple[str, ...]:
    require_auth_context(auth)
    raw_values = issuers.split(",") if isinstance(issuers, str) else issuers
    values = [part.strip() for part in raw_values]
    values = [part for part in values if part]
    normalized = ",".join(values)
    if len(normalized) > 2000:
        raise HostValidationError("expected issuers too long (max 2000 chars)")
    if len(values) > 50:
        raise HostValidationError("too many issuers (max 50)")
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        repo = SqliteHostRepository(db_path)
        host = repo.get(host_id)
        if host is None:
            raise HostNotFoundError("host not found")
        repo.set_expected_issuers(host_id, normalized)
    record_audit(
        db_path,
        actor=actor,
        action=audit_action,
        target_type="host",
        target_id=host_id,
        detail={"hostname": host.hostname, "expected_issuers": normalized},
        source_ip=source_ip,
    )
    return tuple(values)


def delete_host(
    db_path: str | Path,
    host_id: str,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
) -> bool:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        deleted = SqliteHostRepository(db_path).delete(host_id)
    record_audit(
        db_path,
        actor=actor,
        action="host.delete",
        target_type="host",
        target_id=host_id,
        source_ip=source_ip,
    )
    return deleted


async def scan_host_now(
    db_path: str | Path,
    host_id: str,
    settings: Settings,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    _scan_fn: Callable[..., Awaitable[tuple[str, str | None]]] | None = None,
) -> ScanResult:
    require_auth_context(auth)
    with get_write_lock():
        ensure_write_scope(auth, db_path, host_id=host_id)
        host = SqliteHostRepository(db_path).get(host_id)
        if host is None:
            raise HostNotFoundError("host not found")
    record_audit(
        db_path,
        actor=actor,
        action="host.scan",
        target_type="host",
        target_id=host_id,
        detail={"hostname": host.hostname, "port": host.port},
        source_ip=source_ip,
    )
    webhook_config = settings.build_webhook_config()
    if _scan_fn is not None:
        status, error = await _scan_fn(
            host.hostname,
            host.port,
            db_path,
            settings,
            pinned_ip=None,
            starttls_mode=host.starttls_mode,
            source="manual",
            webhook_config=webhook_config,
        )
        return ScanResult(status, error)  # type: ignore[arg-type]
    return await _scan_and_store(
        host.hostname,
        host.port,
        db_path,
        settings,
        pinned_ip=None,
        starttls_mode=host.starttls_mode,
        source="manual",
        webhook_config=webhook_config,
    )
