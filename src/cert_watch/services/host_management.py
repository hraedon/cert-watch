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

from cert_watch.alerting import WebhookConfig
from cert_watch.audit import export_audit, record_audit
from cert_watch.auth.scope import (
    ScopeDeniedError,
    ensure_new_tags_in_scope,
    ensure_write_scope,
    ensure_write_scope_on,
    require_auth_context,
    writable_scope_tags,
)
from cert_watch.config import Settings
from cert_watch.database import HostEntry, SqliteHostRepository, get_write_lock
from cert_watch.database.connection import _connect, begin_immediate
from cert_watch.host_validation import canonical_hostname
from cert_watch.scan import (
    STARTTLS_MODES,
    ScanError,
    resolve_and_validate_host,
    scan_host_async,
    store_scanned_async,
)
from cert_watch.scan_freshness import scan_interval_out_of_range
from cert_watch.scheduler import ScanHistory, record_scan_history
from cert_watch.tags import format_tags, merge_tags

logger = logging.getLogger("cert_watch.services.host_management")

COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)
MAX_CSV_ROWS = 500
ScanStatus = Literal["success", "scan_error", "store_error", "refused"]
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
    refused: int


@dataclass(frozen=True)
class HostImportResult:
    imported: int
    errors: tuple[str, ...]


def _record_scan_failure(
    db_path: str | Path,
    *,
    hostname: str,
    port: int,
    error_message: str,
    source: str,
    scope_guard: Callable[[Any], None] | None,
) -> None:
    """Authorize and persist failed-scan bookkeeping in one transaction."""
    from cert_watch.events import EventStreamConfig, emit_scan_failed, load_event_config

    try:
        event_config = load_event_config(db_path)
    except Exception:
        logger.debug("load_event_config failed for %s:%d", hostname, port, exc_info=True)
        event_config = EventStreamConfig()
    pending: list[tuple[Any, Any, int]] = []
    with get_write_lock():
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            if scope_guard is not None:
                scope_guard(conn)
            record_scan_history(
                db_path,
                ScanHistory(
                    hostname=hostname,
                    port=port,
                    status="failure",
                    error_message=error_message,
                ),
                conn=conn,
            )
            try:
                emit_scan_failed(
                    db_path,
                    hostname,
                    port,
                    error_message,
                    source=source,
                    config=event_config,
                    conn=conn,
                    deferred=pending,
                )
            except Exception:
                logger.debug(
                    "emit_scan_failed suppressed for %s:%d", hostname, port, exc_info=True
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    for event, config, row_id in pending:
        try:
            from cert_watch.events import _deliver_webhook, _get_pool

            _get_pool().submit(_deliver_webhook, event, config, str(db_path), row_id)
        except Exception:
            logger.warning("deferred scan-failure webhook submit failed", exc_info=True)


def _scoped_tags(auth: Any, tags: str) -> str:
    scope = getattr(auth, "scope_tag", "") if auth is not None else ""
    return format_tags(merge_tags(tags, scope or ""))


def _add_endpoints_authorized(
    repo: SqliteHostRepository,
    auth: Any,
    hostname: str,
    ports: tuple[int, ...],
    **host_fields: Any,
) -> list[tuple[str, int]]:
    """Add endpoints only while every existing endpoint remains writable.

    ``repo.add`` is idempotent: adding a monitored ``hostname:port`` again
    returns the existing row's id, and the caller then scans it. For a scoped
    caller that would hand over another team's host id and trigger a scan of
    it (#112 review). All ports are authorized before any insert, both in the
    advisory pass and in one ``BEGIN IMMEDIATE`` transaction, so common-port
    creation stays all-or-nothing. The caller must hold the write lock.
    """
    for port in ports:
        existing = repo.get_by_endpoint(hostname, port)
        if existing is not None:
            ensure_write_scope(auth, repo.db_path, host_id=existing.id)
    conn = _connect(repo.db_path)
    try:
        begin_immediate(conn)
        for port in ports:
            row = conn.execute(
                "SELECT id FROM hosts WHERE hostname = ? AND port = ?", (hostname, port)
            ).fetchone()
            if row is not None:
                ensure_write_scope_on(conn, auth, host_id=row["id"])
        added = [
            (repo.add(hostname, port, conn=conn, **host_fields), port)
            for port in ports
        ]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return added


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
    scope_guard: Callable[[Any], None] | None = None,
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
        _record_scan_failure(
            db_path,
            hostname=hostname,
            port=port,
            error_message=result.error_message,
            source=source,
            scope_guard=scope_guard,
        )
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
            guard=scope_guard,
        )
    except ScopeDeniedError:
        raise
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
    try:
        # One spelling from here on: validation, the existing-endpoint scope
        # check, persistence, DNS resolution and the scan all see it.
        hostname = canonical_hostname(hostname.strip())
    except ValueError:
        raise HostValidationError(
            "hostname must be valid and at most 253 IDNA octets"
        ) from None
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
    with get_write_lock():
        added = _add_endpoints_authorized(
            repo,
            auth,
            hostname,
            ports,
            threshold_days=threshold_days,
            tags=normalized_tags,
            scan_interval_hours=scan_interval_hours,
            notes=notes,
            starttls_mode=starttls_mode,
        )
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

    async def scan(job: tuple[str, int]) -> ScanResult:
        host_id, candidate_port = job

        def scope_guard(conn: Any) -> None:
            ensure_write_scope_on(conn, auth, host_id=host_id)

        try:
            if _scan_fn is not None:
                status, error = await _scan_fn(
                    hostname,
                    candidate_port,
                    db_path,
                    settings,
                    pinned_ip=pinned_ip,
                    starttls_mode=starttls_mode,
                    source="scan",
                    webhook_config=settings.build_webhook_config(),
                    scope_guard=scope_guard,
                    _store_error_types=(Exception,),
                )
                return ScanResult(status, error)
            return await _scan_and_store(
                hostname,
                candidate_port,
                db_path,
                settings,
                pinned_ip=pinned_ip,
                starttls_mode=starttls_mode,
                source="scan",
                webhook_config=settings.build_webhook_config(),
                scope_guard=scope_guard,
            )
        except ScopeDeniedError as exc:
            return ScanResult("refused", str(exc))

    scans = await asyncio.gather(*(scan(job) for job in added))
    return HostCreateResult(
        tuple(host_id for host_id, _ in added),
        sum(result.status == "success" for result in scans),
        sum(result.status == "refused" for result in scans),
    )


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
    jobs: list[tuple[int, str, str, int, str | None, str]] = []
    for row_number, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
        if row_number - 1 > MAX_CSV_ROWS:
            raise HostValidationError(f"CSV import limited to {MAX_CSV_ROWS} rows")
        hostname = (row.get("hostname") or "").strip()
        if not hostname:
            errors.append(f"row {row_number}: missing hostname")
            continue
        try:
            hostname = canonical_hostname(hostname)
        except ValueError:
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
            try:
                [(host_id, _)] = _add_endpoints_authorized(
                    repo,
                    auth,
                    hostname,
                    (port,),
                    threshold_days=threshold,
                    tags=tags,
                    scan_interval_hours=interval,
                    notes=(row.get("notes") or "").strip(),
                    starttls_mode=starttls_mode,
                )
            except PermissionError as exc:
                errors.append(f"row {row_number}: {exc}")
                continue
        jobs.append((row_number, host_id, hostname, port, pinned_ip, starttls_mode))

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

    async def scan(job: tuple[int, str, str, int, str | None, str]) -> str | None:
        row_number, host_id, hostname, port, pinned_ip, starttls_mode = job

        def scope_guard(conn: Any) -> None:
            ensure_write_scope_on(conn, auth, host_id=host_id)

        async with semaphore:
            try:
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
                        scope_guard=scope_guard,
                        _store_error_types=(Exception,),
                    )
                    return None
                await _scan_and_store(
                    hostname,
                    port,
                    db_path,
                    settings,
                    pinned_ip=pinned_ip,
                    starttls_mode=starttls_mode,
                    source="scan",
                    webhook_config=settings.build_webhook_config(),
                    scope_guard=scope_guard,
                )
            except ScopeDeniedError as exc:
                return f"row {row_number}: follow-up scan refused: {exc}"
            return None

    scan_errors = await asyncio.gather(*(scan(job) for job in jobs))
    errors.extend(error for error in scan_errors if error is not None)
    return HostImportResult(len(jobs), tuple(errors))


async def scan_all_hosts(
    db_path: str | Path,
    settings: Settings,
    *,
    auth: Any,
    actor: str,
    source_ip: str | None,
    _scan_fn: RouteScan | None = None,
) -> tuple[int, int, int]:
    require_auth_context(auth)
    scope_tags = writable_scope_tags(auth)
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
        def scope_guard(conn: Any) -> None:
            ensure_write_scope_on(conn, auth, host_id=host.id)

        async with semaphore:
            try:
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
                        scope_guard=scope_guard,
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
                    scope_guard=scope_guard,
                )
            except ScopeDeniedError as exc:
                return ScanResult("refused", str(exc))

    results = await asyncio.gather(*(scan(host) for host in hosts))
    successes = sum(result.status == "success" for result in results)
    refused = sum(result.status == "refused" for result in results)
    return successes, len(results) - successes - refused, refused


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
        # Advisory check preserves the route's existing response ordering.
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
        if update.renewal_status not in {"pending", "in_progress"}:
            raise HostValidationError("Choose a valid operator-reported renewal status.")
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            ensure_write_scope_on(conn, auth, host_id=host_id)
            cursor = conn.execute(
                "UPDATE hosts SET scan_interval_hours = ?, threshold_days = ?, "
                "renewal_status = ? WHERE id = ?",
                (
                    update.scan_interval_hours,
                    update.threshold_days,
                    update.renewal_status,
                    host_id,
                ),
            )
            if cursor.rowcount == 0:
                raise HostNotFoundError("host not found")
            row = conn.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
            assert row is not None
            updated = repo._row_to_host(row)
            audit_event = record_audit(
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
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(audit_event)
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
        conn = _connect(db_path)
        try:
            begin_immediate(conn)
            ensure_write_scope_on(conn, auth, host_id=host_id)
            deleted = SqliteHostRepository(db_path).delete(host_id, conn=conn)
            audit_event = record_audit(
                db_path,
                actor=actor,
                action="host.delete",
                target_type="host",
                target_id=host_id,
                source_ip=source_ip,
                conn=conn,
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    export_audit(audit_event)
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

    def scope_guard(conn: Any) -> None:
        ensure_write_scope_on(conn, auth, host_id=host_id)

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
            scope_guard=scope_guard,
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
        scope_guard=scope_guard,
    )
