"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sqlite3
import ssl
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cert_watch.database import CertificateRepository
    from cert_watch.events import EventStreamConfig
    from cert_watch.policy import PolicySet

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import get_write_lock, init_schema, replace_scanned
from cert_watch.retry import backoff_range
from cert_watch.scan_conn import (  # noqa: F401
    _PROTOCOL_RE,
    DEFAULT_SCAN_MAX_OUTPUT_BYTES,
    HSTS_TIMEOUT,
    STARTTLS_MODES,
    ScanOutputTooLargeError,
    _der_enc,
    _get_chain_der,
    _has_native_chain_api,
    _open_tls_connection,
    _probe_hsts,
    _scan_via_openssl,
)
from cert_watch.scan_resolver import (  # noqa: F401
    _ALWAYS_BLOCKED_NETWORKS,
    _PRIVATE_NETWORKS,
    _is_blocked_ip,
    _parse_allowed_subnets,
    _resolve_host,
    _resolve_with_dns,
    resolve_and_validate_host,
    resolve_hostname,
)

logger = logging.getLogger("cert_watch.scan")

DEFAULT_TIMEOUT = 10.0
SCAN_RETRIES = 2
SCAN_RETRY_BACKOFF = 1.0


@dataclass
class ScanError:
    hostname: str
    port: int
    error_message: str


@dataclass
class ScannedEntry:
    host: str
    port: int
    leaf: Certificate
    chain: list[Certificate] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    protocol_version: str = ""
    hsts: bool | None = None
    verify_requested: bool | None = None
    chain_incomplete: bool = False


def _friendly_scan_error(exc: BaseException) -> str:
    """Translate raw socket/TLS exceptions into human-friendly messages."""
    msg = str(exc)
    import errno as _errno
    if isinstance(exc, ConnectionRefusedError) or _errno.ECONNREFUSED in (
        getattr(exc, "errno", None),
    ):
        return "Connection refused — the host is not accepting connections on this port"
    if isinstance(exc, TimeoutError):
        return "Connection timed out — the host did not respond in time"
    if isinstance(exc, OSError):
        if "DNS resolution failed" in msg or "Name or service not known" in msg:
            return f"Could not resolve hostname: {msg}"
        if "blocked address" in msg.lower():
            return msg
        if "timed out" in msg.lower():
            return "Connection timed out — the host did not respond in time"
        if "Network is unreachable" in msg:
            return "Network unreachable — no route to the host"
        return f"Connection failed: {msg}"
    return msg


def scan_host(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
    retries: int = SCAN_RETRIES,
    pinned_ip: str | None = None,
    max_output_bytes: int = DEFAULT_SCAN_MAX_OUTPUT_BYTES,
    hsts_timeout: float = 5.0,
    starttls_mode: str = "",
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06.

    When pinned_ip is None, the hostname is resolved once per attempt and the
    resulting IP is pinned for the entire scan (DNS-rebinding hardening, BC-063).

    When *starttls_mode* is set (e.g. ``smtp``, ``imap``, ``ldap``), the scan
    negotiates a protocol STARTTLS upgrade before reading the certificate,
    instead of assuming implicit (wrapped) TLS.
    """
    last_error: ScanError | None = None
    for _ in backoff_range(retries, SCAN_RETRY_BACKOFF, strategy="exponential"):
        result = _scan_host_once(
            hostname, port, timeout=timeout, verify=verify,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip, max_output_bytes=max_output_bytes,
            hsts_timeout=hsts_timeout, starttls_mode=starttls_mode,
        )
        if isinstance(result, ScannedEntry):
            return result
        last_error = result
    if last_error is None:
        return ScanError(
            hostname=hostname, port=port,
            error_message="no scan attempts made",
        )
    return last_error


def _scan_host_once(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
    pinned_ip: str | None = None,
    max_output_bytes: int = DEFAULT_SCAN_MAX_OUTPUT_BYTES,
    hsts_timeout: float = 5.0,
    starttls_mode: str = "",
) -> ScannedEntry | ScanError:
    """Single TLS handshake attempt — no retry logic.

    When pinned_ip is not supplied, resolves the hostname once and pins the
    resulting IP for the entire scan (prevents DNS-rebinding TOCTOU, BC-063).

    On Python < 3.13, native chain extraction is unavailable. Rather than
    opening a second TLS connection to the same host (which can hit a
    different backend behind a load balancer), we use openssl s_client
    as the primary connection, getting both leaf and chain from one call.
    """
    if pinned_ip is None:
        try:
            _fam, _saddr = _resolve_host(
                hostname, port, allow_private=allow_private, allowed_subnets=allowed_subnets,
                dns_servers=dns_servers,
            )
            pinned_ip = _saddr[0]
        except OSError as exc:
            return ScanError(
                hostname=hostname,
                port=port,
                error_message=f"DNS resolution failed: {_friendly_scan_error(exc)}",
            )

    # The native ssl path can only do implicit (wrapped) TLS, so any STARTTLS
    # scan must go through openssl s_client (-starttls), regardless of Python
    # version — not just the <3.13 chain-API fallback.
    if starttls_mode or not _has_native_chain_api():
        return _scan_host_via_openssl(
            hostname, port, timeout=timeout,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip, verify=verify, max_output_bytes=max_output_bytes,
            hsts_timeout=hsts_timeout, starttls_mode=starttls_mode,
        )

    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify, allow_private=allow_private,
            allowed_subnets=allowed_subnets,
            dns_servers=dns_servers, pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except ValueError as exc:
        # The OSError family (timeouts, socket/SSL handshake failures) is caught
        # above. This handles the remaining non-OSError input errors from TLS setup.
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version = ""
    with contextlib.suppress(ssl.SSLError, OSError, ValueError):
        protocol_version = ssl_sock.version() or ""

    try:
        der_chain = _get_chain_der(ssl_sock, hostname)
    finally:
        with contextlib.suppress(ssl.SSLError, OSError, ValueError):
            ssl_sock.close()

    if not der_chain:
        return ScanError(
            hostname=hostname, port=port, error_message="no certificate presented"
        )

    leaf_parsed = parse_certificate(der_chain[0])
    if not isinstance(leaf_parsed, Certificate):
        return ScanError(
            hostname=hostname, port=port, error_message=leaf_parsed.message
        )

    chain_certs: list[Certificate] = []
    for der in der_chain[1:]:
        cp = parse_certificate(der)
        if isinstance(cp, Certificate):
            cp.is_leaf = False
            chain_certs.append(cp)

    hsts = _probe_hsts(hostname, port, pinned_ip=pinned_ip, verify=verify, timeout=hsts_timeout)

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=chain_certs,
        scanned_at=datetime.now(UTC),
        protocol_version=protocol_version,
        hsts=hsts,
        verify_requested=verify,
    )


def _scan_host_via_openssl(
    hostname: str,
    port: int,
    *,
    timeout: float,
    allow_private: bool,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...],
    pinned_ip: str | None = None,
    verify: bool = False,
    max_output_bytes: int = DEFAULT_SCAN_MAX_OUTPUT_BYTES,
    hsts_timeout: float = 5.0,
    starttls_mode: str = "",
) -> ScannedEntry | ScanError:
    """Scan using openssl s_client only — one connection for both leaf and chain.

    Used on Python < 3.13 where SSLSocket lacks native chain methods, and for
    every STARTTLS scan (the native ssl path can't negotiate STARTTLS).
    If openssl is unavailable or fails, falls back to the Python TLS connection
    (leaf-only, no chain) — except for STARTTLS scans, where a wrapped-TLS
    fallback would target the wrong handshake, so a clear error is returned.
    """
    try:
        der_chain, protocol_version = _scan_via_openssl(
            hostname, port, timeout, allow_private=allow_private,
            allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip, max_output_bytes=max_output_bytes,
            starttls_mode=starttls_mode,
        )
    except ScanOutputTooLargeError as exc:
        return ScanError(hostname=hostname, port=port, error_message=str(exc))

    if der_chain:
        leaf_parsed = parse_certificate(der_chain[0])
        if isinstance(leaf_parsed, Certificate):
            chain_certs: list[Certificate] = []
            for der in der_chain[1:]:
                cp = parse_certificate(der)
                if isinstance(cp, Certificate):
                    cp.is_leaf = False
                    chain_certs.append(cp)
            return ScannedEntry(
                host=hostname,
                port=port,
                leaf=leaf_parsed,
                chain=chain_certs,
                scanned_at=datetime.now(UTC),
                protocol_version=protocol_version,
                hsts=_probe_hsts(
                    hostname, port, pinned_ip=pinned_ip, verify=verify, timeout=hsts_timeout,
                ),
                verify_requested=verify,
            )

    # A STARTTLS scan can't fall back to a wrapped-TLS handshake — that would
    # connect to a cleartext protocol port expecting immediate TLS and fail or
    # mislead. Surface the real cause instead (openssl missing or upgrade failed).
    if starttls_mode:
        return ScanError(
            hostname=hostname, port=port,
            error_message=(
                f"STARTTLS scan ({starttls_mode}) failed: openssl s_client "
                "unavailable or the server did not complete the STARTTLS upgrade"
            ),
        )

    logger.warning(
        "openssl scan degraded for %s:%s — certificate chain will be incomplete",
        hostname, port,
    )
    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except ValueError as exc:
        # The OSError family is caught above; this guards the remaining
        # non-OSError input errors in the openssl fallback path.
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version_fb = ""
    with contextlib.suppress(ssl.SSLError, OSError, ValueError):
        protocol_version_fb = ssl_sock.version() or ""

    try:
        leaf = ssl_sock.getpeercert(binary_form=True)
    finally:
        with contextlib.suppress(ssl.SSLError, OSError, ValueError):
            ssl_sock.close()

    if not leaf:
        return ScanError(
            hostname=hostname, port=port, error_message="no certificate presented"
        )

    leaf_parsed = parse_certificate(leaf)
    if not isinstance(leaf_parsed, Certificate):
        return ScanError(
            hostname=hostname, port=port, error_message=leaf_parsed.message
        )

    return ScannedEntry(
        host=hostname,
        port=port,
        leaf=leaf_parsed,
        chain=[],
        scanned_at=datetime.now(UTC),
        protocol_version=protocol_version_fb,
        hsts=_probe_hsts(hostname, port, pinned_ip=pinned_ip, verify=verify, timeout=hsts_timeout),
        verify_requested=verify,
        chain_incomplete=True,
    )


def _stage_resolve_pending_alerts(
    repo_path: str | Path,
    entry: ScannedEntry,
    webhook_config: object | None,
) -> tuple[list | None, str | None]:
    """Capture pending alerts BEFORE replace_scanned deletes them (BC-160)."""
    pending: list | None = None
    old_leaf_id: str | None = None
    if webhook_config is None:
        return None, None
    from cert_watch.alerts import WebhookConfig
    if not isinstance(webhook_config, WebhookConfig):
        return None, None
    from cert_watch.database import SqliteAlertRepository
    from cert_watch.database.connection import _connect
    with _connect(repo_path) as conn:
        row = conn.execute(
            "SELECT id FROM certificates"
            " WHERE hostname = ? AND port = ? AND is_leaf = 1",
            (entry.host, entry.port),
        ).fetchone()
    if row:
        old_leaf_id = row["id"]
        pending = SqliteAlertRepository(repo_path).list_for_cert(old_leaf_id)
    return pending, old_leaf_id


def _stage_replace(
    repo_path: str | Path,
    entry: ScannedEntry,
    conn: sqlite3.Connection,
) -> tuple[str, str | None]:
    """Persist leaf + chain, removing previous certs for the same (hostname, port)."""
    return replace_scanned(
        repo_path,
        hostname=entry.host,
        port=entry.port,
        leaf=entry.leaf,
        chain=entry.chain,
        chain_valid=None,
        conn=conn,
    )


def _stage_webhook_resolve(
    repo_path: str | Path,
    entry: ScannedEntry,
    replaced_cert_id: str | None,
    webhook_config: object | None,
    pending_for_resolve: list | None,
) -> None:
    """Send resolve events for open incidents on the replaced cert."""
    if not replaced_cert_id or webhook_config is None:
        return
    from cert_watch.alerts import WebhookConfig, resolve_webhook_for_renewed_cert
    if not isinstance(webhook_config, WebhookConfig):
        raise TypeError(f"expected WebhookConfig, got {type(webhook_config).__name__}")
    resolved = resolve_webhook_for_renewed_cert(
        repo_path, replaced_cert_id, webhook_config,
        pending_alerts=pending_for_resolve,
    )
    if resolved:
        logger.info(
            "resolved %d webhook incident(s) for replaced cert %s",
            resolved, replaced_cert_id,
        )


@dataclass
class _PostureEval:
    """Result of posture evaluation (WI-113: computed pre-transaction)."""
    grade: str = ""
    findings: list[dict] = field(default_factory=list)
    chain_status: str | None = None
    protocol_version: str = ""
    ocsp_stapling: bool | None = None
    hsts: bool | None = None
    must_staple: bool = False
    caa_present: bool | None = None
    caa_records: list[str] | None = None


def _evaluate_posture(
    db_path: str | Path,
    entry: ScannedEntry,
    *,
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> _PostureEval:
    """Evaluate TLS posture *without* storing (WI-113).

    Does network I/O (CAA DNS lookup, OCSP/CRL revocation checks) so it
    must run **before** ``BEGIN`` to avoid holding the write lock during
    network calls.  The caller stores the result inside the transaction
    via ``_stage_posture``.
    """
    from cert_watch.cert_chain import chain_status
    from cert_watch.certificate_model import Certificate as _Cert
    from cert_watch.database import SqliteTrustAnchorRepository
    from cert_watch.posture import evaluate_posture

    init_schema(db_path)
    cert = entry.leaf
    chain = entry.chain

    anchors = [_Cert(
        subject=a.subject, issuer=a.issuer,
        not_before=a.not_before, not_after=a.not_after,
        san_dns_names=a.san_dns_names,
        fingerprint_sha256=a.fingerprint_sha256,
        raw_der=a.raw_der,
    ) for a in SqliteTrustAnchorRepository(db_path).list_entries()]

    cs = chain_status(cert, chain, anchors) if chain else None

    caa_present: bool | None = None
    caa_records: list[str] | None = None
    if entry.host:
        from cert_watch.caa_check import check_caa
        try:
            caa_result = check_caa(entry.host)
            caa_present = bool(caa_result.records) and not caa_result.error
            caa_records = caa_result.records
        except (OSError, ValueError):
            caa_present = None

    scan_interval_days: int | None = None
    if entry.host:
        from cert_watch.database.connection import _connect
        with _connect(db_path) as c:
            row = c.execute(
                "SELECT scan_interval_hours FROM hosts WHERE hostname = ? AND port = ?",
                (entry.host, entry.port),
            ).fetchone()
        if row and row["scan_interval_hours"] is not None:
            scan_interval_days = max(row["scan_interval_hours"] // 24, 1)

    issuer_der: bytes | None = None
    if chain and cs == "private":
        for chain_cert in chain:
            if chain_cert.subject == cert.issuer:
                issuer_der = chain_cert.raw_der
                break

    result = evaluate_posture(
        cert=cert,
        protocol_version=entry.protocol_version or None,
        chain_status=cs,
        chain_incomplete=entry.chain_incomplete,
        hsts=entry.hsts,
        check_revocation=check_revocation,
        port=entry.port,
        caa_present=caa_present,
        caa_records=caa_records,
        scan_interval_days=scan_interval_days,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
        issuer_der=issuer_der,
    )

    return _PostureEval(
        grade=result.grade,
        findings=typing.cast("list[dict]", result.findings),
        chain_status=cs,
        protocol_version=result.protocol_version,
        ocsp_stapling=result.ocsp_stapling,
        hsts=result.hsts,
        must_staple=result.must_staple,
        caa_present=caa_present,
        caa_records=caa_records,
    )


def _stage_posture(
    repo_path: str | Path,
    leaf_id: str,
    entry: ScannedEntry,
    *,
    conn: sqlite3.Connection,
    eval_result: _PostureEval,
) -> tuple[str, list[dict], str | None]:
    """Store TLS posture results. Returns (grade, findings, chain_status).

    WI-113: posture *evaluation* (CAA DNS, OCSP/CRL) now runs pre-transaction
    via ``_evaluate_posture``; this stage only writes to the DB inside the
    transaction.
    """
    from cert_watch.database.connection import _iso
    from cert_watch.database.queries import store_scan_posture

    store_scan_posture(
        db_path=repo_path,
        cert_id=leaf_id,
        hostname=entry.host,
        port=entry.port,
        grade=eval_result.grade,
        findings=eval_result.findings,
        protocol_version=eval_result.protocol_version,
        ocsp_stapling=eval_result.ocsp_stapling,
        hsts=eval_result.hsts,
        must_staple=eval_result.must_staple,
        verify_requested=entry.verify_requested,
        chain_incomplete=entry.chain_incomplete,
        chain_status=eval_result.chain_status,
        caa_present=eval_result.caa_present,
        caa_records=eval_result.caa_records,
        scanned_at=_iso(entry.scanned_at),
        conn=conn,
    )
    return eval_result.grade, eval_result.findings, eval_result.chain_status


def _stage_previous_grade(
    repo_path: str | Path,
    leaf_id: str,
) -> str | None:
    """Read previous posture grade before any policy override writes."""
    from cert_watch.database.connection import _connect as _prev_conn
    with _prev_conn(repo_path) as _pc:
        _prev = _pc.execute(
            "SELECT grade FROM scan_posture WHERE cert_id = ?",
            (leaf_id,),
        ).fetchone()
    return _prev["grade"] if _prev else None


def _stage_policy(
    repo_path: str | Path,
    leaf_id: str,
    entry: ScannedEntry,
    posture_grade: str,
    original_findings: list[dict],
    stored_chain_status: str | None,
    *,
    conn: sqlite3.Connection,
    ruleset: PolicySet,
) -> str:
    """Evaluate policy overrides and fire policy violation alerts.

    Returns the (possibly updated) grade.
    """
    from cert_watch.policy import apply_policy_overrides, evaluate_policy
    from cert_watch.posture import Finding as _Finding
    posture_finding_objs: list[_Finding] | None = None
    if original_findings:
        posture_finding_objs = [
            _Finding(
                check=f["check"],
                status=f["status"],
                message=f.get("message", ""),
            )
            for f in original_findings
            if isinstance(f, dict) and "check" in f and "status" in f
        ]
    violations = evaluate_policy(
        cert=entry.leaf,
        chain_status=stored_chain_status,
        chain_incomplete=entry.chain_incomplete,
        protocol_version=entry.protocol_version or None,
        hsts=entry.hsts,
        ocsp_stapling=None,
        ruleset=ruleset,
        posture_findings=posture_finding_objs,
    )
    if violations:
        overridden = apply_policy_overrides(posture_grade, violations)
        if overridden != posture_grade:
            posture_grade = overridden
            from cert_watch.database.queries import store_scan_posture
            store_scan_posture(
                db_path=repo_path,
                cert_id=leaf_id,
                hostname=entry.host,
                port=entry.port,
                grade=overridden,
                findings=original_findings,
                protocol_version=entry.protocol_version,
                ocsp_stapling=None,
                hsts=entry.hsts,
                must_staple=False,
                verify_requested=entry.verify_requested,
                chain_incomplete=entry.chain_incomplete,
                chain_status=stored_chain_status,
                scanned_at=None,
                conn=conn,
            )
        from cert_watch.alerts import evaluate_policy_alerts
        evaluate_policy_alerts(
            cert_id=leaf_id,
            hostname=entry.host,
            violations=violations,
            db_path=str(repo_path),
            subject=entry.leaf.subject,
            conn=conn,
        )
    return posture_grade


def _stage_drift(
    repo_path: str | Path,
    leaf_id: str,
    entry: ScannedEntry,
    posture_grade: str,
    drift_alerts: bool,
    *,
    conn: sqlite3.Connection,
) -> None:
    """Detect drift from previous cert and optionally create alerts."""
    from cert_watch.database.queries import (
        _extract_key_algo,
        _extract_sig_algo,
        create_drift_alert,
        detect_drift,
    )
    key_algo = _extract_key_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
    sig_algo = _extract_sig_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
    drift_events = detect_drift(
        repo_path,
        hostname=entry.host,
        port=entry.port,
        new_leaf=entry.leaf,
        posture_grade=posture_grade,
        protocol_version=entry.protocol_version,
        key_algo=key_algo,
        sig_algo=sig_algo,
        conn=conn,
    )
    if drift_events and drift_alerts:
        create_drift_alert(
            repo_path,
            cert_id=leaf_id,
            hostname=entry.host,
            port=entry.port,
            events=drift_events,
            conn=conn,
        )


def _stage_history(
    repo_path: str | Path,
    entry: ScannedEntry,
    posture_grade: str,
    *,
    conn: sqlite3.Connection,
) -> None:
    """Record cert history entry."""
    from cert_watch.database.queries import record_cert_history
    record_cert_history(
        repo_path,
        hostname=entry.host,
        port=entry.port,
        leaf=entry.leaf,
        posture_grade=posture_grade,
        protocol_version=entry.protocol_version,
        conn=conn,
    )


def _stage_events(
    repo_path: str | Path,
    leaf_id: str,
    entry: ScannedEntry,
    replaced_cert_id: str | None,
    posture_grade: str,
    previous_grade: str | None,
    *,
    conn: sqlite3.Connection,
    event_config: EventStreamConfig,
) -> list[tuple]:
    """Emit cert_added/cert_renewed and posture_changed events.

    Webhook delivery is deferred (``_defer_webhook=True``) so the webhook
    thread pool doesn't fire before the transaction commits — preventing
    phantom events on COMMIT failure (WI-114). Returns a list of
    ``(event, config, row_id)`` tuples for the caller to submit after COMMIT.
    """
    from cert_watch.events import Event, emit_event

    pending: list[tuple] = []

    evt_type = "cert_renewed" if replaced_cert_id else "cert_added"
    event = Event(
        event_type=evt_type,
        timestamp=datetime.now(UTC),
        payload={
            "cert_id": leaf_id,
            "hostname": entry.host,
            "port": entry.port,
            "replaced_cert_id": replaced_cert_id,
        },
        source="scan",
    )
    row_id = emit_event(event, repo_path, config=event_config, conn=conn, _defer_webhook=True)
    if event_config.webhook_url and row_id is not None:
        pending.append((event, event_config, row_id))

    if posture_grade and previous_grade is not None and previous_grade != posture_grade:
        event = Event(
            event_type="posture_changed",
            timestamp=datetime.now(UTC),
            payload={
                "cert_id": leaf_id,
                "hostname": entry.host,
                "port": entry.port,
                "old_grade": previous_grade,
                "new_grade": posture_grade,
            },
            source="scan",
        )
        row_id = emit_event(event, repo_path, config=event_config, conn=conn, _defer_webhook=True)
        if event_config.webhook_url and row_id is not None:
            pending.append((event, event_config, row_id))

    return pending


def store_scanned(
    entry: ScannedEntry,
    repo_path_or_repo: str | Path | CertificateRepository,
    *,
    drift_alerts: bool = True,
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    webhook_config: object | None = None,
) -> str:
    """
    Persist leaf + chain. Accepts either an existing CertificateRepository OR a path
    (so callers can pass the db path directly and we wire up source/hostname/port).
    Removes any previous leaf + chain certs for the same (hostname, port) first to
    avoid accumulation on repeated scans. Also evaluates and stores TLS posture.
    See AC-07.

    All DB-writing stages (replace, posture, policy, drift, history, events) run
    inside a single SQLite transaction on the cached per-thread connection so a
    failure in any stage rolls back the whole scan result. The PagerDuty/Alertmanager
    resolve webhook runs after commit and is best-effort.

    When ``webhook_config`` is a ``WebhookConfig`` with ``kind="pagerduty"``
    or ``kind="alertmanager"``, sends resolve events for any open incidents
    on the replaced cert.
    """
    if isinstance(repo_path_or_repo, str | Path):
        repo_path = repo_path_or_repo
        init_schema(repo_path)
        if entry.chain_incomplete:
            logger.warning(
                "stored scan for %s:%s with incomplete chain (openssl degraded)",
                entry.host, entry.port,
            )

        def _stage(name: str, fn, *args, **kwargs):
            """Run a stage; on failure log with stage name and re-raise."""
            try:
                return fn(*args, **kwargs)
            except Exception:
                logger.warning(
                    "store_scanned [%s] failed for %s:%s",
                    name, entry.host, entry.port,
                    exc_info=True,
                )
                raise

        pending_for_resolve: list | None = None
        old_leaf_id: str | None = None
        previous_grade: str | None = None

        with contextlib.suppress(Exception):
            pending_for_resolve, old_leaf_id = _stage(
                "resolve_pending_alerts",
                _stage_resolve_pending_alerts,
                repo_path, entry, webhook_config,
            )

        with contextlib.suppress(Exception):
            if old_leaf_id:
                previous_grade = _stage(
                    "previous_grade", _stage_previous_grade,
                    repo_path, old_leaf_id,
                )

        # Pre-load configurations that read kv_store so they do not issue inner
        # commits while the scan transaction is active.
        from cert_watch.events import EventStreamConfig, load_event_config
        from cert_watch.policy import default_policy_set, load_policy_set
        try:
            event_config = load_event_config(repo_path)
        except Exception:
            event_config = EventStreamConfig()
        try:
            ruleset = load_policy_set(str(repo_path))
        except Exception:
            ruleset = default_policy_set()

        from cert_watch.database.connection import _connect
        conn = _connect(repo_path)
        leaf_id: str = ""
        replaced_cert_id: str | None = None
        posture_grade: str = ""
        original_findings: list[dict] = []
        stored_chain_status: str | None = None
        pending_event_webhooks: list[tuple] = []

        try:
            # WI-113: evaluate posture (network I/O — CAA DNS, OCSP/CRL)
            # BEFORE BEGIN so the write lock isn't held during network calls.
            posture_eval = _evaluate_posture(
                repo_path, entry,
                check_revocation=check_revocation,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
            )
            conn.execute("BEGIN")
            leaf_id, replaced_cert_id = _stage(
                "replace", _stage_replace, repo_path, entry, conn,
            )
            posture_grade, original_findings, stored_chain_status = _stage(
                "posture", _stage_posture, repo_path, leaf_id, entry,
                conn=conn,
                eval_result=posture_eval,
            )
            posture_grade = _stage(
                "policy", _stage_policy,
                repo_path, leaf_id, entry,
                posture_grade, original_findings, stored_chain_status,
                conn=conn, ruleset=ruleset,
            )
            _stage(
                "drift", _stage_drift,
                repo_path, leaf_id, entry, posture_grade, drift_alerts,
                conn=conn,
            )
            _stage(
                "history", _stage_history,
                repo_path, entry, posture_grade,
                conn=conn,
            )
            pending_event_webhooks = _stage(
                "events", _stage_events,
                repo_path, leaf_id, entry,
                replaced_cert_id, posture_grade, previous_grade,
                conn=conn, event_config=event_config,
            )
            conn.commit()
        except Exception:
            logger.warning(
                "store_scanned transaction failed for %s:%s",
                entry.host, entry.port, exc_info=True,
            )
            with contextlib.suppress(sqlite3.Error):
                conn.rollback()
            return ""

        # Post-transaction HTTP: failures must not invalidate the scan.
        with contextlib.suppress(Exception):
            _stage(
                "webhook_resolve",
                _stage_webhook_resolve,
                repo_path, entry, replaced_cert_id,
                webhook_config, pending_for_resolve,
            )

        # WI-114: fire deferred event webhooks only after COMMIT succeeded.
        for evt, cfg, rid in (pending_event_webhooks or []):
            try:
                from cert_watch.events import _deliver_webhook, _get_pool
                _get_pool().submit(_deliver_webhook, evt, cfg, str(repo_path), rid)
            except Exception:
                logger.warning("deferred event webhook submit failed", exc_info=True)

        return leaf_id

    repo = repo_path_or_repo
    leaf_id = repo.add(entry.leaf)
    for chain_cert in entry.chain:
        repo.add(chain_cert)
    return leaf_id


def _evaluate_and_store_posture(
    db_path: str | Path,
    cert_id: str,
    entry: ScannedEntry,
    *,
    conn: sqlite3.Connection | None = None,
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> tuple[str, list[dict], str | None]:
    """Evaluate TLS posture and store the result. Returns (grade, findings, chain_status).

    Backward-compat wrapper: ``_evaluate_posture`` (pre-transaction, network I/O)
    + ``store_scan_posture`` (in-transaction DB write).  ``store_scanned`` calls
    them separately so network I/O stays outside the transaction (WI-113).
    """
    from cert_watch.database.connection import _iso
    from cert_watch.database.queries import store_scan_posture

    if conn is None:
        init_schema(db_path)
    eval_result = _evaluate_posture(
        db_path,
        entry,
        check_revocation=check_revocation,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
    )
    store_scan_posture(
        db_path=db_path,
        cert_id=cert_id,
        hostname=entry.host,
        port=entry.port,
        grade=eval_result.grade,
        findings=eval_result.findings,
        protocol_version=eval_result.protocol_version,
        ocsp_stapling=eval_result.ocsp_stapling,
        hsts=eval_result.hsts,
        must_staple=eval_result.must_staple,
        verify_requested=entry.verify_requested,
        chain_incomplete=entry.chain_incomplete,
        chain_status=eval_result.chain_status,
        caa_present=eval_result.caa_present,
        caa_records=eval_result.caa_records,
        scanned_at=_iso(entry.scanned_at),
        conn=conn,
    )
    return eval_result.grade, eval_result.findings, eval_result.chain_status


async def scan_host_async(
    hostname: str,
    port: int = 443,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    dns_servers: tuple[str, ...] = (),
    retries: int = SCAN_RETRIES,
    pinned_ip: str | None = None,
    max_output_bytes: int = DEFAULT_SCAN_MAX_OUTPUT_BYTES,
    hsts_timeout: float = 5.0,
    starttls_mode: str = "",
) -> ScannedEntry | ScanError:
    """Async wrapper around scan_host — runs the blocking TLS scan in a thread."""
    return await asyncio.to_thread(
        scan_host,
        hostname,
        port,
        timeout=timeout,
        verify=verify,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
        dns_servers=dns_servers,
        retries=retries,
        pinned_ip=pinned_ip,
        max_output_bytes=max_output_bytes,
        hsts_timeout=hsts_timeout,
        starttls_mode=starttls_mode,
    )


async def store_scanned_async(
    entry: ScannedEntry,
    repo_path_or_repo: str | Path | CertificateRepository,
    *,
    drift_alerts: bool = True,
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    webhook_config: object | None = None,
) -> str:
    """Async wrapper around store_scanned — runs the blocking DB writes in a thread.

    Acquires the cross-thread write lock inside the worker thread so
    request-handler stores mutually exclude with the scheduler's scan cycle
    (which holds the same lock around its direct ``store_scanned`` calls).
    The lock lives here, not inside ``store_scanned`` itself, so the
    scheduler's already-locked path does not re-enter a non-reentrant
    ``threading.Lock``.
    """
    def _run() -> str:
        with get_write_lock():
            return store_scanned(
                entry,
                repo_path_or_repo,
                drift_alerts=drift_alerts,
                check_revocation=check_revocation,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
                webhook_config=webhook_config,
            )
    return await asyncio.to_thread(_run)
