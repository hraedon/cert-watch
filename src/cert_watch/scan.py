"""TLS scanning. See spec wi_fr02_tls_scan.md."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import typing
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import init_schema, replace_scanned
from cert_watch.retry import backoff_range
from cert_watch.scan_conn import (  # noqa: F401
    _PROTOCOL_RE,
    HSTS_TIMEOUT,
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
) -> ScannedEntry | ScanError:
    """Perform a TLS handshake and return ScannedEntry or ScanError. See AC-01..AC-06.

    When pinned_ip is None, the hostname is resolved once per attempt and the
    resulting IP is pinned for the entire scan (DNS-rebinding hardening, BC-063).
    """
    last_error: ScanError | None = None
    for _ in backoff_range(retries, SCAN_RETRY_BACKOFF, strategy="exponential"):
        result = _scan_host_once(
            hostname, port, timeout=timeout, verify=verify,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip,
        )
        if isinstance(result, ScannedEntry):
            return result
        last_error = result
    assert last_error is not None
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

    if not _has_native_chain_api():
        return _scan_host_via_openssl(
            hostname, port, timeout=timeout,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip, verify=verify,
        )

    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=verify, allow_private=allow_private,
            allowed_subnets=allowed_subnets,
            dns_servers=dns_servers, pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version = ""
    with contextlib.suppress(Exception):
        protocol_version = ssl_sock.version() or ""

    try:
        der_chain = _get_chain_der(ssl_sock, hostname)
    finally:
        with contextlib.suppress(Exception):
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

    hsts = _probe_hsts(hostname, port, pinned_ip=pinned_ip)

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
) -> ScannedEntry | ScanError:
    """Scan using openssl s_client only — one connection for both leaf and chain.

    Used on Python < 3.13 where SSLSocket lacks native chain methods.
    If openssl is unavailable or fails, falls back to the Python TLS
    connection (leaf-only, no chain).
    """
    der_chain, protocol_version = _scan_via_openssl(
        hostname, port, timeout, allow_private=allow_private,
        allowed_subnets=allowed_subnets, dns_servers=dns_servers,
        pinned_ip=pinned_ip,
    )

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
                hsts=_probe_hsts(hostname, port, pinned_ip=pinned_ip),
                verify_requested=False,
            )

    logger.warning(
        "openssl scan degraded for %s:%s — certificate chain will be incomplete",
        hostname, port,
    )
    try:
        ssl_sock = _open_tls_connection(
            hostname, port, timeout, verify=False,
            allow_private=allow_private, allowed_subnets=allowed_subnets, dns_servers=dns_servers,
            pinned_ip=pinned_ip,
        )
    except (TimeoutError, OSError) as exc:
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))
    except Exception as exc:  # noqa: BLE001
        return ScanError(hostname=hostname, port=port, error_message=_friendly_scan_error(exc))

    protocol_version_fb = ""
    with contextlib.suppress(Exception):
        protocol_version_fb = ssl_sock.version() or ""

    try:
        leaf = ssl_sock.getpeercert(binary_form=True)
    finally:
        with contextlib.suppress(Exception):
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
        hsts=_probe_hsts(hostname, port, pinned_ip=pinned_ip),
        verify_requested=False,
        chain_incomplete=True,
    )


def store_scanned(
    entry: ScannedEntry,
    repo_path_or_repo,
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

    When ``webhook_config`` is a ``WebhookConfig`` with ``kind="pagerduty"``
    or ``kind="alertmanager"``, sends resolve events for any open incidents
    on the replaced cert.
    """
    if isinstance(repo_path_or_repo, str | Path):
        init_schema(repo_path_or_repo)
        if entry.chain_incomplete:
            logger.warning(
                "stored scan for %s:%s with incomplete chain (openssl degraded)",
                entry.host, entry.port,
            )
        # Capture pending alerts BEFORE replace_scanned deletes them (BC-160).
        pending_for_resolve: list | None = None
        old_leaf_id_for_resolve: str | None = None
        if webhook_config is not None:
            try:
                from cert_watch.alerts import WebhookConfig
                if isinstance(webhook_config, WebhookConfig):
                    from cert_watch.database import SqliteAlertRepository
                    from cert_watch.database.connection import _connect
                    with _connect(repo_path_or_repo) as conn:
                        row = conn.execute(
                            "SELECT id FROM certificates"
                            " WHERE hostname = ? AND port = ? AND is_leaf = 1",
                            (entry.host, entry.port),
                        ).fetchone()
                    if row:
                        old_leaf_id_for_resolve = row["id"]
                        pending_for_resolve = SqliteAlertRepository(
                            repo_path_or_repo
                        ).list_for_cert(old_leaf_id_for_resolve)
            except Exception:  # noqa: BLE001
                logger.debug("pre-fetch alerts for resolve failed", exc_info=True)

        leaf_id, replaced_cert_id = replace_scanned(
            repo_path_or_repo,
            hostname=entry.host,
            port=entry.port,
            leaf=entry.leaf,
            chain=entry.chain,
            chain_valid=None,
        )
        if replaced_cert_id and webhook_config is not None:
            try:
                from cert_watch.alerts import WebhookConfig, resolve_webhook_for_renewed_cert
                if not isinstance(webhook_config, WebhookConfig):
                    raise TypeError(f"expected WebhookConfig, got {type(webhook_config).__name__}")
                resolved = resolve_webhook_for_renewed_cert(
                    repo_path_or_repo, replaced_cert_id, webhook_config,
                    pending_alerts=pending_for_resolve,
                )
                if resolved:
                    logger.info(
                        "resolved %d webhook incident(s) for replaced cert %s",
                        resolved, replaced_cert_id,
                    )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "webhook resolve failed for %s:%s",
                    entry.host, entry.port,
                    exc_info=True,
                )
        posture_grade = ""
        original_findings: list[dict] = []
        try:
            posture_grade, original_findings = _evaluate_and_store_posture(
                repo_path_or_repo, leaf_id, entry,
                check_revocation=check_revocation,
                allow_private=allow_private,
                allowed_subnets=allowed_subnets,
            )
        except Exception:  # noqa: BLE001
            logger.debug(
                "posture evaluation skipped for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        # Read previous grade BEFORE any policy override writes, so the
        # posture_changed event compares against the correct baseline.
        previous_grade: str | None = None
        try:
            from cert_watch.database.connection import _connect as _prev_conn

            with _prev_conn(repo_path_or_repo) as _pc:
                _prev = _pc.execute(
                    "SELECT grade FROM scan_posture WHERE cert_id = ?",
                    (leaf_id,),
                ).fetchone()
            if _prev:
                previous_grade = _prev["grade"]
        except Exception:  # noqa: BLE001
            logger.debug("previous grade read skipped for %s:%s", entry.host, entry.port)
        try:
            from cert_watch.policy import apply_policy_overrides, evaluate_policy, load_policy_set
            from cert_watch.posture import Finding as _Finding
            ruleset = load_policy_set(str(repo_path_or_repo))
            # Reconstruct Finding objects from the stored dicts so
            # evaluate_policy can skip rules that posture already flagged (WI-014).
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
                chain_status=None,
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
                    try:
                        from cert_watch.database.queries import store_scan_posture

                        # Preserve the original findings from the posture evaluation
                        # rather than wiping them with an empty list (C3).
                        store_scan_posture(
                            db_path=repo_path_or_repo,
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
                            chain_status=None,
                            scanned_at=None,
                        )
                    except Exception:  # noqa: BLE001
                        logger.debug(
                            "policy grade override write failed for %s:%s",
                            entry.host, entry.port, exc_info=True,
                        )
                from cert_watch.alerts import evaluate_policy_alerts
                evaluate_policy_alerts(
                    cert_id=leaf_id,
                    hostname=entry.host,
                    violations=violations,
                    db_path=str(repo_path_or_repo),
                    subject=entry.leaf.subject,
                )
        except Exception:  # noqa: BLE001
            logger.debug(
                "policy evaluation skipped for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        try:
            from cert_watch.database.queries import (
                _extract_key_algo,
                _extract_sig_algo,
                create_drift_alert,
                detect_drift,
            )
            key_algo = _extract_key_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
            sig_algo = _extract_sig_algo(entry.leaf.raw_der) if entry.leaf.raw_der else ""
            drift_events = detect_drift(
                repo_path_or_repo,
                hostname=entry.host,
                port=entry.port,
                new_leaf=entry.leaf,
                posture_grade=posture_grade,
                protocol_version=entry.protocol_version,
                key_algo=key_algo,
                sig_algo=sig_algo,
            )
            if drift_events and drift_alerts:
                try:
                    create_drift_alert(
                        repo_path_or_repo,
                        cert_id=leaf_id,
                        hostname=entry.host,
                        port=entry.port,
                        events=drift_events,
                    )
                except Exception:  # noqa: BLE001
                    logger.debug(
                        "drift alert creation skipped for %s:%s", entry.host, entry.port,
                        exc_info=True,
                    )
        except Exception:  # noqa: BLE001
            logger.warning(
                "drift detection failed for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        try:
            from cert_watch.database.queries import record_cert_history
            record_cert_history(
                repo_path_or_repo,
                hostname=entry.host,
                port=entry.port,
                leaf=entry.leaf,
                posture_grade=posture_grade,
                protocol_version=entry.protocol_version,
            )
        except Exception:  # noqa: BLE001
            logger.warning(
                "cert_history write failed for %s:%s", entry.host, entry.port,
                exc_info=True,
            )
        try:
            from cert_watch.events import Event, emit_event

            evt_type = "cert_renewed" if replaced_cert_id else "cert_added"
            emit_event(
                Event(
                    event_type=evt_type,
                    timestamp=datetime.now(UTC),
                    payload={
                        "cert_id": leaf_id,
                        "hostname": entry.host,
                        "port": entry.port,
                        "replaced_cert_id": replaced_cert_id,
                    },
                    source="scan",
                ),
                repo_path_or_repo,
            )
        except Exception:  # noqa: BLE001
            logger.debug("event emit skipped for %s:%s", entry.host, entry.port, exc_info=True)
        try:
            if posture_grade and previous_grade is not None and previous_grade != posture_grade:
                from cert_watch.events import Event, emit_event

                emit_event(
                    Event(
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
                    ),
                    repo_path_or_repo,
                )
        except Exception:  # noqa: BLE001
            logger.debug(
                "posture_changed event skipped for %s:%s",
                entry.host, entry.port, exc_info=True,
            )
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
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
) -> tuple[str, list[dict]]:
    """Evaluate TLS posture and store the result. Returns (grade, findings)."""
    from cert_watch.cert_chain import chain_status
    from cert_watch.certificate_model import Certificate as _Cert
    from cert_watch.database import SqliteTrustAnchorRepository
    from cert_watch.database.connection import _iso
    from cert_watch.database.queries import store_scan_posture
    from cert_watch.posture import evaluate_posture

    cert = entry.leaf
    chain = entry.chain

    init_schema(db_path)
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
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
    )

    store_scan_posture(
        db_path=db_path,
        cert_id=cert_id,
        hostname=entry.host,
        port=entry.port,
        grade=result.grade,
        findings=typing.cast("list[dict]", result.findings),
        protocol_version=result.protocol_version,
        ocsp_stapling=result.ocsp_stapling,
        hsts=result.hsts,
        must_staple=result.must_staple,
        verify_requested=entry.verify_requested,
        chain_incomplete=entry.chain_incomplete,
        chain_status=cs,
        caa_present=caa_present,
        caa_records=caa_records,
        scanned_at=_iso(entry.scanned_at),
    )
    return result.grade, typing.cast("list[dict]", result.findings)


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
    )


async def store_scanned_async(
    entry: ScannedEntry,
    repo_path_or_repo,
    *,
    drift_alerts: bool = True,
    check_revocation: bool = False,
    allow_private: bool = True,
    allowed_subnets: tuple[str, ...] = (),
    webhook_config: object | None = None,
) -> str:
    """Async wrapper around store_scanned — runs the blocking DB writes in a thread."""
    return await asyncio.to_thread(
        store_scanned,
        entry,
        repo_path_or_repo,
        drift_alerts=drift_alerts,
        check_revocation=check_revocation,
        allow_private=allow_private,
        allowed_subnets=allowed_subnets,
        webhook_config=webhook_config,
    )
