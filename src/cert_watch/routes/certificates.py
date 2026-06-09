"""Certificate detail, delete, notes, upload, and trust anchor routes."""

from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse

from cert_watch import __commit__, __version__
from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
from cert_watch.cert_chain import validate_is_ca_certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteTrustAnchorRepository,
    _connect,
    _row_to_cert,
    delete_certificate_cascade,
    get_renewal_history,
)
from cert_watch.filters import (
    compute_urgency,
    friendly_issuer,
    issuer_cn,
    subject_cn,
)
from cert_watch.middleware import (
    _extract_client_ip,
    check_rate_limit,
    get_auth_context,
    get_csrf_context,
    require_auth,
    require_write_form,
)
from cert_watch.routes._deps import IdParam, _db_path, get_templates
from cert_watch.upload import ParseError, store_uploaded, upload_certificate

logger = logging.getLogger("cert_watch.routes.certificates")

router = APIRouter()

templates = get_templates()

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@router.get("/certificates/{cert_id}", response_class=HTMLResponse, response_model=None)
def certificate_detail(request: Request, cert_id: IdParam) -> HTMLResponse | RedirectResponse:
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        # No cert — maybe this is a pending host (scan failed, no cert stored yet).
        host_repo = SqliteHostRepository(db)
        host = host_repo.get(cert_id)
        if host is not None:
            # Get latest scan status/error for this host
            with _connect(db) as conn:
                scan_row = conn.execute(
                    "SELECT status, scanned_at, error_message FROM scan_history "
                    "WHERE hostname = ? AND port = ? "
                    "ORDER BY scanned_at DESC LIMIT 1",
                    (host.hostname, host.port),
                ).fetchone()
            csrf_ctx = get_csrf_context(request)
            auth_ctx = get_auth_context(request)
            return templates.TemplateResponse(
                request=request,
                name="host_detail.html",
                context={
                    "host": host,
                    "scan_status": scan_row["status"] if scan_row else None,
                    "scan_error": scan_row["error_message"] if scan_row else None,
                    "scan_at": scan_row["scanned_at"] if scan_row else None,
                    **auth_ctx,
                    **csrf_ctx,
                    "active_page": "dashboard",
                    "version": __version__,
                    "commit": __commit__,
                },
            )
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    # Parse key type and signature algorithm from raw DER
    try:
        x509_cert = x509.load_der_x509_certificate(cert.raw_der)
        key_info = x509_cert.public_key()
        key_type_str = type(key_info).__name__
        try:
            if isinstance(key_info, rsa.RSAPublicKey):
                key_type_str = f"RSA {key_info.key_size}"
            elif isinstance(key_info, ec.EllipticCurvePublicKey):
                key_type_str = f"ECDSA {key_info.curve.name}"
            elif isinstance(key_info, ed25519.Ed25519PublicKey):
                key_type_str = "Ed25519"
            elif isinstance(key_info, ed448.Ed448PublicKey):
                key_type_str = "Ed448"
        except Exception:
            pass
        sig_alg = x509_cert.signature_algorithm_oid._name
        serial = format(x509_cert.serial_number, "X")
        serial = ":".join(serial[i : i + 2] for i in range(0, len(serial), 2))
    except Exception:
        key_type_str = "unknown"
        sig_alg = "unknown"
        serial = "unknown"

    fp_hex = cert.fingerprint_sha256
    if ":" not in fp_hex and len(fp_hex) == 64:
        fp_hex = ":".join(fp_hex[i : i + 2] for i in range(0, len(fp_hex), 2)).upper()

    # Get chain (non-leaf certs with this cert as parent)
    with _connect(db) as conn:
        chain_rows = conn.execute(
            "SELECT * FROM certificates WHERE parent_cert_id = ? AND is_leaf = 0",
            (cert_id,),
        ).fetchall()

    chain_certs = []
    for cr in chain_rows:
        c = _row_to_cert(cr)
        chain_days = c.days_until_expiry()
        # Determine key type from raw DER
        kt = "unknown"
        try:
            x509_chain = x509.load_der_x509_certificate(c.raw_der)
            k = x509_chain.public_key()
            kt = type(k).__name__
            if isinstance(k, rsa.RSAPublicKey):
                kt = f"RSA {k.key_size}"
            elif isinstance(k, ec.EllipticCurvePublicKey):
                kt = f"ECDSA {k.curve.name}"
            elif isinstance(k, ed25519.Ed25519PublicKey):
                kt = "Ed25519"
            elif isinstance(k, ed448.Ed448PublicKey):
                kt = "Ed448"
        except Exception:
            pass
        chain_certs.append(
            {
                "id": cr["id"],
                "subject": c.subject,
                "issuer": c.issuer,
                "not_after": c.not_after.isoformat(),
                "days_remaining": chain_days,
                "subject_cn": subject_cn(c.subject),
                "issuer_org": friendly_issuer(c.issuer),
                "key_type": kt,
            }
        )

    # Determine chain status
    from cert_watch.cert_chain import chain_status as _chain_status

    anchors = SqliteTrustAnchorRepository(db).list_entries()
    chain_certs_objects = [_row_to_cert(cr) for cr in chain_rows]
    cs = _chain_status(cert, chain_certs_objects, anchors)

    # Compute urgency from the cert and chain
    leaf_days = cert.days_until_expiry()
    all_chain_days = [ch["days_remaining"] for ch in chain_certs]
    worst_days = min([leaf_days] + all_chain_days) if all_chain_days else leaf_days
    urgency = compute_urgency(worst_days)

    # Override urgency if chain issue
    chain_issue = None
    if cs in ("incomplete", "invalid"):
        chain_issue = cs

    # Get host info if scanned
    hostname = ""
    port = 443
    with _connect(db) as conn:
        host_row = conn.execute(
            "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
        ).fetchone()
        if host_row:
            hostname = host_row["hostname"] or ""
            port = host_row["port"] or 443

    # Get last scan time
    last_scan = None
    if hostname:
        with _connect(db) as conn:
            scan_row = conn.execute(
                "SELECT scanned_at FROM scan_history "
                "WHERE hostname = ? AND port = ? "
                "ORDER BY scanned_at DESC LIMIT 1",
                (hostname, port),
            ).fetchone()
            if scan_row:
                last_scan = scan_row["scanned_at"]

    # Get host info for operation summary
    host_info = None
    host_id = ""
    renewal_method_label = ""
    renewal_method_indicator = ""
    if hostname:
        with _connect(db) as conn:
            host_row = conn.execute(
                "SELECT * FROM hosts WHERE hostname = ? AND port = ?",
                (hostname, port),
            ).fetchone()
        if host_row:
            h = dict(host_row)
            host_id = h.get("id", "")
            host_info = {
                "owner_name": h.get("owner_name") or None,
                "owner_email": h.get("owner_email") or None,
                "owner_slack": h.get("owner_slack") or None,
                "renewal_status": h.get("renewal_status", "pending"),
                "renewal_method": h.get("renewal_method", ""),
                "runbook_url": h.get("runbook_url") or None,
                "notes": h.get("notes", ""),
            }
            rm = h.get("renewal_method", "")
            if rm == "acme":
                renewal_method_label = "ACME"
                renewal_method_indicator = "auto-renews"
            elif rm == "cert-manager":
                renewal_method_label = "cert-manager"
                renewal_method_indicator = "auto-renews"
            elif rm == "manual":
                renewal_method_label = "Manual"
                renewal_method_indicator = "requires manual action"
            elif rm:
                renewal_method_label = rm.capitalize()

    # Get renewal history
    renewal_history = get_renewal_history(db, cert_id)

    # Get drift events from cert_history (compare consecutive entries)
    drift_events = []
    if hostname:
        from cert_watch.database import list_cert_history

        history_entries = list_cert_history(db, hostname, port, limit=50)
        for i in range(len(history_entries) - 1):
            curr = history_entries[i]
            prev = history_entries[i + 1]
            changes = []
            if (
                curr.get("issuer") and prev.get("issuer")
                and curr["issuer"] != prev["issuer"]
            ):
                prev_issuer = issuer_cn(prev["issuer"])
                curr_issuer = issuer_cn(curr["issuer"])
                changes.append({
                    "field": "Issuer changed",
                    "change": f"{prev_issuer} → {curr_issuer}",
                    "sev": "high",
                })
            if (
                curr.get("key_algo") and prev.get("key_algo")
                and curr["key_algo"] != prev["key_algo"]
            ):
                changes.append({
                    "field": "Key algorithm changed",
                    "change": f'{prev["key_algo"]} → {curr["key_algo"]}',
                    "sev": "high",
                })
            if (
                curr.get("sig_algo") and prev.get("sig_algo")
                and curr["sig_algo"] != prev["sig_algo"]
            ):
                curr_sig = (curr["sig_algo"] or "").lower()
                prev_sig = (prev["sig_algo"] or "").lower()
                is_downgrade = "sha1" in curr_sig and "sha1" not in prev_sig
                changes.append({
                    "field": "Signature algorithm changed",
                    "change": f'{prev["sig_algo"]} → {curr["sig_algo"]}',
                    "sev": "high" if is_downgrade else "info",
                })
            if (
                curr.get("posture_grade") and prev.get("posture_grade")
                and curr["posture_grade"] != prev["posture_grade"]
            ):
                from cert_watch.posture import GRADE_WORST_ORDER

                grade_order = GRADE_WORST_ORDER
                curr_g = grade_order.get(curr["posture_grade"], 0)
                prev_g = grade_order.get(prev["posture_grade"], 0)
                if curr_g > prev_g:
                    changes.append({
                        "field": "Posture grade dropped",
                        "change": (
                            f'{prev["posture_grade"]} '
                            f'→ {curr["posture_grade"]}'
                        ),
                        "sev": "high",
                    })
            for change in changes:
                change["when"] = curr.get("scanned_at", "")[:10]
                drift_events.append(change)

    # Get posture evaluation
    from cert_watch.database import get_posture_for_cert
    from cert_watch.posture import evaluate_posture

    _posture = get_posture_for_cert(db, cert_id)
    posture_data: dict | None = None
    if _posture:
        posture_data = _posture
    else:
        try:
            result = evaluate_posture(
                cert=cert,
                chain_status=cs,
                chain_incomplete=bool(_posture.get('chain_incomplete')) if _posture else False,
            )
            posture_data = {
                "grade": result.grade,
                "findings": [
                    {"check": f.check, "status": f.status, "message": f.message}
                    for f in result.findings
                ],
                "protocol_version": result.protocol_version,
                "ocsp_stapling": result.ocsp_stapling,
                "hsts": result.hsts,
                "must_staple": result.must_staple,
            }
        except Exception:  # noqa: BLE001
            logger.exception("posture evaluation failed for cert %s", cert_id)
            pass

    csrf_ctx = get_csrf_context(request)
    auth_ctx = get_auth_context(request)
    from datetime import UTC, datetime

    return templates.TemplateResponse(
        request=request,
        name="certificate_detail.html",
        context={
            "cert": cert,
            "cert_id": cert_id,
            "version": __version__,
            "commit": __commit__,
            **auth_ctx,
            "active_page": "dashboard",
            "key_type": key_type_str,
            "sig_alg": sig_alg,
            "serial": serial,
            "fingerprint": fp_hex,
            "chain": chain_certs,
            "chain_status": cs,
            "urgency": urgency,
            "days_remaining": leaf_days,
            "subject_cn": subject_cn(cert.subject),
            "issuer_org": friendly_issuer(cert.issuer),
            "issuer_cn": issuer_cn(cert.issuer),
            "hostname": hostname,
            "port": port,
            "host_id": host_id,
            "last_scan": last_scan,
            "host_info": host_info,
            "chain_issue": chain_issue,
            "renewal_history": renewal_history,
            "renewal_method_label": renewal_method_label,
            "renewal_method_indicator": renewal_method_indicator,
            "now": datetime.now(UTC),
            "posture": posture_data,
            "drift_events": drift_events,
            **csrf_ctx,
        },
    )


@router.get("/api/certificates/{cert_id}/posture", response_model=None)
def certificate_posture_api(request: Request, cert_id: IdParam, _auth: str = Depends(require_auth)):
    """Return the latest posture evaluation for a certificate as JSON."""
    db = _db_path(request)
    from cert_watch.database import get_posture_for_cert

    posture = get_posture_for_cert(db, cert_id)
    if posture is None:
        return {"error": "no posture data", "cert_id": cert_id}
    return {
        "cert_id": cert_id,
        "grade": posture["grade"],
        "findings": posture["findings"],
        "protocol_version": posture.get("protocol_version", ""),
        "ocsp_stapling": posture.get("ocsp_stapling"),
        "hsts": posture.get("hsts"),
        "must_staple": posture.get("must_staple", False),
        "scanned_at": posture.get("scanned_at", ""),
    }


@router.post("/certificates/{cert_id}/delete")
async def delete_certificate(request: Request, cert_id: IdParam) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)
    delete_certificate_cascade(db, cert_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="cert.delete",
        target_type="certificate",
        target_id=cert_id,
        source_ip=resolve_source_ip(request),
    )
    logger.info("deleted certificate %s (cascade)", cert_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/certificates/{cert_id}/notes")
async def update_certificate_notes(
    request: Request, cert_id: IdParam, notes: str = Form(...)
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    if len(notes) > 10000:
        return RedirectResponse(
            url=f"/?error={quote('notes too long (max 10000)')}", status_code=303
        )
    db = _db_path(request)

    repo = SqliteCertificateRepository(db)
    if repo.get_by_id(cert_id) is None:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    repo.update_notes(cert_id, notes)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="cert.update_notes",
        target_type="certificate",
        target_id=cert_id,
        detail={"notes_length": len(notes)},
        source_ip=resolve_source_ip(request),
    )
    logger.info("updated notes for certificate %s", cert_id)
    return RedirectResponse(url="/", status_code=303)


@router.post("/certificates/{cert_id}/owner")
async def update_certificate_owner(
    request: Request,
    cert_id: IdParam,
    owner_name: str = Form(""),
    owner_email: str = Form(""),
    owner_slack: str = Form(""),
    renewal_method: str = Form(""),
    runbook_url: str = Form(""),
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)

    # If no cert exists, the cert_id may be a host_id (pending/failed scan).
    host_repo = SqliteHostRepository(db)
    host = host_repo.get(cert_id)
    if host is not None:
        # Pending host path — apply updates directly.
        host_id = cert_id
        hostname = host.hostname
        port = host.port
    else:
        repo = SqliteCertificateRepository(db)
        cert = repo.get_by_id(cert_id)
        if cert is None:
            return RedirectResponse(url="/?error=certificate+not+found", status_code=303)

        # Find host by certificate hostname/port
        hostname = ""
        port = 443
        with _connect(db) as conn:
            row = conn.execute(
                "SELECT hostname, port FROM certificates WHERE id = ?", (cert_id,)
            ).fetchone()
            if row:
                hostname = row["hostname"] or ""
                port = row["port"] or 443

        if not hostname:
            return RedirectResponse(
                url=f"/certificates/{cert_id}?error={quote('no host associated')}",
                status_code=303,
            )

        with _connect(db) as conn:
            host_row = conn.execute(
                "SELECT id FROM hosts WHERE hostname = ? AND port = ?", (hostname, port)
            ).fetchone()
        if not host_row:
            return RedirectResponse(
                url=f"/certificates/{cert_id}?error={quote('host not found')}", status_code=303,
            )

        host_id = host_row["id"]
    valid_methods = {"", "acme", "cert-manager", "manual"}
    if renewal_method not in valid_methods:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote('invalid renewal method')}", status_code=303,
        )
    if owner_email and "@" not in owner_email:
        return RedirectResponse(
            url=f"/certificates/{cert_id}?error={quote('invalid email')}", status_code=303,
        )
    if runbook_url:
        from cert_watch.routes.api._shared import _runbook_url_error
        err = _runbook_url_error(runbook_url)
        if err:
            return RedirectResponse(
                url=f"/certificates/{cert_id}?error={quote(err)}", status_code=303,
            )

    host_repo.update_owner(
        host_id,
        owner_name=owner_name,
        owner_email=owner_email,
        owner_slack=owner_slack,
    )
    host_repo.update_renewal(
        host_id,
        renewal_method=renewal_method,
        runbook_url=runbook_url,
    )
    record_audit(
        db,
        actor=resolve_actor(request),
        action="owner.update",
        target_type="host",
        target_id=host_id,
        detail={
            "owner_name": owner_name,
            "owner_email": owner_email,
            "owner_slack": owner_slack,
            "renewal_method": renewal_method,
            "runbook_url": runbook_url,
        },
        source_ip=resolve_source_ip(request),
    )
    logger.info("updated owner for host %s via certificate %s", host_id, cert_id)
    return RedirectResponse(url=f"/certificates/{cert_id}", status_code=303)


@router.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),  # noqa: B008
) -> RedirectResponse:
    csrf_err = await require_write_form(request)
    if csrf_err:
        return csrf_err
    if not check_rate_limit(f"upload:{_extract_client_ip(request)}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path(request)
    allowed_suffixes = {".pem", ".crt", ".cer", ".der", ".pfx", ".p12", ".p7b", ".p7c"}
    raw_suffix = Path(file.filename or "uploaded").suffix.lower()
    suffix = raw_suffix if raw_suffix in allowed_suffixes else ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            return RedirectResponse(
                url=f"/?error={quote('file too large (max 10 MB)')}", status_code=303
            )
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        pw_bytes = password.encode("utf-8") if password else None
        entry = upload_certificate(tmp_path, password=pw_bytes)
        if isinstance(entry, ParseError):
            return RedirectResponse(url=f"/?error={quote(entry.error_message)}", status_code=303)
        entry.file_name = file.filename or entry.file_name
        store_uploaded(entry, db)
        record_audit(
            db,
            actor=resolve_actor(request),
            action="cert.upload",
            target_type="certificate",
            target_id="upload",
            detail={"filename": file.filename or "unknown"},
            source_ip=resolve_source_ip(request),
        )
        logger.info("uploaded certificate: %s", file.filename or "unknown")
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors")
async def add_trust_anchor(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)
    allowed_suffixes = {".pem", ".crt", ".cer", ".der"}
    raw_suffix = Path(file.filename or "uploaded").suffix.lower()
    suffix = raw_suffix if raw_suffix in allowed_suffixes else ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            tmp.close()
            Path(tmp.name).unlink(missing_ok=True)
            return RedirectResponse(
                url=f"/?error={quote('file too large (max 10 MB)')}", status_code=303
            )
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        entry = upload_certificate(tmp_path)
        if isinstance(entry, ParseError):
            return RedirectResponse(url=f"/?error={quote(entry.error_message)}", status_code=303)
        # Validate that the certificate is suitable as a CA trust anchor
        ca_err = validate_is_ca_certificate(entry.leaf.raw_der)
        if ca_err:
            return RedirectResponse(
                url=f"/?error={quote('Invalid trust anchor: ' + ca_err)}", status_code=303
            )
        # Store as a trust anchor (not a certificate for monitoring)
        repo = SqliteTrustAnchorRepository(db)
        anchor_id = repo.add(entry.leaf)
        record_audit(
            db,
            actor=resolve_actor(request),
            action="trust_anchor.add",
            target_type="trust_anchor",
            target_id=anchor_id,
            detail={"subject": entry.leaf.subject},
            source_ip=resolve_source_ip(request),
        )
        logger.info("uploaded trust anchor: %s", entry.leaf.subject)
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)


@router.post("/trust-anchors/{anchor_id}/delete")
async def delete_trust_anchor(request: Request, anchor_id: IdParam) -> RedirectResponse:
    write_err = await require_write_form(request)
    if write_err:
        return write_err
    db = _db_path(request)
    repo = SqliteTrustAnchorRepository(db)
    repo.delete(anchor_id)
    record_audit(
        db,
        actor=resolve_actor(request),
        action="trust_anchor.delete",
        target_type="trust_anchor",
        target_id=anchor_id,
        source_ip=resolve_source_ip(request),
    )
    logger.info("deleted trust anchor %s", anchor_id)
    return RedirectResponse(url="/", status_code=303)
