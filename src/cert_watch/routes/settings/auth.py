"""Authentication-related settings routes (LDAP, OAuth, local admin, role mapping)."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import ssl

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from cert_watch.database import kv_set, kv_set_secret
from cert_watch.middleware import check_csrf, require_admin_form, require_admin_write
from cert_watch.routes._deps import _db_path, _get_settings
from cert_watch.routes.settings.ca_probe import _is_cert_verify_error
from cert_watch.routes.settings.config import _AUTH_KEYS
from cert_watch.routes.settings.core import _sanitize_test_error, _save_config_section, logger

router = APIRouter()


@router.post("/settings/auth")
async def save_auth_config(request: Request) -> RedirectResponse:
    resp = await _save_config_section(request, _AUTH_KEYS, "auth", encrypt=True, rebuild=True)
    if resp.status_code == 303 and ("saved=1" in str(resp.headers.get("location", ""))):
        try:
            s = _get_settings(request)
            auth = s.build_auth_provider()
            request.app.state.auth_provider = auth
            request.app.state.needs_setup = False
            logger.info("settings: auth provider updated to '%s'", s.auth_provider)
        except Exception as exc:
            logger.warning("settings: auth provider rebuild failed: %s", exc)
            return RedirectResponse(
                url=f"/settings?tab=auth&error={str(exc)[:120].replace(chr(10), ' ')}",
                status_code=303,
            )
    return resp


@router.post("/settings/ldap-role-map")
async def save_ldap_role_map(request: Request) -> RedirectResponse:
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/settings?tab=auth&error={csrf_err}", status_code=303)

    form = await request.form()
    from cert_watch.database import SqliteRoleRepository, kv_set

    role_repo = SqliteRoleRepository(_db_path(request))
    map_data = {}
    for key in form:
        if key.startswith("role_map_"):
            role_id = key[len("role_map_"):]
            groups = str(form.get(key) or "").strip()
            if groups:
                role = role_repo.get(role_id)
                if role:
                    map_data[role.name] = {
                        "groups": [g.strip() for g in groups.split(",") if g.strip()]
                    }
    kv_set(_db_path(request), "ldap_role_map", json.dumps(map_data))
    return RedirectResponse(url="/settings?tab=auth&saved=1", status_code=303)


# ---------- Test LDAP connection ----------


def _parse_ldap_form(form) -> tuple[str, str, str, str, str, bool, int] | JSONResponse:
    _server = form.get("ldap_server", "")
    _base = form.get("ldap_base_dn", "")
    _bind = form.get("ldap_bind_dn", "")
    _pw = form.get("ldap_bind_password", "")
    _ca = form.get("ldap_ca_cert", "")
    _timeout = form.get("ldap_connect_timeout", "5")
    server = _server.strip() if isinstance(_server, str) else ""
    base_dn = _base.strip() if isinstance(_base, str) else ""
    bind_dn = _bind.strip() if isinstance(_bind, str) else ""
    bind_password = _pw.strip() if isinstance(_pw, str) else ""
    start_tls = form.get("ldap_start_tls", "0") == "1"
    ca_cert = _ca.strip() if isinstance(_ca, str) else ""
    _timeout_str = _timeout.strip() if isinstance(_timeout, str) else ""
    try:
        connect_timeout = int(_timeout_str) if _timeout_str else 5
    except ValueError:
        return JSONResponse(
            {"ok": False, "error": "Connect timeout must be a whole number of seconds"}
        )

    if not server or not base_dn:
        return JSONResponse({"ok": False, "error": "LDAP server and base DN are required"})
    return server, base_dn, bind_dn, bind_password, ca_cert, start_tls, connect_timeout


def _check_ldap_ssrf(server: str) -> JSONResponse | None:
    from cert_watch.scan import _is_blocked_ip
    from cert_watch.scan_resolver import resolve_and_validate_host

    for s in [s.strip() for s in server.split(",") if s.strip()]:
        host_part = s.split("://", 1)[-1].split(":")[0].split("/")[0]
        try:
            ip = ipaddress.ip_address(host_part)
            if _is_blocked_ip(ip):
                return JSONResponse(
                    {"ok": False, "error": f"LDAP server IP blocked: {ip}"},
                )
        except ValueError:
            err, _ = resolve_and_validate_host(host_part, allow_private=False)
            if err:
                return JSONResponse({"ok": False, "error": f"LDAP server blocked: {err}"})
    return None


def _build_ldap_tls(use_tls: bool, tmp_path: str | None, ldap3):
    if not use_tls:
        return None
    kwargs: dict = {"validate": ssl.CERT_REQUIRED}
    if tmp_path:
        kwargs["ca_certs_file"] = tmp_path
    return ldap3.Tls(**kwargs)


async def _probe_single_ldap_url(
    url: str,
    bind_dn: str,
    bind_password: str,
    start_tls: bool,
    ca_cert_tmp: str | None,
    connect_timeout: int,
    request: Request,
) -> tuple[JSONResponse | None, bool]:
    import ldap3

    srv_is_ldaps = url.lower().startswith("ldaps://")
    use_tls = srv_is_ldaps or start_tls
    tls = _build_ldap_tls(use_tls, ca_cert_tmp, ldap3)
    try:
        srv = ldap3.Server(url, tls=tls, connect_timeout=connect_timeout)
        conn = ldap3.Connection(
            srv,
            user=bind_dn or None,
            password=bind_password or None,
            auto_bind=(
                ldap3.AUTO_BIND_TLS_BEFORE_BIND
                if (start_tls and not srv_is_ldaps)
                else True
            ),
            read_only=True,
        )
    except Exception as exc:  # noqa: BLE001
        if use_tls and _is_cert_verify_error(exc):
            from cert_watch.routes.settings import _capture_ldaps_chain, _capture_starttls_chain

            settings = getattr(request.app.state, "settings", None)
            _allow_private = settings.allow_private if settings else True
            _allowed_subnets = settings.allowed_subnets if settings else ()
            tofu_chain = _capture_ldaps_chain(
                url,
                timeout=connect_timeout,
                allow_private=_allow_private,
                allowed_subnets=_allowed_subnets,
            )
            if not tofu_chain and start_tls and not srv_is_ldaps:
                tofu_chain = _capture_starttls_chain(
                    url,
                    timeout=connect_timeout,
                    allow_private=_allow_private,
                    allowed_subnets=_allowed_subnets,
                )
            if tofu_chain:
                return JSONResponse({
                    "ok": False,
                    "error": _sanitize_test_error(f"{url}: {exc}"),
                    "tofu": {
                        "chain": [
                            {
                                "subject": c["subject"],
                                "issuer": c["issuer"],
                                "not_after": c["not_after"],
                                "sha256": c["sha256"],
                            }
                            for c in tofu_chain
                        ],
                        "pem": "".join(c["pem"] for c in tofu_chain),
                    },
                }), False
        return JSONResponse(
            {"ok": False, "error": _sanitize_test_error(f"{url}: {exc}")}
        ), False

    tls_active = srv_is_ldaps or bool(getattr(conn, "tls_started", False))
    conn.unbind()
    if use_tls and not tls_active:
        return JSONResponse({
            "ok": False,
            "error": f"{url}: TLS was requested but not established",
        }), False
    return None, use_tls


async def _run_ldap_probe(
    server: str,
    _base_dn: str,
    bind_dn: str,
    bind_password: str,
    ca_cert: str,
    start_tls: bool,
    connect_timeout: int,
    request: Request,
) -> JSONResponse:
    import os
    import tempfile

    server_urls = [s.strip() for s in server.split(",") if s.strip()]

    tmp_path: str | None = None
    if ca_cert:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False)  # noqa: SIM115
        tmp.write(ca_cert)
        tmp.close()
        tmp_path = tmp.name

    any_tls = False
    try:
        for url in server_urls:
            failure, tls_active = await _probe_single_ldap_url(
                url, bind_dn, bind_password, start_tls, tmp_path, connect_timeout, request
            )
            if failure is not None:
                return failure
            if tls_active:
                any_tls = True
    finally:
        if tmp_path:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    n = len(server_urls)
    msg = f"All {n} server{'' if n == 1 else 's'} reachable; bind succeeded"
    if any_tls:
        msg += "; TLS validated against " + (
            "the pinned CA certificate"
            if ca_cert
            else "the system trust store (no CA certificate pinned)"
        )
    elif start_tls:
        msg += " (StartTLS requested but no server negotiated TLS)"
    return JSONResponse({"ok": True, "message": msg})


@router.post("/settings/test-ldap")
async def test_ldap_connection(
    request: Request,
    _auth: str = Depends(require_admin_write),
) -> JSONResponse:
    form = await request.form()
    parsed = _parse_ldap_form(form)
    if isinstance(parsed, JSONResponse):
        return parsed

    server = parsed[0]
    ssrf_err = _check_ldap_ssrf(server)
    if ssrf_err:
        return ssrf_err

    try:
        return await _run_ldap_probe(*parsed, request)
    except ImportError:
        return JSONResponse({
            "ok": False,
            "error": "ldap3 not installed (pip install cert-watch[auth-ldap])",
        })
    except Exception as exc:
        logger.warning("LDAP test failed: %s", exc)
        return JSONResponse({"ok": False, "error": _sanitize_test_error(str(exc))})


# ---------- Pin LDAP CA (TOFU trust) ----------


@router.post("/settings/pin-ldap-ca")
async def pin_ldap_ca(
    request: Request,
    _auth: str = Depends(require_admin_write),
) -> JSONResponse:
    form = await request.form()
    _pem = form.get("ldap_ca_cert", "")
    pem = _pem.strip() if isinstance(_pem, str) else ""
    if not pem:
        return JSONResponse({"ok": False, "error": "No CA certificate provided"})

    db = _db_path(request)
    from cert_watch.routes.settings import _get_encryption_key

    enc_key = _get_encryption_key(request)

    if enc_key:
        kv_set_secret(db, "ldap_ca_cert", pem, enc_key)
    else:
        kv_set(db, "ldap_ca_cert", pem)

    from cert_watch.audit import record_audit, resolve_actor, resolve_source_ip
    from cert_watch.certificate_model import extract_chain_from_pem

    chain = extract_chain_from_pem(pem)
    fps = [c.fingerprint_sha256 for c in chain]
    subjects = [c.subject for c in chain]
    record_audit(
        db,
        actor=resolve_actor(request),
        action="ca_pinned",
        target_type="ldap_ca",
        target_id=fps[0] if fps else "unknown",
        detail={
            "subjects": subjects,
            "sha256s": fps,
            "count": len(chain),
            "source": "tofu",
        },
        source_ip=resolve_source_ip(request),
    )

    return JSONResponse({"ok": True, "message": "CA certificate pinned successfully"})
