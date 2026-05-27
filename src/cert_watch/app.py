from __future__ import annotations

import collections
import csv
import hashlib
import hmac
import io
import ipaddress
import logging
import os as _os
import secrets as _secrets
import socket
import tempfile
import threading as _threading
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, Request, UploadFile

from cert_watch.auth import _sign_session
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cert_watch import __version__, ct_lookup
from cert_watch.alerts import evaluate_all_certs, process_pending
from cert_watch.auth import (
    SESSION_COOKIE,
    SESSION_TTL,
    NoAuthProvider,
    create_session,
    validate_session,
)
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteHostRepository,
    delete_certificate_cascade,
    init_schema,
    list_alerts_with_subject,
    list_dashboard_rows,
    list_scan_history,
)
from cert_watch.scan import ScanError, _is_blocked_ip, scan_host, store_scanned
from cert_watch.scheduler import (
    ScanHistory,
    record_scan_history,
    run_scan_now,
    start_scheduler,
    stop_scheduler,
)
from cert_watch.upload import ParseError, store_uploaded, upload_certificate

logger = logging.getLogger("cert_watch.app")


_COOKIE_SECURE = _os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") == "1"


def _setup_logging() -> None:
    """Configure structured logging for cert-watch."""
    import sys
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    root = logging.getLogger("cert_watch")
    if not root.handlers:
        root.addHandler(handler)
        root.setLevel(logging.INFO)

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

# ---------- SSRF mitigation ----------
# The authoritative blocklist lives in scan.py (_BLOCKED_NETWORKS, _is_blocked_ip).
# _is_blocked_host below is a UX pre-check for the add-host form; enforcement
# happens at scan time in scan._resolve_host().


def _is_blocked_host(hostname: str) -> str | None:
    """Return an error message if hostname resolves to a blocked IP, else None.

    Only blocks when DNS resolution succeeds AND returns a private/link-local IP.
    Unresolvable hostnames are allowed through (they'll fail at connection time).
    The authoritative check happens at scan time in scan._resolve_host().
    """
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    for _family, *_rest in infos:
        ip_str = _rest[3][0] if _rest else None
        if ip_str is None:
            continue
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_blocked_ip(ip):
            return f"hostname resolves to blocked address {ip}"
    return None


# ---------- CSRF protection (double-submit cookie) ----------

_CSRF_SECRET = _os.environ.get("CERT_WATCH_CSRF_SECRET") or _secrets.token_hex(32)
_CSRF_TOKEN_TTL = 3600 * 8  # 8 hours


def _make_csrf_token(session_id: str) -> str:
    payload = f"{session_id}:{int(datetime.now(UTC).timestamp())}"
    sig = hmac.new(_CSRF_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}:{sig}"


def _validate_csrf_token(token: str, session_id: str) -> bool:
    parts = token.split(":")
    if len(parts) != 3:
        return False
    ts_str, sig = parts[1], parts[2]
    payload = f"{session_id}:{ts_str}"
    expected = hmac.new(_CSRF_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    if not hmac.compare_digest(sig, expected):
        return False
    try:
        ts = int(ts_str)
    except ValueError:
        return False
    return (datetime.now(UTC).timestamp() - ts) < _CSRF_TOKEN_TTL


def _get_session_id(request: Request) -> str:
    sid = request.cookies.get("cw_sid")
    if sid:
        return sid
    # Check if middleware set a new session ID for this request
    scope_sid = request.scope.get("session_id")
    if scope_sid:
        return scope_sid
    return _secrets.token_hex(16)


# ---------- Rate limiting (in-memory sliding window) ----------

_rate_lock = _threading.Lock()
_rate_windows: dict[str, collections.deque] = {}


def _check_rate_limit(key: str, max_requests: int, window_seconds: int) -> bool:
    """Return True if request is allowed, False if rate-limited."""
    now = datetime.now(UTC).timestamp()
    with _rate_lock:
        if key not in _rate_windows:
            _rate_windows[key] = collections.deque()
        window = _rate_windows[key]
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= max_requests:
            return False
        window.append(now)
        return True


async def _check_csrf(request: Request) -> str | None:
    """Validate CSRF double-submit cookie. Returns error message or None.

    Checks: x-csrf-token header, _csrf_token form field, then query param (fallback).
    Skipped when CERT_WATCH_CSRF_DISABLED=1 (for testing).
    """
    if _os.environ.get("CERT_WATCH_CSRF_DISABLED") == "1":
        return None
    token = request.headers.get("x-csrf-token") or request.query_params.get("_csrf_token") or ""
    if not token:
        try:
            form = await request.form()
            token = form.get("_csrf_token", "")
        except Exception:
            pass
    if not token:
        return "missing CSRF token"
    session_id = request.cookies.get("cw_sid", "")
    if not _validate_csrf_token(token, session_id):
        return "invalid or expired CSRF token"
    return None


def _get_csrf_context(request: Request) -> dict:
    """Return template context dict with CSRF token for the current session."""
    session_id = _get_session_id(request)
    token = _make_csrf_token(session_id)
    return {"csrf_token": token}


def humanize_expiry(dt) -> str:
    """Render a datetime (or ISO string) as 'YYYY-MM-DD (in 3 days)'.

    Registered as a Jinja filter. See FR gap-fix #9.
    """
    if dt is None:
        return ""
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    now = datetime.now(UTC)
    delta_days = (dt.date() - now.date()).days
    abs_str = dt.strftime("%Y-%m-%d")
    rel = _relative(delta_days)
    return f"{abs_str} ({rel})"


def _relative(days: int) -> str:
    if days == 0:
        return "today"
    past = days < 0
    n = abs(days)
    if n < 60:
        unit = "day" if n == 1 else "days"
        amount = f"{n} {unit}"
    elif n < 730:
        months = round(n / 30)
        unit = "month" if months == 1 else "months"
        amount = f"{months} {unit}"
    else:
        years = round(n / 365)
        unit = "year" if years == 1 else "years"
        amount = f"{years} {unit}"
    return f"expired {amount} ago" if past else f"in {amount}"


templates.env.filters["humanize_expiry"] = humanize_expiry


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: starts the daily scheduler and tears it down on shutdown.

    Triggered by socratic-specification debate 005 — the original spec omitted
    the wiring between scheduler module and the app boot path.
    """
    _setup_logging()
    s = Settings.from_env()
    init_schema(s.db_path)
    auth = s.build_auth_provider()
    app.state.auth_provider = auth
    logger.info("cert-watch starting, db=%s, sched=%02d:%02d, tls_verify=%s, auth=%s",
                s.db_path, s.sched_hour, s.sched_min, s.tls_verify, auth.provider_name)
    alert_cfg = s.build_alert_config()
    webhook_cfg = s.build_webhook_config()

    def _scan_all() -> dict:
        host_repo = SqliteHostRepository(s.db_path)
        hosts = [(h.hostname, h.port) for h in host_repo.list_all()]
        return run_scan_now(
            scan_fn=lambda host, port: scan_host(host, port, verify=s.tls_verify),
            alert_fn=lambda: {"sent": 0, "failed": 0},
            db_path=s.db_path,
            host_provider=lambda: hosts,
            store_fn=lambda r: store_scanned(r, s.db_path),
        )

    def _alerts() -> dict:
        repo = SqliteAlertRepository(s.db_path)
        evaluate_all_certs(s.db_path, repo)
        return process_pending(repo, alert_cfg, webhook_config=webhook_cfg)

    def _ct_check() -> dict:
        """Scheduled CT monitoring: query crt.sh for every tracked host domain."""
        from cert_watch.ct_monitor import run_ct_monitor
        return run_ct_monitor(s.db_path)

    start_scheduler(
        scan_fn=_scan_all,
        alert_fn=_alerts,
        ct_fn=_ct_check,
        hour=s.sched_hour,
        minute=s.sched_min,
    )
    try:
        yield
    finally:
        stop_scheduler()
    logger.info("cert-watch shutting down")


app = FastAPI(title="cert-watch", version=__version__, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.middleware("http")
async def csrf_session_middleware(request: Request, call_next):
    """Ensure every visitor has a session cookie for CSRF protection."""
    if not request.cookies.get("cw_sid"):
        sid = _secrets.token_hex(16)
        request.scope["session_id"] = sid
        response = await call_next(request)
        response.set_cookie(
            "cw_sid", sid, httponly=False, samesite="strict", max_age=_CSRF_TOKEN_TTL,
            secure=_COOKIE_SECURE,
        )
        return response
    return await call_next(request)


_PUBLIC_PATHS = frozenset({
    "/healthz", "/login", "/auth/callback", "/auth/logout",
})


def _is_public_path(path: str) -> bool:
    return (
        path in _PUBLIC_PATHS
        or path.startswith("/static/")
        or path.startswith("/api/")
        or path.startswith("/metrics")
    )


@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    """Enforce authentication when AUTH_PROVIDER is configured.

    Public paths (/healthz, /metrics, /api/*, /static, /login, /auth/*) are exempt.
    Unauthenticated UI requests redirect to /login; API requests get 401.
    """
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return await call_next(request)

    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)

    token = request.cookies.get(SESSION_COOKIE, "")
    username = validate_session(token)
    if username:
        request.scope["auth_user"] = username
        return await call_next(request)

    # Unauthenticated
    if path.startswith("/api/"):
        return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
    return RedirectResponse(url="/login", status_code=303)


def _db_path() -> Path:
    return Settings.from_env().db_path


@app.get("/healthz")
def healthz() -> dict:
    db = _db_path()
    checks: dict[str, str] = {}
    ok = True
    # DB connectivity
    try:
        import sqlite3
        with sqlite3.connect(str(db), timeout=5) as conn:
            conn.execute("SELECT 1")
        checks["database"] = "ok"
    except Exception as exc:
        checks["database"] = f"error: {exc}"
        ok = False
    # Last scan
    try:
        rows = list_scan_history(db)
        if rows:
            checks["last_scan"] = rows[0].get("scanned_at", "unknown")
            checks["last_scan_status"] = rows[0].get("status", "unknown")
        else:
            checks["last_scan"] = "none"
    except Exception:
        checks["last_scan"] = "unavailable"
    # Scheduler
    from cert_watch.scheduler import _scheduler_thread
    if _scheduler_thread is not None and _scheduler_thread.is_alive():
        checks["scheduler"] = "running"
    else:
        checks["scheduler"] = "not running"
    # Certificate counts
    try:
        dash_rows = list_dashboard_rows(db)
        checks["certificates"] = str(len(dash_rows))
        expired = sum(1 for r in dash_rows if r.get("days_remaining", 0) < 0)
        checks["expired"] = str(expired)
    except Exception:
        pass
    return {"status": "ok" if ok else "degraded", "version": __version__, "checks": checks}


# ---------- Auth routes ----------


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str | None = None) -> HTMLResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "version": __version__,
            "provider": auth.provider_name,
            "supports_form_login": auth.supports_form_login,
            "error": error,
        },
    )


@app.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    result = auth.authenticate(username, password)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'login failed')}", status_code=303
        )
    token = create_session(result.username)
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE,
    )
    logger.info("user logged in: %s (%s)", result.username, auth.provider_name)
    return response


@app.get("/auth/login")
def oauth_start(request: Request) -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    # Build redirect URI pointing back to /auth/callback
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/auth/callback"
    result = auth.start_oauth_flow(redirect_uri)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth start failed')}", status_code=303
        )
    response = RedirectResponse(url=result.redirect_url, status_code=303)
    # BC-009: store signed state in a cookie for callback verification
    if result.error:
        response.set_cookie(
            "cw_oauth_state",
            result.error,
            httponly=True,
            samesite="lax",
            max_age=600,
            secure=_COOKIE_SECURE,
        )
    return response


@app.get("/auth/callback")
def oauth_callback(request: Request, code: str = "", error: str = "", state: str = "") -> RedirectResponse:
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is None or isinstance(auth, NoAuthProvider):
        return RedirectResponse(url="/", status_code=303)
    if error:
        return RedirectResponse(
            url=f"/login?error={quote(error)}", status_code=303
        )
    if not code:
        return RedirectResponse(
            url="/login?error=no+authorization+code", status_code=303
        )
    # BC-009: verify state parameter
    signed_state = request.cookies.get("cw_oauth_state", "")
    base = str(request.base_url).rstrip("/")
    redirect_uri = f"{base}/auth/callback"
    result = auth.complete_oauth_flow(code, redirect_uri, state=signed_state)
    if not result.success:
        return RedirectResponse(
            url=f"/login?error={quote(result.error or 'OAuth failed')}", status_code=303
        )
    token = create_session(result.username)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("cw_oauth_state")
    response.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="strict", max_age=SESSION_TTL,
        secure=_COOKIE_SECURE,
    )
    logger.info("user logged in via OAuth: %s", result.username)
    return response


@app.get("/auth/logout")
def logout(request: Request) -> RedirectResponse:
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    error: str | None = None,
    q: str | None = None,
    urgency: str | None = None,
    source: str | None = None,
    page: int = 1,
) -> HTMLResponse:
    db = _db_path()
    rows = list_dashboard_rows(db)
    if q:
        ql = q.lower()
        rows = [
            r for r in rows
            if ql in r["subject"].lower()
            or ql in r["issuer"].lower()
            or ql in r["host"].lower()
        ]
    if urgency:
        rows = [r for r in rows if r["urgency"] == urgency]
    if source:
        rows = [r for r in rows if r["source"] == source]
    hosts = SqliteHostRepository(db).list_all()
    ctx = _get_csrf_context(request)
    auth_user = request.scope.get("auth_user", "")

    per_page = 25
    total = len(rows)
    total_pages = max((total + per_page - 1) // per_page, 1)
    page = max(1, min(page, total_pages))
    start = (page - 1) * per_page
    page_rows = rows[start : start + per_page]

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "certificates": page_rows,
            "hosts": hosts,
            "version": __version__,
            "error": error,
            "auth_user": auth_user,
            "filter_q": q or "",
            "filter_urgency": urgency or "",
            "filter_source": source or "",
            "page": page,
            "total_pages": total_pages,
            "total_certs": total,
            "has_prev": page > 1,
            "has_next": page < total_pages,
            **ctx,
        },
    )


COMMON_TLS_PORTS = (443, 8443, 993, 995, 465, 636, 5061, 6443)


@app.post("/hosts")
async def add_host(
    request: Request,
    hostname: str = Form(...),
    port: int = Form(443),
    threshold_days: int | None = Form(None),
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
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not _check_rate_limit(f"add_host:{request.client.host}", 20, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    ssrf_err = _is_blocked_host(hostname)
    if ssrf_err:
        return RedirectResponse(url=f"/?error={quote(ssrf_err)}", status_code=303)
    db = _db_path()
    host_repo = SqliteHostRepository(db)
    ports = COMMON_TLS_PORTS if common_ports else (port,)
    scanned = 0
    for p in ports:
        host_repo.add(hostname, p, threshold_days=threshold_days)
        result = scan_host(hostname, p)
        if not isinstance(result, ScanError):
            store_scanned(result, db)
            scanned += 1
            record_scan_history(
                db, ScanHistory(hostname=hostname, port=p, status="success")
            )
            logger.info("added and scanned host %s:%d", hostname, p)
        else:
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
    if common_ports:
        logger.info("common-ports scan for %s: %d/%d succeeded", hostname, scanned, len(ports))
    return RedirectResponse(url="/", status_code=303)


@app.post("/hosts/import")
async def import_hosts(request: Request, file: UploadFile = File(...)) -> RedirectResponse:  # noqa: B008
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not _check_rate_limit(f"import_hosts:{request.client.host}", 5, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path()
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
    imported = 0
    errors: list[str] = []
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
        ssrf_err = _is_blocked_host(hostname)
        if ssrf_err:
            errors.append(f"row {i}: {ssrf_err}")
            continue
        host_repo.add(hostname, port, threshold_days=threshold)
        result = scan_host(hostname, port)
        if not isinstance(result, ScanError):
            store_scanned(result, db)
            record_scan_history(
                db, ScanHistory(hostname=hostname, port=port, status="success")
            )
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


@app.post("/hosts/{host_id}/delete")
async def delete_host(request: Request, host_id: str) -> RedirectResponse:
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    db = _db_path()
    SqliteHostRepository(db).delete(host_id)
    logger.info("deleted host %s", host_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/hosts/{host_id}/scan")
async def scan_host_now(request: Request, host_id: str) -> RedirectResponse:
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not _check_rate_limit(f"scan_host:{request.client.host}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many scan requests')}", status_code=303
        )
    db = _db_path()
    host = SqliteHostRepository(db).get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    result = scan_host(host.hostname, host.port)
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
    return RedirectResponse(url=f"/?error={quote(msg)}", status_code=303)


@app.post("/certificates/{cert_id}/delete")
async def delete_certificate(request: Request, cert_id: str) -> RedirectResponse:
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    db = _db_path()
    delete_certificate_cascade(db, cert_id)
    logger.info("deleted certificate %s (cascade)", cert_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/certificates/{cert_id}/notes")
async def update_certificate_notes(
    request: Request, cert_id: str, notes: str = Form(...)
) -> RedirectResponse:
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if len(notes) > 10000:
        return RedirectResponse(
            url=f"/?error={quote('notes too long (max 10000)')}", status_code=303
        )
    db = _db_path()
    from cert_watch.database import SqliteCertificateRepository

    repo = SqliteCertificateRepository(db)
    if repo.get_by_id(cert_id) is None:
        return RedirectResponse(url="/?error=certificate+not+found", status_code=303)
    repo.update_notes(cert_id, notes)
    logger.info("updated notes for certificate %s", cert_id)
    return RedirectResponse(url="/", status_code=303)


@app.get("/alerts", response_class=HTMLResponse)
def alerts_view(request: Request) -> HTMLResponse:
    db = _db_path()
    rows = list_alerts_with_subject(db)
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={"alerts": rows, "version": __version__, "auth_user": auth_user},
    )


@app.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request) -> HTMLResponse:
    db = _db_path()
    rows = list_scan_history(db)
    auth_user = request.scope.get("auth_user", "")
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={"history": rows, "version": __version__, "auth_user": auth_user},
    )


@app.get("/ct-lookup/{domain}")
def ct_lookup_view(domain: str) -> dict:
    result = ct_lookup.query_ct_log(domain)
    if isinstance(result, str):
        return {"error": result}
    return {
        "domain": domain,
        "count": len(result),
        "entries": [
            {
                "common_name": e.common_name,
                "issuer_name": e.issuer_name,
                "name_value": e.name_value,
                "not_before": e.not_before.isoformat(),
                "not_after": e.not_after.isoformat(),
                "serial_number": e.serial_number,
            }
            for e in result
        ],
    }


@app.get("/caa-check/{domain}")
def caa_check_view(domain: str) -> dict:
    """FEAT-010: Return CAA records and issuance policy for a domain."""
    from cert_watch.caa_check import check_caa
    result = check_caa(domain)
    if result.error:
        return {"domain": domain, "error": result.error}
    return {
        "domain": domain,
        "records": result.records,
        "issue_allowed": result.issue_allowed,
        "issuewild_allowed": result.issuewild_allowed,
    }


@app.post("/upload")
async def upload(
    request: Request,
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),  # noqa: B008
) -> RedirectResponse:
    csrf_err = await _check_csrf(request)
    if csrf_err:
        return RedirectResponse(url=f"/?error={quote(csrf_err)}", status_code=303)
    if not _check_rate_limit(f"upload:{request.client.host}", 10, 60):
        return RedirectResponse(
            url=f"/?error={quote('rate limited: too many requests')}", status_code=303
        )
    db = _db_path()
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
            return RedirectResponse(
                url=f"/?error={quote(entry.error_message)}", status_code=303
            )
        entry.file_name = file.filename or entry.file_name
        store_uploaded(entry, db)
        logger.info("uploaded certificate: %s", file.filename or "unknown")
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)


# ---------- REST API (JSON) ----------


@app.get("/api/certificates")
def api_list_certificates(page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path()
    rows = list_dashboard_rows(db)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = len(rows)
    start = (page - 1) * limit
    end = start + limit
    page_rows = rows[start:end]
    return JSONResponse(content={
        "certificates": page_rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit else 0,
        },
    })


@app.get("/api/certificates/{cert_id}")
def api_get_certificate(cert_id: str) -> JSONResponse:
    db = _db_path()
    from cert_watch.database import SqliteCertificateRepository

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    return JSONResponse(content={
        "id": cert_id,
        "subject": cert.subject,
        "issuer": cert.issuer,
        "not_before": cert.not_before.isoformat(),
        "not_after": cert.not_after.isoformat(),
        "san_dns_names": cert.san_dns_names,
        "fingerprint_sha256": cert.fingerprint_sha256,
        "is_leaf": cert.is_leaf,
        "days_until_expiry": cert.days_until_expiry(),
        "notes": cert.notes,
    })


@app.patch("/api/certificates/{cert_id}/notes")
async def api_update_notes(cert_id: str, request: Request) -> JSONResponse:
    # BC-012: PATCH notes requires auth and CSRF when authentication is enabled
    auth = getattr(request.app.state, "auth_provider", None)
    if auth is not None and not isinstance(auth, NoAuthProvider):
        token = request.cookies.get(SESSION_COOKIE, "")
        username = validate_session(token)
        if not username:
            return JSONResponse(content={"error": "unauthenticated"}, status_code=401)
        csrf_err = await _check_csrf(request)
        if csrf_err:
            return JSONResponse(content={"error": csrf_err}, status_code=403)
    db = _db_path()
    from cert_watch.database import SqliteCertificateRepository

    repo = SqliteCertificateRepository(db)
    cert = repo.get_by_id(cert_id)
    if cert is None:
        return JSONResponse(content={"error": "not found"}, status_code=404)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(content={"error": "invalid JSON"}, status_code=400)
    notes = body.get("notes", "")
    if not isinstance(notes, str):
        return JSONResponse(content={"error": "notes must be a string"}, status_code=400)
    if len(notes) > 10000:
        return JSONResponse(content={"error": "notes too long (max 10000)"}, status_code=400)
    repo.update_notes(cert_id, notes)
    return JSONResponse(content={"id": cert_id, "notes": notes})


@app.get("/api/hosts")
def api_list_hosts(page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path()
    hosts = SqliteHostRepository(db).list_all()
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = len(hosts)
    start = (page - 1) * limit
    end = start + limit
    page_hosts = hosts[start:end]
    return JSONResponse(content={
        "hosts": [
            {
                "id": h.id,
                "hostname": h.hostname,
                "port": h.port,
                "added_at": h.added_at.isoformat(),
            }
            for h in page_hosts
        ],
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit else 0,
        },
    })


@app.get("/api/alerts")
def api_list_alerts(page: int = 1, limit: int = 50) -> JSONResponse:
    db = _db_path()
    rows = list_alerts_with_subject(db)
    limit = min(max(limit, 1), 200)
    page = max(page, 1)
    total = len(rows)
    start = (page - 1) * limit
    end = start + limit
    page_rows = rows[start:end]
    return JSONResponse(content={
        "alerts": page_rows,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit if limit else 0,
        },
    })


@app.get("/api/export/certificates.csv")
def api_export_certificates_csv() -> PlainTextResponse:
    """Export all certificates as CSV for compliance reporting."""
    db = _db_path()
    rows = list_dashboard_rows(db)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "host", "source", "subject", "issuer", "not_after",
        "days_remaining", "urgency", "chain_valid", "leaf_subject",
        "leaf_issuer", "leaf_not_after",
    ])
    for r in rows:
        writer.writerow([
            r["host"],
            r["source"],
            r["subject"],
            r["issuer"],
            r["not_after"],
            r["days_remaining"],
            r["urgency"],
            r.get("chain_valid", ""),
            r["subject"],
            r["issuer"],
            r["not_after"],
        ])
        for chain in r.get("chain", []):
            writer.writerow([
                r["host"],
                r["source"],
                chain["subject"],
                chain["issuer"],
                chain["not_after"],
                chain["days_remaining"],
                chain["urgency"],
                "",
                r["subject"],
                r["issuer"],
                r["not_after"],
            ])
    return PlainTextResponse(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=certificates.csv"},
    )


@app.get("/api/export/certificates.json")
def api_export_certificates_json() -> JSONResponse:
    """Export all certificates as JSON for compliance reporting."""
    db = _db_path()
    rows = list_dashboard_rows(db)
    return JSONResponse(
        content={"certificates": rows},
        headers={"Content-Disposition": "attachment; filename=certificates.json"},
    )


@app.get("/metrics", response_class=PlainTextResponse)
def metrics() -> str:
    db = _db_path()
    rows = list_dashboard_rows(db)
    hosts = SqliteHostRepository(db).list_all()
    lines: list[str] = []
    lines.append("# HELP cert_watch_cert_expiry_days Days until certificate expiry")
    lines.append("# TYPE cert_watch_cert_expiry_days gauge")
    for r in rows:
        host_label = r["host"].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        subject_label = r["subject"].replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
        lines.append(
            f'cert_watch_cert_expiry_days{{host="{host_label}",'
            f'subject="{subject_label}"}} {r["days_remaining"]}'
        )
    lines.append("# HELP cert_watch_hosts_tracked Number of tracked hosts")
    lines.append("# TYPE cert_watch_hosts_tracked gauge")
    lines.append(f"cert_watch_hosts_tracked {len(hosts)}")
    lines.append("# HELP cert_watch_certificates_tracked Number of certificate groups")
    lines.append("# TYPE cert_watch_certificates_tracked gauge")
    lines.append(f"cert_watch_certificates_tracked {len(rows)}")
    expired = sum(1 for r in rows if r["days_remaining"] < 0)
    lines.append("# HELP cert_watch_certificates_expired Number of expired certificates")
    lines.append("# TYPE cert_watch_certificates_expired gauge")
    lines.append(f"cert_watch_certificates_expired {expired}")
    return "\n".join(lines) + "\n"
