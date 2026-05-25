from __future__ import annotations

import tempfile
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.alerts import process_pending
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
from cert_watch.scan import scan_host, store_scanned
from cert_watch.scheduler import run_scan_now, start_scheduler, stop_scheduler
from cert_watch.upload import store_uploaded, upload_certificate

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


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
    s = Settings.from_env()
    init_schema(s.db_path)
    alert_cfg = s.build_alert_config()

    def _scan_all() -> dict:
        host_repo = SqliteHostRepository(s.db_path)
        hosts = [(h.hostname, h.port) for h in host_repo.list_all()]
        return run_scan_now(
            scan_fn=lambda host, port: scan_host(host, port),
            alert_fn=lambda: {"sent": 0, "failed": 0},
            db_path=s.db_path,
            host_provider=lambda: hosts,
            store_fn=lambda r: store_scanned(r, s.db_path),
        )

    def _alerts() -> dict:
        repo = SqliteAlertRepository(s.db_path)
        return process_pending(repo, alert_cfg)

    start_scheduler(
        scan_fn=_scan_all,
        alert_fn=_alerts,
        hour=s.sched_hour,
        minute=s.sched_min,
    )
    try:
        yield
    finally:
        stop_scheduler()


app = FastAPI(title="cert-watch", version=__version__, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def _db_path() -> Path:
    s = Settings.from_env()
    init_schema(s.db_path)
    return s.db_path


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, error: str | None = None) -> HTMLResponse:
    db = _db_path()
    rows = list_dashboard_rows(db)
    hosts = SqliteHostRepository(db).list_all()
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "certificates": rows,
            "hosts": hosts,
            "version": __version__,
            "error": error,
        },
    )


@app.post("/hosts")
async def add_host(
    hostname: str = Form(...),
    port: int = Form(443),
) -> RedirectResponse:
    # TODO(v0.3): SSRF / port-scan guard, bulk CSV/YAML import, auth,
    # PKCS#7 (.p7b/.p7c) and JKS support, /metrics Prometheus endpoint.
    db = _db_path()
    host_repo = SqliteHostRepository(db)
    host_repo.add(hostname, port)
    result = scan_host(hostname, port)
    if not hasattr(result, "error_message"):
        store_scanned(result, db)
    return RedirectResponse(url="/", status_code=303)


@app.post("/hosts/{host_id}/delete")
async def delete_host(host_id: str) -> RedirectResponse:
    db = _db_path()
    SqliteHostRepository(db).delete(host_id)
    return RedirectResponse(url="/", status_code=303)


@app.post("/hosts/{host_id}/scan")
async def scan_host_now(host_id: str) -> RedirectResponse:
    db = _db_path()
    host = SqliteHostRepository(db).get(host_id)
    if host is None:
        return RedirectResponse(url="/?error=host+not+found", status_code=303)
    result = scan_host(host.hostname, host.port)
    if not hasattr(result, "error_message"):
        store_scanned(result, db)
    return RedirectResponse(url="/", status_code=303)


@app.post("/certificates/{cert_id}/delete")
async def delete_certificate(cert_id: str) -> RedirectResponse:
    db = _db_path()
    delete_certificate_cascade(db, cert_id)
    return RedirectResponse(url="/", status_code=303)


@app.get("/alerts", response_class=HTMLResponse)
def alerts_view(request: Request) -> HTMLResponse:
    db = _db_path()
    rows = list_alerts_with_subject(db)
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={"alerts": rows, "version": __version__},
    )


@app.get("/scan-history", response_class=HTMLResponse)
def scan_history_view(request: Request) -> HTMLResponse:
    db = _db_path()
    rows = list_scan_history(db)
    return templates.TemplateResponse(
        request=request,
        name="scan_history.html",
        context={"history": rows, "version": __version__},
    )


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),  # noqa: B008
) -> RedirectResponse:
    db = _db_path()
    suffix = Path(file.filename or "uploaded").suffix or ".pem"
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
        if hasattr(entry, "error_message"):
            return RedirectResponse(
                url=f"/?error={quote(entry.error_message)}", status_code=303
            )
        entry.file_name = file.filename or entry.file_name
        store_uploaded(entry, db)
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)
