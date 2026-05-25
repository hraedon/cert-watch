from __future__ import annotations

import tempfile
from pathlib import Path

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteHostRepository,
    init_schema,
    list_dashboard_rows,
)
from cert_watch.scan import scan_host, store_scanned
from cert_watch.upload import store_uploaded, upload_certificate

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="cert-watch", version=__version__)
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
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "certificates": rows,
            "version": __version__,
            "error": error,
        },
    )


@app.post("/hosts")
async def add_host(
    hostname: str = Form(...),
    port: int = Form(443),
) -> RedirectResponse:
    db = _db_path()
    host_repo = SqliteHostRepository(db)
    host_repo.add(hostname, port)
    result = scan_host(hostname, port)
    if not hasattr(result, "error_message"):
        store_scanned(result, db)
    return RedirectResponse(url="/", status_code=303)


@app.post("/upload")
async def upload(
    file: UploadFile = File(...),  # noqa: B008 — FastAPI dependency injection pattern
    password: str | None = Form(None),  # noqa: B008
) -> RedirectResponse:
    db = _db_path()
    suffix = Path(file.filename or "uploaded").suffix or ".pem"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        tmp_path = Path(tmp.name)
    try:
        pw_bytes = password.encode("utf-8") if password else None
        entry = upload_certificate(tmp_path, password=pw_bytes)
        if hasattr(entry, "error_message"):
            return RedirectResponse(
                url=f"/?error={entry.error_message}", status_code=303
            )
        entry.file_name = file.filename or entry.file_name
        store_uploaded(entry, db)
    finally:
        tmp_path.unlink(missing_ok=True)
    return RedirectResponse(url="/", status_code=303)
