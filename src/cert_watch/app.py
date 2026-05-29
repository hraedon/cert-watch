"""FastAPI application factory. Routes live in cert_watch.routes.*."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteHostRepository,
    init_schema,
)
from cert_watch.filters import register_filters
from cert_watch.middleware import (
    auth_middleware,
    csrf_session_middleware,
    rate_limit_headers_middleware,
)
from cert_watch.routes import api as route_modules
from cert_watch.scan import scan_host, store_scanned
from cert_watch.scheduler import run_scan_now, start_scheduler, stop_scheduler

logger = logging.getLogger("cert_watch.app")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_filters(templates)


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


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: starts the daily scheduler and tears it down on shutdown."""
    _setup_logging()
    s = Settings.from_env()
    init_schema(s.db_path)
    auth = s.build_auth_provider()
    app.state.auth_provider = auth
    app.state.settings = s
    logger.info("cert-watch starting, db=%s, sched=%02d:%02d, tls_verify=%s, auth=%s",
                s.db_path, s.sched_hour, s.sched_min, s.tls_verify, auth.provider_name)
    alert_cfg = s.build_alert_config()
    webhook_cfg = s.build_webhook_config()

    def _scan_all() -> dict:
        host_repo = SqliteHostRepository(s.db_path)
        hosts = [(h.hostname, h.port) for h in host_repo.list_all()]
        return run_scan_now(
            scan_fn=lambda host, port: scan_host(
                host, port, verify=s.tls_verify, allow_private=s.allow_private,
                dns_servers=s.dns_servers,
            ),
            alert_fn=lambda: {"sent": 0, "failed": 0},
            db_path=s.db_path,
            host_provider=lambda: hosts,
            store_fn=lambda r: store_scanned(r, s.db_path),
        )

    def _alerts() -> dict:
        from cert_watch.alerts import evaluate_all_certs, process_pending, send_expiry_digest

        repo = SqliteAlertRepository(s.db_path)
        if s.alert_digest_only:
            delivered = send_expiry_digest(s.db_path, alert_cfg, webhook_config=webhook_cfg)
            return {"sent": 1 if delivered else 0, "failed": 0 if delivered else 1}
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
        db_path=s.db_path,
    )
    try:
        yield
    finally:
        stop_scheduler()
    logger.info("cert-watch shutting down")


app = FastAPI(title="cert-watch", version=__version__, lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Register middleware (order matters: last registered = first executed)
app.middleware("http")(rate_limit_headers_middleware)
app.middleware("http")(csrf_session_middleware)
app.middleware("http")(auth_middleware)

# Mount route modules
for router in route_modules:
    app.include_router(router)
