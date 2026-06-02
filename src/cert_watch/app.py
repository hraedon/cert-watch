"""FastAPI application factory. Routes live in cert_watch.routes.*."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cert_watch import __version__
from cert_watch.auth import NoAuthProvider, set_signing_key
from cert_watch.config import Settings
from cert_watch.database import (
    SqliteAlertRepository,
    SqliteHostRepository,
    init_schema,
    kv_get,
)
from cert_watch.filters import register_filters
from cert_watch.middleware import (
    _init_rate_db,
    auth_middleware,
    csrf_session_middleware,
    rate_limit_headers_middleware,
    security_headers_middleware,
    set_csrf_secret,
    setup_redirect_middleware,
)
from cert_watch.routes import api as route_modules
from cert_watch.scan import scan_host, store_scanned
from cert_watch.scheduler import run_scan_now, start_scheduler, stop_scheduler
from cert_watch.security import SecurityContext

logger = logging.getLogger("cert_watch.app")

BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_filters(templates)


def _setup_logging(log_format: str = "text") -> None:
    """Configure logging for cert-watch. Supports 'text' (default) and 'json' formats."""
    import json as _json
    import sys

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            entry = {
                "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[1]:
                entry["exception"] = self.formatException(record.exc_info)
            extra = {
                k: v for k, v in record.__dict__.items()
                if k not in logging.LogRecord(
                    "", 0, "", 0, "", (), None
                ).__dict__ and k not in ("message", "asctime")
            }
            if extra:
                entry["extra"] = extra
            return _json.dumps(entry, default=str)

    handler = logging.StreamHandler(sys.stdout)
    if log_format == "json":
        handler.setFormatter(_JsonFormatter())
    else:
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


def _resolve_security(s: Settings) -> SecurityContext:
    """Resolve signing material from env / persisted secrets (Plan 014 + 018 B1).

    The auth secret persists to data_dir/.auth_secret so sessions survive
    restarts even without the env var; the CSRF secret derives from it unless
    overridden. Returned as an immutable SecurityContext carried on app.state.
    """
    from cert_watch.config import resolve_or_persist_secret

    auth_secret = resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", s.data_dir, ".auth_secret")
    csrf_env = os.environ.get("CERT_WATCH_CSRF_SECRET") or None
    if csrf_env and csrf_env.strip():
        csrf_secret = csrf_env.strip()
    else:
        csrf_secret = hashlib.sha256((auth_secret + "csrf").encode()).hexdigest()
    return SecurityContext(signing_key=auth_secret, csrf_secret=csrf_secret)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: starts the daily scheduler and tears it down on shutdown.

    Dependencies (settings, security, auth provider) may be injected via
    ``create_app(...)`` for tests; otherwise they are resolved from the
    environment here (the production path).
    """
    s = getattr(app.state, "_injected_settings", None) or Settings.from_env()
    _setup_logging(log_format=s.log_format)
    init_schema(s.db_path)
    _init_rate_db(s.db_path)

    security = getattr(app.state, "_injected_security", None) or _resolve_security(s)
    # Phase-1 backward compat: keep the module-level signing/CSRF globals in sync
    # so fallback paths (OAuth state signing, direct unit-test calls) use the
    # same keys. The request path reads app.state.security directly.
    set_signing_key(security.signing_key)
    set_csrf_secret(security.csrf_secret)

    auth = getattr(app.state, "_injected_auth", None) or s.build_auth_provider()

    # Slice 3: setup wizard detection
    host_count = 0
    with contextlib.suppress(Exception):
        host_count = len(SqliteHostRepository(s.db_path).list_all())
    setup_complete = kv_get(s.db_path, "setup_complete") == "1"
    needs_setup = False
    if (
        isinstance(auth, NoAuthProvider)
        and host_count == 0
        and not setup_complete
        and not s.allow_unauth
    ):
        needs_setup = True
    app.state.needs_setup = needs_setup
    app.state.auth_provider = auth
    app.state.settings = s
    app.state.security = security
    logger.info("cert-watch starting, db=%s, sched=%02d:%02d, tls_verify=%s, auth=%s",
                s.db_path, s.sched_hour, s.sched_min, s.tls_verify, auth.provider_name)

    # Slice 4: warn when running without auth on a non-loopback address
    if isinstance(auth, NoAuthProvider):
        bind_host = os.environ.get("CERT_WATCH_HOST", "0.0.0.0")
        if bind_host not in ("127.0.0.1", "::1", "localhost") and not s.allow_unauth:
            bind_port = os.environ.get("CERT_WATCH_PORT", "8000")
            logger.warning(
                "CERT-WATCH WARNING: running without authentication on %s:%s. "
                "All certificate and host data is publicly accessible. "
                "Set AUTH_PROVIDER + a local admin (visit /setup) to secure this instance. "
                "Set CERT_WATCH_ALLOW_UNAUTH=1 to suppress this warning.",
                bind_host, bind_port,
            )
    alert_cfg = s.build_alert_config()
    webhook_cfg = s.build_webhook_config()

    def _scan_all() -> dict:
        host_repo = SqliteHostRepository(s.db_path)
        hosts = [(h.hostname, h.port) for h in host_repo.list_all()]
        return run_scan_now(
            scan_fn=lambda host, port: scan_host(
                host, port, verify=s.tls_verify, allow_private=s.allow_private,
                allowed_subnets=s.allowed_subnets,
                dns_servers=s.dns_servers,
            ),
            alert_fn=lambda: {"sent": 0, "failed": 0},
            db_path=s.db_path,
            host_provider=lambda: hosts,
            store_fn=lambda r: store_scanned(
                r, s.db_path,
                drift_alerts=s.drift_alerts,
                check_revocation=s.check_revocation,
            ),
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

    def _maintenance() -> None:
        """Daily housekeeping: trim audit log, cert history, and alerts to retention windows."""
        from cert_watch.audit import purge_old_audit
        from cert_watch.database.queries import purge_old_alerts, purge_old_history
        purge_old_audit(s.db_path, s.audit_retention_days)
        purge_old_history(s.db_path, s.history_retention_days)
        purge_old_alerts(s.db_path, s.alert_retention_days)

    # Purge once at startup too — restarts (e.g. k8s rollouts) are frequent and
    # shouldn't have to wait for the next daily cycle to reclaim the audit log.
    _maintenance()

    start_scheduler(
        scan_fn=_scan_all,
        alert_fn=_alerts,
        ct_fn=_ct_check,
        maintenance_fn=_maintenance,
        hour=s.sched_hour,
        minute=s.sched_min,
        db_path=s.db_path,
    )
    try:
        yield
    finally:
        stop_scheduler()
    logger.info("cert-watch shutting down")


def create_app(
    *,
    security: SecurityContext | None = None,
    auth_provider=None,
    settings: Settings | None = None,
) -> FastAPI:
    """Construct and configure the FastAPI application (Plan 018 B1).

    Dependencies may be injected explicitly (tests) or left ``None`` to be
    resolved from the environment in the lifespan (production / the module-level
    ``app`` below). Injected values are stashed on ``app.state`` and consumed by
    ``lifespan`` when the app starts.
    """
    application = FastAPI(title="cert-watch", version=__version__, lifespan=lifespan)
    application.state._injected_security = security
    application.state._injected_auth = auth_provider
    application.state._injected_settings = settings
    application.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    # Register middleware (order matters: last registered = first executed)
    application.middleware("http")(security_headers_middleware)
    application.middleware("http")(rate_limit_headers_middleware)
    application.middleware("http")(csrf_session_middleware)
    application.middleware("http")(setup_redirect_middleware)
    application.middleware("http")(auth_middleware)

    # Mount route modules
    for router in route_modules:
        application.include_router(router)
    return application


# Module-level app for uvicorn (`cert_watch.app:app`); deps resolved from env.
app = create_app()
