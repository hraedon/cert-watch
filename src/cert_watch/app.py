"""FastAPI application factory. Routes live in cert_watch.routes.*."""

from __future__ import annotations

import hashlib
import logging
import os
import typing
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
    get_write_lock,
    init_schema,
    kv_get,
)
from cert_watch.database.queries import check_encrypted_values, derive_encryption_key
from cert_watch.filters import register_filters
from cert_watch.firstrun import FirstRunPosture, first_run_action, is_network_exposed
from cert_watch.middleware import (
    CSPNonceMiddleware,
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
# Templates read the per-request CSP nonce via {{ request.state.csp_nonce }}
# (set by CSPNonceMiddleware). That works across every route module's own
# Jinja2Templates instance because Starlette always injects `request` into the
# context — no per-instance context processor to keep in sync (BC-075).
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
register_filters(templates)


def _setup_logging(log_format: str = "text") -> None:
    """Configure logging for cert-watch. Supports 'text' (default) and 'json' formats."""
    import json as _json
    import sys

    _LOG_RECORD_KEYS = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__
    )

    class _JsonFormatter(logging.Formatter):
        def format(self, record: logging.LogRecord) -> str:
            _entry: dict[str, typing.Any] = {
                "timestamp": self.formatTime(record, datefmt="%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            if record.exc_info and record.exc_info[1]:
                _entry["exception"] = self.formatException(record.exc_info)
            extra = {
                k: v for k, v in record.__dict__.items()
                if k not in _LOG_RECORD_KEYS and k not in ("message", "asctime")
            }
            if extra:
                _entry["extra"] = extra
            return str(_json.dumps(_entry, default=str))

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


def _provision_initial_admin(s: Settings) -> None:
    """Create a local admin with a generated password on first run.

    Called for a network-exposed instance with no auth configured, so the app
    comes up authenticated instead of serving open. The one-time password is
    written to ``data_dir/initial-admin-password`` (mode 0600) — never logged.
    The admin is persisted to ``kv_store`` (same keys the /setup wizard writes),
    so subsequent restarts resolve a ``LocalAdminProvider`` and skip this.
    """
    import secrets as _secrets

    from cert_watch.auth import _scrypt_hash
    from cert_watch.database import kv_set

    username = "admin"
    password = _secrets.token_urlsafe(18)
    kv_set(s.db_path, "local_admin_user", username)
    kv_set(s.db_path, "local_admin_password_hash", _scrypt_hash(password))
    kv_set(s.db_path, "local_admin_autogenerated", "1")
    kv_set(s.db_path, "setup_complete", "1")

    pw_file = s.data_dir / "initial-admin-password"
    wrote_file = False
    try:
        s.data_dir.mkdir(parents=True, exist_ok=True)
        pw_file.write_text(f"username: {username}\npassword: {password}\n")
        pw_file.chmod(0o600)
        wrote_file = True
    except OSError:
        logger.warning("could not write %s", pw_file)

    where = (
        f"One-time password written to {pw_file} (chmod 600)."
        if wrote_file
        else (
            f"Could not write password file to {pw_file}. "
            "To recover: set CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH via "
            "'cert-watch hash-password' or fix the data directory permissions and restart."
        )
    )
    logger.warning(
        "No authentication was configured; created an initial admin '%s' so the "
        "app does not serve open on a network. %s Log in, then configure "
        "AUTH_PROVIDER (LDAP/OAuth) or pin a password via "
        "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH, and delete the password file. "
        "Set CERT_WATCH_ALLOW_UNAUTH=1 to intentionally run open.",
        username, where,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI lifespan: starts the daily scheduler and tears it down on shutdown.

    Dependencies (settings, security, auth provider) may be injected via
    ``create_app(...)`` for tests; otherwise they are resolved from the
    environment here (the production path).
    """
    s = getattr(app.state, "_injected_settings", None)
    if s is None:
        # Two-phase boot: env first (to get data_dir), then merge kv_store for
        # auth/smtp/alert persistence (BC-159). Without this, GUI-configured LDAP,
        # OAuth, SMTP, and alert settings evaporate on restart.
        base = Settings.from_env()
        security = _resolve_security(base)
        encryption_key = derive_encryption_key(security.signing_key)
        # Schema MUST exist before any kv_store read; init_schema is idempotent.
        init_schema(base.db_path)
        try:
            s = Settings.from_env_with_kv(base.db_path, encryption_key)
        except Exception:
            logger.warning("Could not merge kv_store settings, using env-only")
            s = base
        # Phase-1 backward compat: keep the module-level signing/CSRF globals in sync
        # so fallback paths (OAuth state signing, direct unit-test calls) use the
        # same keys. The request path reads app.state.security directly.
        set_signing_key(security.signing_key)
        set_csrf_secret(security.csrf_secret)
    else:
        security = getattr(app.state, "_injected_security", None) or _resolve_security(s)
        set_signing_key(security.signing_key)
        set_csrf_secret(security.csrf_secret)
        init_schema(s.db_path)

    _setup_logging(log_format=s.log_format)
    _init_rate_db(s.db_path)

    auth = getattr(app.state, "_injected_auth", None) or s.build_auth_provider()

    # BC-083 / first-run posture. CERT_WATCH_HOST is the source of truth for the
    # bind — the entrypoint (__main__) normalizes --host/env into it so exposure
    # detection can't diverge from the real bind (BC-090). The decision itself is
    # the pure first_run_action (BC-114), kept out of this side-effecting lifespan
    # so it can be table-tested.
    bind_host = os.environ.get("CERT_WATCH_HOST", "0.0.0.0")
    trust_proxy = os.environ.get("CERT_WATCH_TRUST_PROXY", "") == "1"
    trusted_proxies = os.environ.get("CERT_WATCH_TRUSTED_PROXIES", "")
    if trust_proxy and not trusted_proxies:
        logger.warning(
            "CERT_WATCH_TRUST_PROXY=1 but CERT_WATCH_TRUSTED_PROXIES is empty. "
            "Using rightmost X-Forwarded-For entry for client IP. "
            "Set CERT_WATCH_TRUSTED_PROXIES if you have multiple proxy hops."
        )
    exposed = is_network_exposed(bind_host, trust_proxy)

    def _posture() -> FirstRunPosture:
        return first_run_action(
            has_provider=not isinstance(auth, NoAuthProvider),
            allow_unauth=s.allow_unauth,
            network_exposed=exposed,
        )

    # First run on a network-exposed instance with no auth: provision a local
    # admin with a generated password so the app comes up *authenticated* rather
    # than open. Bare loopback dev stays open (+ the /setup wizard); an explicit
    # CERT_WATCH_ALLOW_UNAUTH=1 forces open anywhere. Provisioning is skipped when
    # a provider was injected (tests) — the injection is the escape hatch.
    posture = _posture()
    if posture is FirstRunPosture.PROVISION_ADMIN and (
        getattr(app.state, "_injected_auth", None) is None
    ):
        _provision_initial_admin(s)
        auth = s.build_auth_provider()
        posture = _posture()

    # Setup wizard detection (bare loopback dev path; provisioned instances have
    # a provider now, so needs_setup is False for them).
    setup_complete = kv_get(s.db_path, "setup_complete") == "1"
    needs_setup = isinstance(auth, NoAuthProvider) and not s.allow_unauth and not setup_complete
    app.state.needs_setup = needs_setup
    app.state.auth_provider = auth
    app.state.settings = s
    app.state.security = security

    encryption_key = derive_encryption_key(security.signing_key)
    undecryptable = check_encrypted_values(s.db_path, encryption_key)
    if undecryptable:
        logger.warning(
            "kv_store: %d encrypted value(s) could not be decrypted with the "
            "current signing key: %s. If .auth_secret was recently regenerated, "
            "run 'cert-watch re-encrypt <old_key>' to re-encrypt with the new key.",
            len(undecryptable), ", ".join(undecryptable),
        )
    logger.info("cert-watch starting, db=%s, sched=%02d:%02d, tls_verify=%s, auth=%s",
                s.db_path, s.sched_hour, s.sched_min, s.tls_verify, auth.provider_name)
    if os.environ.get("CERT_WATCH_CSRF_DISABLED") == "1":
        logger.warning(
            "CSRF protection is DISABLED via CERT_WATCH_CSRF_DISABLED=1. "
            "This should only be used for testing — never in production."
        )
    if os.environ.get("CERT_WATCH_COOKIE_SECURE", "1") != "1":
        logger.warning(
            "Session cookie Secure flag is DISABLED via CERT_WATCH_COOKIE_SECURE=0. "
            "Cookies will be sent over plain HTTP — never use in production."
        )

    # BC-083 fail-closed fallback: if after the provisioning attempt we still
    # have no auth on a network-exposed bind (e.g. provisioning could not persist
    # the admin, or a NoAuth provider was injected on an exposed bind), the
    # posture is still PROVISION_ADMIN — refuse to serve open rather than expose
    # an unauthenticated app.
    if posture is FirstRunPosture.PROVISION_ADMIN:
        raise SystemExit(
            "cert-watch could not auto-provision an admin and no authentication "
            f"is configured, but the instance is network-exposed (bind={bind_host}, "
            f"trust_proxy={trust_proxy}). Refusing to serve open. Either:\n"
            "  1) Configure a directory provider: AUTH_PROVIDER=ldap or "
            "AUTH_PROVIDER=oauth, with the matching LDAP_*/OAUTH_* settings,\n"
            "  2) Configure a local admin: generate a hash with "
            "'cert-watch hash-password' and set CERT_WATCH_LOCAL_ADMIN_USER + "
            "CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH,\n"
            "  3) Set CERT_WATCH_ALLOW_UNAUTH=1 to intentionally run open "
            "(not recommended for production), or\n"
            "  4) Ensure CERT_WATCH_DATA_DIR is writable so the admin can persist.\n"
            "Bare loopback binds (no proxy) are exempt and serve the /setup wizard."
        )
    alert_cfg = s.build_alert_config()
    webhook_cfg = s.build_webhook_config()

    def _scan_all() -> dict:
        with get_write_lock():
            host_repo = SqliteHostRepository(s.db_path)
            hosts = [(h.hostname, h.port) for h in host_repo.list_all()]
            return run_scan_now(
                scan_fn=lambda host, port: scan_host(
                    host, port, verify=s.tls_verify, timeout=s.scan_timeout,
                    retries=s.scan_retries, allow_private=s.allow_private,
                    allowed_subnets=s.allowed_subnets,
                    dns_servers=s.dns_servers,
                    max_output_bytes=s.scan_max_output_bytes,
                    hsts_timeout=s.hsts_timeout,
                ),
                alert_fn=lambda: {"sent": 0, "failed": 0},
                db_path=s.db_path,
                host_provider=lambda: hosts,
                store_fn=lambda r: store_scanned(
                    r, s.db_path,  # type: ignore[arg-type]
                    drift_alerts=s.drift_alerts,
                    check_revocation=s.check_revocation,
                    allow_private=s.allow_private,
                    allowed_subnets=s.allowed_subnets,
                    webhook_config=webhook_cfg,
                ),
            )

    import datetime as _dt_init
    _weekly_digest_day: int = _dt_init.datetime.now(_dt_init.UTC).weekday()
    # Track the ISO (year, week) the expiry digest last went out so it sends
    # weekly rather than on every (daily) alert cycle. Seeded to the current week
    # so a (re)start mid-week does not immediately re-send; it fires at the next
    # week boundary.
    _iso_init = _dt_init.datetime.now(_dt_init.UTC).isocalendar()
    _expiry_digest_week: tuple[int, int] = (_iso_init[0], _iso_init[1])

    def _max_group_cadence(
        db_path: str | Path, *, default: int = 30
    ) -> int:
        from cert_watch.database import SqliteAlertGroupRepository

        try:
            groups = SqliteAlertGroupRepository(db_path).list_all()
        except Exception:  # noqa: BLE001 — best-effort; schema may not be ready
            return default
        cadences = [g.digest_cadence_days for g in groups if g.digest_cadence_days > 0]
        return max(cadences) if cadences else default

    def _alerts() -> dict:
        import datetime as _dt

        from cert_watch.alerts import (
            evaluate_all_certs,
            evaluate_renewal_window,
            process_pending,
            send_expiry_digest,
        )

        nonlocal _expiry_digest_week
        repo = SqliteAlertRepository(s.db_path)
        if s.alert_digest_only:
            # Even in digest mode, the final-countdown (<= URGENT_THRESHOLD_DAYS)
            # per-certificate alerts still fire every cycle; the digest only
            # replaces the routine heads-up thresholds.
            evaluate_all_certs(s.db_path, repo, urgent_only=True)
            evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
            result = process_pending(repo, alert_cfg, webhook_config=webhook_cfg)
            # The summary digest is weekly, not daily.
            iso = _dt.datetime.now(_dt.UTC).isocalendar()
            this_week = (iso[0], iso[1])
            if this_week != _expiry_digest_week:
                _expiry_digest_week = this_week
                delivered = send_expiry_digest(
                    s.db_path, alert_cfg, webhook_config=webhook_cfg,
                    cadence_days=_max_group_cadence(s.db_path),
                )
                result["sent"] = result.get("sent", 0) + (1 if delivered else 0)
                result["failed"] = result.get("failed", 0) + (0 if delivered else 1)
            return result
        evaluate_all_certs(s.db_path, repo)
        evaluate_renewal_window(s.db_path, repo, s.renewal_window_days)
        return process_pending(repo, alert_cfg, webhook_config=webhook_cfg)

    def _weekly_digest() -> None:
        from cert_watch.digest import send_renewal_digest

        send_renewal_digest(
            s.db_path, alert_cfg, webhook_cfg,
            cadence_days=_max_group_cadence(s.db_path, default=7),
        )

    def _maybe_run_weekly_digest() -> dict:
        import datetime as _dt

        nonlocal _weekly_digest_day
        today = _dt.datetime.now(_dt.UTC).weekday()
        if today != _weekly_digest_day:
            _weekly_digest_day = today
            try:
                _weekly_digest()
            except Exception:
                logger.exception("weekly renewal digest failed")
        return {"sent": 0, "failed": 0}

    def _maintenance() -> None:
        """Daily housekeeping: trim audit log, cert history, alerts, and events."""
        from cert_watch.audit import purge_old_audit
        from cert_watch.database.queries import purge_old_alerts, purge_old_history
        from cert_watch.events import purge_old_events

        purge_old_audit(s.db_path, s.audit_retention_days)
        purge_old_history(s.db_path, s.history_retention_days)
        purge_old_alerts(s.db_path, s.alert_retention_days)
        purge_old_events(s.db_path, s.event_retention_days)

    # Purge once at startup too — restarts (e.g. k8s rollouts) are frequent and
    # shouldn't have to wait for the next daily cycle to reclaim the audit log.
    _maintenance()

    start_scheduler(
        scan_fn=_scan_all,
        alert_fn=_alerts,
        maintenance_fn=_maintenance,
        digest_fn=_maybe_run_weekly_digest,
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
    application.middleware("http")(csrf_session_middleware)
    application.middleware("http")(setup_redirect_middleware)
    application.middleware("http")(auth_middleware)
    application.middleware("http")(rate_limit_headers_middleware)
    # Outermost (runs first): issue the per-request CSP nonce into scope state
    # before any other middleware/endpoint, so the template context processor and
    # security_headers_middleware share it (BC-075).
    application.add_middleware(CSPNonceMiddleware)

    # Mount route modules
    for router in route_modules:
        application.include_router(router)
    return application


# Module-level app for uvicorn (`cert_watch.app:app`); deps resolved from env.
app = create_app()
