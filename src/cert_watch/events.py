"""Event streaming — append-only event log with optional webhook fan-out (Plan 044)."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cert_watch.database.connection import _connect
from cert_watch.retry import backoff_range

logger = logging.getLogger("cert_watch.events")

ALL_EVENT_TYPES = (
    "cert_added",
    "cert_renewed",
    "posture_changed",
    "scan_failed",
    "policy_violation",
    "alert_acknowledged",
    "renewal_overdue",
)

ALL_SOURCES = ("scan", "upload", "ct", "manual", "scheduler")


@dataclass
class Event:
    event_type: str
    timestamp: datetime
    payload: dict
    source: str

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "payload": self.payload,
            "source": self.source,
        }


@dataclass
class EventStreamConfig:
    enabled_event_types: list[str] = field(default_factory=lambda: list(ALL_EVENT_TYPES))
    webhook_url: str | None = None
    webhook_kind: str = "generic"
    pagerduty_routing_key: str = ""
    rate_limit_per_second: int = 100

    def to_json(self) -> str:
        return json.dumps({
            "enabled_event_types": self.enabled_event_types,
            "webhook_url": self.webhook_url,
            "webhook_kind": self.webhook_kind,
            "rate_limit_per_second": self.rate_limit_per_second,
        })

    @classmethod
    def from_json(cls, raw: str) -> EventStreamConfig:
        d = json.loads(raw)
        # ``pagerduty_routing_key`` is no longer serialized in the blob (WI-065:
        # stored separately as an enc:v1: secret). It is still read here for
        # backward compat with pre-WI-065 blobs that hold it as plaintext, so
        # existing deployments do not lose their key on upgrade (it is migrated
        # to the encrypted kv secret on the next save).
        return cls(
            enabled_event_types=d.get("enabled_event_types", list(ALL_EVENT_TYPES)),
            webhook_url=d.get("webhook_url"),
            webhook_kind=d.get("webhook_kind", "generic"),
            pagerduty_routing_key=d.get("pagerduty_routing_key", ""),
            rate_limit_per_second=d.get("rate_limit_per_second", 100),
        )


_KV_KEY = "event_stream_config"
# The PagerDuty routing key is persisted separately as an enc:v1: secret rather
# than inside the EventStreamConfig JSON blob, mirroring the alert-path handling
# of ``pagerduty_routing_key`` (a SENSITIVE_SETTING_KEY). WI-065.
_KV_ROUTING_KEY = "event_stream_pagerduty_routing_key"


def _resolve_encryption_key(db_path: str | Path) -> str | None:
    """Best-effort Fernet key for the event-stream PagerDuty secret (WI-065).

    Derived from the same signing material the app lifespan uses
    (``CERT_WATCH_AUTH_SECRET`` env / ``_FILE`` / ``data_dir/.auth_secret``).
    Read-only — never generates, so a missing secret returns ``None`` and
    encrypted values are not decrypted (PagerDuty delivery is then skipped,
    matching the alert path's behavior when the signing key is lost). ``db_path``
    lives under ``data_dir``, so its parent holds ``.auth_secret``.
    """
    from cert_watch.config.helpers import read_secret

    signing_key = read_secret("CERT_WATCH_AUTH_SECRET")
    if not signing_key:
        secret_file = Path(db_path).parent / ".auth_secret"
        try:
            signing_key = secret_file.read_text().strip() or None
        except OSError:
            signing_key = None
    if not signing_key:
        return None
    from cert_watch.database.encryption import derive_encryption_key

    return derive_encryption_key(signing_key)


def load_event_config(
    db_path: str | Path, *, encryption_key: str | None = None
) -> EventStreamConfig:
    from cert_watch.database.kv_store import kv_get

    raw = kv_get(db_path, _KV_KEY)
    cfg = EventStreamConfig.from_json(raw) if raw is not None else EventStreamConfig()
    # PagerDuty routing key: prefer the dedicated enc:v1: secret (WI-065); fall
    # back to the legacy plaintext field read by from_json for old blobs.
    if encryption_key is None:
        encryption_key = _resolve_encryption_key(db_path)
    secret = kv_get(db_path, _KV_ROUTING_KEY, encryption_key)
    if secret and not (encryption_key is None and secret.startswith("enc:v1:")):
        cfg.pagerduty_routing_key = secret
    return cfg


def save_event_config(
    db_path: str | Path, config: EventStreamConfig, *, encryption_key: str | None = None
) -> None:
    from cert_watch.database.kv_store import kv_set_multi

    if encryption_key is None:
        encryption_key = _resolve_encryption_key(db_path)
    pairs: dict[str, str] = {_KV_KEY: config.to_json()}
    if config.pagerduty_routing_key:
        if encryption_key:
            from cert_watch.database.encryption import fernet_encrypt

            pairs[_KV_ROUTING_KEY] = fernet_encrypt(
                config.pagerduty_routing_key, encryption_key
            )
        else:
            # No signing key available (e.g. tests / ephemeral key): store
            # plaintext so the value still round-trips. Production persists
            # .auth_secret, so this branch is not reached there.
            pairs[_KV_ROUTING_KEY] = config.pagerduty_routing_key
    kv_set_multi(db_path, pairs)


_rate_lock = threading.Lock()
_rate_timestamps: deque[float] = deque()


def _check_rate(limit_per_second: int) -> bool:
    now = time.monotonic()
    with _rate_lock:
        while _rate_timestamps and _rate_timestamps[0] < now - 1.0:
            _rate_timestamps.popleft()
        if len(_rate_timestamps) >= limit_per_second:
            return False
        _rate_timestamps.append(now)
    return True


_pool: ThreadPoolExecutor | None = None
_pool_lock = threading.Lock()


def _get_pool() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cw-evt")
    return _pool


def reset_pool() -> None:
    global _pool
    with _pool_lock:
        if _pool is not None:
            _pool.shutdown(wait=False, cancel_futures=True)
            _pool = None


def _write_event_log(
    db_path: str | Path,
    event: Event,
    delivery_status: str,
    error_message: str | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> int | None:
    from cert_watch.database import init_schema

    if conn is None:
        init_schema(db_path)
    ts = event.timestamp.isoformat()
    created_at = datetime.now(UTC).isoformat()
    payload_json = json.dumps(event.payload, default=str)
    params = (
        event.event_type, ts, event.source,
        payload_json, delivery_status, error_message,
        created_at,
    )
    if conn is None:
        with _connect(db_path) as conn:
            cur = conn.execute(
                "INSERT INTO event_log"
                " (event_type, timestamp, source, payload,"
                " delivery_status, error_message, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                params,
            )
            conn.commit()
            return cur.lastrowid
    cur = conn.execute(
        "INSERT INTO event_log"
        " (event_type, timestamp, source, payload,"
        " delivery_status, error_message, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        params,
    )
    return cur.lastrowid


def _resolve_ssrf_policy(db_path: str | Path) -> tuple[bool, tuple[str, ...]]:
    """Resolve the SSRF allow-policy for event-stream webhook delivery (WI-063).

    Mirrors ``Settings``: ``allow_private`` is env-only
    (``CERT_WATCH_ALLOW_PRIVATE_IPS``); ``allowed_subnets`` is env
    (``CERT_WATCH_ALLOWED_SUBNETS``) winning over the kv_store value set by the
    setup wizard. Resolved live at delivery time (not snapshotted into the
    event-stream config) so a policy change takes effect without re-saving it.
    """
    import os

    from cert_watch.database.kv_store import kv_get

    allow_private = os.environ.get("CERT_WATCH_ALLOW_PRIVATE_IPS", "1") == "1"
    env_subnets = os.environ.get("CERT_WATCH_ALLOWED_SUBNETS", "")
    if env_subnets.strip():
        subnets = tuple(s.strip() for s in env_subnets.split(",") if s.strip())
    else:
        raw = kv_get(db_path, "allowed_subnets") or ""
        subnets = tuple(s.strip() for s in raw.split(",") if s.strip())
    return allow_private, subnets


def _deliver_webhook(
    event: Event,
    config: EventStreamConfig,
    db_path: str | Path,
    row_id: int,
) -> None:
    from cert_watch.alerts import Alert, WebhookConfig, send_webhook

    payload = event.payload
    friendly_msg = (
        f"[{event.event_type}] {payload.get('hostname', '')}"
        f" (cert {payload.get('cert_id', '')})"
    )
    if event.event_type == "posture_changed":
        friendly_msg = (
            f"Posture changed for {payload.get('hostname', '')}"
            f": {payload.get('old_grade', '?')} → {payload.get('new_grade', '?')}"
        )
    elif event.event_type == "cert_added":
        friendly_msg = (
            f"Certificate added: {payload.get('hostname', '')}"
            f" (cert {payload.get('cert_id', '')})"
        )
    elif event.event_type == "cert_renewed":
        friendly_msg = (
            f"Certificate renewed: {payload.get('hostname', '')}"
            f" (cert {payload.get('cert_id', '')})"
        )
    elif event.event_type == "scan_failed":
        friendly_msg = (
            f"Scan failed: {payload.get('hostname', '')}"
            f":{payload.get('port', '')}"
            f" — {payload.get('error_message', 'unknown error')}"
        )
    elif event.event_type == "policy_violation":
        friendly_msg = (
            f"Policy violation: {payload.get('hostname', '')}"
            f" — {payload.get('message', '')}"
        )

    alert = Alert(
        cert_id=payload.get("cert_id", ""),
        alert_type=event.event_type,
        status="event",
        message=friendly_msg,
        threshold_days=None,
    )
    try:
        allow_private, allowed_subnets = _resolve_ssrf_policy(db_path)
        wc = WebhookConfig(
            url=config.webhook_url or "",
            kind=config.webhook_kind,
            routing_key=config.pagerduty_routing_key,
            allow_private=allow_private,
            allowed_subnets=allowed_subnets,
        )
        success = False
        last_error = ""
        for _ in backoff_range(2, 1.0, strategy="exponential"):
            if send_webhook(alert, wc):
                success = True
                break
            last_error = alert.error_message or "unknown"
        new_status = "delivered" if success else "failed"
        err = None if success else last_error
    except Exception as exc:
        new_status = "failed"
        err = str(exc)[:500]
    with _connect(db_path) as conn:
        conn.execute(
            "UPDATE event_log SET delivery_status = ?, error_message = ? WHERE id = ?",
            (new_status, err, row_id),
        )
        conn.commit()


def emit_event(
    event: Event,
    db_path: str | Path,
    config: EventStreamConfig | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> int | None:
    try:
        if config is None:
            if conn is not None:
                raise ValueError("config is required when conn is provided")
            config = load_event_config(db_path)
        if event.event_type not in config.enabled_event_types:
            return None
        if config.webhook_url and not _check_rate(config.rate_limit_per_second):
            logger.debug("event rate-limited: %s", event.event_type)
            return None
        delivery_status = "pending"
        if not config.webhook_url:
            delivery_status = "delivered"
        row_id = _write_event_log(db_path, event, delivery_status, conn=conn)
        if config.webhook_url and row_id is not None:
            try:
                _get_pool().submit(_deliver_webhook, event, config, str(db_path), row_id)
            except Exception:
                logger.warning("event webhook submit failed", exc_info=True)
        return row_id
    except (sqlite3.DatabaseError, TypeError, ValueError):
        if conn is not None:
            raise
        logger.warning("emit_event failed", exc_info=True)
        return None


def get_events(
    db_path: str | Path,
    *,
    event_type: str | None = None,
    source: str | None = None,
    since: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    conditions: list[str] = []
    params: list = []
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)
    if source:
        conditions.append("source = ?")
        params.append(source)
    if since:
        conditions.append("timestamp >= ?")
        params.append(since)
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"SELECT * FROM event_log{where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
    return [dict(r) for r in rows]


def get_failed_deliveries(db_path: str | Path, *, limit: int = 50) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM event_log WHERE delivery_status = 'failed' ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def emit_scan_failed(
    db_path: str | Path,
    hostname: str,
    port: int,
    error_message: str,
    source: str = "scan",
) -> int | None:
    return emit_event(
        Event(
            event_type="scan_failed",
            timestamp=datetime.now(UTC),
            payload={"hostname": hostname, "port": port, "error_message": error_message},
            source=source,
        ),
        db_path,
    )


def purge_old_events(db_path: str | Path, retention_days: int) -> int:
    """Delete event_log entries older than *retention_days*. Returns count deleted."""
    if retention_days <= 0:
        return 0
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
    with _connect(db_path) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM event_log WHERE created_at < ?", (cutoff,)
        ).fetchone()[0]
        conn.execute("DELETE FROM event_log WHERE created_at < ?", (cutoff,))
        conn.commit()
    return count