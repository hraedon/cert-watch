import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("cert_watch.config")


@dataclass(frozen=True)
class Settings:
    db_path: Path
    data_dir: Path
    sched_hour: int = 6
    sched_min: int = 0
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    alert_from: str | None = None
    alert_recipients: tuple[str, ...] = ()
    webhook_url: str | None = None
    webhook_headers: dict[str, str] | None = None
    tls_verify: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("CERT_WATCH_DATA_DIR", "/var/lib/cert-watch"))
        recipients = tuple(
            r.strip()
            for r in os.environ.get("ALERT_RECIPIENTS", "").split(",")
            if r.strip()
        )
        webhook_url = os.environ.get("ALERT_WEBHOOK_URL") or None
        webhook_headers_str = os.environ.get("ALERT_WEBHOOK_HEADERS") or ""
        webhook_headers = None
        if webhook_headers_str:
            try:
                webhook_headers = json.loads(webhook_headers_str)
            except (json.JSONDecodeError, ValueError):
                webhook_headers = None
        sched_hour_str = os.environ.get("CERT_WATCH_SCHED_HOUR", "6")
        sched_min_str = os.environ.get("CERT_WATCH_SCHED_MIN", "0")
        smtp_port_str = os.environ.get("SMTP_PORT", "587")
        try:
            sched_hour = int(sched_hour_str)
        except ValueError:
            logger.warning("Invalid CERT_WATCH_SCHED_HOUR=%r, using default 6", sched_hour_str)
            sched_hour = 6
        try:
            sched_min = int(sched_min_str)
        except ValueError:
            logger.warning("Invalid CERT_WATCH_SCHED_MIN=%r, using default 0", sched_min_str)
            sched_min = 0
        try:
            smtp_port = int(smtp_port_str)
        except ValueError:
            logger.warning("Invalid SMTP_PORT=%r, using default 587", smtp_port_str)
            smtp_port = 587
        return cls(
            db_path=data_dir / "cert-watch.sqlite3",
            data_dir=data_dir,
            sched_hour=sched_hour,
            sched_min=sched_min,
            smtp_host=os.environ.get("SMTP_HOST") or None,
            smtp_port=smtp_port,
            smtp_user=os.environ.get("SMTP_USER") or None,
            smtp_password=os.environ.get("SMTP_PASSWORD") or None,
            alert_from=os.environ.get("ALERT_FROM") or None,
            alert_recipients=recipients,
            webhook_url=webhook_url,
            webhook_headers=webhook_headers,
            tls_verify=os.environ.get("CERT_WATCH_TLS_VERIFY", "0") == "1",
        )

    def build_alert_config(self):
        """Return an AlertConfig if SMTP envs are sufficiently populated, else None.

        Preserves the existing convention: when host/from/recipients are absent,
        return None so process_pending() no-ops.
        """
        from cert_watch.alerts import AlertConfig

        if not (self.smtp_host and self.alert_from and self.alert_recipients):
            return None
        return AlertConfig(
            smtp_host=self.smtp_host,
            smtp_port=self.smtp_port,
            smtp_user=self.smtp_user or "",
            smtp_password=self.smtp_password or "",
            from_addr=self.alert_from,
            recipients=list(self.alert_recipients),
        )

    def build_webhook_config(self):
        """Return a WebhookConfig if webhook URL is set, else None."""
        from cert_watch.alerts import WebhookConfig

        if not self.webhook_url:
            return None
        return WebhookConfig(
            url=self.webhook_url,
            headers=self.webhook_headers or {},
        )


settings = Settings.from_env()
