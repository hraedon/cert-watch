import os
from dataclasses import dataclass
from pathlib import Path


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

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("CERT_WATCH_DATA_DIR", "/var/lib/cert-watch"))
        recipients = tuple(
            r.strip()
            for r in os.environ.get("ALERT_RECIPIENTS", "").split(",")
            if r.strip()
        )
        return cls(
            db_path=data_dir / "cert-watch.sqlite3",
            data_dir=data_dir,
            sched_hour=int(os.environ.get("CERT_WATCH_SCHED_HOUR", "6")),
            sched_min=int(os.environ.get("CERT_WATCH_SCHED_MIN", "0")),
            smtp_host=os.environ.get("SMTP_HOST") or None,
            smtp_port=int(os.environ.get("SMTP_PORT", "587")),
            smtp_user=os.environ.get("SMTP_USER") or None,
            smtp_password=os.environ.get("SMTP_PASSWORD") or None,
            alert_from=os.environ.get("ALERT_FROM") or None,
            alert_recipients=recipients,
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


settings = Settings.from_env()
