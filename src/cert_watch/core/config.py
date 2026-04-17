"""Configuration module for cert-watch.

This is the SINGLE canonical location for all configuration.
Use Settings.get() to access configuration values.
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="cert-watch")
    debug: bool = Field(default=False)

    # Database
    database_url: str = Field(default="sqlite:///./cert_watch.db")
    data_dir: Path = Field(default=Path("./data"))

    # SMTP / Email Alerts
    smtp_host: Optional[str] = Field(default=None)
    smtp_port: int = Field(default=587)
    smtp_user: Optional[str] = Field(default=None)
    smtp_password: Optional[str] = Field(default=None)
    smtp_use_tls: bool = Field(default=True)
    smtp_from_addr: Optional[str] = Field(default=None)
    alert_recipients: list[str] = Field(default_factory=list)

    # Alert Thresholds (days before expiry)
    leaf_alert_thresholds: list[int] = Field(default_factory=lambda: [14, 7, 3, 1])
    chain_alert_thresholds: list[int] = Field(default_factory=lambda: [30, 14, 7])

    # Scheduler
    scan_time: str = Field(default="06:00")  # HH:MM format
    scan_timezone: str = Field(default="UTC")

    @property
    def database_path(self) -> Path:
        """Get the SQLite database file path."""
        if self.database_url.startswith("sqlite:///"):
            path_str = self.database_url.replace("sqlite:///", "")
            return Path(path_str)
        return Path("./cert_watch.db")

    @classmethod
    def get(cls, settings: Optional["Settings"] = None) -> "Settings":
        """Get the singleton settings instance.

        This is the ONLY way to access settings in the application.
        In tests, pass a settings instance to use that instead of the singleton.
        """
        if settings is not None:
            return settings
        return _get_cached_settings()

    def ensure_data_dirs(self) -> None:
        """Create data directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def _get_cached_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
