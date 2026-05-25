import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path
    data_dir: Path

    @classmethod
    def from_env(cls) -> "Settings":
        data_dir = Path(os.environ.get("CERT_WATCH_DATA_DIR", "/var/lib/cert-watch"))
        return cls(db_path=data_dir / "cert-watch.sqlite3", data_dir=data_dir)


settings = Settings.from_env()
