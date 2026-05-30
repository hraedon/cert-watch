"""cert-watch CLI entry point.

Provides ``cert-watch`` (web server) and ``cert-watch backup <path>``
(subcommand for WAL-safe database backup).
"""

from __future__ import annotations

import argparse
import logging
import os

logger = logging.getLogger("cert_watch")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="cert-watch",
        description="TLS certificate expiration tracker",
    )
    sub = parser.add_subparsers(dest="command")

    backup_parser = sub.add_parser("backup", help="Create a WAL-safe backup of the database")
    backup_parser.add_argument("path", help="Output path for the backup file")

    args = parser.parse_args(argv)

    if args.command == "backup":
        from cert_watch.config import Settings
        from cert_watch.database import init_schema
        from cert_watch.migrations.runner import create_backup

        s = Settings.from_env()
        init_schema(s.db_path)
        result = create_backup(s.db_path, args.path)
        print(f"Backup created: {result}")
        return

    # Default: run the web server
    import uvicorn

    port_str = os.environ.get("CERT_WATCH_PORT", "8000")
    try:
        port = int(port_str)
    except ValueError:
        logger.warning("Invalid CERT_WATCH_PORT=%r, using default 8000", port_str)
        port = 8000
    uvicorn.run(
        "cert_watch.app:app",
        host=os.environ.get("CERT_WATCH_HOST", "0.0.0.0"),
        port=port,
        reload=os.environ.get("CERT_WATCH_RELOAD") == "1",
    )


if __name__ == "__main__":
    main()