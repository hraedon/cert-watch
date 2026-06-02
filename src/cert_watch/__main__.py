"""cert-watch CLI entry point.

Provides ``cert-watch`` (web server), ``cert-watch backup <path>``
(WAL-safe database backup), and ``cert-watch hash-password``
(generate scrypt password hash for CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH).
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

    sub.add_parser(
        "hash-password",
        help="Generate scrypt hash for CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH",
    )

    # Server bind options (default command). These are the *single source of
    # truth* for the bind address: __main__ normalizes CERT_WATCH_HOST to the
    # resolved host before launching uvicorn, so the BC-083 secure-by-default
    # check (which reads CERT_WATCH_HOST) always sees exactly what we bind —
    # whether the host came from the CLI (IIS HttpPlatformHandler) or the env.
    parser.add_argument(
        "--host",
        default=None,
        help="Bind address (overrides CERT_WATCH_HOST; default 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port (overrides CERT_WATCH_PORT; default 8000)",
    )

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

    if args.command == "hash-password":
        import getpass

        from cert_watch.auth import _scrypt_hash

        password = getpass.getpass("Password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            raise SystemExit(1)
        if not password:
            print("Password cannot be empty.")
            raise SystemExit(1)
        print(_scrypt_hash(password))
        return

    # Default: run the web server
    import uvicorn

    # Resolve the bind host: --host wins, then CERT_WATCH_HOST, then 0.0.0.0.
    host = args.host or os.environ.get("CERT_WATCH_HOST", "0.0.0.0")
    # Normalize the env var to the resolved host so the app lifespan's BC-083
    # secure-by-default check (cert_watch.app, which reads CERT_WATCH_HOST) sees
    # the address we actually bind — closes the IIS HttpPlatformHandler gap
    # where --host was passed but the env var defaulted to 0.0.0.0 (BC-090).
    os.environ["CERT_WATCH_HOST"] = host

    if args.port is not None:
        port = args.port
    else:
        port_str = os.environ.get("CERT_WATCH_PORT", "8000")
        try:
            port = int(port_str)
        except ValueError:
            logger.warning("Invalid CERT_WATCH_PORT=%r, using default 8000", port_str)
            port = 8000
    uvicorn.run(
        "cert_watch.app:app",
        host=host,
        port=port,
        reload=os.environ.get("CERT_WATCH_RELOAD") == "1",
    )


if __name__ == "__main__":
    main()