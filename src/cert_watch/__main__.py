"""cert-watch CLI entry point.

Provides ``cert-watch`` (web server), ``cert-watch backup <path>``
(WAL-safe database backup), ``cert-watch hash-password``
(generate scrypt password hash for CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH),
``cert-watch re-encrypt <old_key>`` (re-encrypt kv_store secrets after
signing key rotation), and ``cert-watch verify-report <file>`` (verify
HMAC signature of a compliance report).
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

    reencrypt_parser = sub.add_parser(
        "re-encrypt",
        help="Re-encrypt kv_store secrets after .auth_secret rotation",
    )
    reencrypt_parser.add_argument(
        "old_key",
        help="The old signing key (from the previous .auth_secret file, "
        "or set CERT_WATCH_AUTH_SECRET to the old value)",
    )

    verify_parser = sub.add_parser(
        "verify-report",
        help="Verify HMAC signature of a signed compliance report (JSON)",
    )
    verify_parser.add_argument(
        "report_path",
        help="Path to the compliance report JSON file to verify",
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

    if args.command == "re-encrypt":
        from cert_watch.config import Settings, resolve_or_persist_secret
        from cert_watch.database import init_schema
        from cert_watch.database.queries import derive_encryption_key, re_encrypt_kv_store

        s = Settings.from_env()
        init_schema(s.db_path)
        new_key = derive_encryption_key(
            resolve_or_persist_secret("CERT_WATCH_AUTH_SECRET", s.data_dir, ".auth_secret")
        )
        old_enc_key = derive_encryption_key(args.old_key)
        count = re_encrypt_kv_store(s.db_path, old_enc_key, new_key)
        print(f"Re-encrypted {count} kv_store value(s).")
        return

    if args.command == "verify-report":
        import json as _json

        from cert_watch.compliance import verify_report_signature
        from cert_watch.config import Settings, resolve_or_persist_secret

        s = Settings.from_env()
        signing_key = resolve_or_persist_secret(
            "CERT_WATCH_AUTH_SECRET", s.data_dir, ".auth_secret"
        )
        try:
            with open(args.report_path) as f:
                report_data = _json.load(f)
        except _json.JSONDecodeError:
            print(
                "FAIL — could not parse as JSON. Tamper-evidence is verified "
                "against the JSON report (compliance-report.json), not the CSV "
                "export. Re-download the JSON report and verify that."
            )
            raise SystemExit(1) from None
        if not isinstance(report_data, dict):
            print("FAIL — report is not a JSON object")
            raise SystemExit(1)
        ok, msg = verify_report_signature(report_data, signing_key)
        if ok:
            print(f"PASS — {msg}")
            print(f"  Generated at: {report_data.get('generated_at', 'unknown')}")
            print(f"  Content SHA-256: {report_data.get('content_sha256', '')}")
        else:
            print(f"FAIL — {msg}")
            raise SystemExit(1)
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