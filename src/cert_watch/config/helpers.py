"""Config helpers: secret reading, role-map parsing, group-DN splitting.

Moved from the monolithic config.py (BC-144a / config decomposition).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path, PureWindowsPath
from typing import Any

logger = logging.getLogger("cert_watch.config")


# Setting keys (kv_store column names) whose values are secrets: encrypted at
# rest when written via the GUI, decrypted on read, and masked in the UI. Single
# source of truth — `routes/settings.py` imports this so the encrypt/decrypt/mask
# sides cannot drift.
SENSITIVE_SETTING_KEYS = frozenset({
    "ldap_bind_password",
    "ldap_ca_cert",
    "oauth_client_secret",
    "smtp_password",
    "pagerduty_routing_key",
    "local_admin_password_hash",
    # A Bearer token or shared secret commonly lives in a custom webhook header
    # (the UI placeholder suggests ``Authorization: Bearer ...``); treat the
    # whole JSON blob as sensitive so it is encrypted at rest and masked in the
    # UI rather than stored / rendered in cleartext.
    "webhook_headers",
})


def resolve_or_persist_secret(env_name: str, data_dir: Path, filename: str) -> str:
    """Return env/_FILE secret if set (treating empty/whitespace as unset);
    else read data_dir/filename; else generate 32-byte hex, persist 0600, return it.
    """
    value = read_secret(env_name)
    if value and value.strip():
        return value
    secret_file = data_dir / filename
    try:
        if secret_file.exists():
            persisted = secret_file.read_text().strip()
            if persisted:
                logger.warning(
                    "Using persisted %s from %s (no %s env var set; "
                    "consider setting %s in production for explicit control)",
                    filename, secret_file, env_name, env_name,
                )
                return persisted
    except OSError:
        logger.debug("could not read %s, will regenerate", secret_file)
    import secrets
    generated = secrets.token_hex(32)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(generated + "\n")
        secret_file.chmod(0o600)
        logger.info("generated and persisted %s to %s", filename, secret_file)
    except OSError:
        logger.warning(
            "could not persist %s to %s; using ephemeral key (sessions will not survive restart)",
            filename, secret_file,
        )
    return generated


def _parse_role_map(raw: str) -> dict[str, dict[str, Any]]:
    """Parse CERT_WATCH_ROLE_MAP JSON.  Returns {} on empty / invalid input."""
    if not raw:
        return {}
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, TypeError):
        return {}


def split_group_dns(raw: str) -> tuple[str, ...]:
    """Split a list of LDAP group DNs on semicolons or newlines.

    Group DNs contain commas (``CN=admins,OU=Groups,DC=example,DC=com``), so a
    comma-delimited list is ambiguous: it shreds each DN into its RDN fragments
    (``CN=admins``, ``OU=Groups``, ``DC=example``, …), and the resulting group
    filter matches nothing — every LDAP_REQUIRED_GROUPS login fails as "not in
    required group(s)". Semicolons/newlines do not appear in normal AD DNs, so
    they are the safe delimiter for a list of DNs.
    """
    parts = raw.replace("\n", ";").split(";")
    return tuple(p.strip() for p in parts if p.strip())


def read_secret(name: str) -> str | None:
    """Return the value of env var $name, or the file contents of $name_FILE.

    The ``_FILE`` convention is standard in Docker/Kubernetes secret mounts:
    the operator sets e.g. ``LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap_pw``
    instead of putting the secret value directly in the environment.

    Returns ``None`` when neither is set.  When the ``_FILE`` variant is used,
    the file contents are stripped of trailing whitespace/newlines.
    """
    value = os.environ.get(name)
    if value is not None:
        return value
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        try:
            return Path(file_path).read_text().strip()
        except OSError:
            logger.warning("read_secret: %s_FILE=%s could not be read", name, file_path)
            return None
    return None


def _default_data_dir_str(os_name: str, programdata: str | None) -> str:
    """Compute the default data-dir path string for *os_name*.

    Split out so the platform branch is testable on any host (building a
    concrete ``WindowsPath`` is impossible on POSIX, so we join with
    ``PureWindowsPath`` and return a plain string).
    """
    if os_name == "nt":
        base = programdata or r"C:\ProgramData"
        return str(PureWindowsPath(base, "cert-watch"))
    return "/var/lib/cert-watch"


def _default_data_dir() -> Path:
    r"""Platform-appropriate default data directory.

    Always overridable via ``CERT_WATCH_DATA_DIR``. On Windows there is no
    ``/var`` hierarchy, so default to ``%PROGRAMDATA%\cert-watch`` (normally
    ``C:\ProgramData\cert-watch``); on POSIX keep ``/var/lib/cert-watch``.
    """
    return Path(_default_data_dir_str(os.name, os.environ.get("PROGRAMDATA")))


def _validate_range(
    value: int, name: str,
    min_value: int | None = None, max_value: int | None = None,
) -> int:
    """Raise ValueError if *value* falls outside the allowed range."""
    if min_value is not None and value < min_value:
        raise ValueError(f"{name}={value} is below minimum {min_value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"{name}={value} exceeds maximum {max_value}")
    return value


def _parse_int(raw: str, default: int, name: str, *,
               min_value: int | None = None, max_value: int | None = None) -> int:
    """Parse an integer env var with fallback, warning on invalid input, and range check.

    On non-integer input, warns and returns *default*. On out-of-range input,
    raises ``ValueError`` so the application fails fast at startup rather than
    silently misbehaving (e.g. ``CERT_WATCH_SCHED_HOUR=25``).
    """
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default
    _validate_range(value, name, min_value, max_value)
    return value


def _parse_float(raw: str, default: float, name: str) -> float:
    """Parse a float env var with fallback and warning on invalid input."""
    try:
        return float(raw)
    except ValueError:
        logger.warning("Invalid %s=%r, using default %s", name, raw, default)
        return default
