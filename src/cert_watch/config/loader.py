"""One resolver for Settings defaults, environment variables, and kv_store."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cert_watch.config.field_specs import FIELD_SPECS, FieldSpec

logger = logging.getLogger("cert_watch.config")


def _default(spec: FieldSpec) -> Any:
    return spec.default() if callable(spec.default) else spec.default


def setting_env_source(field_name: str, env: Mapping[str, str] | None = None) -> str | None:
    """Return the effective env source (including ``_FILE``), if any.

    GUI-backed settings preserve the historical rule that an empty or
    whitespace-only environment value is unset, so deployment placeholders
    such as ``SMTP_PASSWORD: ""`` do not mask a saved value.  An empty
    ``_FILE`` path is always unset.
    """
    environ = os.environ if env is None else env
    spec = FIELD_SPECS[field_name]
    for name in spec.env_names:
        if name in environ:
            if spec.kv_key is None or environ[name].strip():
                return name
        file_name = f"{name}_FILE"
        if spec.sensitive and environ.get(file_name, "").strip():
            return file_name
    return None


def setting_env_is_set(field_name: str, env: Mapping[str, str] | None = None) -> bool:
    return setting_env_source(field_name, env) is not None


def _read_env(spec: FieldSpec, source: str, env: Mapping[str, str]) -> str:
    if source.endswith("_FILE") and spec.sensitive:
        from cert_watch.config.helpers import _read_secret_file

        return _read_secret_file(source, env[source])
    return env[source]


def _parse(field_name: str, raw: str, spec: FieldSpec, *, source: str) -> Any:
    if not raw and spec.empty_uses_default:
        return _default(spec)
    parser = spec.parser
    if parser in {"str", "secret-file"}:
        value: Any = raw
    elif parser == "path":
        value = Path(raw)
    elif parser == "bool":
        # Environment booleans historically accept only "1"; persisted UI
        # values additionally accept legacy "true" rows.
        value = raw == "1" or (source == "kv" and raw.lower() == "true")
    elif parser == "int":
        try:
            value = int(raw)
        except ValueError:
            logger.warning(
                "Invalid %s=%r, using default %s", _label(field_name, spec), raw, _default(spec)
            )
            return _default(spec)
        if spec.minimum is not None and value < spec.minimum:
            raise ValueError(f"{_label(field_name, spec)}={value} is below minimum {spec.minimum}")
        if spec.maximum is not None and value > spec.maximum:
            raise ValueError(f"{_label(field_name, spec)}={value} exceeds maximum {spec.maximum}")
    elif parser == "float":
        try:
            value = float(raw)
        except ValueError:
            logger.warning(
                "Invalid %s=%r, using default %s", _label(field_name, spec), raw, _default(spec)
            )
            return _default(spec)
    elif parser == "csv":
        if spec.normalize == "group-dns":
            value = tuple(
                part.strip() for part in raw.replace("\n", ";").split(";") if part.strip()
            )
        else:
            value = tuple(part.strip() for part in raw.split(",") if part.strip())
    elif parser == "json":
        if not raw.strip():
            return _default(spec)
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            if field_name == "renewal_webhook_headers":
                logger.warning("CERT_WATCH_RENEWAL_WEBHOOK_HEADERS is not valid JSON; ignoring")
            return _default(spec)
        if field_name == "role_map":
            value = value if isinstance(value, dict) else {}
        elif spec.normalize == "string-dict":
            value = {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else None
    else:  # pragma: no cover - Literal plus exhaustive table makes this defensive
        raise AssertionError(f"unsupported parser {parser!r}")

    if spec.normalize == "strip":
        value = value.strip()
    elif spec.normalize == "rstrip-slash":
        value = value.rstrip("/")
    elif spec.normalize == "lower":
        value = value.lower()
    if spec.optional and value == "":
        return None
    return value


def _label(field_name: str, spec: FieldSpec) -> str:
    return spec.env_names[0] if spec.env_names else field_name


def load_env_values(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Resolve every field from an explicitly-set env var or its default."""
    environ = os.environ if env is None else env
    values: dict[str, Any] = {}
    # Resolve dependencies (data_dir -> db_path) independent of dataclass order.
    for field_name, spec in FIELD_SPECS.items():
        if spec.derived_from:
            continue
        source = setting_env_source(field_name, environ)
        if source is None:
            values[field_name] = _default(spec)
        else:
            values[field_name] = _parse(
                field_name, _read_env(spec, source, environ), spec, source="env"
            )
    for field_name, spec in FIELD_SPECS.items():
        if spec.derived_from:
            values[field_name] = Path(values[spec.derived_from]) / str(_default(spec))
    return values


def merge_kv_values(
    base_values: Mapping[str, Any],
    kv: Mapping[str, str],
    *,
    encryption_key: str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Apply the single precedence rule: explicit env, then nonblank kv, then default.

    ``base_values`` supplies env/default values and preserves constructed Settings
    values for non-kv fields. Invalid legacy kv values fall back to that base value;
    explicit invalid/out-of-range env values retain their fail-fast semantics.
    """
    environ = os.environ if env is None else env
    merged = dict(base_values)
    for field_name, spec in FIELD_SPECS.items():
        if spec.kv_key is None or setting_env_is_set(field_name, environ):
            continue
        raw = kv.get(spec.kv_key, "")
        if not raw:
            continue
        if encryption_key and spec.sensitive:
            from cert_watch.database import fernet_decrypt

            raw = fernet_decrypt(raw, encryption_key) or ""
        try:
            merged[field_name] = _parse(field_name, raw, spec, source="kv")
        except ValueError:
            logger.warning("Invalid saved %s; using the environment/default value", spec.kv_key)
    return merged


def ui_field_map(field_names: tuple[str, ...]) -> dict[str, str]:
    """Return the settings-form kv-key -> primary env-name map from the table."""
    result: dict[str, str] = {}
    for field_name in field_names:
        spec = FIELD_SPECS[field_name]
        if spec.kv_key is None or not spec.env_names:
            raise ValueError(f"{field_name} is not a GUI-configurable env setting")
        result[spec.kv_key] = spec.env_names[0]
    return result
