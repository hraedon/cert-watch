"""Shared helpers for the settings route package."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse

from cert_watch.config import Settings
from cert_watch.middleware import require_admin_form
from cert_watch.routes._deps import _db_path
from cert_watch.routes.settings.config import _SENSITIVE_KEYS, _get_encryption_key

logger = logging.getLogger("cert_watch.routes.settings")

# Regex to strip IP addresses and ports from error messages to prevent info leakage.
_IP_ADDR_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b"
    r"|\[?(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}\]?(?::\d+)?"
)


def _sanitize_test_error(msg: str) -> str:
    """Strip IP addresses and internal details from error messages returned to the client."""
    return _IP_ADDR_RE.sub("<redacted>", msg)


def _rebuild_settings(request: Request, db_path: Path) -> None:
    """Rebuild Settings from env + kv_store and update app.state."""
    enc_key = _get_encryption_key(request)
    s = Settings.from_env_with_kv(db_path, encryption_key=enc_key)
    request.app.state.settings = s


async def _save_config_section(
    request: Request,
    keys: dict[str, str],
    tab_name: str,
    *,
    encrypt: bool = False,
    rebuild: bool = True,
) -> RedirectResponse:
    """Shared logic for saving a settings tab to kv_store.

    *encrypt*  – when True, sensitive keys (members of ``_SENSITIVE_KEYS``)
                   that are non-blank are stored encrypted (BC-082).
    *rebuild*  – when True, ``_rebuild_settings`` is called after saving.
    """
    admin_err = require_admin_form(request)
    if admin_err:
        return admin_err

    from cert_watch.database import get_write_lock, kv_set, kv_set_secret
    from cert_watch.middleware import check_csrf

    csrf_err = await check_csrf(request)
    if csrf_err:
        return RedirectResponse(
            url=f"/settings?tab={tab_name}&error={csrf_err}", status_code=303
        )

    db = _db_path(request)
    form = await request.form()
    enc_key = _get_encryption_key(request) if encrypt else None

    with get_write_lock():
        for kv_key in keys:
            raw = form.get(kv_key, "")
            val = raw.strip() if isinstance(raw, str) else ""
            if kv_key in _SENSITIVE_KEYS:
                if not val:
                    continue
                if enc_key:
                    kv_set_secret(db, kv_key, val, enc_key)
                else:
                    kv_set(db, kv_key, val)
            else:
                kv_set(db, kv_key, val)

    if rebuild:
        _rebuild_settings(request, db)

    return RedirectResponse(url=f"/settings?tab={tab_name}&saved=1", status_code=303)
