"""Shared helpers for the settings route package."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse

from cert_watch.auth.guards import MutationGuard, admin_settings_form
from cert_watch.config import Settings, invalidate_settings, resolve_and_publish_settings
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


def settings_tab_form(tab: str) -> MutationGuard:
    """The guard for a POST from the Settings *tab* page (see
    :func:`~cert_watch.auth.guards.admin_settings_form`)."""
    return admin_settings_form(f"/settings?tab={tab}")


def _rebuild_settings(request: Request, db_path: Path) -> None:
    """Rebuild Settings from env + kv_store and update app.state."""
    enc_key = _get_encryption_key(request)
    # Every persisted settings save advances the generation.  A rebuild that
    # started before this save will then be refused when it tries to publish.
    invalidate_settings(db_path)

    def apply(s: Settings) -> None:
        context = getattr(request.app.state, "scheduler_context", None)
        if context is not None:
            context.update_settings(s, publish=False)
        request.app.state.settings = s

    resolve_and_publish_settings(db_path, encryption_key=enc_key, apply=apply)


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

    Performs no authorization: the calling route declares
    ``Depends(settings_tab_form(tab_name))``.
    """
    from cert_watch.database import get_write_lock, kv_set, kv_set_secret

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
