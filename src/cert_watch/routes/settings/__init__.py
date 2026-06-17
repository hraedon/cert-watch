"""Settings route package — mounts all settings sub-routers."""

from __future__ import annotations

from fastapi import APIRouter

from cert_watch.routes.settings.alert_groups import router as alert_groups_router
from cert_watch.routes.settings.alerts import router as alerts_router
from cert_watch.routes.settings.api_keys import router as api_keys_router
from cert_watch.routes.settings.auth import router as auth_router
from cert_watch.routes.settings.ca_probe import (
    _capture_ldaps_chain,
    _capture_starttls_chain,
    _der_chain_to_ca_dicts,
    _is_cert_verify_error,
    _probe_tls_chain,
)
from cert_watch.routes.settings.config import (
    _SENSITIVE_KEYS,
    _SMTP_KEYS,
    _effective_config,
    _get_encryption_key,
)
from cert_watch.routes.settings.events import router as events_router
from cert_watch.routes.settings.general import router as general_router
from cert_watch.routes.settings.password import router as password_router
from cert_watch.routes.settings.policy import router as policy_router
from cert_watch.routes.settings.roles import router as roles_router
from cert_watch.routes.settings.smtp import router as smtp_router

__all__ = [
    "router",
    "_SENSITIVE_KEYS",
    "_is_cert_verify_error",
    "_capture_ldaps_chain",
    "_capture_starttls_chain",
    "_probe_tls_chain",
    "_der_chain_to_ca_dicts",
    "_SMTP_KEYS",
    "_effective_config",
    "_get_encryption_key",
]

router = APIRouter()

router.include_router(general_router)
router.include_router(auth_router)
router.include_router(api_keys_router)
router.include_router(smtp_router)
router.include_router(alerts_router)
router.include_router(alert_groups_router)
router.include_router(policy_router)
router.include_router(events_router)
router.include_router(password_router)
router.include_router(roles_router)
