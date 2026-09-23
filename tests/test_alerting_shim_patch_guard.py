"""Plan 058 removed the four deprecated alerting module paths."""

from __future__ import annotations

import importlib.util

import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "cert_watch.alerts",
        "cert_watch.alert_delivery",
        "cert_watch.alert_adapters",
        "cert_watch.digest",
    ],
)
def test_deprecated_alerting_shim_is_gone(module_name: str) -> None:
    assert importlib.util.find_spec(module_name) is None
