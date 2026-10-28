"""Credential reminders retain their severity across delivery adapters."""

import pytest

from cert_watch.alerting.transports.adapters import (
    _alertname,
    _pd_severity,
    _slack_color,
    _status_color,
    _status_urgency,
)


@pytest.mark.parametrize("kind,expected", [
    ("application_secret_expired", (0xCC0000, "attention", "critical", "danger")),
    ("application_secret_expiry", (0xE0A800, "warning", "warning", "warning")),
])
def test_credential_severity(kind, expected):
    assert (_status_color(kind), _status_urgency(kind), _pd_severity(kind, 14),
            _slack_color(kind)) == expected
    assert _alertname(kind) in {"ApplicationSecretExpired", "ApplicationSecretExpiry"}


def test_urgent_credential_reminder_pages_as_error():
    assert _pd_severity("application_secret_expiry", 1) == "error"
