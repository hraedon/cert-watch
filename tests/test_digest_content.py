"""Golden tests for the user-visible digest bodies."""

from __future__ import annotations

from cert_watch.alerting.digest.expiry import _build_digest_message as build_expiry_message
from cert_watch.alerting.digest.renewal import (
    RenewalDigest,
)
from cert_watch.alerting.digest.renewal import (
    _build_digest_message as build_renewal_message,
)


def test_expiry_digest_body_golden() -> None:
    body, subject = build_expiry_message(
        [
            {
                "subject": "CN=expired.example.test",
                "hostname": "expired.example.test",
                "port": 8443,
                "not_after": "2026-09-20T12:00:00+00:00",
                "days_remaining": -3,
            },
            {
                "subject": "CN=uploaded.example.test",
                "hostname": "",
                "port": 443,
                "not_after": "2026-10-04T12:00:00+00:00",
                "days_remaining": 11,
            },
        ],
        owner_name="Ada Lovelace",
        cadence_days=14,
    )

    assert subject == "[cert-watch] Expiry Digest: 2 cert(s) expiring soon"
    assert body == (
        "[cert-watch] Expiry Digest — 2 certificate(s) expiring within 14 days\n"
        "You are receiving this digest as the owner of the following certificates.\n"
        "\n"
        "\n"
        "  - CN=expired.example.test (expired.example.test:8443) — EXPIRED — "
        "expires 2026-09-20T12:00:00+00:00\n"
        "  - CN=uploaded.example.test ((uploaded)) — 11d remaining — "
        "expires 2026-10-04T12:00:00+00:00"
    )


def test_renewal_digest_body_golden() -> None:
    body = build_renewal_message(
        RenewalDigest(
            days=14,
            renewed_count=2,
            renewed_hosts=["api.example.test", "mail.example.test:8443"],
            overdue_count=1,
            overdue_hosts=["legacy.example.test (port unknown)"],
            shortened_count=1,
            shortened_hosts=["api.example.test"],
            host_expiry={
                "api.example.test": "2026-11-30T12:00:00+00:00",
                "mail.example.test:8443": "2026-12-15T12:00:00+00:00",
                "legacy.example.test (port unknown)": None,
            },
        )
    )

    assert body == (
        "[cert-watch] Renewal Digest — last 14 days\n"
        "\n"
        "Renewed on schedule: 2\n"
        "  - api.example.test (expires 2026-11-30)\n"
        "  - mail.example.test:8443 (expires 2026-12-15)\n"
        "\n"
        "Overdue: 1\n"
        "  - legacy.example.test (port unknown)\n"
        "\n"
        "Lifetimes shortened: 1\n"
        "  - api.example.test (expires 2026-11-30)"
    )
