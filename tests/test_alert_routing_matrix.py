"""Plan 050 routing evidence through SQLite and local delivery endpoints.

These hermetic tests run in the explicit receipt integration CI job. SMTP
receipt means the local receiver accepted DATA; HTTP receipt means that
endpoint received the request. Neither is a claim about a production mailbox
or third-party provider.

Current dispatch is SMTP first, with one configured global webhook as fallback.
Group matching controls SMTP recipients, not independent webhook fan-out.
"""

from __future__ import annotations

import json
from collections import Counter
from contextlib import ExitStack
from email.utils import getaddresses
from pathlib import Path

import pytest

from cert_watch.alerts import (
    ALERT_MAX_RETRIES,
    AlertConfig,
    WebhookConfig,
    evaluate_all_certs,
    find_orphan_certs,
    process_pending,
)
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.database import (
    Role,
    SqliteAlertGroupRepository,
    SqliteAlertRepository,
    SqliteCertificateRepository,
    SqliteHostRepository,
    SqliteRoleRepository,
)
from cert_watch.database.users_roles import SqliteUserRepository, User
from tests._integration_servers import allow_loopback_transport
from tests._mock_targets import capturing_http_target, smtp_target
from tests.conftest import _make_cert

pytestmark = pytest.mark.integration

GLOBAL_RECIPIENT = "global@example.test"
FROM_ADDRESS = "cert-watch@example.test"


def _add_leaf(
    db: Path,
    hostname: str,
    *,
    host_tags: str = "",
    cert_tags: str = "",
    owner_email: str = "",
    renewal_status: str = "pending",
    days_valid: int = 5,
) -> str:
    """Parse real DER, then persist via the same repositories routing reads."""
    generated = _make_cert(
        hostname,
        days_valid=days_valid,
        not_before_days_ago=360,
        san_dns=[hostname],
    )
    cert = parse_certificate(generated.der)
    assert isinstance(cert, Certificate)
    if days_valid == 5:
        assert 3 < cert.days_until_expiry() <= 5
    SqliteHostRepository(db).add(
        hostname,
        tags=host_tags,
        owner_email=owner_email,
        renewal_status=renewal_status,
    )
    repo = SqliteCertificateRepository(db, hostname=hostname, port=443)
    cert_id = repo.add(cert)
    repo.set_tags(cert_id, cert_tags)
    return cert_id


def _add_role_members(db: Path, team_email: str, members: list[str]) -> None:
    role_id = SqliteRoleRepository(db).add(
        Role(name=f"team-{team_email}", email=team_email)
    )
    for index, email in enumerate(members):
        SqliteUserRepository(db).add(User(
            username=f"{team_email}-{index}",
            email=email,
            password_hash="test-only-no-login",
            role_id=role_id,
        ))


def _smtp_config(sink, *, recipients: list[str] | None = None) -> AlertConfig:
    return AlertConfig(
        smtp_host=sink.host,
        smtp_port=sink.port,
        smtp_user=sink.username,
        smtp_password=sink.password,
        from_addr=FROM_ADDRESS,
        recipients=[GLOBAL_RECIPIENT] if recipients is None else recipients,
        allow_private=True,
    )


def _assert_receipts(sink, expected: dict[str, list[str]]) -> None:
    """Assert the entire receiver ledger, including unexpected destinations."""
    assert len(sink.messages) == len(expected)
    observed: set[str] = set()
    for receipt in sink.messages:
        message = receipt.message
        body = message.get_content()
        matching_hosts = [
            host for host in expected if body.startswith(f"Certificate '{host}' ")
        ]
        assert len(matching_hosts) == 1, body
        hostname = matching_hosts[0]
        assert hostname not in observed, f"duplicate DATA for {hostname}"
        observed.add(hostname)
        assert Counter(receipt.recipients) == Counter(expected[hostname])
        assert Counter(address for _, address in getaddresses(message.get_all("To", []))) == (
            Counter(expected[hostname])
        )
        assert receipt.mail_from == FROM_ADDRESS
        assert receipt.tls and receipt.authenticated
        assert str(message["Subject"]).startswith("[cert-watch] expiry_warning:")
        assert "Recommended action:" in body
    assert observed == set(expected)


def test_routing_matrix_delivers_exact_recipient_unions(db, tmp_path, monkeypatch):
    groups = SqliteAlertGroupRepository(db)
    groups.create("alpha", [" alpha@example.test ", "shared@example.test"], ["alpha"])
    groups.create("beta", ["SHARED@example.test", "beta@example.test"], ["beta"])
    groups.create("unicode", ["unicode@example.test"], [" Straße "])
    linked_group = groups.create("role-linked", ["linked@example.test"], ["unmatched"])
    manual_group = groups.create("manual", ["manual@example.test"], [])
    groups.create("negative", ["never@example.test"], ["never-matched"])
    SqliteRoleRepository(db).add(Role(
        name="linked-role", scope_tag="scope-only", alert_group_id=linked_group,
    ))
    _add_role_members(db, "team@example.test", ["member@example.test", GLOBAL_RECIPIENT])

    cases = {
        "host-only.routing.test": ({"host_tags": " ALPHA "}, [
            GLOBAL_RECIPIENT, "alpha@example.test", "shared@example.test",
        ]),
        "cert-only.routing.test": ({"cert_tags": " beta "}, [
            GLOBAL_RECIPIENT, "SHARED@example.test", "beta@example.test",
        ]),
        "merged.routing.test": ({
            "host_tags": " alpha, ALPHA ",
            "cert_tags": " BeTa,alpha ",
            "owner_email": "shared@example.test",
        }, [GLOBAL_RECIPIENT, "alpha@example.test", "shared@example.test", "beta@example.test"]),
        "unicode.routing.test": ({"host_tags": " STRASSE "}, [
            GLOBAL_RECIPIENT, "unicode@example.test",
        ]),
        "linked.routing.test": ({"cert_tags": "SCOPE-ONLY"}, [
            GLOBAL_RECIPIENT, "linked@example.test",
        ]),
        "manual.routing.test": ({}, [GLOBAL_RECIPIENT, "manual@example.test"]),
        "owned.routing.test": ({"owner_email": "TEAM@example.test"}, [
            GLOBAL_RECIPIENT, "TEAM@example.test", "member@example.test",
        ]),
        "orphan.routing.test": ({}, [GLOBAL_RECIPIENT]),
    }
    cert_ids = {host: _add_leaf(db, host, **options) for host, (options, _) in cases.items()}
    groups.assign_cert(manual_group, cert_ids["manual.routing.test"])
    healthy_id = _add_leaf(db, "healthy.routing.test", host_tags="alpha", days_valid=365)
    renewed_id = _add_leaf(
        db, "renewed.routing.test", host_tags="alpha", renewal_status="renewed",
    )
    assert [item["cert_id"] for item in find_orphan_certs(db)] == [
        cert_ids["orphan.routing.test"],
    ]

    repo = SqliteAlertRepository(db)
    created = evaluate_all_certs(db, repo)
    assert Counter(alert.cert_id for alert in created) == Counter(cert_ids.values())
    assert all(alert.threshold_days == 7 for alert in created)
    # Re-evaluation while delivery is pending must not multiply a multi-match alert.
    assert evaluate_all_certs(db, repo) == []

    with (
        allow_loopback_transport(monkeypatch),
        smtp_target(tmp_path, monkeypatch) as smtp,
        capturing_http_target("/global", "/negative") as http,
    ):
        fallback = WebhookConfig(url=http.url("/global"), allow_private=True)
        assert process_pending(repo, _smtp_config(smtp), fallback) == {
            "sent": len(cases), "failed": 0,
        }
        _assert_receipts(smtp, {host: recipients for host, (_, recipients) in cases.items()})
        assert http.requests == []  # SMTP success does not also fan out to a webhook.
        assert process_pending(repo, _smtp_config(smtp), fallback) == {"sent": 0, "failed": 0}
        assert evaluate_all_certs(db, repo) == []
        assert len(smtp.messages) == len(cases)
        assert http.requests == []

    assert len(repo.list_all()) == len(cases)
    assert all(alert.status == "sent" and alert.sent_at is not None for alert in repo.list_all())
    assert repo.list_for_cert(healthy_id) == []
    assert repo.list_for_cert(renewed_id) == []


def test_zero_group_estate_still_delivers_global_owner_and_role_routes(db, tmp_path, monkeypatch):
    _add_role_members(db, "team@example.test", ["member@example.test", GLOBAL_RECIPIENT])
    orphan_id = _add_leaf(db, "orphan.routing.test")
    _add_leaf(db, "owned.routing.test", owner_email="team@example.test")
    assert [item["cert_id"] for item in find_orphan_certs(db)] == [orphan_id]
    repo = SqliteAlertRepository(db)
    assert len(evaluate_all_certs(db, repo)) == 2

    with allow_loopback_transport(monkeypatch), smtp_target(tmp_path, monkeypatch) as smtp:
        assert process_pending(repo, _smtp_config(smtp)) == {"sent": 2, "failed": 0}
        _assert_receipts(smtp, {
            "orphan.routing.test": [GLOBAL_RECIPIENT],
            "owned.routing.test": [GLOBAL_RECIPIENT, "team@example.test", "member@example.test"],
        })


@pytest.mark.parametrize("smtp_available", [False, True], ids=["no-smtp", "smtp-auth-rejected"])
def test_global_webhook_receives_alert_when_smtp_unavailable(
    db, tmp_path, monkeypatch, smtp_available,
):
    cert_id = _add_leaf(db, "fallback.routing.test", host_tags="alpha")
    SqliteAlertGroupRepository(db).create("alpha", ["alpha@example.test"], ["alpha"])
    repo = SqliteAlertRepository(db)
    assert len(evaluate_all_certs(db, repo)) == 1

    with ExitStack() as stack:
        stack.enter_context(allow_loopback_transport(monkeypatch))
        http = stack.enter_context(capturing_http_target("/global", "/negative"))
        smtp = None
        config = None
        if smtp_available:
            smtp = stack.enter_context(smtp_target(tmp_path, monkeypatch))
            config = _smtp_config(smtp)
            config.smtp_password = "deliberately-wrong-test-password"
        webhook = WebhookConfig(
            url=http.url("/global"), allow_private=True,
            headers={"X-Routing-Probe": "global-fallback"},
        )
        assert process_pending(repo, config, webhook) == {"sent": 1, "failed": 0}
        assert len(http.requests) == 1
        receipt = http.requests[0]
        assert receipt.path == "/global" and receipt.method == "POST"
        assert receipt.headers["X-Routing-Probe"] == "global-fallback"
        payload = json.loads(receipt.body)
        assert payload["cert_id"] == cert_id
        assert payload["alert_type"] == "expiry_warning"
        assert payload["threshold_days"] == 7
        assert http.received("/negative") == []
        if smtp is not None:
            assert smtp.auth_attempts
            assert smtp.messages == []
        assert process_pending(repo, config, webhook) == {"sent": 0, "failed": 0}
        assert len(http.requests) == 1

    row = repo.list_for_cert(cert_id)[0]
    assert row.status == "sent" and row.sent_at is not None


def test_http_failure_and_later_success_reuse_the_persisted_alert(db, monkeypatch):
    cert_id = _add_leaf(db, "retry.routing.test")
    repo = SqliteAlertRepository(db)
    alert_id = evaluate_all_certs(db, repo)[0].id
    with (
        allow_loopback_transport(monkeypatch),
        capturing_http_target("/unavailable", "/negative", statuses={"/unavailable": 503}) as http,
    ):
        webhook = WebhookConfig(url=http.url("/unavailable"), allow_private=True)
        assert process_pending(repo, None, webhook) == {"sent": 0, "failed": 1}
        assert len(http.requests) == ALERT_MAX_RETRIES
        assert all(request.path == "/unavailable" for request in http.requests)
        assert all(json.loads(request.body)["cert_id"] == cert_id for request in http.requests)
        assert http.received("/negative") == []
    rows = repo.list_for_cert(cert_id)
    assert len(rows) == 1 and rows[0].id == alert_id and rows[0].status == "failed"
    assert "503" in rows[0].error_message
    assert rows[0].sent_at is None
    assert [alert.id for alert in evaluate_all_certs(db, repo)] == [alert_id]
    assert len(repo.list_all()) == 1

    with (
        allow_loopback_transport(monkeypatch),
        capturing_http_target("/recovered", "/negative") as http,
    ):
        webhook = WebhookConfig(url=http.url("/recovered"), allow_private=True)
        assert process_pending(repo, None, webhook) == {"sent": 1, "failed": 0}
        assert len(http.requests) == 1
        assert json.loads(http.requests[0].body)["cert_id"] == cert_id
        assert http.received("/negative") == []
        assert process_pending(repo, None, webhook) == {"sent": 0, "failed": 0}
        assert len(http.requests) == 1
    final = repo.list_for_cert(cert_id)
    assert len(final) == 1 and final[0].id == alert_id and final[0].status == "sent"
    assert final[0].error_message is None
    assert final[0].sent_at is not None


def test_orphan_without_global_recipients_is_failed_without_smtp_data(db, tmp_path, monkeypatch):
    cert_id = _add_leaf(db, "unroutable.routing.test")
    repo = SqliteAlertRepository(db)
    evaluate_all_certs(db, repo)
    with allow_loopback_transport(monkeypatch), smtp_target(tmp_path, monkeypatch) as smtp:
        assert process_pending(repo, _smtp_config(smtp, recipients=[])) == {"sent": 0, "failed": 1}
        assert smtp.messages == []
        assert smtp.auth_attempts == []
    row = repo.list_for_cert(cert_id)[0]
    assert row.status == "failed" and row.sent_at is None
