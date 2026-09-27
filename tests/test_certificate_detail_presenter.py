from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cert_watch.certificate_model import Certificate
from cert_watch.chain_guidance import ChainGuidance
from cert_watch.database import Alert, HostEntry, LatestScanRecord
from cert_watch.presenters.browse import PivotGroupView, _present_entry
from cert_watch.presenters.certificate_detail import (
    _chain_guidance_for_role,
    _delivery_routes,
    _detail_actions,
    _detail_axes,
    present_certificate_detail,
    present_certificate_technical_details,
)
from cert_watch.scan_freshness import ScanEvidence
from cert_watch.services.certificate_detail import (
    PendingHostDetailData,
    StoredCertificateDetailData,
)
from cert_watch.upload import UploadedEntry, upload_certificate


def test_presenter_builds_template_values_without_http(leaf_pem_file) -> None:
    uploaded = upload_certificate(leaf_pem_file)
    assert isinstance(uploaded, UploadedEntry)

    view = present_certificate_technical_details(uploaded.leaf, [], "public")
    context = view.template_context()

    assert view.key_type.startswith("RSA ")
    assert view.sig_alg != "unknown"
    assert view.serial != "unknown"
    assert context["chain"] == []
    assert context["days_remaining"] == uploaded.leaf.days_until_expiry()
    assert context["chain_issue"] is None


def test_presenter_degrades_unparseable_crypto_and_surfaces_chain_issue() -> None:
    now = datetime.now(UTC)
    cert = Certificate(
        subject="CN=leaf.example.test",
        issuer="CN=Test CA",
        not_before=now - timedelta(days=1),
        not_after=now + timedelta(days=90),
        fingerprint_sha256="ab" * 32,
        raw_der=b"not a certificate",
    )

    view = present_certificate_technical_details(cert, [], "incomplete")

    assert view.key_type == view.sig_alg == view.serial == "unknown"
    assert view.fingerprint == ":".join(["AB"] * 32)
    assert view.chain_issue == "incomplete"
    assert view.urgency == "warning"


def test_presenter_labels_and_grades_a_real_certificate_chain(
    chain_pem_file,
    chain_triplet,
) -> None:
    uploaded = upload_certificate(chain_pem_file)
    assert isinstance(uploaded, UploadedEntry)
    assert len(uploaded.chain) == 2
    now = uploaded.chain[0].not_after - timedelta(days=3)

    view = present_certificate_technical_details(
        uploaded.leaf,
        [("intermediate-id", uploaded.chain[0]), ("root-id", uploaded.chain[1])],
        "private",
        now=now,
    )

    assert [item.role_label for item in view.chain] == [
        "Intermediate CA",
        "Root CA (self-issued)",
    ]
    assert [item.urgency for item in view.chain] == ["critical", "healthy"]
    assert view.chain[0].subject_cn == chain_triplet["intermediate"].subject_cn
    assert view.chain[1].self_issued is True


def _host() -> HostEntry:
    return HostEntry(
        id="host-1",
        hostname="vpn.example.test",
        port=443,
        tags="production, network",
        owner_name="Network team",
        renewal_method="manual",
        renewal_status="in_progress",
        runbook_url="https://runbooks.example.test/vpn",
        threshold_days=14,
        scan_interval_hours=12,
    )


@pytest.mark.parametrize(
    ("condition", "days", "current_label", "current_tone"),
    [
        ("expired", -3, "Expired 3 days ago", "t-expired"),
        ("le7", 5, "5 days left", "t-crit"),
        ("8to30", 20, "20 days left", "t-warn"),
        ("ok", 60, "60 days left", "t-ok"),
    ],
)
@pytest.mark.parametrize(
    ("state_name", "monitoring"),
    [
        ("current", "current"),
        ("failing", "failing"),
        ("overdue", "failing"),
        ("never scanned", "never_scanned"),
        ("uploaded", "not_monitored"),
    ],
)
def test_condition_header_agrees_across_detail_browse_and_pivot(
    condition: str,
    days: int,
    current_label: str,
    current_tone: str,
    state_name: str,
    monitoring: str,
) -> None:
    """One display contract covers every monitoring and expiry state."""
    stale = monitoring not in {"current", "not_monitored"}
    if stale and condition == "ok":
        expected_label = f"Last seen OK · expires in {days} days"
    elif stale:
        expected_label = f"Last seen · {current_label.lower()}"
    else:
        expected_label = current_label
    expected_tone = "t-muted" if stale and condition == "ok" else current_tone
    status = {
        "condition": {"state": condition, "effective_days": days},
        "monitoring": {"state": monitoring},
        "renewal": {"state": "manual"},
        "delivery": {"state": "ok", "channels": []},
    }
    now = datetime(2026, 9, 22, 12, tzinfo=UTC)
    cert = Certificate(
        subject="CN=agreement.example.test",
        issuer="CN=Example CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=days),
        fingerprint_sha256=f"agreement-{condition}-{state_name}",
        source="uploaded" if monitoring == "not_monitored" else "scanned",
    )
    detail = _detail_axes(
        model=status,
        cert=cert,
        host=None if monitoring == "not_monitored" else _host(),
        evidence=None,
        days=days,
        now=now,
    )[0]
    browse = _present_entry(
        {
            "id": cert.fingerprint_sha256,
            "host_id": None if monitoring == "not_monitored" else "host-1",
            "kind": "uploaded" if monitoring == "not_monitored" else "scanned",
            "source": cert.source,
            "name": "agreement.example.test",
            "condition": condition,
            "effective_days": days,
            "days_remaining": days,
            "monitoring": monitoring,
            "renewal": "manual",
            "delivery": "ok",
            "status": status,
        },
        {},
        {},
    )
    pivot = PivotGroupView(
        key="Agreement",
        count=1,
        worst_urgency="healthy",
        earliest_expiry=days,
        condition=condition,
        monitoring=monitoring,
        renewal="manual",
        delivery="ok",
        chain_trust_problem=False,
        monitoring_failing_count=int(monitoring == "failing"),
        monitoring_overdue_count=int(state_name == "overdue"),
        monitoring_since=None,
    )

    assert {
        (detail.value, detail.tone),
        (browse.condition_label, browse.condition_tone),
        (pivot.condition_label, pivot.condition_tone),
    } == {(expected_label, expected_tone)}


def test_full_detail_presenter_builds_stored_certificate_view() -> None:
    now = datetime(2026, 9, 22, 12, tzinfo=UTC)
    cert = Certificate(
        subject="CN=vpn.example.test",
        issuer="CN=Example CA",
        not_before=now - timedelta(days=30),
        not_after=now + timedelta(days=60),
        san_dns_names=["vpn.example.test", "alt.example.test"],
        fingerprint_sha256="ab" * 32,
        raw_der=b"not a certificate",
        source="scanned",
    )
    data = StoredCertificateDetailData(
        cert_id="cert-1",
        cert=cert,
        chain=(),
        chain_status="public",
        hostname="vpn.example.test",
        port=443,
        host=_host(),
        scan_evidence=None,
        posture={
            "grade": "B",
            "findings": [
                {
                    "check": "chain_completeness",
                    "status": "pass",
                    "message": "Certificate chain is complete",
                }
            ],
            "protocol_version": "TLSv1.3",
            "scanned_at": "2026-09-22T08:00:00+00:00",
            "chain_incomplete": False,
            "chain_status": "public",
        },
        posture_is_stored=True,
        renewal_history=[
            {
                "id": "cert-1",
                "fingerprint_sha256": "abcdef123456",
                "not_before": "2026-08-23T12:00:00+00:00",
                "is_current": True,
            }
        ],
        history_entries=[
            {
                "issuer": "CN=New CA",
                "key_algo": "RSA 2048",
                "sig_algo": "sha256",
                "posture_grade": "B",
                "scanned_at": "2026-09-22T08:00:00+00:00",
            },
            {
                "issuer": "CN=Old CA",
                "key_algo": "RSA 2048",
                "sig_algo": "sha256",
                "posture_grade": "A",
                "scanned_at": "2026-08-22T08:00:00+00:00",
            },
        ],
        cert_tags=["production"],
        effective_tags=["production", "network"],
        all_tags=["network", "production"],
        alerts=(
            Alert(
                cert_id="cert-1",
                alert_type="expiry_warning",
                status="sending",
                message="Certificate expires soon",
            ),
            Alert(
                cert_id="cert-1",
                alert_type="expiry_warning",
                status="failed",
                message="Delivery attempts exhausted",
            ),
        ),
    )

    view = present_certificate_detail(
        data,
        settings_writable=True,
        is_admin=True,
        slack_configured=False,
        now=now,
    )

    assert view.source_label == "Scanned"
    assert view.source_meta == "scanned from vpn.example.test:443"
    assert view.renewal_method_label == "Manual"
    assert view.renewal_method_indicator == "requires manual action"
    assert view.host_info is not None
    assert view.host_info.scan_cadence_label == "Every 12 hours"
    assert view.host_info.renewal_status_label == "In progress — operator reported"
    assert view.validity_percent == 33
    assert view.shown_tags[1].inherited is True
    assert view.renewal_history[0].fingerprint_short == "abcdef12"
    assert {event.field for event in view.drift_events} == {
        "Issuer changed",
        "Posture grade dropped",
    }
    assert [alert.status_label for alert in view.certificate_alerts] == [
        "Sending",
        "Failed",
    ]
    assert [alert.status_tone for alert in view.certificate_alerts] == [
        "t-muted",
        "t-crit",
    ]


def test_full_detail_presenter_builds_pending_host_view() -> None:
    data = PendingHostDetailData(
        cert_id="host-1",
        host=_host(),
        latest_scan=LatestScanRecord(
            status="failure",
            scanned_at="2026-09-22T08:00:00+00:00",
            error_message="connection refused",
        ),
        scan_evidence=None,
        all_tags=["network", "production"],
    )

    view = present_certificate_detail(
        data,
        settings_writable=False,
        is_admin=False,
        slack_configured=True,
    )

    assert view.cert is None
    assert view.subject_cn == "vpn.example.test:443"
    assert view.scan_status == "failure"
    assert view.scan_error == "connection refused"
    assert view.source_label == "Monitored"
    assert view.source_meta == "last scan failed"
    assert [tag.label for tag in view.shown_tags] == ["production", "network"]
    assert view.host_info is not None
    assert view.host_info.settings_writable is False


def test_detail_delivery_failure_shows_time_but_hides_identity_for_readers() -> None:
    data = PendingHostDetailData(
        cert_id="host-1",
        host=_host(),
        latest_scan=None,
        scan_evidence=None,
        all_tags=["network", "production"],
        status={
            "condition": {"state": None},
            "monitoring": {"state": "never_scanned"},
            "renewal": {"state": "manual"},
            "delivery": {
                "state": "failing",
                "recipients": [],
                "matching_groups": ["Network on-call"],
                "channels": [
                    {
                        "channel": "webhook:generic",
                        "recipients": ["Network on-call"],
                        "configured": True,
                        "can_deliver": False,
                        "last_outcome": "failed",
                        "last_attempt_at": "2026-09-22T08:30:00+00:00",
                    }
                ],
            },
        },
    )

    reader = present_certificate_detail(
        data,
        settings_writable=False,
        is_admin=False,
        slack_configured=False,
        reveal_delivery_identities=False,
    )
    writer = present_certificate_detail(
        data,
        settings_writable=True,
        is_admin=True,
        slack_configured=False,
        reveal_delivery_identities=True,
    )

    assert reader.delivery_routes[0].recipient == "1 matched alert group"
    assert "Network on-call" not in {route.recipient for route in reader.delivery_routes}
    assert writer.delivery_routes[0].recipient == "1 matched alert group"
    assert [r.recipient for r in writer.delivery_routes].count("Network on-call") == 1
    assert writer.delivery_routes[0].status == "Failed"
    assert writer.delivery_routes[0].detail == ("Latest delivery failed at 2026-09-22 08:30 UTC.")
    assert any(
        action.title == "Check Webhook delivery." and "2026-09-22 08:30 UTC" in action.detail
        for action in writer.actions
    )


def test_detail_actions_separate_host_steps_from_admin_only_settings_steps() -> None:
    status = {
        "monitoring": {
            "state": "failing",
            "cause": "The endpoint refused the connection.",
            "raw_error": "[Errno 111] Connection refused",
        },
        "condition": {"state": "le7"},
        "chain_trust_problem": True,
        "delivery": {
            "state": "failing",
            "channels": [
                {
                    "channel": "smtp",
                    "recipients": ["owner@example.test"],
                    "configured": False,
                    "last_outcome": "partial",
                    "last_attempt_at": "2026-09-22T08:30:00+00:00",
                }
            ],
        },
    }

    guidance = ChainGuidance(
        "missing_issuer",
        "Unable to reach a trusted root",
        "The issuer is unavailable.",
        "Configure the TLS endpoint with its intermediate, then scan again. If the "
        "issuer is a private root, verify it and add it in Settings → Trust anchors "
        "instead.",
    )
    admin = _detail_actions(
        view_status=status,
        hostname="vpn.example.test",
        port=443,
        days=5,
        runbook_url="",
        chain_guidance=guidance,
        may_write=True,
        is_admin=True,
        has_host=True,
        uploaded=False,
    )
    operator = _detail_actions(
        view_status=status,
        hostname="vpn.example.test",
        port=443,
        days=5,
        runbook_url="",
        chain_guidance=_chain_guidance_for_role(guidance, False),
        may_write=True,
        is_admin=False,
        has_host=True,
        uploaded=False,
    )
    reader = _detail_actions(
        view_status=status,
        hostname="vpn.example.test",
        port=443,
        days=5,
        runbook_url="",
        chain_guidance=_chain_guidance_for_role(guidance, False),
        may_write=False,
        is_admin=False,
        has_host=True,
        uploaded=False,
    )

    assert admin[0].raw_error == "[Errno 111] Connection refused"
    assert admin[0].command.startswith("openssl s_client")
    assert any(action.title == "Press Scan now once it is fixed." for action in admin)
    assert any(action.title == "Configure email delivery." for action in admin)
    assert any(action.title == "Check Email delivery." for action in admin)
    assert any(
        "verify it and add it in Settings → Trust anchors" in action.detail
        and "ask an administrator" not in action.detail
        for action in admin
    )

    assert operator[0].command.startswith("openssl s_client")
    assert any(action.title == "Press Scan now once it is fixed." for action in operator)
    assert any(
        action.title == "Ask an administrator to configure email delivery."
        for action in operator
    )
    assert any(
        action.title == "Ask an administrator to check Email delivery."
        for action in operator
    )
    assert any(
        "ask an administrator to verify it and add it in Settings → Trust anchors"
        in action.detail
        for action in operator
    )
    # The role rewrite is applied once; it doubled the phrase when the steps
    # builder rewrote guidance that was already adjusted for the role.
    assert all(
        action.detail.count("ask an administrator") <= 1 for action in operator + reader
    )
    once = _chain_guidance_for_role(guidance, False)
    assert _chain_guidance_for_role(once, False) == once
    assert all(not action.command for action in reader)
    assert all(
        action.title.startswith(("Ask an administrator", "Ask the certificate's owner"))
        for action in reader
    )
    assert any("partially delivered" in action.detail for action in admin)
    assert all("latest attempt failed" not in action.detail.lower() for action in admin)


def test_overdue_scan_is_not_described_as_a_connection_failure() -> None:
    now = datetime(2026, 9, 22, 12, tzinfo=UTC)
    evidence = ScanEvidence(
        host_id="host-1",
        last_success=now - timedelta(days=2),
        last_attempt=now - timedelta(days=2),
        attempt_status="success",
        due_at=now - timedelta(days=1),
        next_attempt_at=now - timedelta(hours=1),
        state="overdue",
    )
    status = {
        "monitoring": {
            "state": "failing",
            "cause": "The scheduled scan is overdue.",
        },
        "condition": {"state": "ok"},
        "renewal": {"state": "manual"},
        "delivery": {"state": "ok", "channels": []},
    }

    axes = _detail_axes(
        model=status,
        cert=None,
        host=_host(),
        evidence=evidence,
        days=0,
        now=now,
    )
    actions = _detail_actions(
        view_status=status,
        hostname="vpn.example.test",
        port=443,
        days=0,
        runbook_url="",
        chain_guidance=None,
        may_write=True,
        is_admin=True,
        has_host=True,
        uploaded=False,
    )

    assert axes[1].value.startswith("Scan overdue since")
    assert "Automatic retry is due now" in axes[1].detail
    assert actions[0].title == "Run the overdue scan and check the scheduler."
    assert all(not action.command for action in actions)


def test_uploaded_certificate_routing_action_never_suggests_an_owner() -> None:
    admin = _detail_actions(
        view_status={"delivery": {"state": "unrouted"}},
        hostname="",
        port=0,
        days=60,
        runbook_url="",
        chain_guidance=None,
        may_write=True,
        is_admin=True,
        has_host=False,
        uploaded=True,
    )
    operator = _detail_actions(
        view_status={"delivery": {"state": "unrouted"}},
        hostname="",
        port=0,
        days=60,
        runbook_url="",
        chain_guidance=None,
        may_write=True,
        is_admin=False,
        has_host=False,
        uploaded=True,
    )
    viewer = _detail_actions(
        view_status={"delivery": {"state": "unrouted"}},
        hostname="",
        port=0,
        days=60,
        runbook_url="",
        chain_guidance=None,
        may_write=False,
        is_admin=False,
        has_host=False,
        uploaded=True,
    )

    assert admin[0].title == "Add an alert group for this uploaded certificate."
    assert operator[0].title == (
        "Ask an administrator to add an alert group for this uploaded certificate."
    )
    assert viewer[0].title == (
        "Ask an administrator to add an alert group for this uploaded certificate."
    )
    assert all(
        "owner" not in action.title.lower()
        for action in (*admin, *operator, *viewer)
    )


def test_unconfigured_delivery_is_warning_and_nonfinal_outcomes_are_honest() -> None:
    model = {
        "condition": {"state": None},
        "monitoring": {"state": "never_scanned"},
        "renewal": {"state": "unknown"},
        "delivery": {
            "state": "failing",
            "matching_groups": ["Operations"],
            "channels": [
                {
                    "channel": "smtp",
                    "recipients": ["owner@example.test"],
                    "configured": False,
                    "can_deliver": False,
                    "last_outcome": None,
                    "last_attempt_at": None,
                },
                {
                    "channel": "webhook:generic",
                    "recipients": ["Operations"],
                    "configured": True,
                    "can_deliver": False,
                    "last_outcome": "unknown",
                    "last_attempt_at": "2026-09-22T08:30:00+00:00",
                },
            ],
        },
    }

    axes = _detail_axes(
        model=model,
        cert=None,
        host=_host(),
        evidence=None,
        days=0,
        now=datetime(2026, 9, 22, 12, tzinfo=UTC),
    )
    routes = _delivery_routes(model, reveal=True)

    assert axes[-1].tone == "t-warn"
    assert any(route.status == "Outcome unknown" for route in routes)
    assert all("failed" not in route.detail.lower() for route in routes)
    assert [route.recipient for route in routes].count("Operations") == 1
