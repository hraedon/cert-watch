"""Tests for renewal digest (WI-3.1 / Plan 048)."""
from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.digest import (
    _flush_digest_pool,
    build_renewal_digest,
    send_renewal_digest,
    shutdown_digest_pool,
    start_digest_pool,
)
from cert_watch.events import Event, emit_event


@pytest.fixture(autouse=True)
def _reset_digest_pool():
    start_digest_pool()
    yield
    _flush_digest_pool()


def _add_host(db: Path, hostname: str, owner_email: str = ""):
    repo = SqliteHostRepository(db)
    repo.add(hostname, owner_name="Owner", owner_email=owner_email)


def _emit_renewal(db: Path, hostname: str, cert_id: str = "c1"):
    emit_event(
        Event(
            event_type="cert_renewed",
            timestamp=datetime.now(UTC),
            payload={"hostname": hostname, "cert_id": cert_id},
            source="scan",
        ),
        db,
    )


def _emit_overdue(db: Path, hostname: str, cert_id: str = "c1"):
    emit_event(
        Event(
            event_type="renewal_overdue",
            timestamp=datetime.now(UTC),
            payload={
                "hostname": hostname,
                "cert_fingerprint": "aa" * 32,
                "days_remaining": 3,
                "expected_renewal_at_days": 7,
                "days_overdue": 4,
                "confidence": "medium",
            },
            source="scheduler",
        ),
        db,
    )


@pytest.fixture
def empty_db(tmp_path) -> str:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)
    return str(db)


class TestBuildRenewalDigest:
    def test_zero_activity_returns_empty(self, empty_db):
        result = build_renewal_digest(empty_db, days=7)
        assert result == []

    def test_mixed_week_produces_digest(self, empty_db):
        db = empty_db
        _add_host(db, "host-a.example.com")
        _add_host(db, "host-b.example.com")
        _emit_renewal(db, "host-a.example.com")
        _emit_overdue(db, "host-b.example.com")
        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.renewed_count == 1
        assert "host-a.example.com" in digest.renewed_hosts
        assert digest.overdue_count == 1
        assert "host-b.example.com" in digest.overdue_hosts

    def test_per_owner_routing(self, empty_db):
        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@example.com")
        _add_host(db, "host-b.example.com", owner_email="bob@example.com")
        _emit_renewal(db, "host-a.example.com")
        _emit_overdue(db, "host-b.example.com")
        result = build_renewal_digest(db, days=7)
        by_owner = {d.owner_email: d for d in result}
        assert "alice@example.com" in by_owner
        assert "bob@example.com" in by_owner
        assert by_owner["alice@example.com"].renewed_count == 1
        assert by_owner["bob@example.com"].overdue_count == 1

    def test_events_outside_window_ignored(self, empty_db):
        db = empty_db
        _add_host(db, "host-old.example.com")
        old = datetime.now(UTC) - timedelta(days=10)
        emit_event(
            Event(
                event_type="cert_renewed",
                timestamp=old,
                payload={"hostname": "host-old.example.com", "cert_id": "old"},
                source="scan",
            ),
            db,
        )
        result = build_renewal_digest(db, days=7)
        assert result == []

    def test_multiple_renewals_same_host_aggregated(self, empty_db):
        db = empty_db
        _add_host(db, "host-multi.example.com")
        _emit_renewal(db, "host-multi.example.com", "c1")
        _emit_renewal(db, "host-multi.example.com", "c2")
        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        assert result[0].renewed_count == 2
        assert result[0].renewed_hosts == ["host-multi.example.com"]


class TestDigestExpiry:
    """The digest body shows each host's current cert expiry (not_after)."""

    def test_message_includes_expiry_per_host(self, empty_db):
        from cert_watch.certificate_model import Certificate
        from cert_watch.database import record_cert_history
        from cert_watch.digest import _build_digest_message

        db = empty_db
        _add_host(db, "host-renewed.example.com")
        _add_host(db, "host-overdue.example.com")

        def _seed(hostname: str, not_after: datetime, fp: str) -> None:
            record_cert_history(
                db, hostname, 443,
                Certificate(
                    subject=f"CN={hostname}",
                    issuer="CN=CA",
                    not_before=datetime(2026, 1, 1, tzinfo=UTC),
                    not_after=not_after,
                    san_dns_names=[hostname],
                    fingerprint_sha256=fp,
                    raw_der=b"",
                ),
                scanned_at=datetime.now(UTC).isoformat(),
            )

        _seed("host-renewed.example.com", datetime(2026, 12, 31, tzinfo=UTC), "fp1")
        _seed("host-overdue.example.com", datetime(2026, 8, 20, tzinfo=UTC), "fp2")

        _emit_renewal(db, "host-renewed.example.com")
        _emit_overdue(db, "host-overdue.example.com")

        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.host_expiry.get("host-renewed.example.com") is not None
        assert digest.host_expiry.get("host-overdue.example.com") is not None

        msg = _build_digest_message(digest)
        assert "expires 2026-12-31" in msg  # renewed host
        assert "expires 2026-08-20" in msg  # overdue host

    def test_message_without_history_omits_expiry(self, empty_db):
        from cert_watch.digest import _build_digest_message

        db = empty_db
        _add_host(db, "host-nohistory.example.com")
        _emit_renewal(db, "host-nohistory.example.com")

        result = build_renewal_digest(db, days=7)
        assert len(result) == 1
        digest = result[0]
        assert digest.host_expiry.get("host-nohistory.example.com") is None

        msg = _build_digest_message(digest)
        assert "expires" not in msg


class TestSendRenewalDigest:
    def test_no_configs_returns_false(self, empty_db):
        result = send_renewal_digest(empty_db, None, None, days=7)
        assert result is False

    def test_zero_activity_returns_true(self, empty_db):
        from cert_watch.alerts import AlertConfig

        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["c@d"],
        )
        result = send_renewal_digest(empty_db, config, None, days=7)
        assert result is True

    def test_with_activity_sends_smtp(self, empty_db):
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["c@d"],
        )
        smtp_mock = MagicMock()
        smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
        smtp_mock.__exit__ = MagicMock(return_value=False)
        with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
            result = send_renewal_digest(db, config, None, days=7)
        assert result is True
        smtp_mock.send_message.assert_called()

    def test_webhook_offloaded_to_pool(self, empty_db):
        """WI-134: Webhook delivery is offloaded to a thread pool, not blocking."""
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        with patch("cert_watch.alerts.send_webhook", return_value=True) as mock_send, \
             patch("cert_watch.retry.time.sleep"):
            result = send_renewal_digest(db, None, wh, days=7)
            _flush_digest_pool()
        assert result is True
        assert mock_send.call_count >= 1

    def test_webhook_retries_on_failure(self, empty_db):
        """WI-134: Retries still work when offloaded."""
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        with patch("cert_watch.alerts.send_webhook", side_effect=[False, True]) as mock_send, \
             patch("cert_watch.retry.time.sleep"):
            result = send_renewal_digest(db, None, wh, days=7)
            _flush_digest_pool()
        assert result is True
        assert mock_send.call_count == 2

    def test_webhook_inline_fallback_on_submit_error(self, empty_db):
        """WI-134: Falls back to inline delivery if pool submit fails."""
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        with patch("cert_watch.alerts.send_webhook", return_value=True) as mock_send, \
             patch(
                 "cert_watch.digest._digest_pool.submit",
                 side_effect=RuntimeError("pool closed"),
             ), \
             patch("cert_watch.retry.time.sleep"):
            result = send_renewal_digest(db, None, wh, days=7)
            _flush_digest_pool()
        assert result is True
        assert mock_send.call_count >= 1

    def test_webhook_all_retries_fail_returns_true(self, empty_db):
        """WI-134: All retries failing logs a warning, returns True (async)."""
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        with patch("cert_watch.alerts.send_webhook", return_value=False), \
             patch("cert_watch.retry.time.sleep"):
            result = send_renewal_digest(db, None, wh, days=7)
            _flush_digest_pool()
        assert result is True

    def test_webhook_success_callback_runs_only_after_delivery(self, empty_db):
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        callback = MagicMock()
        with patch("cert_watch.alerts.send_webhook", return_value=True):
            result = send_renewal_digest(
                db,
                None,
                wh,
                days=7,
                delivery_completion_callback=callback,
            )
            assert result is None
            _flush_digest_pool()
        callback.assert_called_once_with(True)

    def test_webhook_failure_reports_completion_failure(self, empty_db):
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        callback = MagicMock()
        with (
            patch("cert_watch.alerts.send_webhook", return_value=False),
            patch("cert_watch.retry.time.sleep"),
        ):
            result = send_renewal_digest(
                db,
                None,
                wh,
                days=7,
                delivery_completion_callback=callback,
            )
            assert result is None
            _flush_digest_pool()
        callback.assert_called_once_with(False)

    def test_shutdown_waits_for_delivery_completion_callback(self, empty_db):
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        wh = WebhookConfig(url="http://localhost:9999/hook")
        entered = threading.Event()
        release = threading.Event()
        callback = MagicMock()

        def blocked_delivery(*args, **kwargs):
            entered.set()
            assert release.wait(timeout=5)
            return True

        with patch("cert_watch.alerts.send_webhook", side_effect=blocked_delivery):
            result = send_renewal_digest(
                db,
                None,
                wh,
                days=7,
                delivery_completion_callback=callback,
            )
            assert result is None
            assert entered.wait(timeout=5)
            shutdown_thread = threading.Thread(target=shutdown_digest_pool)
            shutdown_thread.start()
            assert shutdown_thread.is_alive()
            release.set()
            shutdown_thread.join(timeout=5)

        assert not shutdown_thread.is_alive()
        callback.assert_called_once_with(True)
        start_digest_pool()

    def test_shutdown_rejects_new_webhook_submission(self, empty_db):
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        callback = MagicMock()
        shutdown_digest_pool()
        try:
            with patch("cert_watch.alerts.send_webhook") as send:
                result = send_renewal_digest(
                    db,
                    None,
                    WebhookConfig(url="http://localhost:9999/hook"),
                    delivery_completion_callback=callback,
                )
            assert result is None
            send.assert_not_called()
            callback.assert_called_once_with(False)
        finally:
            start_digest_pool()

    def test_global_digest_sent_in_smtp_fallback(self, empty_db):
        """Global digest must be sent even when the initial SMTP connection fails.

        Regression: when _open_smtp_connection returned None, the fallback path
        only sent owner-specific digests and silently dropped the global digest.
        """
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@test")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["global@recipient.test"],
        )
        smtp = MagicMock()
        smtp.send_message.return_value = {}
        with patch(
            "cert_watch.alerts._open_smtp_connection",
            side_effect=[None, smtp, smtp],
        ), patch("cert_watch.retry.time.sleep"):
            result = send_renewal_digest(db, config, None, days=7)
        assert result is True
        sent_tos = [
            str(call.args[0]["To"]) for call in smtp.send_message.call_args_list
        ]
        assert any("global@recipient.test" in to for to in sent_tos), \
            "global digest must be sent via fallback when initial SMTP connection fails"

    def test_owner_digest_to_header_uses_original_casing(self, empty_db):
        """The To header must use the original email casing, not casefolded."""
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="Alice@Example.COM")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["global@recipient.test"],
        )
        smtp_mock = MagicMock()
        with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock):
            send_renewal_digest(db, config, None, days=7)

        sent_msgs = smtp_mock.send_message.call_args_list
        owner_msgs = [
            call.args[0] for call in sent_msgs
            if "Alice@Example.COM" in str(call.args[0]["To"])
        ]
        assert len(owner_msgs) == 1, "owner digest To header must use original casing"

    def test_owner_digest_merges_case_variant_addresses(self, empty_db):
        """One mailbox receives all of its hosts despite inconsistent casing."""
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="Alice@Example.COM")
        _add_host(db, "host-b.example.com", owner_email="alice@example.com")
        _emit_renewal(db, "host-a.example.com")
        _emit_renewal(db, "host-b.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=[],
        )
        smtp = MagicMock()
        smtp.send_message.return_value = {}

        with patch("cert_watch.digest.send_orphan_notice"), patch(
            "cert_watch.alerts._open_smtp_connection", return_value=smtp
        ):
            assert send_renewal_digest(db, config, None, days=7) is True

        smtp.send_message.assert_called_once()
        message = smtp.send_message.call_args.args[0]
        assert str(message["To"]) == "Alice@Example.COM"
        body = message.get_content()
        assert "host-a.example.com" in body
        assert "host-b.example.com" in body

    def test_webhook_tried_when_smtp_fails(self, empty_db):
        """Webhook must be tried as a fallback when SMTP delivery fails.

        Regression: when SMTP had failures, the function returned False
        immediately without trying the webhook fallback.
        """
        from cert_watch.alerts import AlertConfig, WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["global@recipient.test"],
        )
        wh = WebhookConfig(url="http://localhost:9999/hook")
        with patch("cert_watch.alerts.smtplib.SMTP", side_effect=ConnectionRefusedError("nope")), \
             patch("cert_watch.retry.time.sleep"), \
             patch("cert_watch.alerts.send_webhook", return_value=True) as mock_wh:
            result = send_renewal_digest(db, config, wh, days=7)
            _flush_digest_pool()
        assert result is True
        assert mock_wh.call_count >= 1

    def test_smtp_deliveries_use_retrying_per_digest_sender(self, empty_db):
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@test")
        _add_host(db, "host-b.example.com", owner_email="bob@test")
        _emit_renewal(db, "host-a.example.com")
        _emit_renewal(db, "host-b.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["global@test"],
        )
        smtp = MagicMock()
        smtp.send_message.return_value = {}
        with patch("cert_watch.retry.time.sleep"), patch(
            "cert_watch.alerts._open_smtp_connection", return_value=smtp
        ):
            send_renewal_digest(db, config, None, days=7)

        assert smtp.send_message.call_count == 3  # global + one digest per owner

    def test_smtp_refused_recipient_retries_without_resending_accepted(self, empty_db):
        from cert_watch.alerts import AlertConfig
        from cert_watch.database import _connect

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["Accepted@Test", "Refused@Test"],
        )
        smtp = MagicMock()
        smtp.send_message.side_effect = [
            {"Refused@Test": (550, b"mailbox unavailable")},
            {},
        ]

        with patch("cert_watch.alerts._open_smtp_connection", return_value=smtp), patch(
            "cert_watch.retry.time.sleep"
        ):
            assert send_renewal_digest(db, config, None, days=7) is True

        assert smtp.send_message.call_count == 2
        first_to = str(smtp.send_message.call_args_list[0].args[0]["To"])
        retry_to = str(smtp.send_message.call_args_list[1].args[0]["To"])
        assert "Accepted@Test" in first_to and "Refused@Test" in first_to
        assert retry_to == "Refused@Test"
        with _connect(db) as conn:
            rows = conn.execute(
                "SELECT target, status, lease_owner FROM digest_deliveries "
                "WHERE channel = 'smtp' ORDER BY target"
            ).fetchall()
        assert [(row["target"], row["status"], row["lease_owner"]) for row in rows] == [
            ("accepted@test", "sent", None),
            ("refused@test", "sent", None),
        ]

    def test_permanently_refused_recipient_releases_failed_claim(self, empty_db):
        from cert_watch.alerts import ALERT_MAX_RETRIES, AlertConfig
        from cert_watch.database import _connect

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["Accepted@Test", "Refused@Test"],
        )
        smtp = MagicMock()
        smtp.send_message.side_effect = [
            {"Refused@Test": (550, b"mailbox unavailable")}
            for _ in range(ALERT_MAX_RETRIES)
        ]

        with patch("cert_watch.alerts._open_smtp_connection", return_value=smtp), patch(
            "cert_watch.retry.time.sleep"
        ):
            assert send_renewal_digest(db, config, None, days=7) is False

        assert smtp.send_message.call_count == ALERT_MAX_RETRIES
        assert "Accepted@Test" in str(smtp.send_message.call_args_list[0].args[0]["To"])
        assert all(
            str(call.args[0]["To"]) == "Refused@Test"
            for call in smtp.send_message.call_args_list[1:]
        )
        with _connect(db) as conn:
            rows = conn.execute(
                "SELECT target, status, lease_owner, lease_expires_at "
                "FROM digest_deliveries WHERE channel = 'smtp' ORDER BY target"
            ).fetchall()
        assert [tuple(row) for row in rows] == [
            ("accepted@test", "sent", None, None),
            ("refused@test", "failed", None, None),
        ]

    def test_partial_webhook_retry_skips_successful_owner(self, empty_db):
        from cert_watch.alerts import WebhookConfig

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@test")
        _add_host(db, "host-b.example.com", owner_email="bob@test")
        _emit_renewal(db, "host-a.example.com")
        _emit_renewal(db, "host-b.example.com")
        webhook = WebhookConfig(url="http://localhost:9999/hook", kind="pagerduty")
        first_callback = MagicMock()
        second_callback = MagicMock()

        with patch("cert_watch.digest.send_orphan_notice"), patch(
            "cert_watch.alerts.send_webhook",
            side_effect=[True, False, False, False, True],
        ) as send:
            send_renewal_digest(
                db, None, webhook, delivery_completion_callback=first_callback
            )
            _flush_digest_pool()
            send_renewal_digest(
                db, None, webhook, delivery_completion_callback=second_callback
            )
            _flush_digest_pool()

        first_callback.assert_called_once_with(False)
        second_callback.assert_called_once_with(True)
        assert send.call_count == 5
        cert_ids = [call.args[0].cert_id for call in send.call_args_list]
        assert cert_ids[0] not in cert_ids[1:]
        assert len(set(cert_ids[1:])) == 1

    def test_overlapping_processes_send_recipient_once(self, empty_db):
        from cert_watch.alerts import AlertConfig

        db = empty_db
        _add_host(db, "host-a.example.com")
        _emit_renewal(db, "host-a.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=["global@test"],
        )
        entered = threading.Event()
        release = threading.Event()
        first_result: list[bool | None] = []

        def blocked_send(*args, **kwargs):
            entered.set()
            assert release.wait(timeout=5)
            return True

        smtp = MagicMock()
        smtp.send_message.side_effect = blocked_send
        with patch("cert_watch.digest.send_orphan_notice"), patch(
            "cert_watch.alerts._open_smtp_connection", return_value=smtp
        ):
            first = threading.Thread(
                target=lambda: first_result.append(
                    send_renewal_digest(db, config, None, days=7)
                )
            )
            first.start()
            assert entered.wait(timeout=5)
            second_result = send_renewal_digest(db, config, None, days=7)
            release.set()
            first.join(timeout=5)

        assert not first.is_alive()
        assert first_result == [True]
        assert second_result is False
        smtp.send_message.assert_called_once()

    def test_webhook_claim_is_acquired_only_when_owner_send_starts(self, empty_db):
        from cert_watch.alerts import WebhookConfig
        from cert_watch.database import _connect

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@test")
        _add_host(db, "host-b.example.com", owner_email="bob@test")
        _emit_renewal(db, "host-a.example.com")
        _emit_renewal(db, "host-b.example.com")
        entered = threading.Event()
        release = threading.Event()

        def slow_first_send(*args, **kwargs):
            entered.set()
            assert release.wait(timeout=5)
            return True

        with patch("cert_watch.digest.send_orphan_notice"), patch(
            "cert_watch.alerts.send_webhook", side_effect=slow_first_send
        ):
            send_renewal_digest(
                db,
                None,
                WebhookConfig(url="http://localhost:9999/hook"),
            )
            assert entered.wait(timeout=5)
            with _connect(db) as conn:
                rows = conn.execute(
                    "SELECT target, status FROM digest_deliveries "
                    "WHERE channel LIKE 'webhook:%'"
                ).fetchall()
            assert [(row["target"], row["status"]) for row in rows] == [
                ("alice@test", "claimed")
            ]
            release.set()
            _flush_digest_pool()

    def test_smtp_claim_is_acquired_only_when_owner_send_starts(self, empty_db):
        from cert_watch.alerts import AlertConfig
        from cert_watch.database import _connect

        db = empty_db
        _add_host(db, "host-a.example.com", owner_email="alice@test")
        _add_host(db, "host-b.example.com", owner_email="bob@test")
        _emit_renewal(db, "host-a.example.com")
        _emit_renewal(db, "host-b.example.com")
        config = AlertConfig(
            smtp_host="smtp.example",
            smtp_user="u",
            smtp_password="p",
            from_addr="a@b",
            recipients=[],
        )
        entered = threading.Event()
        release = threading.Event()
        result: list[bool | None] = []
        smtp = MagicMock()

        def slow_first_send(*args, **kwargs):
            entered.set()
            assert release.wait(timeout=5)
            return {}

        smtp.send_message.side_effect = slow_first_send
        with patch("cert_watch.digest.send_orphan_notice"), patch(
            "cert_watch.alerts._open_smtp_connection", return_value=smtp
        ):
            worker = threading.Thread(
                target=lambda: result.append(
                    send_renewal_digest(db, config, None, days=7)
                )
            )
            worker.start()
            assert entered.wait(timeout=5)
            with _connect(db) as conn:
                rows = conn.execute(
                    "SELECT target, status FROM digest_deliveries "
                    "WHERE channel = 'smtp'"
                ).fetchall()
            assert [(row["target"], row["status"]) for row in rows] == [
                ("alice@test", "claimed")
            ]
            release.set()
            worker.join(timeout=5)

        assert not worker.is_alive()
        assert result == [True]
