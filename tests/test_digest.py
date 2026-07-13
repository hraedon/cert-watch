"""Tests for renewal digest (WI-3.1 / Plan 048)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.digest import (
    _flush_digest_pool,
    build_renewal_digest,
    send_renewal_digest,
)
from cert_watch.events import Event, emit_event


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
        with patch("cert_watch.alerts.smtplib.SMTP", side_effect=ConnectionRefusedError("nope")), \
             patch("cert_watch.retry.time.sleep"), \
             patch("cert_watch.digest._send_digest_email_msg", return_value=True) as mock_fallback:
            result = send_renewal_digest(db, config, None, days=7)
        assert result is True  # global + owner retried via _send_digest_email_msg, both succeeded
        sent_tos = [
            str(call.args[0]["To"]) for call in mock_fallback.call_args_list
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

    def test_smtp_connection_break_falls_back_to_per_send(self, empty_db):
        """If a send fails on the shared SMTP connection, remaining sends
        must be retried with new connections via _send_digest_email_msg."""
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
        smtp_mock = MagicMock()
        # First send (global) succeeds, second send (first owner) fails,
        # breaking the connection. Remaining owner should be retried.
        smtp_mock.send_message.side_effect = [None, ConnectionError("conn dropped")]
        with patch("cert_watch.alerts.smtplib.SMTP", return_value=smtp_mock), \
             patch("cert_watch.retry.time.sleep"), \
             patch("cert_watch.digest._send_digest_email_msg", return_value=True) as mock_fallback:
            send_renewal_digest(db, config, None, days=7)

        # The shared connection made 2 calls (global + failed owner).
        # The fallback _send_digest_email_msg must have been called for the
        # remaining unsent owner (proving the retry fired).
        assert smtp_mock.send_message.call_count == 2
        assert mock_fallback.call_count >= 1, \
            "unsent owner digest must be retried via _send_digest_email_msg"
