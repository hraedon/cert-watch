"""Target selection contracts for the concrete digest kinds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.alerting import AlertConfig
from cert_watch.alerting.digest.engine import DigestEngine
from cert_watch.alerting.digest.expiry import ExpiryDigestKind
from cert_watch.alerting.digest.renewal import RenewalDigestKind, build_renewal_digest
from cert_watch.alerting.model import SendResult
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect
from cert_watch.database.digest_deliveries import digest_period_key
from cert_watch.events import Event, emit_event
from tests._helpers import seed_certificate

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _config(recipients: list[str]) -> AlertConfig:
    return AlertConfig(
        smtp_host="smtp.example",
        smtp_user="u",
        smtp_password="p",
        from_addr="cert-watch@example.test",
        recipients=recipients,
    )


def _seed_leaf(db, hostname: str, *, days: int, fingerprint: str) -> None:
    seed_certificate(
        db,
        Certificate(
            subject=f"CN={hostname}",
            issuer="CN=issuer",
            not_before=NOW - timedelta(days=90),
            not_after=NOW + timedelta(days=days),
            san_dns_names=[hostname],
            fingerprint_sha256=fingerprint,
            raw_der=b"",
            is_leaf=True,
        ),
        hostname=hostname,
        port=443,
    )


def test_expiry_kind_builds_global_and_owner_targets_for_real_window(tmp_path) -> None:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add(
        "alice.example.test",
        owner_name="Alice",
        owner_email="Alice@Example.COM",
    )
    hosts.add(
        "bob.example.test",
        owner_name="Bob",
        owner_email="bob@example.test",
    )
    hosts.add("later.example.test")
    _seed_leaf(db, "alice.example.test", days=3, fingerprint="a" * 64)
    _seed_leaf(db, "bob.example.test", days=7, fingerprint="b" * 64)
    _seed_leaf(db, "later.example.test", days=20, fingerprint="c" * 64)

    kind = ExpiryDigestKind(
        _config(["Ops@Example.Test", "alice@example.com"])
    )
    targets = kind.targets(db, NOW, 14)

    assert [target.key for target in targets] == ["global", "bob@example.test"]
    assert targets[0].smtp_recipients == (
        "Ops@Example.Test",
        "alice@example.com",
    )
    assert targets[1].smtp_recipients == ("bob@example.test",)
    global_message = kind.render(targets[0])
    owner_message = kind.render(targets[1])
    assert "within 14 days" in global_message.body
    assert "alice.example.test" in global_message.body
    assert "bob.example.test" in global_message.body
    assert "later.example.test" not in global_message.body
    assert "following certificates" in owner_message.body
    assert "bob.example.test" in owner_message.body
    assert "alice.example.test" not in owner_message.body


def test_renewal_kind_merges_case_variant_owner_targets(tmp_path) -> None:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add("one.example.test", owner_email="Alice@Example.COM")
    hosts.add("two.example.test", owner_email="alice@example.com")
    for index, hostname in enumerate(("one.example.test", "two.example.test")):
        emit_event(
            Event(
                event_type="cert_renewed",
                timestamp=NOW - timedelta(days=1),
                payload={"hostname": hostname, "port": 443, "cert_id": f"c{index}"},
                source="scan",
            ),
            db,
        )

    kind = RenewalDigestKind(_config(["ops@example.test"]))
    targets = kind.targets(db, NOW, 7)

    assert [target.key for target in targets] == ["global", "alice@example.com"]
    owner = targets[1]
    assert owner.smtp_recipients == ("Alice@Example.COM",)
    assert owner.webhook_subject == "Renewal Digest (7d)"
    message = kind.render(owner)
    assert "one.example.test" in message.body
    assert "two.example.test" in message.body
    assert "Renewed on schedule: 2" in message.body


def test_concrete_kinds_produce_no_empty_noise(tmp_path) -> None:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)

    assert ExpiryDigestKind(_config(["ops@example.test"])).targets(db, NOW, 30) == []
    assert RenewalDigestKind(_config(["ops@example.test"])).targets(db, NOW, 7) == []


def _seed_problem_attempt(
    db,
    hostname: str,
    *,
    attempt_id: str,
    state: str,
    failure_at: datetime | None = None,
    raised_at: datetime | None = None,
) -> None:
    with _connect(db) as conn:
        host_id = conn.execute(
            "SELECT id FROM hosts WHERE hostname=?", (hostname,)
        ).fetchone()[0]
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,failure_attempt_id,
                failure_reported_at,failure_cleared_at,raised_at,
                baseline_lease_claimed)
               VALUES (?,?,1,'api_key:private-key-id',?,1,0,?,?,?,?,?,1)""",
            (
                attempt_id,
                host_id,
                state,
                (failure_at or raised_at or NOW).isoformat(),
                attempt_id if failure_at else None,
                failure_at.isoformat() if failure_at else None,
                (
                    (failure_at + timedelta(hours=1)).isoformat()
                    if failure_at and state in {"verified", "cancelled"}
                    else None
                ),
                raised_at.isoformat() if raised_at else None,
            ),
        )
        if failure_at:
            conn.execute(
                """INSERT INTO renewal_reports
                   (report_id,host_id,hostname_snapshot,port_snapshot,outcome,message,
                    tool,correlation_id,received_at,source,effect,attempt_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    f"report-{attempt_id}",
                    host_id,
                    hostname,
                    443,
                    "failed",
                    "private report message",
                    "private-tool",
                    "private-correlation",
                    failure_at.isoformat(),
                    "api_key:private-key-id",
                    "applied",
                    attempt_id,
                ),
            )
        conn.commit()


def test_renewal_problem_digest_uses_attempts_current_owner_and_ledger(tmp_path) -> None:
    db = tmp_path / "digest.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    hosts.add(
        "failed.example.test",
        owner_email="old-owner@example.test",
        tags="scope-before",
    )
    hosts.add("unowned.example.test", tags="scope-before")
    hosts.add("recovered.example.test", owner_email="recovered@example.test")
    failure_at = NOW - timedelta(days=1)
    raised_at = NOW - timedelta(hours=12)
    _seed_problem_attempt(
        db,
        "failed.example.test",
        attempt_id="failed-attempt",
        state="verifying",
        failure_at=failure_at,
    )
    _seed_problem_attempt(
        db,
        "unowned.example.test",
        attempt_id="not-deployed-attempt",
        state="not_deployed",
        failure_at=failure_at,
        raised_at=raised_at,
    )
    _seed_problem_attempt(
        db,
        "recovered.example.test",
        attempt_id="recovered-attempt",
        state="verified",
        failure_at=failure_at,
        raised_at=raised_at,
    )
    with _connect(db) as conn:
        conn.execute(
            "UPDATE hosts SET owner_email='new-owner@example.test',tags='scope-after' "
            "WHERE hostname='failed.example.test'"
        )
        conn.execute(
            "UPDATE hosts SET tags='scope-after' WHERE hostname='unowned.example.test'"
        )
        conn.execute("DELETE FROM event_log")
        conn.commit()

    digests = build_renewal_digest(db, cadence_days=7, now=NOW)
    by_owner = {digest.owner_email: digest for digest in digests}
    assert set(by_owner) == {
        "new-owner@example.test",
        "recovered@example.test",
        "",
    }
    assert (by_owner["new-owner@example.test"].failed_count, by_owner[""].failed_count) == (
        1,
        1,
    )
    assert by_owner[""].not_deployed_count == 1
    assert by_owner["recovered@example.test"].failed_count == 1
    assert any(
        "recovered.example.test" in entry
        for entry in by_owner["recovered@example.test"].failed_entries
    )

    kind = RenewalDigestKind(_config(["new-owner@example.test"]))
    targets = kind.targets(db, NOW, 7)
    owner = next(target for target in targets if target.key == "new-owner@example.test")
    unowned = next(target for target in targets if target.key == "_unowned")
    assert owner.smtp_recipients == ()
    assert unowned.smtp_recipients == ()
    rendered = "\n".join(kind.render(target).body for target in targets)
    assert "Renewal failed: 3" in rendered
    assert "Reported but not deployed: 1" in rendered
    assert "2026-09-22 12:00 UTC" in rendered
    for private in (
        "private report message",
        "private-tool",
        "private-correlation",
        "private-key-id",
        "new-owner@example.test",
        "old-owner@example.test",
        "scope-before",
        "scope-after",
    ):
        assert private not in rendered

    sent = []

    class SMTP:
        channel = "smtp"
        destination_id = ""

        def send(self, message):
            sent.append(message)
            return SendResult("accepted", accepted=message.recipients)

    period = digest_period_key("renewal", 7, now=NOW)
    engine = DigestEngine(db, [SMTP()], clock=lambda: NOW)
    first = engine.run(kind, period)
    retry = engine.run(kind, period)
    assert (first.sent, retry.sent, retry.skipped, len(sent)) == (2, 0, 2, 2)


def test_failure_digest_uses_condition_history_across_successor_attempts(tmp_path) -> None:
    db = tmp_path / "digest-history.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("retry.example.test", 443)
    failure_at = NOW - timedelta(days=2)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at)
               VALUES ('failure-origin',?,0,'test','failed',1,0,?,1,
                       'failure-origin',?)""",
            (host_id, failure_at.isoformat(), failure_at.isoformat()),
        )
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,
                failure_attempt_id,failure_reported_at)
               VALUES ('retry-attempt',?,1,'test','open',2,0,?,1,
                       'failure-origin',?)""",
            (
                host_id,
                (failure_at + timedelta(hours=1)).isoformat(),
                failure_at.isoformat(),
            ),
        )
        conn.commit()

    [digest] = build_renewal_digest(db, cadence_days=7, now=NOW)
    assert digest.failed_count == 1
    reported = failure_at.strftime("%Y-%m-%d %H:%M UTC")
    assert digest.failed_entries == [f"retry.example.test at {reported}"]


def test_failure_digest_includes_period_overlap_and_excludes_prior_clear(tmp_path) -> None:
    db = tmp_path / "digest-overlap.sqlite3"
    init_schema(db)
    hosts = SqliteHostRepository(db)
    names = (
        "still-open.example.test",
        "cleared-in.example.test",
        "cleared-before.example.test",
    )
    for name in names:
        hosts.add(name, 443)
        _seed_problem_attempt(
            db,
            name,
            attempt_id=name,
            state="failed",
            failure_at=NOW - timedelta(days=10),
        )
    with _connect(db) as conn:
        conn.execute(
            """UPDATE renewal_attempts SET failure_cleared_at=?
               WHERE attempt_id='cleared-in.example.test'""",
            ((NOW - timedelta(days=2)).isoformat(),),
        )
        conn.execute(
            """UPDATE renewal_attempts SET failure_cleared_at=?
               WHERE attempt_id='cleared-before.example.test'""",
            ((NOW - timedelta(days=8)).isoformat(),),
        )
        conn.commit()

    [digest] = build_renewal_digest(db, cadence_days=7, now=NOW)
    assert digest.failed_count == 2
    assert {entry.split(" at ", 1)[0] for entry in digest.failed_entries} == {
        "still-open.example.test",
        "cleared-in.example.test",
    }


def test_not_deployed_digest_falls_back_when_raised_at_is_null(tmp_path) -> None:
    db = tmp_path / "digest-null-raised.sqlite3"
    init_schema(db)
    host_id = SqliteHostRepository(db).add("legacy-not-deployed.example.test", 443)
    received_at = NOW - timedelta(hours=4)
    with _connect(db) as conn:
        conn.execute(
            """INSERT INTO renewal_attempts
               (attempt_id,host_id,is_current,source,state,opened_seq,
                suppresses_stalled,received_at,baseline_lease_claimed,raised_at)
               VALUES ('legacy-not-deployed',?,1,'test','not_deployed',1,0,?,1,NULL)""",
            (host_id, received_at.isoformat()),
        )
        conn.commit()

    [digest] = build_renewal_digest(db, cadence_days=7, now=NOW)
    assert digest.not_deployed_count == 1
    received = received_at.strftime("%Y-%m-%d %H:%M UTC")
    assert digest.not_deployed_entries == [
        f"legacy-not-deployed.example.test at {received}"
    ]
