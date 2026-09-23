"""Target selection contracts for the concrete digest kinds."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cert_watch.alerting import AlertConfig
from cert_watch.alerting.digest.expiry import ExpiryDigestKind
from cert_watch.alerting.digest.renewal import RenewalDigestKind
from cert_watch.certificate_model import Certificate
from cert_watch.database import SqliteHostRepository, init_schema
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
