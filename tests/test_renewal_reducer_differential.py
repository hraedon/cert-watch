"""Differential guard: failure tracking is only an overlay on the main reducer."""

from __future__ import annotations

import random
import uuid
from contextlib import ExitStack
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from cert_watch.database.connection import _connect
from cert_watch.renewal_verification import evaluate_after_scan
from cert_watch.services import renewal_reports
from cert_watch.services.renewal_reports import (
    create_report,
    expire_renewal_leases,
    resolve_target,
)
from tests.test_renewal_reports import (
    HOST,
    NOW,
    _auth,
    _report,
)

pytest_plugins = ("tests.test_renewal_reports",)

# These are exactly the attempt columns maintained by the S2/S4 reducer on
# origin/main. S5-owned failure markers and their rule wake are deliberately
# absent.
MAIN_COLUMNS = (
    "state",
    "is_current",
    "attempt_id",
    "opened_seq",
    "baseline_fingerprint",
    "baseline_not_after",
    "baseline_lease_claimed",
    "new_fingerprint",
    "verified_fingerprint",
    "lease_expires_at",
    "suppresses_stalled",
    "success_received_at",
    "next_check_at",
    "closed_reason",
)

FINGERPRINT_A = "a" * 64
FINGERPRINT_B = "b" * 64


def _report_action(
    outcome: str,
    *,
    correlation_id: str | None = None,
    new_fingerprint: str | None = None,
    hours: int = 0,
    minutes: int = 0,
) -> tuple[str, object, object, object]:
    return outcome, correlation_id, new_fingerprint, timedelta(hours=hours, minutes=minutes)


# Includes every report-driven normative transition, the verification and
# deployment-warning scan paths, and the three round-7 reviewer sequences.
NORMATIVE_AND_REVIEW_SEQUENCES = (
    (_report_action("started"), _report_action("started", minutes=10)),
    (_report_action("failed"), _report_action("failed", minutes=10)),
    (_report_action("started"), _report_action("failed", minutes=10)),
    (_report_action("succeeded"), _report_action("succeeded", minutes=10)),
    (_report_action("succeeded"), _report_action("failed", minutes=10)),
    (
        _report_action("started", correlation_id="old"),
        ("expire", None, None, timedelta(hours=25)),
        _report_action("failed", correlation_id="old", hours=26),
        _report_action("failed", correlation_id="old", hours=27),
    ),
    (
        _report_action("failed"),
        _report_action("started", correlation_id="one", hours=1),
        _report_action("started", correlation_id="two", hours=20),
        _report_action("started", correlation_id="three", hours=40),
    ),
    (
        _report_action("succeeded", correlation_id="run-1", new_fingerprint=FINGERPRINT_A),
        ("scan", None, FINGERPRINT_A, timedelta(minutes=10)),
        _report_action("failed", correlation_id="run-1", minutes=20),
    ),
    (
        _report_action("failed"),
        _report_action("started", hours=1),
        _report_action("failed", hours=2),
    ),
    (
        _report_action("succeeded", new_fingerprint=FINGERPRINT_A),
        ("scan", None, FINGERPRINT_B, timedelta(minutes=10)),
        ("scan", None, FINGERPRINT_A, timedelta(minutes=20)),
    ),
)


def _random_sequences() -> list[tuple[tuple[str, object, object, object], ...]]:
    rng = random.Random(118_005)
    sequences = []
    for _ in range(30):
        actions = []
        for step in range(12):
            if rng.random() < 0.2:
                actions.append(
                    (
                        "scan",
                        None,
                        None,
                        timedelta(minutes=step * 10),
                    )
                )
                continue
            actions.append(
                _report_action(
                    rng.choice(("started", "failed", "succeeded")),
                    correlation_id=rng.choice((None, "run-0", "run-1", "run-2")),
                    new_fingerprint=rng.choice((None, FINGERPRINT_A, FINGERPRINT_B)),
                    minutes=step * 10,
                )
            )
        sequences.append(tuple(actions))
    return sequences


def _snapshot(db: Path) -> list[tuple[object, ...]]:
    with _connect(db) as conn:
        rows = conn.execute("SELECT * FROM renewal_attempts ORDER BY opened_seq").fetchall()
    return [tuple(row[column] for column in MAIN_COLUMNS) for row in rows]


def _remove_failure_overlay(db: Path) -> None:
    with _connect(db) as conn:
        conn.execute(
            """UPDATE renewal_attempts
               SET failure_attempt_id=NULL,failure_reported_at=NULL,
                   failure_cleared_at=NULL,failure_expected_fingerprint=NULL,
                   rule_due_at=NULL"""
        )
        conn.commit()


def _run_sequence(
    db: Path,
    settings,
    actions: tuple[tuple[str, object, object, object], ...],
    *,
    origin_main: bool,
) -> list[tuple[tuple[str | None, str | None, str | None] | None, list[tuple[object, ...]]]]:
    auth = _auth("differential", "prod")
    target = resolve_target(db, auth, hostname=HOST, port=443)
    observed = []
    ids = (uuid.UUID(int=value) for value in range(1, 10_000))
    with ExitStack() as stack:
        stack.enter_context(patch.object(renewal_reports.uuid, "uuid4", side_effect=ids))
        if origin_main:
            # This removes only the S5 hooks. The surrounding reducer is kept
            # line-for-line with origin/main and runs against the same schema.
            stack.enter_context(
                patch.object(renewal_reports, "_open_failure", return_value=(None, None, None))
            )
            stack.enter_context(patch.object(renewal_reports, "_record_failed_report_on"))
        for index, (kind, correlation, fingerprint, offset) in enumerate(actions):
            instant = NOW + offset
            result_tuple = None
            if kind == "scan":
                if fingerprint is None:
                    with _connect(db) as conn:
                        fingerprint = conn.execute(
                            """SELECT fingerprint_sha256 FROM certificates
                               WHERE hostname=? AND port=? AND is_leaf=1""",
                            (HOST, 443),
                        ).fetchone()[0]
                result = evaluate_after_scan(
                    db,
                    HOST,
                    443,
                    str(fingerprint),
                    started_at=instant,
                    settings=settings,
                )
                if result is not None:
                    result_tuple = (result.state, result.reason, result.next_check_at)
            elif kind == "expire":
                expire_renewal_leases(db, now=instant)
            else:
                result, replayed = create_report(
                    db,
                    settings,
                    target,
                    _report(
                        kind,
                        correlation_id=correlation,
                        new_fingerprint=fingerprint,
                    ),
                    auth=auth,
                    actor="api_key:differential",
                    source_ip="192.0.2.20",
                    idempotency_key=None,
                    body_sha256=f"differential-{index}",
                    now=instant,
                )
                assert not replayed
                result_tuple = (result.state, result.effect, result.attempt_id)
            if origin_main:
                _remove_failure_overlay(db)
            observed.append((result_tuple, _snapshot(db)))
    return observed


@pytest.mark.parametrize(
    "actions", [*NORMATIVE_AND_REVIEW_SEQUENCES, *_random_sequences()]
)
def test_failure_overlay_matches_origin_main_at_every_step(estate, tmp_path, actions):
    source_db, _repo, _host_id, _other_id, _fingerprint, settings = estate
    main_db = tmp_path / "origin-main.sqlite3"
    overlay_db = tmp_path / "failure-overlay.sqlite3"
    with _connect(source_db) as source, _connect(main_db) as main:
        source.backup(main)
    with _connect(source_db) as source, _connect(overlay_db) as overlay:
        source.backup(overlay)

    main_settings = replace(settings, db_path=main_db, data_dir=tmp_path / "main")
    overlay_settings = replace(settings, db_path=overlay_db, data_dir=tmp_path / "overlay")
    expected = _run_sequence(main_db, main_settings, actions, origin_main=True)
    actual = _run_sequence(overlay_db, overlay_settings, actions, origin_main=False)

    assert actual == expected
