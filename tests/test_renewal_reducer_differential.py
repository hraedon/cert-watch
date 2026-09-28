"""Differential guard against the reducer pinned from this branch's merge base."""

from __future__ import annotations

import hashlib
import json
import random
import sqlite3
import sys
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import patch

import pytest

from cert_watch.auth.rbac import AuthContext
from cert_watch.certificate_model import Certificate, parse_certificate
from cert_watch.config import Settings
from cert_watch.database import SqliteHostRepository, init_schema
from cert_watch.database.connection import _connect, close_connections
from cert_watch.services import renewal_reports
from tests.conftest import _make_cert
from tests.fixtures.main_renewal_reducer import renewal_verification as main_verification
from tests.fixtures.main_renewal_reducer.services import renewal_reports as main_reports

HOST = "renewal.example.test"
NOW = datetime(2026, 9, 27, 12, tzinfo=UTC)

# These files are byte-for-byte copies from the branch merge base,
# 9b814fe88030172f22196d3add8680b2aa05953b. Refresh deliberately with:
# git show "$(git merge-base HEAD origin/main)":<source-path> > <fixture-path>
VENDORED_SHA256 = {
    "services/renewal_reports.py": (
        "c72f38d0ed9bc4a82aeb899e41cc94c29d6a5827df06b8a118c7a5c020ab174e"
    ),
    "renewal_verification.py": "e98396f619179a955864133bb95b32b047b9daaa1c088b0b038d1206fc34ec42",
}

# Corpus sequences on which the one documented exception (a failed report
# carrying a verified attempt's correlation is ignored as late) fires.
EXPECTED_DIVERGENT_SEQUENCES = [0, 1, 19, 40, 44]

# Columns S5 adds to renewal_attempts for the failure overlay (migration 0049).
# Every other attempt column is part of the base reducer's contract and must
# match the merge-base reducer exactly.
OVERLAY_COLUMNS = frozenset(
    {
        "failure_attempt_id",
        "failure_reported_at",
        "failure_cleared_at",
        "failure_expected_fingerprint",
        "rule_due_at",
    }
)

Action = tuple[str, str | None, str | None, int]
Observation = tuple[
    tuple[str | None, str | None, str | None] | None,
    str | None,
    tuple[tuple[object, ...], ...],
]


@dataclass(frozen=True)
class DifferentialSeed:
    db: Path
    leaves: dict[str, Certificate]


@dataclass
class Side:
    db: Path
    settings: Settings
    reports: Any
    verification: ModuleType
    target: object
    ids: Iterator[uuid.UUID]
    overlay: bool


def _sequences() -> tuple[tuple[Action, ...], ...]:
    """Return the reviewed corpus plus broader generated state-machine paths."""
    sequences: list[list[Action]] = [
        [("succeeded", "run-1", "A", 0), ("store", None, "A", 10), ("failed", "run-1", None, 20)],
        [("succeeded", "run-1", None, 0), ("store", None, "A", 10), ("failed", "run-1", None, 20)],
        [("succeeded", None, None, 0), ("store", None, "A", 10), ("failed", None, None, 20)],
        [
            ("failed", None, None, 0),
            ("store", None, "A", 10),
            ("started", None, None, 20),
            ("failed", None, None, 30),
        ],
        [
            ("failed", None, "A", 0),
            ("started", None, None, 5),
            ("store", None, "B", 10),
            ("failed", None, None, 20),
        ],
        [
            ("succeeded", None, "A", 0),
            ("scan", None, None, 60 * 25),
            ("scan", None, None, 60 * 26),
            ("failed", None, None, 60 * 27),
            ("store", None, "B", 60 * 28),
        ],
        [
            ("failed", None, None, 0),
            ("started", "c1", None, 60),
            ("started", "c2", None, 1200),
            ("expire", None, None, 3000),
            ("started", None, None, 3100),
        ],
    ]
    rng = random.Random(9)
    for _ in range(60):
        sequence: list[Action] = []
        minute = 0
        for _ in range(10):
            minute += rng.choice((1, 5, 30, 600, 1500))
            choice = rng.random()
            if choice < 0.15:
                sequence.append(("store", None, rng.choice(("A", "B")), minute))
            elif choice < 0.25:
                sequence.append(("scan", None, None, minute))
            elif choice < 0.3:
                sequence.append(("expire", None, None, minute))
            else:
                sequence.append(
                    (
                        rng.choice(("started", "failed", "succeeded")),
                        rng.choice((None, "r0", "r1")),
                        rng.choice((None, "A", "B")),
                        minute,
                    )
                )
        sequences.append(sequence)

    sequences.extend(
        [
            [("failed", None, None, 0), ("clear", None, None, 5), ("failed", None, None, 10)],
            [("failed", None, None, 0), ("store", None, "A", 5), ("failed", None, None, 10)],
            [
                ("failed", None, None, 0),
                ("clear", None, None, 5),
                ("succeeded", None, "A", 10),
                ("failed", None, None, 15),
            ],
        ]
    )

    # Every generated case deliberately covers the operations omitted by the
    # original corpus: stored successors, compatibility writes, manual clears,
    # and a failure-condition restart after clear. Vary the surrounding
    # reports and timings without making the differential expensive enough to
    # discourage running it locally.
    for seed in range(10):
        rng = random.Random(seed)
        for _ in range(13):
            minute = 0
            sequence = []
            for _ in range(rng.randint(1, 3)):
                minute += rng.choice((1, 5, 30, 600))
                sequence.append(
                    (
                        rng.choice(("started", "failed", "succeeded")),
                        rng.choice((None, "g0", "g1")),
                        rng.choice((None, "A", "B")),
                        minute,
                    )
                )
            minute += rng.choice((1, 5, 30))
            sequence.append(("store", None, rng.choice(("A", "B")), minute))
            minute += rng.choice((1, 5, 30))
            sequence.append(("legacy_in_progress", None, None, minute))
            minute += rng.choice((1, 5, 30))
            sequence.append(("failed", rng.choice((None, "g0", "g1")), None, minute))
            minute += rng.choice((1, 5, 30))
            sequence.append(("clear", None, None, minute))
            minute += rng.choice((1, 5, 30))
            sequence.append(("failed", rng.choice((None, "g0", "g1")), None, minute))
            minute += rng.choice((1, 5, 30))
            sequence.append(("legacy_pending", None, None, minute))
            sequences.append(sequence)
    return tuple(tuple(sequence) for sequence in sequences)


SEQUENCES = _sequences()


@pytest.fixture(scope="module")
def differential_seed(tmp_path_factory: pytest.TempPathFactory) -> DifferentialSeed:
    root = tmp_path_factory.mktemp("renewal-reducer-seed")
    db = root / "seed.sqlite3"
    init_schema(db)
    SqliteHostRepository(db).add(HOST, 443, tags="prod")
    initial_leaf = parse_certificate(_make_cert(HOST, days_valid=60).der)
    assert isinstance(initial_leaf, Certificate)
    _store_leaf_sql(db, initial_leaf, NOW - timedelta(days=1), "seed")
    leaves = {
        name: parse_certificate(_make_cert(HOST, days_valid=days).der)
        for name, days in (("A", 90), ("B", 120))
    }
    return DifferentialSeed(db, leaves)


def test_vendored_main_reducers_have_recorded_merge_base_hashes() -> None:
    fixture_dir = Path(__file__).parent / "fixtures" / "main_renewal_reducer"
    observed = {
        name: hashlib.sha256((fixture_dir / name).read_bytes()).hexdigest()
        for name in VENDORED_SHA256
    }
    assert observed == VENDORED_SHA256


def test_sequence_corpus_contains_reviewed_and_generated_paths() -> None:
    assert len(SEQUENCES) == 200
    generated = SEQUENCES[70:]
    for required in ("clear", "legacy_in_progress", "legacy_pending", "store"):
        assert all(any(action[0] == required for action in sequence) for sequence in generated)


def _auth() -> AuthContext:
    return AuthContext.renewal_report_key(
        "differential",
        principal_id="differential",
        binding="all",
        bound_tags=(),
    )


def _clone(source: Path, destination: Path) -> None:
    # Do not consume entries in cert-watch's small per-thread connection cache:
    # this corpus creates two fresh databases for every sequence it runs.
    with (
        closing(sqlite3.connect(source)) as source_conn,
        closing(sqlite3.connect(destination)) as destination_conn,
        destination_conn,
    ):
        source_conn.backup(destination_conn)


def _side(
    seed: DifferentialSeed,
    db: Path,
    data_dir: Path,
    reports: ModuleType,
    verification: ModuleType,
    *,
    overlay: bool,
) -> Side:
    _clone(seed.db, db)
    settings = Settings(db_path=db, data_dir=data_dir)
    target = reports.resolve_target(db, _auth(), hostname=HOST, port=443)
    return Side(
        db,
        settings,
        reports,
        verification,
        target,
        (uuid.UUID(int=value) for value in range(1, 100_000)),
        overlay,
    )


def _base_columns(conn: sqlite3.Connection) -> tuple[str, ...]:
    columns = tuple(
        str(row[1]) for row in conn.execute("PRAGMA table_info(renewal_attempts)")
    )
    return tuple(column for column in columns if column not in OVERLAY_COLUMNS)


def _snapshot(db: Path) -> tuple[tuple[object, ...], ...]:
    with _connect(db) as conn:
        columns = _base_columns(conn)
        rows = conn.execute("SELECT * FROM renewal_attempts ORDER BY opened_seq").fetchall()
    return tuple(tuple(row[column] for column in columns) for row in rows)


def _latest_report_effect(db: Path, report_id: str) -> str:
    with _connect(db) as conn:
        row = conn.execute(
            "SELECT effect FROM renewal_reports WHERE report_id=?", (report_id,)
        ).fetchone()
    assert row is not None
    return str(row[0])


def _current_fingerprint(db: Path) -> str:
    with _connect(db) as conn:
        row = conn.execute(
            """SELECT fingerprint_sha256 FROM certificates
               WHERE hostname=? AND port=? AND is_leaf=1
               ORDER BY created_at DESC,rowid DESC LIMIT 1""",
            (HOST, 443),
        ).fetchone()
    assert row is not None
    return str(row[0])


def _store_leaf_sql(
    db: Path,
    leaf: Certificate,
    instant: datetime,
    identity: object,
    *,
    store_hook: Callable[..., object] | None = None,
) -> None:
    """Seed scan evidence without executing either branch's scan-storage code.

    ``store_hook`` runs inside the same transaction, where the branch's real
    scan store calls it (the PR side passes its store-time failure hook; the
    merge base has none)."""
    created_at = instant.astimezone(UTC).isoformat()
    leaf_id = f"differential-leaf-{identity}"
    with _connect(db) as conn:
        previous = conn.execute(
            """SELECT id,fingerprint_sha256 FROM certificates
               WHERE hostname=? AND port=? AND is_leaf=1 AND source='scanned'
               ORDER BY created_at DESC,rowid DESC LIMIT 1""",
            (HOST, 443),
        ).fetchone()
        if previous is not None:
            conn.execute("DELETE FROM certificates WHERE parent_cert_id=?", (previous["id"],))
        conn.execute(
            "DELETE FROM certificates WHERE hostname=? AND port=? AND is_leaf=1",
            (HOST, 443),
        )
        conn.execute(
            """INSERT INTO certificates
               (id,subject,issuer,not_before,not_after,san_dns_names,
                fingerprint_sha256,raw_der,source,hostname,port,is_leaf,
                parent_cert_id,chain_valid,replaces_cert_id,created_at,updated_at,tags)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                leaf_id,
                leaf.subject,
                leaf.issuer,
                leaf.not_before.astimezone(UTC).isoformat(),
                leaf.not_after.astimezone(UTC).isoformat(),
                json.dumps(leaf.san_dns_names),
                leaf.fingerprint_sha256,
                leaf.raw_der,
                "scanned",
                HOST,
                443,
                1,
                None,
                None,
                str(previous["id"]) if previous is not None else None,
                created_at,
                created_at,
                "prod",
            ),
        )
        if previous is not None and previous["fingerprint_sha256"] != leaf.fingerprint_sha256:
            conn.execute(
                """INSERT OR IGNORE INTO certificate_lineage
                   (old_cert_id,new_cert_id,hostname,port,created_at,old_fingerprint)
                   VALUES (?,?,?,?,?,?)""",
                (
                    previous["id"],
                    leaf_id,
                    HOST,
                    443,
                    created_at,
                    previous["fingerprint_sha256"],
                ),
            )
        if store_hook is not None:
            store_hook(conn, HOST, 443, leaf.fingerprint_sha256, observed_at=instant)
        conn.commit()


def _clear_overlay(side: Side, instant: datetime) -> None:
    if not side.overlay:
        return
    with _connect(side.db) as conn:
        row = conn.execute("SELECT id FROM hosts WHERE hostname=?", (HOST,)).fetchone()
    assert row is not None
    side.reports.clear_renewal_failure(
        side.db,
        str(row[0]),
        auth=_auth(),
        actor="api_key:differential",
        source_ip=None,
        now=instant,
    )


def _run_action(
    side: Side, action: Action, leaves: dict[str, Certificate], index: int
) -> Observation:
    kind, correlation, leaf_name, minutes = action
    instant = NOW + timedelta(minutes=minutes)
    returned: tuple[str | None, str | None, str | None] | None = None
    stored_effect = None
    with patch.object(side.reports.uuid, "uuid4", side_effect=side.ids):
        if kind == "store":
            assert leaf_name is not None
            leaf = leaves[leaf_name]
            _store_leaf_sql(
                side.db,
                leaf,
                instant,
                index,
                store_hook=(
                    side.verification.observe_failure_successor_on if side.overlay else None
                ),
            )
            result = side.verification.evaluate_after_scan(
                side.db,
                HOST,
                443,
                leaf.fingerprint_sha256,
                started_at=instant,
                settings=side.settings,
            )
            if result is not None:
                returned = (result.state, None, result.reason)
        elif kind == "scan":
            result = side.verification.evaluate_after_scan(
                side.db,
                HOST,
                443,
                _current_fingerprint(side.db),
                started_at=instant,
                settings=side.settings,
            )
            if result is not None:
                returned = (result.state, None, result.reason)
        elif kind == "expire":
            side.reports.expire_renewal_leases(side.db, now=instant)
        elif kind == "clear":
            _clear_overlay(side, instant)
        elif kind.startswith("legacy_"):
            status = kind.removeprefix("legacy_")
            with _connect(side.db) as conn:
                row = conn.execute(
                    "SELECT id FROM hosts WHERE hostname=? AND port=?", (HOST, 443)
                ).fetchone()
                assert row is not None
                side.reports.write_through_renewal_status_on(
                    conn,
                    side.db,
                    side.settings,
                    str(row["id"]),
                    status,
                    auth=AuthContext.system(),
                    actor="system",
                    source_ip=None,
                    now=instant,
                )
                conn.commit()
        else:
            report = side.reports.RenewalReportInput(
                kind,
                None,
                None,
                correlation,
                leaves[leaf_name].fingerprint_sha256 if leaf_name else None,
                None,
            )
            # The vendored report reducer imports verification inside the
            # acceptance call. Redirect that one import to its vendored peer,
            # then restore sys.modules before the overlay side runs.
            verification_modules = (
                {"cert_watch.renewal_verification": side.verification} if not side.overlay else {}
            )
            with patch.dict(sys.modules, verification_modules):
                result, replayed = side.reports.create_report(
                    side.db,
                    side.settings,
                    side.target,
                    report,
                    auth=_auth(),
                    actor="api_key:differential",
                    source_ip="192.0.2.20",
                    idempotency_key=None,
                    body_sha256=f"differential-{index}",
                    now=instant,
                )
            assert not replayed
            returned = (result.state, result.effect, str(result.attempt_id))
            stored_effect = _latest_report_effect(side.db, str(result.report_id))
    return returned, stored_effect, _snapshot(side.db)


def _is_verified_correlated_late_failure(db: Path, action: Action) -> bool:
    kind, correlation, _leaf, _minutes = action
    if kind != "failed" or correlation is None:
        return False
    with _connect(db) as conn:
        row = conn.execute(
            """SELECT a.state,ac.attempt_id AS owner_id,a.attempt_id AS current_id
               FROM renewal_attempts a
               LEFT JOIN renewal_attempt_correlations ac
                 ON ac.host_id=a.host_id AND ac.source='api_key:differential'
                AND ac.correlation_id=?
               WHERE a.is_current=1""",
            (correlation,),
        ).fetchone()
    return bool(
        row is not None and row["state"] == "verified" and row["owner_id"] == row["current_id"]
    )


def _is_exact_allowed_divergence(
    expected: Observation,
    actual: Observation,
    before_overlay: tuple[tuple[object, ...], ...],
) -> bool:
    expected_result, expected_effect, _expected_rows = expected
    actual_result, actual_effect, _actual_rows = actual
    return bool(
        expected_result is not None
        and actual_result is not None
        and expected_result[:2] == ("failed", "applied")
        and actual_result[:2] == ("verified", "ignored_late")
        and expected_effect == "applied"
        and actual_effect == "ignored_late"
        and actual[2] == before_overlay
    )


@dataclass(frozen=True)
class AllowedDivergence:
    step_index: int
    action: Action


def _assert_sequence_matches(
    seed: DifferentialSeed,
    tmp_path: Path,
    actions: Sequence[Action],
    *,
    mutate_overlay: Callable[[Side], None] | None = None,
) -> AllowedDivergence | None:
    main = _side(
        seed,
        tmp_path / "origin-main.sqlite3",
        tmp_path / "origin-main-data",
        main_reports,
        main_verification,
        overlay=False,
    )
    current_verification = __import__(
        "cert_watch.renewal_verification", fromlist=["evaluate_after_scan"]
    )
    overlay = _side(
        seed,
        tmp_path / "failure-overlay.sqlite3",
        tmp_path / "failure-overlay-data",
        renewal_reports,
        current_verification,
        overlay=True,
    )
    if mutate_overlay is not None:
        mutate_overlay(overlay)

    try:
        for index, action in enumerate(actions):
            allowed = _is_verified_correlated_late_failure(overlay.db, action)
            before_overlay = _snapshot(overlay.db)
            expected = _run_action(main, action, seed.leaves, index)
            actual = _run_action(overlay, action, seed.leaves, index)
            if actual == expected:
                continue
            if allowed and _is_exact_allowed_divergence(expected, actual, before_overlay):
                return AllowedDivergence(index, action)
            assert actual == expected, f"differential mismatch at step {index}: {action}"
    finally:
        close_connections()
    return None


@pytest.mark.parametrize("sequence_index", range(len(SEQUENCES)))
def test_failure_overlay_matches_pinned_main_reducer(
    differential_seed: DifferentialSeed,
    tmp_path: Path,
    sequence_index: int,
    request: pytest.FixtureRequest,
) -> None:
    divergence = _assert_sequence_matches(differential_seed, tmp_path, SEQUENCES[sequence_index])
    if divergence is not None:
        request.node.user_properties.append(
            (
                "allowed_divergence",
                f"step={divergence.step_index} action={divergence.action!r}",
            )
        )


def test_allowed_divergence_records_and_ends_the_sequence(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    actions: tuple[Action, ...] = (
        ("succeeded", "owned-run", "A", 0),
        ("store", None, "A", 10),
        ("failed", "owned-run", None, 20),
        ("invalid-tail-must-not-run", None, None, 30),
    )

    assert _assert_sequence_matches(differential_seed, tmp_path, actions) == (
        AllowedDivergence(2, actions[2])
    )


def test_differential_self_check_catches_plain_repeated_start_regression(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    def install_mutant(side: Side) -> None:
        original = side.reports.create_report

        def regrant_repeated_start(*args: Any, **kwargs: Any) -> Any:
            result, replayed = original(*args, **kwargs)
            report = args[3]
            if report.outcome == "started" and result.effect == "duplicate":
                instant = kwargs["now"]
                lease = (instant + timedelta(hours=24)).isoformat()
                with _connect(side.db) as conn:
                    conn.execute(
                        "UPDATE renewal_attempts SET lease_expires_at=? WHERE attempt_id=?",
                        (lease, result.attempt_id),
                    )
                    conn.commit()
            return result, replayed

        side.reports = _ModuleProxy(side.reports, create_report=regrant_repeated_start)

    with pytest.raises(AssertionError, match="differential mismatch"):
        _assert_sequence_matches(
            differential_seed,
            tmp_path,
            (("started", None, None, 0), ("started", None, None, 10)),
            mutate_overlay=install_mutant,
        )


def test_differential_self_check_catches_acceptance_verification_regression(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    def install_mutant(side: Side) -> None:
        original_create = side.reports.create_report
        original_evaluate = side.verification.evaluate_evidence_on

        def stop_acceptance_verification(*args: Any, **kwargs: Any) -> Any:
            if not kwargs["count_check"]:
                attempt = args[1]
                return side.verification.VerificationResult(
                    str(attempt["state"]), attempt["next_check_at"], None
                )
            return original_evaluate(*args, **kwargs)

        def create_with_mutant(*args: Any, **kwargs: Any) -> Any:
            with patch.object(
                side.verification,
                "evaluate_evidence_on",
                stop_acceptance_verification,
            ):
                return original_create(*args, **kwargs)

        side.reports = _ModuleProxy(side.reports, create_report=create_with_mutant)

    with pytest.raises(AssertionError, match="differential mismatch"):
        _assert_sequence_matches(
            differential_seed,
            tmp_path,
            (("store", None, "A", 0), ("succeeded", None, "A", 5)),
            mutate_overlay=install_mutant,
        )


def test_differential_self_check_catches_store_hook_touching_base_state(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    """The PR-only store-time hook must never alter base attempt columns."""

    def install_mutant(side: Side) -> None:
        original = side.verification.observe_failure_successor_on

        def hook_that_verifies(conn: sqlite3.Connection, *args: Any, **kwargs: Any) -> Any:
            result = original(conn, *args, **kwargs)
            conn.execute("UPDATE renewal_attempts SET state='verified' WHERE is_current=1")
            return result

        side.verification = _ModuleProxy(
            side.verification, observe_failure_successor_on=hook_that_verifies
        )

    with pytest.raises(AssertionError, match="differential mismatch"):
        _assert_sequence_matches(
            differential_seed,
            tmp_path,
            (("started", "run", None, 0), ("store", None, "A", 5)),
            mutate_overlay=install_mutant,
        )


def test_main_side_acceptance_runs_the_vendored_verification(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    """Pin the sys.modules redirect: the merge-base reducer's acceptance call
    must reach the vendored verification module, not the live one."""
    seen: list[str] = []
    original = main_verification.evaluate_evidence_on

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.append("vendored")
        return original(*args, **kwargs)

    with patch.object(main_verification, "evaluate_evidence_on", spy):
        _assert_sequence_matches(
            differential_seed,
            tmp_path,
            (("store", None, "A", 0), ("succeeded", None, "A", 5)),
        )
    assert seen, "main-side acceptance did not call the vendored verification module"


class _ModuleProxy:
    def __init__(self, module: ModuleType, **overrides: object) -> None:
        self._module = module
        self._overrides = overrides

    def __getattr__(self, name: str) -> object:
        if name in self._overrides:
            return self._overrides[name]
        return getattr(self._module, name)


def _divergent_sequences(seed: DifferentialSeed, tmp_path: Path) -> list[int]:
    divergent: list[int] = []
    for index, actions in enumerate(SEQUENCES):
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        if _assert_sequence_matches(seed, case_dir, actions) is not None:
            divergent.append(index)
    return divergent


def test_allowed_divergence_occurs_exactly_where_recorded(
    differential_seed: DifferentialSeed, tmp_path: Path
) -> None:
    """Make the recorded divergences observable: the documented exception must
    fire on exactly these corpus sequences, no more and no fewer."""
    assert _divergent_sequences(differential_seed, tmp_path) == EXPECTED_DIVERGENT_SEQUENCES
