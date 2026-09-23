"""SQL date arithmetic follows the application clock, never SQLite's wall clock.

Queries that derived urgency buckets and day counts from ``julianday('now')``
read the process wall clock, so frozen test time and injected clocks silently
stopped applying to them. The page-HTML goldens went red on 2026-09-23 without
a code change because ``browse?view=issuer`` rendered a day count computed by
SQLite while every Python-derived value on the page followed the frozen clock.

These tests pin the reference instant decades away from the real date in both
directions, so any query still reading SQLite's ``'now'`` disagrees with the
Python-side urgency no matter when the suite runs. The static guard at the end
keeps new ``'now'`` literals out of SQL.
"""

from __future__ import annotations

import ast
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from freezegun import freeze_time

from cert_watch.certificate_model import Certificate
from cert_watch.database import (
    SqliteCertificateRepository,
    SqliteHostRepository,
    dashboard_expiry_stats,
    init_schema,
    list_dashboard_grouped_page,
    list_fleet_pivot,
    replace_scanned,
)

PAST = datetime(2001, 3, 4, 12, tzinfo=UTC)
FUTURE = datetime(2099, 3, 4, 12, tzinfo=UTC)

# Offsets straddle every bucket boundary and exercise the CAST truncation
# (6.9 days is critical, 29.9 is warning, 60.25 is 60 days).
OFFSETS = {
    "expired.example.test": timedelta(days=-1),
    "critical.example.test": timedelta(days=6, hours=22),
    "warning-low.example.test": timedelta(days=7, hours=12),
    "warning-high.example.test": timedelta(days=29, hours=22),
    "healthy.example.test": timedelta(days=60, hours=6),
}


def _python_days(delta: timedelta) -> int:
    return delta.days


def _python_urgency(days: int) -> str:
    if days < 0:
        return "expired"
    if days < 7:
        return "critical"
    if days < 30:
        return "warning"
    return "healthy"


def _seed(db: Path, ref: datetime) -> None:
    init_schema(db)
    for name, delta in OFFSETS.items():
        SqliteHostRepository(db).add(name, 443)
        cert = Certificate(
            subject=f"CN={name}",
            issuer=f"CN=CA for {name}",
            not_before=ref - timedelta(days=365),
            not_after=ref + delta,
            fingerprint_sha256=name,
        )
        replace_scanned(db, name, 443, cert, [], True)


@pytest.fixture(autouse=True)
def _public_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    # Chain grading can lift urgency; this file is about the clock only.
    monkeypatch.setattr("cert_watch.cert_chain.chain_status", lambda *args: "public")


def _expected_buckets() -> dict[str, int]:
    counts = {"expired": 0, "critical": 0, "warning": 0, "healthy": 0}
    for delta in OFFSETS.values():
        counts[_python_urgency(_python_days(delta))] += 1
    return counts


@pytest.mark.parametrize("ref", [PAST, FUTURE], ids=["past", "future"])
@pytest.mark.parametrize("mode", ["frozen", "injected"])
def test_sql_urgency_matches_python_days_remaining(
    tmp_path: Path, ref: datetime, mode: str
) -> None:
    db = tmp_path / "clock.sqlite3"
    _seed(db, ref)
    kwargs = {"now": ref} if mode == "injected" else {}

    def run_queries() -> None:
        # Fleet pivot: per-group day count and worst urgency come from SQL.
        groups = {
            g["key"]: g for g in list_fleet_pivot(db, "issuer", **kwargs)
        }
        for name, delta in OFFSETS.items():
            group = groups[f"CA for {name}"]
            days = _python_days(delta)
            expected_days = -1 if delta < timedelta(0) else days
            assert group["earliest_expiry"] == expected_days, name
            assert group["worst_urgency"] == _python_urgency(days), name

        # Home expiry cards: SQL CASE buckets.
        assert dashboard_expiry_stats(db, **kwargs) == _expected_buckets()

        # Grouped Browse: the SQL HAVING filter on urgency rank must select
        # the same rows the Python urgency labels. Its Python half reads the
        # process clock, so it takes no injected instant; frozen time only.
        if mode == "frozen":
            for urgency in ("expired", "critical", "warning", "healthy"):
                entries, _ = list_dashboard_grouped_page(
                    db, urgency=urgency, per_page=0
                )
                got = sorted(e["host"].split(":")[0] for e in entries)
                want = sorted(
                    name
                    for name, delta in OFFSETS.items()
                    if _python_urgency(_python_days(delta)) == urgency
                )
                assert got == want, urgency

        # Repository window query.
        within = SqliteCertificateRepository(db).list_expiring_within(30, **kwargs)
        assert sorted(c.subject.removeprefix("CN=") for c in within) == sorted(
            name for name, delta in OFFSETS.items() if delta <= timedelta(days=30)
        )

    if mode == "frozen":
        with freeze_time(ref):
            run_queries()
    else:
        # Wall clock left alone: only the injected reference may apply.
        run_queries()


# --- static guard -----------------------------------------------------------

_SRC = Path(__file__).resolve().parents[1] / "src" / "cert_watch"
_SQL_WALL_CLOCK = re.compile(
    r"'now'|\bCURRENT_(?:TIMESTAMP|DATE|TIME)\b", re.IGNORECASE
)
# Paths (relative to src/cert_watch) allowed to read SQLite's clock, with why.
_ALLOWLIST: dict[str, str] = {
    # Migrations stamp schema_migrations.applied_at with the real time the
    # migration ran. That is bookkeeping, not application logic, and must
    # never follow an injected or frozen clock.
    "migrations/": "applied_at bookkeeping records real migration time",
}


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            ids.add(id(node.value))
    return ids


def _wall_clock_sql_literals(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    skip = _docstring_ids(tree)
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in skip
            and _SQL_WALL_CLOCK.search(node.value)
        ):
            hits.append((node.lineno, node.value.strip()[:80]))
    return hits


def test_no_sqlite_wall_clock_in_sql_literals() -> None:
    offenders: list[str] = []
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()
        if any(rel.startswith(prefix) for prefix in _ALLOWLIST):
            continue
        for lineno, text in _wall_clock_sql_literals(path):
            offenders.append(f"{rel}:{lineno}: {text}")
    assert not offenders, (
        "SQL reads SQLite's wall clock ('now' / CURRENT_TIMESTAMP). Bind "
        "cert_watch.database.connection._sql_now(now) as a parameter instead:\n"
        + "\n".join(offenders)
    )


def test_static_guard_detects_now_literal(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        '"""Docstrings may mention \'now\'."""\n'
        "SQL = \"SELECT julianday('now')\"\n"
        "OTHER = f\"SELECT {1} WHERE x < CURRENT_TIMESTAMP\"\n",
        encoding="utf-8",
    )
    assert [line for line, _ in _wall_clock_sql_literals(sample)] == [2, 3]
