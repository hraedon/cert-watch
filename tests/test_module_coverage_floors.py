"""Per-module coverage floors for security-critical modules.

Prevents a security-critical module from silently dropping to low coverage
while the global average stays high. This is a *ratchet*: floors are set at
current actual percentages (rounded down). ONLY GOES UP — if coverage improves,
raise the floor.

Run with the full suite so coverage.json reflects real numbers:
    pytest --cov=cert_watch --cov-report=json:coverage.json -n auto
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

COVERAGE_JSON = Path(__file__).resolve().parent.parent / "coverage.json"

MODULE_FLOORS: dict[str, int] = {
    "src/cert_watch/auth/ldap_provider.py": 90,
    "src/cert_watch/auth/oauth_provider.py": 84,
    "src/cert_watch/middleware.py": 88,
    "src/cert_watch/security.py": 100,
    "src/cert_watch/routes/settings.py": 86,
    "src/cert_watch/scan.py": 99,
}


def _load_coverage() -> dict:
    return json.loads(COVERAGE_JSON.read_text(encoding="utf-8"))


# coverage.json is .gitignored and pytest-cov only writes it at session end, so
# in a single-pass run (local or CI) it is absent while this test executes —
# hence skipif, not a hard fail. A prior "hardening" change turned this into
# pytest.fail(), which broke CI because the gate cannot be satisfied in a single
# pass. Until CI does a two-pass run (generate coverage.json, then run these),
# the floors only enforce when a coverage.json from an earlier run is present.
@pytest.mark.skipif(not COVERAGE_JSON.exists(), reason="coverage.json not found")
@pytest.mark.parametrize(
    "path,floor",
    list(MODULE_FLOORS.items()),
    ids=[p.split("/")[-1] for p in MODULE_FLOORS],
)
def test_module_coverage_floor(path: str, floor: int):
    data = _load_coverage()
    files = data.get("files", {})
    assert path in files, (
        f"{path} not found in coverage.json — file may have been renamed "
        f"or coverage.json is stale/partial"
    )
    actual = files[path]["summary"]["percent_covered"]
    assert actual >= floor, (
        f"{path} coverage is {actual:.1f}%, floor is {floor}%. "
        f"Either fix the coverage drop or lower the floor if this is intentional."
    )
