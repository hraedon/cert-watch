"""Every opt-in test module has a named runner (WI-149).

The default marker expression skips ``integration``, ``e2e`` and ``deploy``
tests, so each module carrying one of those markers runs only where something
selects it on purpose. Fifteen root-level integration tests once ran nowhere
because the CI step listed files by name. This inventory fails when a marked
module has no owner, or when an owner's selector disappears from the file that
is supposed to run it.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"

_OPT_IN = re.compile(r"pytest\.mark\.(integration|deploy)\b")

# path prefix (relative to the repo) -> (file that runs it, selector text in that file)
OWNERS: dict[str, tuple[str, str]] = {
    "tests/integration/": (
        ".github/workflows/ci.yml", "pytest -m integration tests/integration",
    ),
    "tests/e2e/test_ldap_login.py": (
        ".github/workflows/e2e.yml", "tests/e2e/test_ldap_login.py",
    ),
    # Needs a real directory; run against the lab with CW_LDAP_E2E=1.
    "tests/e2e/test_ldap_login_real.py": (
        "scripts/e2e/ldap-e2e.sh", "tests/e2e/test_ldap_login_real.py",
    ),
    # Local mirrors of the shell checks deploy-smoke.yml runs on every PR and
    # release (Docker, Linux entrypoint, kind); kept for running by hand.
    "tests/deploy/": (".github/workflows/deploy-smoke.yml", "Verify /readyz"),
    # Everything else under tests/: selected by directory, minus the above.
    "tests/": (
        ".github/workflows/ci.yml",
        "--ignore=tests/e2e --ignore=tests/integration --ignore=tests/deploy",
    ),
}


def _owner(relative: str) -> str:
    # Longest prefix wins, so "tests/" is only the fallback.
    matches = [prefix for prefix in OWNERS if relative.startswith(prefix)]
    return max(matches, key=len)


def _opt_in_modules() -> list[str]:
    return sorted(
        path.relative_to(ROOT).as_posix()
        for path in TESTS.rglob("test_*.py")
        if _OPT_IN.search(path.read_text(encoding="utf-8"))
    )


def test_the_inventory_sees_the_known_opt_in_modules():
    modules = _opt_in_modules()
    # The two modules WI-149 found unselected, and one per other owner.
    for expected in (
        "tests/test_scan_integration.py",
        "tests/test_ssrf_integration.py",
        "tests/test_alert_targets.py",
        "tests/integration/test_samba_ad_real.py",
        "tests/e2e/test_ldap_login.py",
        "tests/deploy/test_docker.py",
    ):
        assert expected in modules


def test_every_e2e_integration_module_has_an_explicit_owner():
    """tests/e2e is excluded from the directory-wide CI step, so a new
    integration module there needs its own entry."""
    orphans = [
        module for module in _opt_in_modules()
        if module.startswith("tests/e2e/") and _owner(module) == "tests/"
    ]
    assert orphans == [], f"add these to OWNERS and to a workflow: {orphans}"


def test_every_owner_still_selects_its_tests():
    for prefix, (runner, selector) in OWNERS.items():
        text = (ROOT / runner).read_text(encoding="utf-8")
        flat = " ".join(text.split())  # YAML folded scalars span lines
        assert selector in flat, f"{runner} no longer selects {prefix} ({selector!r})"
