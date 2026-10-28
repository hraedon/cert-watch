"""The Windows install closure comes from uv.lock, by hash, never a live resolve.

A bare ``pip install <checkout>`` re-resolved every dependency from the index
at install time, so a server could land on versions CI never tested. The
installer now installs hash-locked files exported from uv.lock and then the
project with ``--no-deps``. These tests keep the exports in step with uv.lock
and keep the installers from drifting back to a floating install.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INSTALLER = ROOT / "scripts" / "install-windows.ps1"
SMOKE = ROOT / ".github" / "workflows" / "deploy-smoke.yml"
LOCKS = ROOT / "deploy" / "iis"
REQUIREMENT = re.compile(r"^([a-z0-9][a-z0-9._-]*)==", re.IGNORECASE | re.MULTILINE)


def _packages(name: str) -> set[str]:
    return {match.lower() for match in REQUIREMENT.findall((LOCKS / name).read_text())}


def test_install_locks_match_uv_lock() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/export_install_locks.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_build_group_is_the_build_backend() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["dependency-groups"]["build"] == project["build-system"]["requires"]


def test_each_lock_carries_its_selection_and_only_hashed_pins() -> None:
    base = _packages("requirements.lock.txt")
    assert {"fastapi", "cryptography", "uvicorn"} <= base
    assert not {"ldap3", "authlib", "pywin32", "pytest", "hatchling"} & base
    assert {"ldap3", "authlib", "joserfc", "requests"} <= _packages("requirements-auth.lock.txt")
    assert base < _packages("requirements-auth.lock.txt")
    assert _packages("requirements-windows.lock.txt") == base | {"pywin32"}
    assert "hatchling" in _packages("requirements-build.lock.txt")
    for path in LOCKS.glob("requirements*.lock.txt"):
        text = path.read_text()
        # Every pin is followed by at least one hash; pip refuses the file
        # under --require-hashes otherwise, but fail here first.
        for block in re.split(r"\n(?=[a-z0-9])", text, flags=re.IGNORECASE):
            if REQUIREMENT.match(block):
                assert "--hash=sha256:" in block, f"{path.name}: {block.splitlines()[0]}"
        assert "-e " not in text and "file://" not in text


def _pip_installs(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines()
            if re.search(r"-m pip install\b", line) and not line.lstrip().startswith("#")]


def test_windows_installer_installs_by_hash_then_the_project_without_deps() -> None:
    text = INSTALLER.read_text()
    installs = _pip_installs(text)
    assert installs == [
        "& $venvPy -m pip install --require-hashes --only-binary :all: -r $requirements",
        "& $venvPy -m pip install --require-hashes --only-binary :all: -r $buildRequirements",
        "& $venvPy -m pip install --upgrade --no-build-isolation --no-deps $pkg",
    ]
    assert '"requirements-auth.lock.txt"' in text and '"requirements.lock.txt"' in text
    assert "deploy\\iis\\requirements-build.lock.txt" in text
    # The default and -WithAuthExtras selections are the only runtime locks.
    assert re.search(
        r'\$lockName = if \(\$WithAuthExtras\) \{ "requirements-auth\.lock\.txt" \}'
        r' else \{ "requirements\.lock\.txt" \}',
        text,
    )


def test_event_log_extra_installs_by_hash_in_smoke_and_runbooks() -> None:
    expected = (
        "pip install --require-hashes --only-binary :all: "
        "-r deploy\\iis\\requirements-windows.lock.txt"
    )
    assert [line for line in _pip_installs(SMOKE.read_text())] == [
        "& $venvPy -m " + expected,
    ]
    for runbook in ("deploy/iis/README.md", "docs/install.md"):
        text = (ROOT / runbook).read_text()
        assert expected in text, runbook
        assert not re.search(r"pip install (--upgrade )?(\$package|\"cert-watch\[)", text), runbook


def test_monthly_lock_refresh_re_exports_the_install_locks() -> None:
    workflow = (ROOT / ".github" / "workflows" / "dependency-update.yml").read_text()
    refresh = workflow.index("run: uv lock")
    export = workflow.index("run: python3 scripts/export_install_locks.py")
    assert refresh < export < workflow.index("create-pull-request")
    assert "deploy/iis/requirements*.lock.txt" in workflow
