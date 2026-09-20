"""The release gate that reads the attestations instead of assuming them.

The fixtures below are the shapes `docker buildx imagetools inspect` actually
emits for an index pushed with `provenance: mode=max` and `sbom: true`
(captured from a real buildx push; trimmed to the fields the gate reads).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_release_attestations.py"
COMMIT = "599cd57c66d25bac2b8e3bf00b131dc5f4425efe"
SHORT = "599cd57"
PLATFORMS = ("linux/amd64", "linux/arm64")


def _provenance(
    *, short_commit: str = SHORT, revision: str | None = COMMIT,
) -> dict[str, Any]:
    root_args: dict[str, str] = {"build-arg:GIT_COMMIT": short_commit}
    if revision is not None:
        root_args["vcs:revision"] = revision
    predicate = {
        "buildDefinition": {
            "externalParameters": {
                "configSource": {"path": "Dockerfile"},
                "request": {
                    "frontend": "dockerfile.v0",
                    "args": {"build-arg:GIT_COMMIT": short_commit},
                    "root": {"request": {"args": root_args}},
                },
            },
        },
    }
    return {platform: {"SLSA": predicate} for platform in PLATFORMS}


def _sbom(*, packages: int = 3) -> dict[str, Any]:
    spdx = {"SPDXID": "SPDXRef-DOCUMENT", "packages": [{"name": f"p{i}"} for i in range(packages)]}
    return {platform: {"SPDX": spdx} for platform in PLATFORMS}


def _run(
    tmp_path: Path, provenance: object, sbom: object, *, commit: str = COMMIT,
) -> tuple[int, str]:
    (tmp_path / "prov.json").write_text(json.dumps(provenance))
    (tmp_path / "sbom.json").write_text(json.dumps(sbom))
    result = subprocess.run(
        [
            sys.executable, str(SCRIPT),
            "--provenance", str(tmp_path / "prov.json"),
            "--sbom", str(tmp_path / "sbom.json"),
            "--commit", commit,
            "--short-commit", SHORT,
            *[arg for platform in PLATFORMS for arg in ("--platform", platform)],
        ],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout + result.stderr


def test_attestations_describing_the_released_commit_pass(tmp_path: Path) -> None:
    code, output = _run(tmp_path, _provenance(), _sbom())

    assert code == 0, output
    assert COMMIT in output


def test_provenance_for_another_commit_is_refused(tmp_path: Path) -> None:
    """The failure an unread attestation hides: a signed image of something else."""
    code, output = _run(tmp_path, _provenance(short_commit="0badc0d"), _sbom())

    assert code == 1
    assert "build-arg:GIT_COMMIT" in output


def test_provenance_from_another_revision_is_refused(tmp_path: Path) -> None:
    code, output = _run(tmp_path, _provenance(revision="f" * 40), _sbom())

    assert code == 1
    assert "vcs:revision" in output


def test_a_missing_vcs_revision_is_not_treated_as_a_mismatch(tmp_path: Path) -> None:
    """buildkit only records it when it can see the git metadata; the build arg
    is what the workflow itself controls, so absence must not fail a release."""
    code, output = _run(tmp_path, _provenance(revision=None), _sbom())

    assert code == 0, output


@pytest.mark.parametrize("missing", PLATFORMS)
def test_a_platform_published_without_provenance_is_refused(
    tmp_path: Path, missing: str,
) -> None:
    provenance = _provenance()
    provenance[missing] = {}

    code, output = _run(tmp_path, provenance, _sbom())

    assert code == 1
    assert f"{missing}: no SLSA provenance" in output


def test_an_empty_sbom_is_refused(tmp_path: Path) -> None:
    code, output = _run(tmp_path, _provenance(), _sbom(packages=0))

    assert code == 1
    assert "no SBOM packages" in output


def test_an_index_with_no_attestations_at_all_is_refused(tmp_path: Path) -> None:
    """What the registry returns when the exporters are silently disabled."""
    code, output = _run(tmp_path, {}, {})

    assert code == 1
    for platform in PLATFORMS:
        assert f"{platform}: no SLSA provenance" in output
