"""Structural regression checks for the publish gate wiring."""

from __future__ import annotations

from pathlib import Path

_WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"


def _workflow(name: str) -> str:
    return (_WORKFLOWS / name).read_text()


def test_release_waits_for_exact_commit_gates_and_accepts_version_tags() -> None:
    release = _workflow("release.yml")

    assert "tags:\n      - 'v*'" in release
    for name in ("ci", "e2e", "deploy-smoke"):
        assert f"uses: ./.github/workflows/{name}.yml" in release
    assert "needs: [ci, e2e, deploy-smoke]" in release


def test_reusable_gates_run_directly_on_pull_requests() -> None:
    for name in ("ci", "e2e", "deploy-smoke"):
        workflow = _workflow(f"{name}.yml")
        assert "workflow_call:" in workflow
        assert "pull_request:" in workflow


def test_tag_release_cannot_write_deployment_manifests() -> None:
    """Every step that can move the deployment pointer must be main-only.

    Checked by walking the steps rather than by indexing two step names. The
    name-pinned form broke the moment the steps were renamed, and — worse —
    could only ever vouch for the two steps it named: a newly added step that
    wrote a manifest without the guard was invisible to it. A tag build
    publishes an image for a commit that is not main's tip; letting one rewrite
    the kustomization would point the cluster wherever that tag happens to be.
    """
    import yaml

    workflow = yaml.safe_load(_workflow("release.yml"))
    steps = workflow["jobs"]["build-and-bump"]["steps"]
    writes_manifests = [
        step for step in steps
        if any(token in (step.get("run") or "")
               for token in ("kustomize edit", "bump_deploy_image", "kustomization.yaml"))
    ]

    assert writes_manifests, "no manifest-writing step found — has the bump moved?"
    for step in writes_manifests:
        assert step.get("if") == "github.ref == 'refs/heads/main'", (
            f"step {step.get('name')!r} can write deployment manifests without the "
            "main-only guard"
        )

    assert "Tag $release_tag disagrees with pyproject.toml version" in _workflow("release.yml")
    assert "Tag $release_tag disagrees with _version.txt version" in _workflow("release.yml")


def test_the_deployment_bump_is_the_last_step_of_the_release() -> None:
    """`bump_deploy_image.py` resets the checkout to the remote tip.

    That is safe only because the image has already been built, scanned and
    pushed from this checkout by the time it runs. A step added after it would
    silently operate on main's tip instead of the commit the release is for —
    a difference that would not show up until two merges landed close together,
    which is the same rare timing that produced #35 in the first place.
    """
    import yaml

    workflow = yaml.safe_load(_workflow("release.yml"))
    steps = workflow["jobs"]["build-and-bump"]["steps"]

    assert "bump_deploy_image" in (steps[-1].get("run") or ""), (
        "the deployment bump must remain the final step; it rewinds the checkout"
    )


def test_windows_smoke_installs_production_preload_prerequisite() -> None:
    smoke = _workflow("deploy-smoke.yml")
    install = smoke.index("Install-WindowsFeature Web-AppInit")
    verify = smoke.index("Verify deployment (structured report)", install)

    assert install < verify
    assert "ApplicationInitializationModule is not registered" in smoke
    assert "warmup.dll" in smoke


def test_version_tag_computation_in_isolated_repository(tmp_path) -> None:
    """Exercise the actual workflow shell without building or publishing an image.

    The script reads ``pyproject.toml`` with ``python3 -c ... tomllib``. On the
    runner that is Python 3.12; on a dev box ``python3`` is whatever the distro
    ships (Ubuntu 22.04: 3.10, no ``tomllib``), which failed the test for a
    property of the host rather than of the workflow. The interpreter running
    the tests is >=3.12 by ``requires-python``, so shim it in as ``python3``.
    """
    import os
    import subprocess
    import sys

    import yaml

    workflow = yaml.safe_load(_workflow("release.yml"))
    step = next(s for s in workflow["jobs"]["build-and-bump"]["steps"] if s.get("id") == "tag")
    script = step["run"].replace("${{ github.repository_owner }}", "test-owner")
    (tmp_path / "src/cert_watch").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion="1.2.3"\n')
    (tmp_path / "src/cert_watch/_version.txt").write_text("1.2.3\n")

    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-q")
    git("add", ".")
    git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "commit", "-qm",
        "Release fixture\n\nCo-Authored-By: GPT-6 <noreply@openai.com>")
    git("tag", "v1.2.3")
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "python3").symlink_to(sys.executable)

    output = tmp_path / "outputs"
    env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3",
           "GITHUB_OUTPUT": str(output),
           "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}"}
    command = ["bash", "-e", "-o", "pipefail", "-c", script]
    valid = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True)
    assert valid.returncode == 0, valid.stderr.decode()
    assert "cert-watch:v1.2.3" in output.read_text()
    assert "cert-watch:latest" not in output.read_text()

    (tmp_path / "pyproject.toml").write_text('[project]\nversion="1.2.2"\n')
    mismatch = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True)
    assert mismatch.returncode != 0
    assert b"disagrees with pyproject.toml" in mismatch.stderr

    git("tag", "-d", "v1.2.3")
    git("tag", "vnot-a-release")
    env["GITHUB_REF_NAME"] = "vnot-a-release"
    invalid = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True)
    assert invalid.returncode != 0
    assert b"must be a semantic version" in invalid.stderr
