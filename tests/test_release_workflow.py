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
    release = _workflow("release.yml")
    main_only = "if: github.ref == 'refs/heads/main'"

    bump = release.index("- name: Bump kustomize image tag")
    commit = release.index("- name: Commit tag bump")
    assert main_only in release[bump:commit]
    assert main_only in release[commit:]
    assert "Tag $release_tag disagrees with pyproject.toml version" in release
    assert "Tag $release_tag disagrees with _version.txt version" in release


def test_windows_smoke_installs_production_preload_prerequisite() -> None:
    smoke = _workflow("deploy-smoke.yml")
    install = smoke.index("Install-WindowsFeature Web-AppInit")
    verify = smoke.index("Verify deployment (structured report)", install)

    assert install < verify
    assert "ApplicationInitializationModule is not registered" in smoke
    assert "warmup.dll" in smoke


def test_version_tag_computation_in_isolated_repository(tmp_path) -> None:
    """Exercise the actual workflow shell without building or publishing an image."""
    import os
    import subprocess

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
    output = tmp_path / "outputs"
    env = {**os.environ, "GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3",
           "GITHUB_OUTPUT": str(output)}
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
