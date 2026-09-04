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
