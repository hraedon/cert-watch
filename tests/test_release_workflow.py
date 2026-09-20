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


def test_published_image_is_signed_and_attested() -> None:
    """Provenance for the artefact a trust-hygiene tool asks its own users to trust.

    Three parts, and each is useless without the others: the push must attach
    an SBOM and provenance, the signature must cover the *digest* (a tag can be
    repointed at an unsigned image), and the signing step must run on the push
    output rather than on tags computed earlier in the job.
    """
    import yaml

    workflow = yaml.safe_load(_workflow("release.yml"))
    job = workflow["jobs"]["build-and-bump"]
    steps = job["steps"]

    assert job["permissions"].get("id-token") == "write", (
        "keyless cosign signing needs an OIDC token"
    )

    push = next(s for s in steps if s.get("id") == "push")
    assert push["with"]["push"] is True
    assert push["with"]["sbom"] is True
    assert push["with"]["provenance"] == "mode=max"

    # The scan build loads into the docker daemon, which cannot carry
    # attestations; leaving them on would fail the build outright.
    scan = next(s for s in steps if s.get("with", {}).get("load") is True)
    assert scan["with"]["provenance"] is False
    assert scan["with"]["sbom"] is False

    sign = next(s for s in steps if "cosign sign" in (s.get("run") or ""))
    assert "steps.push.outputs.digest" in sign["env"]["DIGEST"]
    assert "${IMAGE}@${DIGEST}" in sign["run"], "sign the digest, not a tag"
    assert steps.index(sign) > steps.index(push)


def test_the_signature_is_verified_before_the_deployment_pointer_moves() -> None:
    """Signing without verifying only proves the workflow reached the sign step.

    The bump is what puts an image in front of users, so the gate belongs
    between the two: the digest must verify against this workflow's exact
    keyless identity at a release ref, and the attestations must describe this
    commit, before anything repoints the cluster. An identity regex loose
    enough to match any ref would accept a signature minted by a run of this
    file on an attacker's branch.
    """
    import yaml

    workflow = yaml.safe_load(_workflow("release.yml"))
    steps = workflow["jobs"]["build-and-bump"]["steps"]

    verify = next(s for s in steps if "cosign verify" in (s.get("run") or ""))
    sign = next(s for s in steps if "cosign sign" in (s.get("run") or ""))
    bump = next(s for s in steps if "bump_deploy_image" in (s.get("run") or ""))
    assert steps.index(sign) < steps.index(verify) < steps.index(bump)

    assert "steps.push.outputs.digest" in verify["env"]["DIGEST"]
    assert "${IMAGE}@${DIGEST}" in verify["run"], "verify the digest, not a tag"
    assert (
        verify["env"]["IDENTITY"]
        == "https://github.com/${{ github.repository }}"
        "/.github/workflows/release.yml@${{ github.ref }}"
    )
    assert "--certificate-identity \"${IDENTITY}\"" in verify["run"]
    assert (
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in verify["run"]
    )
    assert "verify_release_attestations.py" in verify["run"]
    assert "--commit \"${GITHUB_SHA}\"" in verify["run"]

    # The identity is only anchored because the workflow cannot run from an
    # arbitrary ref in the first place.
    triggers = workflow[True]["push"]
    assert triggers["branches"] == ["main"]
    assert triggers["tags"] == ["v*"]

    installer = next(s for s in steps if "cosign-installer" in (s.get("uses") or ""))
    assert installer["with"]["cosign-release"].startswith("v"), (
        "pin the cosign binary, not just the action that downloads it"
    )


def test_dependabot_watches_what_the_monthly_lock_refresh_cannot() -> None:
    """Actions and base images are digest-pinned, so nothing else ages them.

    `dependency-update.yml` re-resolves `uv.lock` monthly, which covers Python
    only. The pins this repository adds for supply-chain reasons — action SHAs,
    base-image digests — are inert by design and stay on a stale, eventually
    unsupported version unless something proposes the bump.
    """
    import yaml

    config = yaml.safe_load((Path(__file__).parents[1] / ".github" / "dependabot.yml").read_text())
    ecosystems = {entry["package-ecosystem"] for entry in config["updates"]}

    assert {"github-actions", "docker"} <= ecosystems

    # Bumps to the actions that build, scan and sign the published image are
    # separated from the grouped bump of everything else: main takes direct
    # pushes, so a release-pipeline pin should not arrive inside a PR whose
    # interesting content is a linter bump.
    actions = next(e for e in config["updates"] if e["package-ecosystem"] == "github-actions")
    pipeline = set(actions["groups"]["release-pipeline"]["patterns"])
    assert {"docker/*", "sigstore/*", "aquasecurity/*"} == pipeline
    assert pipeline <= set(actions["groups"]["actions"]["exclude-patterns"])
    assert "pip" not in ecosystems, (
        "uv.lock is the source of truth and Dependabot cannot round-trip it; "
        "dependency-update.yml owns Python"
    )


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
