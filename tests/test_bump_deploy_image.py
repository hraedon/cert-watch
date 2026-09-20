"""The image pointer must only ever move forward (cert-watch #35).

These build real git repositories with a real remote rather than mocking git.
The bug being fixed is entirely about what two processes observe about a shared
ref at different moments, and a mocked ``git push`` cannot be rejected by a
remote that moved -- it would assert the fix's own assumptions back at it.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "bump_deploy_image.py"
IMAGE = "ghcr.io/hraedon/cert-watch"
KUSTOMIZATION_DIRS = ("deploy/k8s", "deploy/k8s-demo")


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()


def _kustomization(tag: str) -> str:
    return (
        "apiVersion: kustomize.config.k8s.io/v1beta1\n"
        "kind: Kustomization\n"
        "resources:\n"
        "- deployment.yaml\n"
        "images:\n"
        f"- name: {IMAGE}\n"
        f"  newName: {IMAGE}\n"
        f"  newTag: {tag}\n"
    )


def _write_kustomizations(repo: Path, tag: str) -> None:
    for directory in KUSTOMIZATION_DIRS:
        (repo / directory).mkdir(parents=True, exist_ok=True)
        (repo / directory / "kustomization.yaml").write_text(_kustomization(tag))


def _fake_kustomize(tmp_path: Path) -> str:
    """A stand-in for `kustomize edit set image` — the real binary is not in CI's PATH here.

    It rewrites `newTag` exactly as kustomize does for this file shape. The
    script's own logic, not kustomize's, is what these tests are about.
    """
    script = tmp_path / "kustomize"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib, re, sys\n"
        "tag = sys.argv[-1].rsplit(':', 1)[1]\n"
        "p = pathlib.Path('kustomization.yaml')\n"
        "p.write_text(re.sub(r'newTag: .*', f'newTag: {tag}', p.read_text()))\n"
    )
    script.chmod(0o755)
    return str(script)


@pytest.fixture
def estate(tmp_path):
    """An origin with one commit, plus two clones standing in for two release runs."""
    origin = tmp_path / "origin.git"
    seed = tmp_path / "seed"
    seed.mkdir()
    _git("init", "-q", "-b", "main", cwd=seed)
    _git("config", "user.email", "t@example.invalid", cwd=seed)
    _git("config", "user.name", "Test", cwd=seed)
    _write_kustomizations(seed, "seed")
    _git("add", "-A", cwd=seed)
    _git("commit", "-qm", "seed", cwd=seed)
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    _git("remote", "add", "origin", str(origin), cwd=seed)
    _git("push", "-q", "origin", "main", cwd=seed)

    def clone(name: str) -> Path:
        path = tmp_path / name
        subprocess.run(["git", "clone", "-q", str(origin), str(path)], check=True)
        _git("config", "user.email", "t@example.invalid", cwd=path)
        _git("config", "user.name", "Test", cwd=path)
        return path

    return {"origin": origin, "seed": seed, "clone": clone,
            "kustomize": _fake_kustomize(tmp_path)}


def _commit_on(repo: Path, message: str) -> str:
    (repo / f"{message}.txt").write_text(message)
    _git("add", "-A", cwd=repo)
    _git("commit", "-qm", message, cwd=repo)
    return _git("rev-parse", "--short", "HEAD", cwd=repo)


def _digest(seed: str = "a") -> str:
    """A syntactically valid sha256 digest for the fake estate."""
    return f"sha256:{seed * 64}"


def _run(repo: Path, *, image_tag: str, kustomize: str, attempts: int = 5,
         digest: str | None = None):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--image-tag", image_tag,
         "--digest", digest or _digest(), "--image", IMAGE,
         "--repo", str(repo), "--kustomize", kustomize, "--attempts", str(attempts)],
        capture_output=True, text=True,
    )


def _published_tag(estate) -> str:
    show = subprocess.run(
        ["git", "show", f"main:{KUSTOMIZATION_DIRS[0]}/kustomization.yaml"],
        cwd=estate["origin"], capture_output=True, text=True, check=True,
    ).stdout
    return [ln for ln in show.splitlines() if "newTag:" in ln][0].split(":")[1].strip()


def _published_kustomization(estate) -> str:
    return subprocess.run(
        ["git", "show", f"main:{KUSTOMIZATION_DIRS[0]}/kustomization.yaml"],
        cwd=estate["origin"], capture_output=True, text=True, check=True,
    ).stdout


def test_bump_pins_the_verified_digest_alongside_the_tag(estate):
    """The deploy pointer is digest-pinned: kustomize renders the digest over
    the tag, so the cluster pulls exactly the image the release job verified."""
    run_a = estate["clone"]("run-a")
    sha = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    digest = _digest("b")
    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"], digest=digest)

    assert result.returncode == 0, result.stderr
    published = _published_kustomization(estate)
    assert f"newTag: {sha}" in published
    assert f"digest: {digest}" in published


def test_digest_replaces_an_existing_pin(estate):
    for directory in KUSTOMIZATION_DIRS:
        k = estate["seed"] / directory / "kustomization.yaml"
        k.write_text(k.read_text().replace(
            "newTag: seed\n", f"newTag: seed\n  digest: {_digest('0')}\n",
        ))
    _git("add", "-A", cwd=estate["seed"])
    _git("commit", "-qm", "pre-pin digest", cwd=estate["seed"])
    _git("push", "-q", "origin", "main", cwd=estate["seed"])

    run_a = estate["clone"]("run-a2")
    sha = _commit_on(run_a, "feature-a2")
    _git("push", "-q", "origin", "main", cwd=run_a)

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"], digest=_digest("c"))

    assert result.returncode == 0, result.stderr
    published = _published_kustomization(estate)
    assert f"digest: {_digest('c')}" in published
    assert _digest("0") not in published


def test_a_malformed_digest_fails_before_touching_the_repo(estate):
    run_a = estate["clone"]("run-a3")
    sha = _commit_on(run_a, "feature-a3")
    _git("push", "-q", "origin", "main", cwd=run_a)

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"], digest="not-a-digest")

    assert result.returncode != 0
    assert "digest" in result.stderr


def test_bump_lands_when_nothing_else_is_racing(estate):
    run_a = estate["clone"]("run-a")
    sha = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert _published_tag(estate) == sha


def test_a_newer_release_is_not_overwritten_by_an_older_one(estate):
    """The regression this script exists for.

    Rebase-then-push -- the obvious fix for the non-fast-forward rejection --
    lands A's pointer after B's and silently deploys the older image. Nothing
    goes red; the estate just runs one commit behind.
    """
    run_a = estate["clone"]("run-a")
    sha_a = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    run_b = estate["clone"]("run-b")
    _git("fetch", "-q", "origin", cwd=run_b)
    _git("reset", "--hard", "-q", "origin/main", cwd=run_b)
    sha_b = _commit_on(run_b, "feature-b")
    _git("push", "-q", "origin", "main", cwd=run_b)

    # B's release finishes first and publishes its pointer.
    assert _run(run_b, image_tag=sha_b, kustomize=estate["kustomize"]).returncode == 0
    assert _published_tag(estate) == sha_b

    # A's release, still checked out at A, finishes afterwards.
    result = _run(run_a, image_tag=sha_a, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert "withdrawing" in result.stdout
    assert _published_tag(estate) == sha_b, "the older image must not replace the newer one"


def test_a_stale_checkout_still_lands_when_it_is_the_newest_build(estate):
    """Main moving on is not by itself a reason to withhold the pointer.

    B's commit is on main but B's own release has not published a pointer --
    it may still be running, or it may have failed its gates. A's image is the
    newest one that actually exists, so it is the right thing to deploy, and
    the plain non-fast-forward failure #35 describes would have dropped it.
    """
    run_a = estate["clone"]("run-a")
    sha_a = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    run_b = estate["clone"]("run-b")
    _git("fetch", "-q", "origin", cwd=run_b)
    _git("reset", "--hard", "-q", "origin/main", cwd=run_b)
    _commit_on(run_b, "feature-b")
    _git("push", "-q", "origin", "main", cwd=run_b)

    result = _run(run_a, image_tag=sha_a, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert _published_tag(estate) == sha_a


def test_republishing_the_same_commit_is_a_no_op(estate):
    run_a = estate["clone"]("run-a")
    sha = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)
    assert _run(run_a, image_tag=sha, kustomize=estate["kustomize"]).returncode == 0
    before = _git("rev-parse", "main", cwd=estate["origin"])

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert _git("rev-parse", "main", cwd=estate["origin"]) == before, "no empty commit"


def test_an_unresolvable_published_tag_does_not_block_the_bump(estate):
    """`latest`, a semver tag, a shallow clone — 'I cannot tell' must not mean 'skip'.

    Withdrawing on a tag the script cannot reason about would freeze the
    pointer wherever it happens to be, which is the failure mode it exists to
    prevent, reached by a more embarrassing route.
    """
    seed = estate["seed"]
    _write_kustomizations(seed, "latest")
    _git("commit", "-qam", "point at a floating tag", cwd=seed)
    _git("push", "-q", "origin", "main", cwd=seed)

    run_a = estate["clone"]("run-a")
    sha = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert _published_tag(estate) == sha


def test_an_unreachable_origin_fails_loudly_rather_than_crashing(estate):
    """A remote that never answers must not be laundered into a benign 'race'.

    It must also not surface as a Python traceback: this runs in a release job
    where the first thing an operator sees is the failing step's tail, and a
    stack trace there reads as a broken script rather than an unreachable
    origin. Exit non-zero, say which, once the retries are spent.
    """
    run_a = estate["clone"]("run-a")
    sha = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)
    _git("remote", "set-url", "origin", str(estate["origin"]) + "-does-not-exist", cwd=run_a)

    result = _run(run_a, image_tag=sha, kustomize=estate["kustomize"], attempts=2)

    assert result.returncode == 1
    assert "Could not land the image bump" in result.stderr
    assert "could not fetch origin/main" in result.stderr
    assert "Traceback" not in result.stderr


def test_a_rejected_push_is_retried_from_the_refreshed_tip(estate):
    """The non-fast-forward rejection from #35 must be survived, not just avoided.

    A commit lands on main between this run's fetch and its push. The first
    push is rejected; the retry re-derives the bump from the new tip and lands
    it, because this run's image is still the newest one built.
    """
    run_a = estate["clone"]("run-a")
    sha_a = _commit_on(run_a, "feature-a")
    _git("push", "-q", "origin", "main", cwd=run_a)

    # A pre-push hook that lands an unrelated commit on origin the first time,
    # so this run's own push is rejected exactly as a concurrent merge would.
    hook = run_a / ".git" / "hooks" / "pre-push"
    interloper = estate["clone"]("interloper")
    hook.write_text(
        "#!/bin/sh\n"
        f'[ -f "{run_a}/.git/raced" ] && exit 0\n'
        f'touch "{run_a}/.git/raced"\n'
        f'cd "{interloper}" && git fetch -q origin && git reset --hard -q origin/main '
        "&& echo x > interloper.txt && git add -A "
        '&& git commit -qm interloper && git push -q origin main\n'
    )
    hook.chmod(0o755)

    result = _run(run_a, image_tag=sha_a, kustomize=estate["kustomize"])

    assert result.returncode == 0, result.stderr
    assert "push rejected, retrying" in result.stderr
    assert _published_tag(estate) == sha_a
