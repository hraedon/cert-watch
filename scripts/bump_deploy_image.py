"""Land the kustomize image bump on main without racing a concurrent release.

``release.yml`` builds an image for the commit that triggered it, then commits a
kustomization pointing at that image. The commit is made from a checkout pinned
to the triggering commit, so by the time it pushes, main may have moved --
``git push`` is rejected non-fast-forward and the run fails. The image is
already in ghcr at that point, so only the pointer is lost (cert-watch #35).

The obvious fix makes things worse
----------------------------------
Rebasing before the push resolves the *rejection* and introduces the exact
failure #35 was worried about. Two merges land close together:

    main:  A ──► B
    run(A): built image A, rebases its bump onto main and pushes  ── newTag: A
    run(B): built image B, pushed its bump first                  ── newTag: B

A's bump now lands *after* B's and the cluster is told to run the older image.
Nothing is red, ArgoCD deploys happily, and the estate is silently one commit
behind -- indistinguishable from a healthy deploy, which is the shape of
problem that stays unnoticed longest.

Concurrency groups do not fix it either, and ``release.yml`` already has one:
serialising the *runs* does not move A's checkout forward, so A still pushes a
pointer to A after B has landed.

What this does instead
----------------------
Each attempt re-derives the bump against the current remote tip, and the bump
is only kept when it would move the pointer *forward*:

* If the kustomization already names a commit that has this run's commit as an
  ancestor, a newer release won -- withdraw, exit 0, report it. Not an error:
  the pointer is already where this run wanted it or better.
* Otherwise apply, commit, push, and on a non-fast-forward rejection start over
  from the new tip.

The rule is a partial order, so it converges and never regresses regardless of
the order runs finish in. It cannot invent freshness: if the newest commit's
own release fails its gates, the pointer stays at the last commit that actually
built, which is the correct thing to deploy.

Run:  python scripts/bump_deploy_image.py --image-tag <short-sha> --digest sha256:... [--dry-run]

The pointer is a digest, not just a tag
--------------------------------------
The tag is only the *selector* for the supersession reasoning above; the
kustomization also pins ``digest:`` to the image digest the release job
verified (signature + attestations) immediately before calling this script.
Kustomize renders the digest over the tag, and a digest cannot be repointed,
so what Argo CD pulls is exactly what the pipeline verified -- not whatever
the mutable short-sha tag resolves to at sync time.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

KUSTOMIZATION_DIRS = ("deploy/k8s", "deploy/k8s-demo")
DEFAULT_ATTEMPTS = 5


class BumpError(RuntimeError):
    """The bump could not be landed and the caller should fail the run."""


def _git(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=check,
    )


def read_current_tag(kustomization: Path) -> str | None:
    """Return the ``newTag`` the kustomization currently names, if any.

    Parsed rather than loaded with a YAML library so this script stays runnable
    from a bare checkout with no dependencies installed -- it runs in the
    release job before (and independently of) the project venv.
    """
    if not kustomization.is_file():
        return None
    in_images = False
    for raw in kustomization.read_text(encoding="utf-8").splitlines():
        stripped = raw.strip()
        if not raw.startswith((" ", "\t", "-")) and stripped.endswith(":"):
            in_images = stripped == "images:"
            continue
        if in_images and stripped.startswith("newTag:"):
            return stripped.split(":", 1)[1].strip().strip("\"'") or None
    return None


def is_superseded(repo: Path, current_tag: str | None, image_tag: str) -> bool:
    """Does the pointer already name a commit at or ahead of ``image_tag``?

    An unresolvable tag (a semver tag, ``latest``, a commit not in this
    checkout's history) is treated as *not* superseding. Withdrawing on a tag we
    cannot reason about would leave the pointer wherever it happens to be, and
    the whole point of this script is that the pointer only moves forward --
    "I do not know" must fall through to the ordinary bump, never to a silent
    no-op.
    """
    if not current_tag:
        return False
    for ref in (current_tag, image_tag):
        if _git("rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}",
                cwd=repo, check=False).returncode != 0:
            return False
    if _git("rev-parse", current_tag, cwd=repo).stdout.strip() == _git(
        "rev-parse", image_tag, cwd=repo
    ).stdout.strip():
        return True
    # `--is-ancestor A B` -> A is an ancestor of B, so this asks whether the
    # commit we would publish is already behind the one that is published.
    return _git("merge-base", "--is-ancestor", image_tag, current_tag,
                cwd=repo, check=False).returncode == 0


def apply_bump(repo: Path, kustomize: str, image: str, image_tag: str, digest: str) -> None:
    for directory in KUSTOMIZATION_DIRS:
        subprocess.run(
            [kustomize, "edit", "set", "image", f"{image}={image}:{image_tag}"],
            cwd=repo / directory, check=True, capture_output=True, text=True,
        )
        _pin_digest(repo / directory / "kustomization.yaml", image, digest)


def _pin_digest(kustomization: Path, image: str, digest: str) -> None:
    """Set the ``digest:`` of *image*'s entry, inserting it after ``newTag:``.

    Text-based for the same reason read_current_tag is: this script runs from
    a bare checkout. The tag stays (it is what the supersession logic reasons
    about); the digest is what the rendered manifest pulls.
    """
    lines = kustomization.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    in_target_image = False
    wrote_digest = False
    insert_at: int | None = None
    insert_indent = "  "
    for raw in lines:
        stripped = raw.strip()
        indent = raw[: len(raw) - len(stripped)]
        if stripped.startswith("- name:"):
            in_target_image = stripped.split(":", 1)[1].strip().strip("\"'") == image
            out.append(raw)
            continue
        if in_target_image and stripped.startswith("newTag:"):
            out.append(raw)
            insert_at = len(out)
            insert_indent = indent
            continue
        if in_target_image and stripped.startswith("digest:"):
            out.append(f"{indent}digest: {digest}")
            wrote_digest = True
            continue
        if not raw.startswith((" ", "\t", "-")) and stripped:
            in_target_image = False
        out.append(raw)
    if not wrote_digest and insert_at is not None:
        out.insert(insert_at, f"{insert_indent}digest: {digest}")
    kustomization.write_text("\n".join(out) + "\n", encoding="utf-8")


def bump_once(
    repo: Path, *, kustomize: str, image: str, image_tag: str, digest: str,
    branch: str, dry_run: bool,
) -> str:
    """One attempt. Returns 'landed', 'superseded', 'unchanged', or 'retry'."""
    # Retryable, not fatal: a fetch fails for a network blip as readily as for a
    # renamed remote, and the two are indistinguishable here. Letting it raise
    # would end the run with a Python traceback in place of a diagnostic, which
    # reads as a broken script rather than an unreachable origin.
    fetched = _git("fetch", "--quiet", "origin", branch, cwd=repo, check=False)
    if fetched.returncode != 0:
        print(f"could not fetch origin/{branch}: {fetched.stderr.strip()}", file=sys.stderr)
        return "retry"
    _git("reset", "--hard", f"origin/{branch}", cwd=repo)

    current = read_current_tag(repo / KUSTOMIZATION_DIRS[0] / "kustomization.yaml")
    if is_superseded(repo, current, image_tag):
        return "superseded"

    apply_bump(repo, kustomize, image, image_tag, digest)
    if _git("diff", "--quiet", cwd=repo, check=False).returncode == 0:
        return "unchanged"

    _git("add", *[f"{d}/kustomization.yaml" for d in KUSTOMIZATION_DIRS], cwd=repo)
    _git("commit", "-m", f"chore(deploy): bump image to {image_tag}", cwd=repo)
    if dry_run:
        return "landed"
    pushed = _git("push", "origin", f"HEAD:{branch}", cwd=repo, check=False)
    if pushed.returncode == 0:
        return "landed"
    # Any push failure is retried from the refreshed tip. A persistent one
    # (permissions, protected branch) exhausts the attempts and fails loudly
    # rather than being mistaken for a race.
    print(f"push rejected, retrying from the new tip: {pushed.stderr.strip()}", file=sys.stderr)
    return "retry"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-tag", required=True, help="short SHA of the built image")
    parser.add_argument(
        "--digest", required=True,
        help="sha256 digest the release job verified; the deploy pointer pins it",
    )
    parser.add_argument("--image", default="ghcr.io/hraedon/cert-watch")
    parser.add_argument("--repo", default=".", type=Path)
    parser.add_argument("--kustomize", default="kustomize")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--attempts", default=DEFAULT_ATTEMPTS, type=int)
    parser.add_argument("--dry-run", action="store_true", help="commit locally, do not push")
    args = parser.parse_args(argv)
    if args.digest.startswith("sha256:") and len(args.digest) == len("sha256:") + 64 \
            and all(c in "0123456789abcdef" for c in args.digest[7:]):
        pass
    else:
        parser.error(
            "--digest must be a sha256 digest (sha256:<64 lowercase hex>); "
            "got " + args.digest
        )

    repo = args.repo.resolve()
    for attempt in range(1, args.attempts + 1):
        outcome = bump_once(
            repo, kustomize=args.kustomize, image=args.image, image_tag=args.image_tag,
            digest=args.digest, branch=args.branch, dry_run=args.dry_run,
        )
        if outcome == "superseded":
            print(f"A newer release already points past {args.image_tag}; withdrawing this bump.")
            return 0
        if outcome == "unchanged":
            print(f"Deployment already points at {args.image_tag}; nothing to commit.")
            return 0
        if outcome == "landed":
            print(f"Bumped deployment image to {args.image_tag} (attempt {attempt}).")
            return 0
    print(
        f"Could not land the image bump for {args.image_tag} in {args.attempts} attempts.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover - exercised via tests/test_bump_deploy_image.py
    raise SystemExit(main())
