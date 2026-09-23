"""Check that a published image's attestations describe the commit being released.

``cosign verify`` answers "was this digest signed by our release workflow"; it
says nothing about *what* the signed artifact is. The attestations buildx
attaches to the pushed index carry that: the SLSA provenance records the build
arguments and the VCS revision it was built from, and the SPDX SBOM records its
contents. Unread, they are decoration -- an image built from an unrelated
revision, or one published with the attestation exporters silently disabled,
verifies exactly the same.

So the release job pipes ``docker buildx imagetools inspect --format
'{{ json .Provenance }}'`` (and ``.SBOM``) in here, and this refuses the
deployment bump unless, for every published platform:

* provenance exists and names ``build-arg:GIT_COMMIT`` equal to the commit the
  workflow is releasing;
* the ``vcs:revision`` buildkit recorded, when present, is that same commit;
* the SBOM exists and lists at least one package.

Both inspect formats are keyed by platform and then by predicate name, e.g.
``{"linux/amd64": {"SLSA": {...}}}`` and ``{"linux/amd64": {"SPDX": {...}}}``.

Run:  python scripts/verify_release_attestations.py --provenance p.json \
          --sbom s.json --commit <sha> --short-commit <short-sha> \
          --platform linux/amd64 --platform linux/arm64
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BUILD_ARG_COMMIT = "build-arg:GIT_COMMIT"
VCS_REVISION = "vcs:revision"


def _request_args(provenance: dict[str, Any]) -> dict[str, str]:
    """Flatten the build request arguments recorded in a SLSA v1 predicate.

    buildkit repeats the arguments under a nested ``root`` request, and only
    that copy carries the ``vcs:*`` keys, so both levels are merged.
    """
    request = provenance.get("buildDefinition", {}).get("externalParameters", {}).get("request", {})
    if not isinstance(request, dict):
        return {}
    root = request.get("root", {})
    root_request = root.get("request", {}) if isinstance(root, dict) else {}
    args: dict[str, str] = {}
    for scope in (request, root_request):
        scope_args = scope.get("args") if isinstance(scope, dict) else None
        if isinstance(scope_args, dict):
            args.update({str(k): str(v) for k, v in scope_args.items()})
    return args


def check_platform(
    platform: str,
    provenance: dict[str, Any],
    sbom: dict[str, Any],
    *,
    commit: str,
    short_commit: str,
) -> list[str]:
    """Return the problems found for one published platform."""
    problems: list[str] = []

    slsa = (provenance.get(platform) or {}).get("SLSA")
    if not isinstance(slsa, dict) or not slsa:
        problems.append(f"{platform}: no SLSA provenance attached")
    else:
        args = _request_args(slsa)
        built_commit = args.get(BUILD_ARG_COMMIT)
        if built_commit != short_commit:
            problems.append(
                f"{platform}: provenance {BUILD_ARG_COMMIT}={built_commit!r}, "
                f"expected {short_commit!r}"
            )
        revision = args.get(VCS_REVISION)
        if revision is not None and revision != commit:
            problems.append(
                f"{platform}: provenance {VCS_REVISION}={revision!r}, expected {commit!r}"
            )

    spdx = (sbom.get(platform) or {}).get("SPDX")
    if not isinstance(spdx, dict) or not spdx.get("packages"):
        problems.append(f"{platform}: no SBOM packages attached")

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", required=True, type=Path)
    parser.add_argument("--sbom", required=True, type=Path)
    parser.add_argument("--commit", required=True, help="full SHA being released")
    parser.add_argument("--short-commit", required=True, help="GIT_COMMIT build arg value")
    parser.add_argument("--platform", action="append", required=True, dest="platforms")
    args = parser.parse_args(argv)

    provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))

    problems: list[str] = []
    for platform in args.platforms:
        problems.extend(
            check_platform(
                platform, provenance, sbom, commit=args.commit, short_commit=args.short_commit,
            )
        )

    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(
        "Attestations describe "
        f"{args.commit} for: {', '.join(args.platforms)}."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via tests
    raise SystemExit(main())
