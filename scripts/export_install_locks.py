#!/usr/bin/env python3
"""Export the hash-locked Windows install requirements from uv.lock.

``scripts/install-windows.ps1`` installs these files with
``pip install --require-hashes`` and then cert-watch itself with
``--no-build-isolation --no-deps``. The closure that lands on the server is
then the one CI tested, and nothing is resolved from the index at install
time. A bare ``pip install <checkout>`` re-resolved every dependency instead.

Run this after every ``uv lock``. ``--check`` exits 1 when a committed file
would install anything different from a fresh export;
``tests/test_install_locks.py`` runs it.
Only uv is needed, not a project environment.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Published path -> the uv export selection that produces it.
LOCKS: dict[str, tuple[str, ...]] = {
    # The default install.
    "deploy/iis/requirements.lock.txt": ("--no-dev",),
    # -WithAuthExtras: the LDAP and OAuth sign-in libraries.
    "deploy/iis/requirements-auth.lock.txt": (
        "--no-dev", "--extra", "auth-ldap", "--extra", "auth-oauth",
    ),
    # The optional Windows Event Log audit sink (pywin32).
    "deploy/iis/requirements-windows.lock.txt": ("--no-dev", "--extra", "windows"),
    # The PEP 517 build backend, so the project builds without isolation.
    "deploy/iis/requirements-build.lock.txt": ("--only-group", "build"),
}


def export(selection: tuple[str, ...]) -> bytes:
    result = subprocess.run(
        [
            "uv", "export", "--locked", "--no-emit-project", "--no-header",
            "--format", "requirements-txt", *selection,
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout


def requirements(text: bytes) -> list[str]:
    """The pins, markers and hashes, without uv's "# via" comments or wrapping.

    ``--check`` compares these, so a uv release that only reflows the
    comments does not fail CI, while any change to what pip installs does.
    """
    joined = text.decode("utf-8").replace("\\\n", " ")
    return [
        " ".join(line.split()) for line in joined.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true",
        help="fail when a committed file differs from a fresh export; write nothing",
    )
    args = parser.parse_args(argv)
    stale: list[str] = []
    for relative, selection in LOCKS.items():
        fresh = export(selection)
        path = ROOT / relative
        if path.exists() and path.read_bytes() == fresh:
            continue
        if args.check:
            if not path.exists() or requirements(path.read_bytes()) != requirements(fresh):
                stale.append(relative)
        else:
            path.write_bytes(fresh)
            print(f"wrote {relative}")
    if stale:
        print(
            "stale install locks (run `python3 scripts/export_install_locks.py`): "
            + ", ".join(stale),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
