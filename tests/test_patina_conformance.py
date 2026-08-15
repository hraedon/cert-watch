"""The patina conformance gate (patina Plan 005).

Fails if the vendored patina block in css/tokens.css was edited, if the
checker itself was edited, if any var() reference doesn't resolve, if
cert-watch redefines a contract token or defines an unprefixed local token,
or if a colour literal appears that isn't fingerprinted in
tests/patina-ratchet.json (swapping one for another does not pass; removing
one always does -- re-baseline with --update-ratchet to lock a fix in).

Drift note: without --upstream the gate proves integrity, not currency -- the
block hash is stored beside the block, so it cannot tell a current vendored
copy from a stale one. Set PATINA_CHECKOUT to a patina working copy to get
real drift detection. CI does not set it today; wiring that up needs cert-watch
CI to have read access to the patina repo, which is an open decision.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(*extra):
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "patina-check.py"),
            str(ROOT / "src" / "cert_watch" / "static"),
            "--prefix",
            "cw",
            "--no-theme",
            "--ratchet-file",
            str(ROOT / "tests" / "patina-ratchet.json"),
            *extra,
        ],
        capture_output=True,
        text=True,
    )


def test_patina_conformance():
    proc = _run()
    assert proc.returncode == 0, f"\n{proc.stdout}{proc.stderr}"


def test_patina_no_drift_from_upstream():
    """Real drift detection, when a patina checkout is available to compare
    against. Skipped rather than silently passing when it isn't."""
    checkout = os.environ.get("PATINA_CHECKOUT")
    if not checkout or not Path(checkout).is_dir():
        pytest.skip("PATINA_CHECKOUT not set to a patina working copy")
    proc = _run("--upstream", checkout)
    assert proc.returncode == 0, f"\n{proc.stdout}{proc.stderr}"
