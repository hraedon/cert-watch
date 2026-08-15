"""The patina conformance gate (patina Plan 005).

Fails if the vendored patina block in css/tokens.css was edited, if any
var() reference doesn't resolve, if cert-watch redefines a contract token
or defines an unprefixed local token, or if the colour-literal count rises
above tests/patina-ratchet.json (it only goes down; lower it and re-baseline
with --update-ratchet).
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_patina_conformance():
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "patina-check.py"),
            str(ROOT / "src" / "cert_watch" / "static"),
            "--prefix",
            "cw",
            "--no-theme",
            "--ratchet-file",
            str(ROOT / "tests" / "patina-ratchet.json"),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"\n{proc.stdout}{proc.stderr}"
