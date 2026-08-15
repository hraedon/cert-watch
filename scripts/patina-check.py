#!/usr/bin/env python3
"""check_patina.py -- the patina conformance gate (Plan 005).

Verifies that a consuming tool's vendored patina assets have not drifted and
that the tool's own CSS honours the token contract. Stdlib only; every family
tool is Python. Vendored into consumers by sync.sh as patina-check.py.

Checks:
  1. tokens block   -- css/tokens.css must carry a /* patina:begin <rev>
                       sha256:<hash> */ ... /* patina:end */ block whose bytes
                       hash to the stamp. Consumers may append CSS below the
                       end marker; edits inside the block fail.
  2. theme.js stamp -- first line // patina:sha256 <hash> must match the rest
                       of the file's bytes.
  3. token contract -- every var(--x) referenced in tool CSS must be defined
                       by the contract block or by the tool itself; the tool
                       must not redefine a contract token; with --prefix, all
                       tool-defined tokens must carry --<prefix>-.
  4. colour ratchet -- raw colour literals (#hex / rgb / hsl / oklch) in tool
                       CSS are counted against a committed baseline that only
                       goes down (the cert-watch test_no_inline_styles.py
                       pattern, generalised). A line containing `patina-allow`
                       is exempt. Size (px) ratcheting was considered and
                       deliberately deferred: patterns.md itself specifies px
                       paddings, so a px ratchet is all noise today.

Usage:
  check_patina.py <static-dir> [--tokens css/tokens.css] [--theme theme.js]
                  [--prefix cw] [--ratchet-file <path>] [--update-ratchet]
                  [--report]

Exit: 0 clean (or --report), 1 on any failure, 2 on usage error.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

BLOCK_RE = re.compile(
    r"/\* patina:begin (?P<rev>\S+) sha256:(?P<hash>[0-9a-f]{64}) \*/\n"
    r"(?P<block>.*\n)"
    r"/\* patina:end \*/",
    re.DOTALL,
)
THEME_STAMP_RE = re.compile(r"^// patina:sha256 (?P<hash>[0-9a-f]{64})")
TOKEN_DEF_RE = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")
TOKEN_REF_RE = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)")
COLOR_RE = re.compile(r"(#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\()")

ALLOW_MARK = "patina-allow"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_comments_keep_lines(text: str) -> str:
    """Blank out /* ... */ spans but keep newlines so line numbers hold."""
    out = []
    i, n = 0, len(text)
    while i < n:
        j = text.find("/*", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        k = text.find("*/", j + 2)
        if k < 0:
            k = n - 2
        span = text[j : k + 2]
        out.append("".join(c if c == "\n" else " " for c in span))
        i = k + 2
    return "".join(out)


class Gate:
    def __init__(self):
        self.failures = []
        self.notes = []

    def ok(self, msg):
        self.notes.append(f"[ok]   {msg}")

    def fail(self, msg):
        self.failures.append(f"[FAIL] {msg}")


def check_tokens_block(gate: Gate, tokens_path: Path):
    """Returns the set of contract-defined token names (empty on failure)."""
    if not tokens_path.is_file():
        gate.fail(f"tokens file missing: {tokens_path}")
        return set()
    text = tokens_path.read_text(encoding="utf-8")
    m = BLOCK_RE.search(text)
    if not m:
        gate.fail(
            f"{tokens_path.name}: no stamped patina block found "
            "(unstamped legacy vendored copy, or hand-maintained fork) -- "
            "re-run patina's sync.sh"
        )
        # Fall back to treating the whole file as the contract so the
        # name checks still produce useful output during migration.
        return set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(text)))
    actual = sha256_text(m.group("block"))
    if actual != m.group("hash"):
        gate.fail(
            f"{tokens_path.name}: patina block was EDITED after vendoring "
            f"(stamp {m.group('hash')[:12]}..., actual {actual[:12]}...) -- "
            "edit patina and re-sync instead"
        )
    else:
        gate.ok(f"tokens block intact (patina {m.group('rev')})")
    return set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(m.group("block"))))


def check_theme(gate: Gate, theme_path: Path):
    if not theme_path.is_file():
        gate.fail(f"theme.js missing: {theme_path}")
        return
    text = theme_path.read_text(encoding="utf-8")
    first_nl = text.find("\n")
    first, rest = text[: first_nl + 1], text[first_nl + 1 :]
    m = THEME_STAMP_RE.match(first)
    if not m:
        gate.fail("theme.js: no patina:sha256 stamp on line 1 -- re-run sync.sh")
        return
    if sha256_text(rest) != m.group("hash"):
        gate.fail("theme.js: bytes differ from stamp -- edited or stale; re-sync")
    else:
        gate.ok("theme.js intact")


STYLE_BLOCK_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)


def tool_css_sources(static_dir: Path, tokens_path: Path):
    """(label, text) pairs: every non-vendored .css file, plus <style> blocks
    in .html files (sluice/switchboard style per-page; those blocks must not
    escape the gate)."""
    sources = []
    for p in sorted(static_dir.rglob("*.css")):
        if p.resolve() != tokens_path.resolve():
            sources.append((p.name, p.read_text(encoding="utf-8")))
    for p in sorted(static_dir.rglob("*.html")):
        for i, block in enumerate(STYLE_BLOCK_RE.findall(p.read_text(encoding="utf-8"))):
            sources.append((f"{p.name}<style#{i + 1}>", block))
    return sources


def check_contract(gate: Gate, contract: set, sources, prefix: str | None):
    defined, referenced = {}, {}
    for label, raw in sources:
        text = strip_comments_keep_lines(raw)
        for name in TOKEN_DEF_RE.findall(text):
            defined.setdefault(name, label)
        for name in TOKEN_REF_RE.findall(text):
            referenced.setdefault(name, label)

    for name, label in sorted(defined.items()):
        if name in contract:
            gate.fail(
                f"{label}: redefines contract token {name} -- "
                "contract values change in patina, not in a consumer"
            )
        elif prefix and not name.startswith(f"--{prefix}-"):
            gate.fail(
                f"{label}: local token {name} lacks the --{prefix}- prefix "
                "(contract rule: shared tokens unprefixed, tool tokens prefixed)"
            )
    undefined = {
        n: l for n, l in referenced.items() if n not in contract and n not in defined
    }
    for name, label in sorted(undefined.items()):
        gate.fail(f"{label}: var({name}) resolves to nothing (typo or drift)")
    if not undefined:
        gate.ok(
            f"token contract: {len(referenced)} names referenced, all resolve "
            f"({len(defined)} tool-local)"
        )


def count_color_literals(sources):
    total, examples = 0, []
    for label, raw in sources:
        allowed = {
            i for i, line in enumerate(raw.splitlines()) if ALLOW_MARK in line
        }
        stripped = strip_comments_keep_lines(raw)
        for i, line in enumerate(stripped.splitlines()):
            if i in allowed:
                continue
            hits = COLOR_RE.findall(line)
            if hits:
                total += len(hits)
                if len(examples) < 5:
                    examples.append(f"{label}:{i + 1}: {line.strip()[:70]}")
    return total, examples


def check_ratchet(gate: Gate, sources, ratchet_file: Path, update: bool):
    count, examples = count_color_literals(sources)
    if update:
        ratchet_file.write_text(
            json.dumps({"color_literals": count}, indent=2) + "\n", encoding="utf-8"
        )
        gate.ok(f"ratchet baselined: {count} colour literals -> {ratchet_file}")
        return
    if not ratchet_file.is_file():
        gate.fail(
            f"no ratchet baseline at {ratchet_file} -- run once with "
            f"--update-ratchet to record the current count ({count})"
        )
        return
    recorded = json.loads(ratchet_file.read_text(encoding="utf-8"))["color_literals"]
    if count > recorded:
        gate.fail(
            f"colour-literal ratchet: {count} > recorded {recorded}. THE COUNT "
            "ONLY GOES DOWN. Use tokens (or a trailing /* patina-allow */ with "
            "a reason). First offenders:\n         "
            + "\n         ".join(examples)
        )
    elif count < recorded:
        gate.fail(
            f"colour-literal ratchet improved: {count} < recorded {recorded} -- "
            "lock it in with --update-ratchet so it can't creep back"
        )
    else:
        gate.ok(f"colour-literal ratchet holds at {count}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("static_dir", type=Path)
    ap.add_argument("--tokens", default="css/tokens.css")
    ap.add_argument("--theme", default="theme.js")
    ap.add_argument(
        "--no-theme",
        action="store_true",
        help="consumer owns its theme bootstrap (e.g. a CSP-nonced inline "
        "script); skip the theme.js check",
    )
    ap.add_argument("--prefix", default=None)
    ap.add_argument("--ratchet-file", type=Path, default=None)
    ap.add_argument("--update-ratchet", action="store_true")
    ap.add_argument(
        "--report", action="store_true", help="print status but always exit 0"
    )
    args = ap.parse_args()

    static_dir = args.static_dir
    if not static_dir.is_dir():
        print(f"error: not a directory: {static_dir}", file=sys.stderr)
        return 2
    tokens_path = static_dir / args.tokens
    ratchet_file = args.ratchet_file or static_dir / "patina-ratchet.json"

    gate = Gate()
    contract = check_tokens_block(gate, tokens_path)
    if not args.no_theme:
        check_theme(gate, static_dir / args.theme)
    sources = tool_css_sources(static_dir, tokens_path)
    if contract:
        check_contract(gate, contract, sources, args.prefix)
    check_ratchet(gate, sources, ratchet_file, args.update_ratchet)

    for line in gate.notes + gate.failures:
        print(line)
    if gate.failures:
        print(f"\ncheck_patina: {len(gate.failures)} failure(s)")
        return 0 if args.report else 1
    print("\ncheck_patina: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
