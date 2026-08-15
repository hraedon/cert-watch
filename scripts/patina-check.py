#!/usr/bin/env python3
# patina:sha256 db7aab7ffaf068d603b2c9edda8ebdd2bb136c3bfcf07c99bb5343ae0ff3b9a9 rev:99a7808
"""check_patina.py -- the patina conformance gate (Plan 005).

Verifies that a consuming tool's vendored patina assets have not drifted and
that the tool's own CSS honours the token contract. Stdlib only; every family
tool is Python. Vendored into consumers by sync.sh as patina-check.py.

Checks:
  0. self stamp     -- a vendored copy carries a `# patina:sha256 <hash>` line
                       directly under the shebang; the gate hashes itself and
                       refuses to run if its own bytes were edited. Running
                       from a patina checkout (unstamped) is fine and noted.
  1. tokens block   -- css/tokens.css must carry EXACTLY ONE
                       /* patina:begin <rev> sha256:<hash> */ ... /* patina:end */
                       pair, in that order, whose bytes hash to the stamp.
                       Consumers may append CSS below the end marker -- that
                       tail is checked like any other tool CSS (checks 3+4).
  2. theme.js stamp -- first line // patina:sha256 <hash> must match the rest
                       of the file's bytes.
  3. token contract -- every var(--x) referenced in tool CSS must be defined
                       by the contract block or by the tool itself; the tool
                       must not redefine a contract token; with --prefix, all
                       tool-defined tokens must carry --<prefix>-.
  4. colour ratchet -- raw colour literals (#hex / rgb / hsl / oklch) in tool
                       CSS are fingerprinted against a committed baseline.
                       A NEW fingerprint fails even if the total is unchanged,
                       so a violation cannot be swapped for another one.
                       Removing one always passes. A line may be exempted with
                       `patina-allow: <reason>`; the reason is mandatory and
                       the number of exemptions is itself ratcheted. Size (px)
                       ratcheting was considered and deliberately deferred:
                       patterns.md itself specifies px paddings, so a px
                       ratchet is all noise today.

What check 1 does and does not prove:

  Without --upstream, the block hash is compared against a stamp stored in the
  same file. That proves INTEGRITY (nothing mangled the block after vendoring)
  and nothing else: anyone who edits a token value can recompute the stamp, and
  a consumer pinned to an old patina rev looks identical to a current one. To
  check actual DRIFT against patina, pass --upstream <patina-checkout>; the
  gate then re-derives the block from that checkout's tokens.css + the accent
  named in the vendored header and compares. Wire --upstream in CI if you want
  drift detection rather than corruption detection.

Usage:
  check_patina.py <static-dir> [--tokens css/tokens.css] [--theme theme.js]
                  [--no-theme] [--prefix cw] [--extra <dir>]...
                  [--upstream <patina-checkout>]
                  [--ratchet-file <path>] [--update-ratchet] [--report]

Exit: 0 clean (or --report), 1 on any failure, 2 on usage error.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

BEGIN_RE = re.compile(
    r"^/\* patina:begin (?P<rev>\S+) sha256:(?P<hash>[0-9a-f]{64}) \*/$", re.M
)
END_RE = re.compile(r"^/\* patina:end \*/$", re.M)
ACCENT_RE = re.compile(r"^/\* accent: (?P<accent>[A-Za-z0-9._-]+) \*/$", re.M)
THEME_STAMP_RE = re.compile(r"^// patina:sha256 (?P<hash>[0-9a-f]{64})")
SELF_STAMP_RE = re.compile(r"^# patina:sha256 (?P<hash>[0-9a-f]{64}) rev:(?P<rev>\S+)$")
TOKEN_DEF_RE = re.compile(r"(--[A-Za-z0-9_-]+)\s*:")
TOKEN_REF_RE = re.compile(r"var\(\s*(--[A-Za-z0-9_-]+)")
COLOR_RE = re.compile(r"(#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|\boklch\()")
STYLE_BLOCK_RE = re.compile(r"<style[^>]*>(.*?)</style>", re.DOTALL | re.IGNORECASE)
INLINE_STYLE_RE = re.compile(r"""\bstyle\s*=\s*["']([^"']*)["']""", re.IGNORECASE)

# `patina-allow` alone is not enough -- an escape hatch with no stated reason
# is just a disabled check. The reason must be substantive (>= 4 chars).
ALLOW_RE = re.compile(r"patina-allow:\s*(?P<reason>\S.{3,})")
ALLOW_MARK = "patina-allow"

RATCHET_VERSION = 2


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


class Source:
    """A chunk of tool-owned CSS, with enough provenance for a useful error."""

    def __init__(self, label, text, line_offset=0):
        self.label = label
        self.text = text
        self.line_offset = line_offset  # lines preceding `text` in its file

    def at(self, i):
        return f"{self.label}:{self.line_offset + i + 1}"


class Gate:
    def __init__(self):
        self.failures = []
        self.notes = []

    def ok(self, msg):
        self.notes.append(f"[ok]   {msg}")

    def note(self, msg):
        self.notes.append(f"[note] {msg}")

    def fail(self, msg):
        self.failures.append(f"[FAIL] {msg}")


def check_self(gate: Gate):
    """A vendored copy must match its own stamp. The enforcement mechanism is
    the highest-leverage single file in the system; an unstamped, silently
    edited checker passes everything."""
    try:
        text = Path(__file__).resolve().read_text(encoding="utf-8")
    except OSError:
        return
    lines = text.split("\n")
    if len(lines) < 2:
        return
    m = SELF_STAMP_RE.match(lines[1])
    if not m:
        gate.note(
            "checker is unstamped -- running from a patina checkout "
            "(a vendored copy is stamped by sync.sh)"
        )
        return
    rest = "\n".join(lines[2:])
    if sha256_text(rest) != m.group("hash"):
        gate.fail(
            "patina-check.py: this checker's own bytes differ from its stamp "
            "-- the gate was edited in the consumer; re-run patina's sync.sh"
        )
    else:
        gate.ok(f"checker intact (patina {m.group('rev')})")


def split_vendored(text: str):
    """-> (rev, stamp, block, tail, tail_line_offset) or (None, err, ...).

    Fails closed. Exactly one begin marker and one end marker, in that order,
    or we refuse to interpret the file at all: every ambiguous shape here is
    either a mangled vendor or a consumer about to lose CSS.
    """
    begins = list(BEGIN_RE.finditer(text))
    ends = list(END_RE.finditer(text))
    if not begins and not ends:
        return None, "no stamped patina block found", None, None, 0
    if len(begins) != 1 or len(ends) != 1:
        return (
            None,
            f"malformed vendor markers ({len(begins)} begin, {len(ends)} end; "
            "expected exactly one of each) -- resolve by hand; re-syncing "
            "will not fix a duplicated marker",
            None,
            None,
            0,
        )
    b, e = begins[0], ends[0]
    if e.start() < b.end():
        return None, "patina:end appears before patina:begin", None, None, 0
    block = text[b.end() + 1 : e.start()]
    tail = text[e.end() :]
    tail = tail[1:] if tail.startswith("\n") else tail
    tail_offset = text[: e.end()].count("\n") + 1
    return b.group("rev"), b.group("hash"), block, tail, tail_offset


def check_tokens_block(gate: Gate, tokens_path: Path, upstream: Path | None):
    """Returns (contract token names, tail Source or None)."""
    if not tokens_path.is_file():
        gate.fail(f"tokens file missing: {tokens_path}")
        return set(), None
    text = tokens_path.read_text(encoding="utf-8")
    rev, stamp_or_err, block, tail, tail_offset = split_vendored(text)
    if rev is None:
        gate.fail(
            f"{tokens_path.name}: {stamp_or_err} "
            "(unstamped legacy vendored copy, or hand-maintained fork) -- "
            "re-run patina's sync.sh"
        )
        # Fall back to treating the whole file as the contract so the
        # name checks still produce useful output during migration.
        return set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(text))), None

    actual = sha256_text(block)
    if actual != stamp_or_err:
        gate.fail(
            f"{tokens_path.name}: patina block was EDITED after vendoring "
            f"(stamp {stamp_or_err[:12]}..., actual {actual[:12]}...) -- "
            "edit patina and re-sync instead"
        )
    elif upstream is not None:
        check_upstream(gate, text, block, rev, upstream)
    else:
        gate.ok(
            f"tokens block matches its stamp (patina {rev}) -- integrity only; "
            "pass --upstream to check drift against patina"
        )

    contract = set(TOKEN_DEF_RE.findall(strip_comments_keep_lines(block)))
    if not contract:
        gate.fail(
            f"{tokens_path.name}: the vendored block defines no tokens "
            "(truncated or corrupt) -- a validly stamped empty block would "
            "silently disable every contract check"
        )
    tail_src = None
    if tail and tail.strip():
        tail_src = Source(f"{tokens_path.name}(below patina:end)", tail, tail_offset)
    return contract, tail_src


def check_upstream(gate: Gate, vendored_text: str, block: str, rev: str, upstream: Path):
    """Re-derive the block from a patina checkout and compare. This is the only
    check in the file that compares consumer bytes to patina bytes."""
    am = ACCENT_RE.search(vendored_text)
    if not am:
        gate.fail(
            "cannot verify against upstream: vendored tokens.css has no "
            "/* accent: <name> */ header -- re-run sync.sh"
        )
        return
    accent = am.group("accent")
    up_tokens = upstream / "tokens.css"
    up_accent = upstream / "accents" / f"{accent}.css"
    for p in (up_tokens, up_accent):
        if not p.is_file():
            gate.fail(f"upstream checkout incomplete: {p} not found")
            return
    derived = (
        up_tokens.read_text(encoding="utf-8")
        + "\n"
        + up_accent.read_text(encoding="utf-8")
    )
    if sha256_text(derived) == sha256_text(block):
        gate.ok(f"tokens block matches upstream patina (accent {accent}, rev {rev})")
    else:
        gate.fail(
            f"tokens block DRIFTED from upstream patina (accent {accent}): the "
            f"vendored copy is stamped {rev} but its bytes do not match the "
            f"checkout at {upstream}. Either the consumer is stale (re-sync) "
            "or the block was edited and re-stamped."
        )


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


def tool_css_sources(static_dir: Path, tokens_path: Path, extra_dirs=()):
    """Every chunk of CSS the tool owns: non-vendored .css files, <style> blocks
    and inline style="..." attributes in .html. The vendored tokens.css is
    excluded here -- its below-marker tail is added separately by the caller,
    because that region is consumer-owned and must not escape the gate."""
    sources = []
    for root in (static_dir, *extra_dirs):
        for p in sorted(root.rglob("*.css")):
            if p.resolve() == tokens_path.resolve():
                continue
            sources.append(Source(p.name, p.read_text(encoding="utf-8")))
        for p in sorted(root.rglob("*.html")):
            text = p.read_text(encoding="utf-8")
            for i, block in enumerate(STYLE_BLOCK_RE.findall(text)):
                sources.append(Source(f"{p.name}<style#{i + 1}>", block))
            inline = INLINE_STYLE_RE.findall(text)
            if inline:
                sources.append(Source(f"{p.name}[style=]", "\n".join(inline)))
    return sources


def check_contract(gate: Gate, contract: set, sources, prefix: str | None):
    defined, referenced = {}, {}
    for src in sources:
        text = strip_comments_keep_lines(src.text)
        for name in TOKEN_DEF_RE.findall(text):
            defined.setdefault(name, src.label)
        for name in TOKEN_REF_RE.findall(text):
            referenced.setdefault(name, src.label)

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


def fingerprint(label: str, line: str) -> str:
    """Identity of a violation: which file, and what the line says -- not where
    it sits, so reformatting and reordering don't churn the baseline."""
    return sha256_text(f"{label}\x00{' '.join(line.split())}")[:16]


def scan_colour_literals(gate: Gate, sources):
    """-> (violations {fp: {...}}, allow_count). Records a failure for every
    exemption that omits a reason."""
    violations, allows = {}, 0
    for src in sources:
        raw_lines = src.text.splitlines()
        exempt = set()
        for i, line in enumerate(raw_lines):
            if ALLOW_MARK not in line:
                continue
            if ALLOW_RE.search(line):
                exempt.add(i)
                allows += 1
            else:
                gate.fail(
                    f"{src.at(i)}: `{ALLOW_MARK}` without a reason -- write "
                    "`/* patina-allow: <why this literal must stay> */`"
                )
        for i, line in enumerate(strip_comments_keep_lines(src.text).splitlines()):
            if i in exempt:
                continue
            hits = COLOR_RE.findall(line)
            if not hits:
                continue
            fp = fingerprint(src.label, line)
            rec = violations.setdefault(
                fp,
                {"n": 0, "where": src.label, "sample": line.strip()[:70]},
            )
            rec["n"] += len(hits)
    return violations, allows


def load_ratchet(gate: Gate, path: Path):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        gate.fail(f"ratchet file {path} is unreadable: {exc}")
        return None
    if not isinstance(data, dict) or data.get("version") != RATCHET_VERSION:
        gate.fail(
            f"ratchet file {path} is not version {RATCHET_VERSION} (a scalar "
            "count cannot detect a swapped violation) -- re-baseline with "
            "--update-ratchet and review the diff"
        )
        return None
    return data


def write_ratchet(path: Path, violations, allows):
    payload = {
        "version": RATCHET_VERSION,
        "allows": allows,
        "color_literals": sorted(
            (
                {"fp": fp, "n": v["n"], "where": v["where"], "sample": v["sample"]}
                for fp, v in violations.items()
            ),
            key=lambda r: (r["where"], r["sample"]),
        ),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def check_ratchet(gate: Gate, sources, ratchet_file: Path, update: bool):
    violations, allows = scan_colour_literals(gate, sources)
    total = sum(v["n"] for v in violations.values())

    if update:
        write_ratchet(ratchet_file, violations, allows)
        gate.ok(
            f"ratchet baselined: {total} colour literals in {len(violations)} "
            f"lines, {allows} exemption(s) -> {ratchet_file}"
        )
        return
    if not ratchet_file.is_file():
        gate.fail(
            f"no ratchet baseline at {ratchet_file} -- run once with "
            f"--update-ratchet to record the current state ({total} literals)"
        )
        return
    data = load_ratchet(gate, ratchet_file)
    if data is None:
        return

    baseline = {r["fp"]: r for r in data.get("color_literals", [])}
    new = []
    for fp, v in violations.items():
        was = baseline.get(fp, {}).get("n", 0)
        if v["n"] > was:
            new.append(f"{v['where']}: {v['sample']}" + ("" if was == 0 else f"  (was {was}, now {v['n']})"))
    if new:
        gate.fail(
            f"colour-literal ratchet: {len(new)} NEW violation(s) not in the "
            "baseline. Swapping one violation for another does not pass -- use "
            "tokens, or `/* patina-allow: <reason> */`:\n         "
            + "\n         ".join(sorted(new)[:5])
        )

    gone = sorted(
        f"{r['where']}: {r['sample']}"
        for fp, r in baseline.items()
        if violations.get(fp, {}).get("n", 0) < r["n"]
    )
    if gone:
        gate.note(
            f"{len(gone)} baselined violation(s) fixed -- re-baseline with "
            "--update-ratchet to lock the improvement in:\n         "
            + "\n         ".join(gone[:5])
        )

    recorded_allows = data.get("allows", 0)
    if allows > recorded_allows:
        gate.fail(
            f"exemption ratchet: {allows} `{ALLOW_MARK}` lines > recorded "
            f"{recorded_allows}. Exemptions are ratcheted too, or the hatch "
            "becomes the mechanism."
        )
    if not new:
        gate.ok(
            f"colour-literal ratchet holds ({total} literals, "
            f"{allows} exemption(s))"
        )


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
    ap.add_argument(
        "--extra",
        type=Path,
        action="append",
        default=[],
        help="additional root to scan for tool CSS (e.g. a templates/ dir "
        "outside static/); repeatable",
    )
    ap.add_argument(
        "--upstream",
        type=Path,
        default=None,
        help="path to a patina checkout; re-derives the vendored block from it "
        "and reports real drift instead of mere integrity",
    )
    ap.add_argument("--ratchet-file", type=Path, default=None)
    ap.add_argument("--update-ratchet", action="store_true")
    ap.add_argument(
        "--report",
        action="store_true",
        help="print status but always exit 0 (advisory; never use in CI)",
    )
    args = ap.parse_args()

    static_dir = args.static_dir
    if not static_dir.is_dir():
        print(f"error: not a directory: {static_dir}", file=sys.stderr)
        return 2
    for extra in args.extra:
        if not extra.is_dir():
            print(f"error: --extra is not a directory: {extra}", file=sys.stderr)
            return 2
    if args.upstream is not None and not args.upstream.is_dir():
        print(f"error: --upstream is not a directory: {args.upstream}", file=sys.stderr)
        return 2
    tokens_path = static_dir / args.tokens
    ratchet_file = args.ratchet_file or static_dir / "patina-ratchet.json"

    gate = Gate()
    check_self(gate)
    if args.ratchet_file is None:
        gate.note(
            f"ratchet baseline defaults to {ratchet_file}, inside the served "
            "static root -- pass --ratchet-file to keep it out of the webroot"
        )
    contract, tail_src = check_tokens_block(gate, tokens_path, args.upstream)
    if not args.no_theme:
        check_theme(gate, static_dir / args.theme)
    sources = tool_css_sources(static_dir, tokens_path, args.extra)
    if tail_src is not None:
        sources.append(tail_src)
    if contract:
        check_contract(gate, contract, sources, args.prefix)
    check_ratchet(gate, sources, ratchet_file, args.update_ratchet)

    for line in gate.notes + gate.failures:
        print(line)
    if gate.failures:
        print(f"\ncheck_patina: {len(gate.failures)} failure(s)")
        if args.report:
            print("(--report: exiting 0 despite failures)")
            return 0
        return 1
    print("\ncheck_patina: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
