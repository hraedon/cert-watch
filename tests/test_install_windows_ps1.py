"""Static invariants for scripts/install-windows.ps1.

This script is exercised in an actual Windows environment only in the deploy
smoke job, so these tests catch structural regressions quickly on the dev box.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "install-windows.ps1"


@pytest.fixture(scope="module")
def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _code_without_block_comments(text: str) -> str:
    """Return the script with <# ... #> block comments removed."""
    return re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)


def test_switch_parameter_declared(script_text: str) -> None:
    assert "[switch]$SharePort443" in script_text


def test_share_port_requires_hostname(script_text: str) -> None:
    """A misuse guard must reject SNI mode without a hostname."""
    code = _code_without_block_comments(script_text)
    assert re.search(
        r"if\s*\(\s*\$SharePort443\s+-and\s+-not\s+\$HostName\s*\)", code
    ), "expected -SharePort443 validation guard"
    assert "-SharePort443 requires -HostName" in code


def test_sni_path_uses_hostnameport_and_sslflags(script_text: str) -> None:
    """SNI branch adds sslcert by hostnameport and sets sslFlags=1."""
    code = _code_without_block_comments(script_text)
    # sslFlags must be set to 1 on the SNI path. Simpler than a full AST:
    # the script computes sslFlagsValue and updates the binding.
    assert "$sslFlagsValue = if ($SharePort443) { 1 } else { 0 }" in code
    assert 'sslFlags=$sslFlagsValue' in code
    assert (
        re.search(
            r"if\s*\(\s*\$SharePort443\s*\)", code
        ) is not None
    ), "expected SharePort443 branch"
    assert (
        re.search(
            r'Ensure-SslCertBinding\s+-BindingArgument\s+"hostnameport=\$hostPort"',
            code,
        )
        is not None
    ), "expected hostnameport binding on SNI path"


def test_default_path_keeps_catch_all_ipport(script_text: str) -> None:
    """Default (non-SNI) branch binds to the catch-all ipport."""
    code = _code_without_block_comments(script_text)
    assert (
        re.search(
            r'Ensure-SslCertBinding\s+-BindingArgument\s+"ipport=\$ipport"',
            code,
        )
        is not None
    ), "expected catch-all ipport binding on default path"
    # It should also clean up a stale SNI binding from a prior SharePort443 run.
    assert "& netsh http delete sslcert hostnameport=\"$hostPort\"" in code


def test_sslflags_zero_is_default_path(script_text: str) -> None:
    """Default path uses sslFlags=0; only SharePort443 path sets 1."""
    code = _code_without_block_comments(script_text)
    # The script centralises the value computation; verify no hard-coded 1 on
    # the default catch-all branch.
    default_branch = re.split(r"if\s*\(\s*\$SharePort443\s*\)", code)[0]
    assert "sslFlags=1" not in default_branch


def test_never_leaves_https_unbound(script_text: str) -> None:
    """Both switch directions add the new binding before deleting the old one.

    A delete-before-add ordering leaves a window with zero HTTPS bindings -- the
    WI-047 regression class (HTTPS dead on a real host). This must hold in BOTH
    directions: default->SNI (add hostnameport, then delete catch-all ipport)
    and SNI->default (add catch-all ipport, then delete hostnameport).
    """
    code = _code_without_block_comments(script_text)
    add_hostnameport = code.find(
        'Ensure-SslCertBinding -BindingArgument "hostnameport=$hostPort"'
    )
    add_ipport = code.find(
        'Ensure-SslCertBinding -BindingArgument "ipport=$ipport"'
    )
    delete_ipport = code.find("& netsh http delete sslcert ipport=")
    delete_hostnameport = code.find('& netsh http delete sslcert hostnameport="$hostPort"')

    # default -> SNI: add hostnameport before delete catch-all
    assert add_hostnameport != -1, "SNI branch must add the hostnameport binding"
    assert delete_ipport != -1, "SNI branch must remove the catch-all binding"
    assert add_hostnameport < delete_ipport, "SNI: add hostnameport before delete catch-all"
    # SNI -> default: add catch-all before delete hostnameport
    assert add_ipport != -1, "default branch must add the catch-all binding"
    assert delete_hostnameport != -1, "default branch must remove the SNI binding"
    assert add_ipport < delete_hostnameport, "default: add catch-all before delete hostnameport"


def test_no_single_quotes_inside_double_quoted_strings(script_text: str) -> None:
    """PowerShell 5.1 ANSI parsing bug rule: never ' inside "..." """
    code = _code_without_block_comments(script_text)
    for lineno, raw_line in enumerate(code.splitlines(), start=1):
        line = raw_line.strip()
        # Skip pure line comments and empty/whitespace-only lines.
        if not line or line.startswith("#"):
            continue
        # Walk the line tracking single- and double-quoted regions. A quote
        # only toggles the matching region type; quotes inside the other kind
        # of string are ignored. Backtick escapes the next character.
        in_double = False
        in_single = False
        escaped = False
        for ch in line:
            if escaped:
                escaped = False
                continue
            if ch == "`":
                escaped = True
                continue
            if ch == "'" and not in_double:
                in_single = not in_single
                continue
            if ch == '"' and not in_single:
                in_double = not in_double
                continue
            if in_double and ch == "'":
                pytest.fail(
                    f"single quote inside double-quoted string at line {lineno}: {raw_line!r}"
                )


def test_catch_all_binding_remains_default(script_text: str) -> None:
    """The default single-site path uses the catch-all ipport binding."""
    code = _code_without_block_comments(script_text)
    # The default branch binds to ipport=0.0.0.0:$bindPort.
    assert "0.0.0.0:$bindPort" in code
