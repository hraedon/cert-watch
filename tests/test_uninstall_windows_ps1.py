"""Static invariants for scripts/uninstall-windows.ps1.

Like the installer, the uninstaller is only exercised end-to-end in a real
Windows deploy job, so these tests catch structural regressions on the dev box.
The load-bearing invariant is the port-443 sharing rule: the uninstaller must
remove only the SSL binding cert-watch owns and must never blind-delete the
catch-all ipport, which a sibling tool (e.g. gpo-lens) may own.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "uninstall-windows.ps1"


@pytest.fixture(scope="module")
def script_text() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _code_without_block_comments(text: str) -> str:
    """Return the script with <# ... #> block comments removed."""
    return re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)


def test_script_exists() -> None:
    assert SCRIPT.is_file(), "uninstall-windows.ps1 must exist alongside the installer"


def test_requires_elevation(script_text: str) -> None:
    code = _code_without_block_comments(script_text)
    assert "WindowsBuiltInRole]::Administrator" in code
    assert re.search(r"throw\s+\"Run from an elevated", code) is not None


def test_defaults_match_installer(script_text: str) -> None:
    """Resource names/paths must mirror install-windows.ps1 or cleanup misses."""
    code = _code_without_block_comments(script_text)
    assert '$InstallDir = "C:\\ProgramData\\cert-watch"' in code
    assert '$AppPool = "cert-watch"' in code
    assert '$SiteName = "cert-watch"' in code
    assert '$SitePath = "C:\\inetpub\\cert-watch"' in code
    assert "$Port = 443" in code


def test_data_preserved_by_default(script_text: str) -> None:
    """Without -RemoveData, the data dir (signing keys + DB) is kept."""
    code = _code_without_block_comments(script_text)
    assert "[switch]$RemoveData" in code
    # The destructive removal is gated on the switch.
    assert re.search(r"if\s*\(\s*\$RemoveData\s*\)", code) is not None


def test_remove_data_is_confirmed(script_text: str) -> None:
    """Destructive data removal must prompt (or require -Force)."""
    code = _code_without_block_comments(script_text)
    assert "[switch]$Force" in code
    assert re.search(r"if\s*\(\s*\$RemoveData\s+-and\s+-not\s+\$Force\s*\)", code) is not None
    assert "Read-Host" in code


def test_inspects_binding_before_removing_site(script_text: str) -> None:
    """The site binding must be read BEFORE the site is removed, so the script
    knows whether it owns the catch-all or an SNI hostnameport binding."""
    code = _code_without_block_comments(script_text)
    inspect = code.find("-Name bindings")
    remove_site = code.find("Remove-Website")
    assert inspect != -1, "expected the site binding to be inspected"
    assert remove_site != -1, "expected Remove-Website"
    assert inspect < remove_site, "binding must be inspected before the site is removed"


def test_decision_keyed_on_sslflags_not_hostname(script_text: str) -> None:
    """Regression (caught live on mvmcitest01): a catch-all binding can carry a
    host header (*:443:host with sslFlags=0). The catch-all-vs-SNI decision must
    therefore be driven by sslFlags (bit 1), not by hostname presence, or the
    real ipport binding is left orphaned."""
    code = _code_without_block_comments(script_text)
    # sslFlags is read and bit-tested (numeric path) with a string fallback.
    assert "$b.sslFlags" in code
    assert "-band 1" in code
    assert re.search(r"\$sf\s+-match\s+\"Sni\"", code) is not None
    # The branch is gated on $isSni, not on $bindingHost alone.
    assert re.search(r"if\s*\(\s*\$isSni\s+-and\s+\$bindingHost\s*\)", code) is not None


def test_sni_install_does_not_touch_catch_all(script_text: str) -> None:
    """The crux: in SNI mode the script removes hostnameport only and leaves the
    catch-all ipport alone (it may belong to a sibling tool sharing port 443)."""
    code = _code_without_block_comments(script_text)
    # SNI branch deletes hostnameport.
    assert 'netsh http delete sslcert hostnameport="$hostnameport"' in code
    # The SNI branch (between the $isSni guard and its else) must NOT delete the
    # catch-all ipport binding.
    sni_branch = code.split("if ($isSni -and $bindingHost) {", 1)[1].split("} else {", 1)[0]
    assert "delete sslcert ipport=" not in sni_branch, (
        "SNI branch must not delete the catch-all ipport binding"
    )


def test_catch_all_install_removes_ipport(script_text: str) -> None:
    """Catch-all (non-SNI) install removes the 0.0.0.0 binding it created."""
    code = _code_without_block_comments(script_text)
    assert 'netsh http delete sslcert ipport="$ipport"' in code
    assert '$ipport = "0.0.0.0:$Port"' in code


def test_prefers_site_physicalpath_over_sitepath(script_text: str) -> None:
    """Regression (caught live on mvmcitest01): removing a fixed site directory
    regardless of the actual site can wipe a DIFFERENT site's directory. The
    script must capture and prefer the site's own physicalPath, only falling
    back to -SitePath when the site is already gone."""
    code = _code_without_block_comments(script_text)
    assert "$sitePhysical" in code
    assert "$site.physicalPath" in code
    assert re.search(r"if\s*\(\s*\$siteFound\s+-and\s+\$sitePhysical\s*\)", code) is not None
    # The old unconditional removal of the param path must be gone.
    assert "Remove-Item $SitePath -Recurse" not in code
    assert "Remove-Item $dirToRemove" in code


def test_port_zero_skips_ssl_cleanup(script_text: str) -> None:
    code = _code_without_block_comments(script_text)
    assert re.search(r"if\s*\(\s*\$Port\s+-gt\s+0\s*\)", code) is not None


def test_no_firewall_rule_removed(script_text: str) -> None:
    """The cert-watch installer creates no firewall rule; the uninstaller must
    not invent one to remove (that would be a misleading no-op or error)."""
    code = _code_without_block_comments(script_text)
    assert "Remove-NetFirewallRule" not in code
    assert "New-NetFirewallRule" not in code


def test_idempotent_skips_missing_resources(script_text: str) -> None:
    """Re-running must be safe: each resource is guarded by an existence check."""
    code = _code_without_block_comments(script_text)
    assert 'Test-Path "IIS:\\AppPools\\$AppPool"' in code
    assert "not found; skipping" in code


def test_no_single_quote_in_double_quoted_string(script_text: str) -> None:
    """PS 5.1 ANSI-codepage quote-tracking hazard (see header STYLE note)."""
    code = _code_without_block_comments(script_text)
    for lineno, line in enumerate(code.splitlines(), 1):
        # crude but matches the installer's own guard intent: flag a literal
        # apostrophe inside a double-quoted segment.
        for m in re.finditer(r'"[^"]*"', line):
            assert "'" not in m.group(0), f"single quote in double-quoted string, line {lineno}"


def test_no_ps7_only_syntax(script_text: str) -> None:
    code = _code_without_block_comments(script_text)
    assert "??" not in code
    assert "&&" not in code
    assert "||" not in code
