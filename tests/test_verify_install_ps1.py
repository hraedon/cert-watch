"""Static invariants for the read-only Windows/IIS verifier."""

import re
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "Verify-Install.ps1"


def _code_without_block_comments(text: str) -> str:
    return re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)


def test_verifier_checks_application_initialization_state() -> None:
    code = _code_without_block_comments(SCRIPT.read_text(encoding="utf-8"))

    assert "Get-WindowsFeature Web-AppInit" in code
    assert "IIS-ApplicationInit" in code
    assert "ApplicationInitializationModule" in code
    assert "warmup.dll" in code
    assert "-Id 'IIS-004'" in code


def test_verifier_checks_application_preload() -> None:
    code = _code_without_block_comments(SCRIPT.read_text(encoding="utf-8"))

    assert "applicationDefaults.preloadEnabled" in code
    assert "Get-ItemProperty" in code
    assert "-Id 'IIS-005'" in code
