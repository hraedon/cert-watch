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


def _code() -> str:
    return _code_without_block_comments(SCRIPT.read_text(encoding="utf-8"))


def test_script_is_ascii() -> None:
    """Windows PowerShell 5.1 reads a BOM-less file as ANSI; keep it ASCII."""
    SCRIPT.read_bytes().decode("ascii")


def test_preload_check_unwraps_configuration_attribute() -> None:
    """IIS-005 must read .Value off the ConfigurationAttribute Get-ItemProperty
    returns. Reading a dotted property name off it yields nothing, so the check
    failed on a site whose preload was verifiably on."""
    code = _code()
    assert "$props.'applicationDefaults.preloadEnabled'" not in code
    assert "function ConvertTo-IisBool" in code
    body = code.split("function ConvertTo-IisBool", 1)[1].split("\nfunction ", 1)[0]
    assert "$Value.Value" in body
    iis005 = code.split("-Id 'IIS-005'", 1)[1].split("Add-Check -Id", 1)[0]
    assert "ConvertTo-IisBool" in iis005
    assert "Get-WebConfigurationProperty" in iis005


def test_skip_cert_check_never_touches_service_point_manager() -> None:
    """A scriptblock callback runs on a thread with no runspace under 5.1, and a
    ServicePointManager callback of any kind trusts every certificate
    process-wide. -SkipCertCheck must use a per-request callback on 5.1 (a
    compiled HttpWebRequest helper) and -SkipCertificateCheck on PowerShell 7."""
    code = _code()
    assert "ServicePointManager]::ServerCertificateValidationCallback" not in code
    assert not re.search(r"ServerCertificateValidationCallback\s*=\s*\{", code)
    assert "Add-Type -TypeDefinition" in code
    assert (
        "req.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback" in code
    )
    assert "req.KeepAlive = false;" in code
    # Re-adding an existing type throws, so the Add-Type must be guarded.
    assert re.search(r"if\s*\(\s*-not\s*\('CertWatchVerify\.\w+'\s*-as\s*\[type\]\)\s*\)", code)
    http = code.split("function Invoke-Http", 1)[1].split("\nfunction ", 1)[0]
    assert "[CertWatchVerify.InsecureProbe]::Get(" in http
    assert "$iwr['SkipCertificateCheck'] = $true" in http
    assert "Invoke-WebRequest @iwr" in http


def test_no_log_or_event_content_and_one_render_path() -> None:
    """Log lines and event messages are free text: they never enter the
    report, even with -FullDiagnostics (only paths/sizes and event ids). All
    output renders from the single sanitized report object."""
    code = _code()
    diag = code.split("function Get-Diagnostics", 1)[1].split("\nfunction ", 1)[0]
    assert "Get-Content" not in diag.replace("Get-Content -Path $wcPath -Raw -ErrorAction Stop", "")
    assert "$_.Message" not in diag
    assert "stdout_logs" in diag
    walk = code.index("$report = Protect-ReportValue $report")
    tail = code[walk:]
    assert walk < code.index("$jsonText = $report | ConvertTo-Json")
    assert "$script:Checks" not in tail
    assert "$hostName" not in tail
    assert "$nextActions" not in tail
    assert "-ErrorAction Stop" in tail.split("Set-Content", 1)[1].split("\n", 1)[0]

def test_report_never_embeds_raw_web_config_or_appcmd_output() -> None:
    """web.config is summarised from an allowlist with grammar-checked values;
    appcmd output keeps only allowlisted fields. Behaviour is tested under pwsh
    in tests/test_windows_tooling_behaviour.py."""
    code = _code()
    assert "ConvertTo-WebConfigSummary $wc.Text" in code
    assert "$d['web_config'] = Limit-Text" not in code
    for m in re.finditer(r"& \$appcmd list (apppool|site) \S+ '/text:\*' 2>&1 \| Out-String", code):
        line_start = code.rfind("\n", 0, m.start())
        line = code[line_start:m.end()]
        assert "Select-AppcmdField" in line or "$raw = " in line, line

def test_backend_process_check_warns_and_runs_before_http_probes() -> None:
    """IIS-006 detects the web.config-edit stall (worker up, no python.exe). It
    must never fail the run and must run before the HTTP probes, which would
    otherwise start the backend on demand and hide the stall."""
    code = _code()
    assert "-Id 'IIS-006'" in code
    iis006 = code.split("-Id 'IIS-006'", 1)[1].split("Add-Check -Id", 1)[0]
    assert "New-Body 'fail'" not in iis006
    assert "New-Body 'warn'" in iis006
    assert "Get-ChildProcessRow" in iis006
    assert "Select-BackendProcess" in iis006
    assert "appcmd recycle apppool" in iis006
    # A wedged WMI provider must not hang the verifier.
    rows = code.split("function Get-ChildProcessRow", 1)[1].split("\nfunction ", 1)[0]
    assert "-OperationTimeoutSec" in rows
    assert code.index("-Id 'IIS-006'") < code.index("-Id 'HTTP-001'")


def test_no_single_quotes_inside_double_quoted_strings() -> None:
    from tests.test_install_windows_ps1 import _find_single_quote_in_double

    problem = _find_single_quote_in_double(_code())
    assert problem is None, problem
