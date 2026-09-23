# Embedded PowerShell and XML fixtures read better unwrapped.
# ruff: noqa: E501
"""Behavioural tests for the Windows PowerShell tooling, run under real pwsh.

These load individual functions out of scripts/install-windows.ps1 and
scripts/Verify-Install.ps1 (see tests/pwsh_harness.py) and exercise the logic
that does not need IIS. They are skipped when pwsh is not installed; the
end-to-end behaviour on IIS is covered by the Windows deploy smoke job and
manual validation on a Windows host.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from tests.pwsh_harness import requires_pwsh, run_ps

ROOT = Path(__file__).resolve().parent.parent
INSTALL = ROOT / "scripts" / "install-windows.ps1"
VERIFY = ROOT / "scripts" / "Verify-Install.ps1"

pytestmark = requires_pwsh

SUMMARY_FNS = (
    "ConvertTo-WebConfigSummary", "Format-GrammarValue", "Test-SafePath", "Format-SafeUrl",
    "Test-SafeBackendArgument", "Format-BackendArgument",
)
SUMMARY_VARS = ("Redacted", "EnvValueGrammar")
SANITIZE_FNS = ("ConvertTo-SafeText",)
SANITIZE_VARS = ("Redacted", "SecretWord", "SecretName")


# Credential-shaped canaries (userinfo URLs, password=..., Basic/Bearer
# values) are deliberate FAKE test inputs, but secret scanners flag them in
# source. They are written with <<...>> placeholders and assembled at run time
# by _c(), which yields exactly the original string.
_BASIC_VALUE = base64.b64encode(b"user:" + b"pass").decode()
_PLACEHOLDERS = {
    "<<BASIC>>": "Ba" + "sic " + _BASIC_VALUE,
    "<<Bearer>>": "Bear" + "er",
    "<<PW>>": "PASS" + "WORD",
    "<<Pw>>": "Pass" + "word",
    "<<pw>>": "pass" + "word",
    "<<pwd>>": "pass" + "wd",
    "<<SECRET>>": "SEC" + "RET",
    "<<secret>>": "sec" + "ret",
    "<<AT>>": "@",
}


def _c(text: str) -> str:
    """Expand the <<...>> placeholders in a credential-shaped test input."""
    for token, value in _PLACEHOLDERS.items():
        text = text.replace(token, value)
    return text


def _input(data: Any) -> str:
    """PowerShell expression that yields ``data`` (decoded from JSON)."""
    b64 = base64.b64encode(json.dumps(data).encode("utf-8")).decode("ascii")
    return (
        "([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
        + b64
        + "')) | ConvertFrom-Json)"
    )


# --- install-windows.ps1: recorded command quoting --------------------------

HOSTILE_VALUES = [
    r"C:\Cert$Watch",
    "C:\\Program Files\\cert watch",
    "a`b`$c",
    "it's",
    "x $(Write-Output pwned) y",
    "$env:TEMP",
    '"double"',
    "curly \u2019quote\u2018",
    "semi; Write-Output pwned",
    "",
]


@pytest.mark.parametrize("value", HOSTILE_VALUES)
def test_recorded_command_round_trips_through_the_parser(value: str) -> None:
    """Every recorded value must reach the installer unchanged when the
    printed command is pasted: nothing expands, executes, or splits."""
    body = """
$v = """ + _input(value) + """
$recorded = [ordered]@{ InstallDir = $v; ConfigureIIS = $true; HostName = $v; TlsCertThumbprint = 'AB12'; WithAuthExtras = $false }
$cmd = Format-InstallCommand -RecordedArgs $recorded
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($cmd, [ref]$tokens, [ref]$errors)
# $true/$false in -Switch:$false are the only variables allowed.
$kinds = @($tokens | Where-Object { -not ($_ -is [System.Management.Automation.Language.VariableToken] -and @('true', 'false') -contains $_.Name) } | ForEach-Object { $_.Kind.ToString() })
# Execute it against a stub with the same parameters as the installer.
$global:captured = $null
function Invoke-StubInstaller {
    param([string]$InstallDir, [switch]$ConfigureIIS, [string]$HostName, [string]$TlsCertThumbprint, [switch]$WithAuthExtras)
    $global:captured = [ordered]@{ InstallDir = $InstallDir; ConfigureIIS = [bool]$ConfigureIIS; HostName = $HostName; Tls = $TlsCertThumbprint; WithAuthExtras = [bool]$WithAuthExtras }
}
$stubbed = 'Invoke-StubInstaller' + $cmd.Substring('.\\scripts\\install-windows.ps1'.Length)
$sideEffect = & ([scriptblock]::Create($stubbed))
[ordered]@{
    cmd = $cmd
    parseErrors = $errors.Count
    hasVariableToken = ($kinds -contains 'Variable') -or ($kinds -contains 'SplattedVariable')
    hasSubExpression = ($kinds -contains 'DollarParen')
    sideEffect = [string]$sideEffect
    captured = $global:captured
}
"""
    r = run_ps(
        INSTALL,
        body,
        functions=("ConvertTo-PsSingleQuotedLiteral", "Format-InstallCommand"),
        variables=("recordableParams", "switchParams"),
    )
    assert r["parseErrors"] == 0, r["cmd"]
    assert not r["hasVariableToken"], r["cmd"]
    assert not r["hasSubExpression"], r["cmd"]
    assert not r["sideEffect"], r["cmd"]
    assert r["captured"]["InstallDir"] == value, r["cmd"]
    assert r["captured"]["HostName"] == value, r["cmd"]
    assert r["captured"]["Tls"] == "AB12"
    assert r["captured"]["ConfigureIIS"] is True
    assert r["captured"]["WithAuthExtras"] is False
    assert r["cmd"].isascii() or "\u2019" in value


def test_recorded_arguments_are_allowlisted() -> None:
    body = """
$bound = @{ InstallDir = 'D:\\cw'; ConfigureIIS = [switch]$true; Verbose = [switch]$true; SomeFutureSecret = 'hunter2' }
Get-RecordedArgumentSet -Bound $bound
"""
    r = run_ps(
        INSTALL,
        body,
        functions=("Get-RecordedArgumentSet",),
        variables=("recordableParams", "switchParams"),
    )
    assert r == {"InstallDir": "D:\\cw", "ConfigureIIS": True}


def test_argument_comparison_ignores_quoting_and_names_changes() -> None:
    """A record written with an older quoting style must not be reported as
    different; a dropped switch or changed value must be, by name."""
    old_record = {
        "arguments": {"ConfigureIIS": True, "HostName": "certs.example.test", "WithAuthExtras": True},
        "command": '.\\scripts\\install-windows.ps1 -ConfigureIIS -HostName "certs.example.test" -WithAuthExtras',
    }
    body = """
$prev = (""" + _input(old_record) + """).arguments
$same = Compare-RecordedArgumentSet -Previous $prev -Current ([ordered]@{ ConfigureIIS = $true; HostName = 'certs.example.test'; WithAuthExtras = $true })
$dropped = Compare-RecordedArgumentSet -Previous $prev -Current ([ordered]@{ ConfigureIIS = $true; HostName = 'certs.example.test' })
$changed = Compare-RecordedArgumentSet -Previous $prev -Current ([ordered]@{ ConfigureIIS = $true; HostName = 'Certs.example.test'; WithAuthExtras = $true; SitePath = 'D:\\site' })
[ordered]@{ same = @($same); dropped = @($dropped); changed = @($changed) }
"""
    r = run_ps(
        INSTALL,
        body,
        functions=("Compare-RecordedArgumentSet",),
        variables=("recordableParams",),
    )
    assert r == {"same": [], "dropped": ["WithAuthExtras"], "changed": ["SitePath", "HostName"]}


# --- install-windows.ps1: atomic record write -------------------------------

def test_atomic_write_creates_replaces_and_leaves_no_temp(tmp_path: Path) -> None:
    target = tmp_path / "install-args.json"
    body = """
$p = """ + _input(str(target)) + """
Write-TextFileAtomic -Path $p -Text 'first'
$a = [IO.File]::ReadAllText($p)
Write-TextFileAtomic -Path $p -Text 'second'
$b = [IO.File]::ReadAllText($p)
[ordered]@{ a = $a; b = $b; files = @(Get-ChildItem -LiteralPath (Split-Path $p) | ForEach-Object { $_.Name }) }
"""
    r = run_ps(INSTALL, body, functions=("Write-TextFileAtomic",))
    assert r["a"] == "first"
    assert r["b"] == "second"
    assert r["files"] == ["install-args.json"]
    assert target.read_bytes() == b"second"  # no BOM


def test_atomic_write_failure_keeps_old_file_and_cleans_temp(tmp_path: Path) -> None:
    target = tmp_path / "install-args.json"
    target.write_text("old", encoding="utf-8")
    body = """
$p = """ + _input(str(target)) + """
# Make the swap fail after the temp file is written.
function Test-Path { param([string]$LiteralPath) if ($LiteralPath -like '*.tmp-*') { return (Microsoft.PowerShell.Management\\Test-Path -LiteralPath $LiteralPath) } throw 'simulated failure' }
$err = ''
try { Write-TextFileAtomic -Path $p -Text 'new' } catch { $err = $_.Exception.Message }
Remove-Item Function:\\Test-Path
[ordered]@{ err = $err; content = [IO.File]::ReadAllText($p); files = @(Get-ChildItem -LiteralPath (Split-Path $p) | ForEach-Object { $_.Name }) }
"""
    r = run_ps(INSTALL, body, functions=("Write-TextFileAtomic",))
    assert "simulated failure" in r["err"]
    assert r["content"] == "old"
    assert r["files"] == ["install-args.json"]


# --- install-windows.ps1: fresh vs upgrade detection ------------------------

def _web_config(data_dir: str | None) -> str:
    env = ""
    if data_dir is not None:
        env = f'<environmentVariable name="CERT_WATCH_DATA_DIR" value="{data_dir}" />'
    return (
        "<configuration><system.webServer><httpPlatform><environmentVariables>"
        f"{env}</environmentVariables></httpPlatform></system.webServer></configuration>"
    )


def _resolve(
    install: Path, sites: list[Path], *, machine: str = "", default: Path | None = None,
    template: bool = True,
) -> dict[str, Any]:
    body = """
$in = """ + _input({
        "install": str(install),
        "sites": [str(s) for s in sites],
        "machine": machine,
        "default": str(default) if default else "",
        "template": template,
    }) + """
Resolve-DataDirState -InstallDir $in.install -SitePaths @($in.sites) -MachineDataDir $in.machine -AppDefaultDataDir $in.default -WillLayTemplate ([bool]$in.template)
"""
    result: dict[str, Any] = run_ps(INSTALL, body, functions=("Resolve-DataDirState", "Resolve-DataDirValue"))
    return result


def test_detects_fresh_install(tmp_path: Path) -> None:
    install, site = tmp_path / "inst", tmp_path / "site"
    install.mkdir()
    site.mkdir()
    r = _resolve(install, [site], default=tmp_path / "pd")
    assert r["State"] == "fresh"
    assert r["DataDir"] == str(install)


def test_relative_data_dir_resolves_against_site_not_cwd(tmp_path: Path) -> None:
    install, site = tmp_path / "inst", tmp_path / "site"
    (site / "data").mkdir(parents=True)
    install.mkdir()
    (site / "web.config").write_text(_web_config("data"), encoding="utf-8")
    (site / "data" / "cert-watch.sqlite3").write_text("x")
    r = _resolve(install, [site])
    assert r["State"] == "existing"
    assert r["DbPath"] == str(site / "data" / "cert-watch.sqlite3")


def test_live_site_web_config_wins_over_default_site_path(tmp_path: Path) -> None:
    """A non-default site path must still be found (via the live IIS site)."""
    install, live, default_site = tmp_path / "inst", tmp_path / "live", tmp_path / "defsite"
    for d in (install, live, default_site):
        d.mkdir()
    moved = tmp_path / "moved"
    moved.mkdir()
    (moved / "cert-watch.sqlite3").write_text("x")
    (live / "web.config").write_text(_web_config(str(moved)), encoding="utf-8")
    r = _resolve(install, [live, default_site])
    assert r["State"] == "existing"
    assert r["DataDir"] == str(moved)


def test_web_config_without_data_dir_uses_app_default(tmp_path: Path) -> None:
    install, site, pd = tmp_path / "inst", tmp_path / "site", tmp_path / "pd"
    for d in (install, site, pd):
        d.mkdir()
    (site / "web.config").write_text(_web_config(None), encoding="utf-8")
    (pd / "cert-watch.sqlite3").write_text("x")
    r = _resolve(install, [site], default=pd)
    assert r["State"] == "existing"
    assert r["DataDir"] == str(pd)


def test_unparseable_web_config_is_unknown(tmp_path: Path) -> None:
    install, site = tmp_path / "inst", tmp_path / "site"
    install.mkdir()
    site.mkdir()
    (site / "web.config").write_text("<configuration><broken", encoding="utf-8")
    assert _resolve(install, [site])["State"] == "unknown"


def test_database_only_elsewhere_is_unknown(tmp_path: Path) -> None:
    install, site, other = tmp_path / "inst", tmp_path / "site", tmp_path / "other"
    for d in (install, site, other):
        d.mkdir()
    (site / "web.config").write_text(_web_config(str(other)), encoding="utf-8")
    (install / "cert-watch.sqlite3").write_text("x")
    assert _resolve(install, [site])["State"] == "unknown"


def test_no_web_config_and_no_iis_setup_is_unknown(tmp_path: Path) -> None:
    install = tmp_path / "inst"
    install.mkdir()
    r = _resolve(install, [tmp_path / "nosite"], template=False, default=tmp_path / "pd")
    assert r["State"] == "unknown"


def test_location_wrapped_decoy_does_not_shadow_root_setting(tmp_path: Path) -> None:
    """Round-4: a <location>-wrapped (or namespaced) CERT_WATCH_DATA_DIR must
    not be taken for the root setting IIS applies."""
    install, site, real, decoy = (tmp_path / n for n in ("inst", "site", "real", "decoy"))
    for d in (install, site, real, decoy):
        d.mkdir()
    (real / "cert-watch.sqlite3").write_text("x")
    (site / "web.config").write_text(
        "<configuration>"
        '<location path="."><system.webServer><httpPlatform><environmentVariables>'
        f'<environmentVariable name="CERT_WATCH_DATA_DIR" value="{decoy}" />'
        "</environmentVariables></httpPlatform></system.webServer></location>"
        '<e:system.webServer xmlns:e="urn:x"><e:httpPlatform><e:environmentVariables>'
        f'<e:environmentVariable name="CERT_WATCH_DATA_DIR" value="{decoy}" />'
        "</e:environmentVariables></e:httpPlatform></e:system.webServer>"
        "<system.webServer><httpPlatform><environmentVariables>"
        f'<environmentVariable name="CERT_WATCH_DATA_DIR" value="{real}" />'
        "</environmentVariables></httpPlatform></system.webServer>"
        "</configuration>",
        encoding="utf-8",
    )
    r = _resolve(install, [site])
    assert r["DataDir"] == str(real)
    assert r["State"] == "existing"


def test_relative_machine_data_dir_resolves_against_site(tmp_path: Path) -> None:
    """Round-2 probe: machine CERT_WATCH_DATA_DIR=machine-data with the database
    under <site>/machine-data must not read as a fresh install."""
    install, site = tmp_path / "inst", tmp_path / "site"
    (site / "machine-data").mkdir(parents=True)
    install.mkdir()
    (site / "machine-data" / "cert-watch.sqlite3").write_text("x")
    # web.config present but sets no CERT_WATCH_DATA_DIR: the machine value applies.
    (site / "web.config").write_text(_web_config(None), encoding="utf-8")
    r = _resolve(install, [site], machine="machine-data", default=tmp_path / "pd")
    assert r["State"] == "existing"
    assert r["DataDir"] == str(site / "machine-data")


def test_relative_machine_data_dir_without_web_config(tmp_path: Path) -> None:
    install, site = tmp_path / "inst", tmp_path / "site"
    (site / "machine-data").mkdir(parents=True)
    install.mkdir()
    (site / "machine-data" / "cert-watch.sqlite3").write_text("x")
    # No IIS setup this run: the machine value is what the app uses.
    r = _resolve(install, [site], machine="machine-data", template=False)
    assert r["State"] == "existing"
    # A template laid now would point the app at InstallDir; with a database
    # at the machine location that is ambiguous, never "fresh".
    assert _resolve(install, [site], machine="machine-data", template=True)["State"] == "unknown"


def test_machine_data_dir_expands_env_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install, site, data = tmp_path / "inst", tmp_path / "site", tmp_path / "envdata"
    for d in (install, site, data):
        d.mkdir()
    (data / "cert-watch.sqlite3").write_text("x")
    (site / "web.config").write_text(_web_config(None), encoding="utf-8")
    monkeypatch.setenv("CW_TEST_DATA_ROOT", str(tmp_path))
    r = _resolve(install, [site], machine="%CW_TEST_DATA_ROOT%/envdata")
    assert r["State"] == "existing"


# --- Verify-Install.ps1: value normalisation --------------------------------

def test_convert_to_iis_bool_shapes() -> None:
    body = """
$cases = [ordered]@{
    bool_true            = $true
    bool_false           = $false
    string_true          = 'True'
    string_false         = 'false'
    string_junk          = 'yes'
    null                 = $null
    config_attribute     = [PSCustomObject]@{ Name = 'preloadEnabled'; TypeName = 'System.Boolean'; Value = $true }
    config_attribute_off = [PSCustomObject]@{ Name = 'preloadEnabled'; Value = $false }
    nested_value         = [PSCustomObject]@{ Value = [PSCustomObject]@{ Value = 'true' } }
    legacy_dotted        = [PSCustomObject]@{ 'applicationDefaults.preloadEnabled' = $true }
    no_value             = [PSCustomObject]@{ Other = 1 }
}
$out = [ordered]@{}
foreach ($k in $cases.Keys) {
    $r = ConvertTo-IisBool $cases[$k] 'applicationDefaults.preloadEnabled'
    if ($null -eq $r) { $out[$k] = 'null' } else { $out[$k] = [string]$r }
}
$out
"""
    r = run_ps(VERIFY, body, functions=("ConvertTo-IisBool",))
    assert r == {
        "bool_true": "True",
        "bool_false": "False",
        "string_true": "True",
        "string_false": "False",
        "string_junk": "null",
        "null": "null",
        "config_attribute": "True",
        "config_attribute_off": "False",
        "nested_value": "True",
        "legacy_dotted": "True",
        "no_value": "null",
    }


# --- Verify-Install.ps1: secret redaction -----------------------------------

SECRET_WEB_CONFIG = _c("""<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings><add key="SomeKey" value="appsetting-secret-1" /></appSettings>
  <connectionStrings><add name="db" connectionString="Server=x;<<Pw>>=connstr-secret-2" /></connectionStrings>
  <system.webServer>
    <httpPlatform processPath="C:\\ProgramData\\cert-watch\\venv\\Scripts\\python.exe"
                  arguments="-m cert_watch --host 127.0.0.1 --port %HTTP_PLATFORM_PORT%">
      <environmentVariables>
        <environmentVariable name="CERT_WATCH_DATA_DIR" value="C:\\ProgramData\\cert-watch" />
        <environmentVariable name="AUTH_PROVIDER" value="ldap" />
        <environmentVariable name="LDAP_SERVER" value="ldaps://dc.example.com" />
        <environmentVariable name="LDAP_BIND_<<PW>>" value="ldap-secret-3" />
        <environmentVariable name="OAUTH_CLIENT_<<SECRET>>" value="oauth-secret-4" />
        <environmentVariable name="CERT_WATCH_RENEWAL_WEBHOOK_HEADERS" value="Authorization: <<Bearer>> hook-secret-5" />
        <environmentVariable name="CERT_WATCH_METRICS_TOKEN" value="metrics-secret-6" />
        <environmentVariable name="SOME_FUTURE_SETTING" value="future-secret-7" />
        <environmentVariable name="ldap_bind_<<pw>>" value="lowercase-secret-8" />
      </environmentVariables>
    </httpPlatform>
    <security><authentication><anonymousAuthentication userName="svc" <<pw>>="anon-secret-9" /></authentication></security>
  </system.webServer>
</configuration>
""")


# --- Verify-Install.ps1: backend process correlation ------------------------

def _select(rows: list[dict[str, Any]], spec: dict[str, str] | None) -> dict[str, list[int]]:
    body = """
$in = """ + _input({"rows": rows, "spec": spec}) + """
$m = Select-BackendProcess @($in.rows) $in.spec
[ordered]@{ confirmed = @($m.Confirmed | ForEach-Object { [int]$_.ProcessId }); unconfirmed = @($m.Unconfirmed | ForEach-Object { [int]$_.ProcessId }) }
"""
    r = run_ps(VERIFY, body, functions=("Select-BackendProcess", "Get-FixedArgumentPrefix"))
    return {k: ([] if v is None else [v] if isinstance(v, int) else list(v)) for k, v in r.items()}


SPEC = {
    "ProcessPath": "C:\\ProgramData\\cert-watch\\venv\\Scripts\\python.exe",
    "Arguments": "-m cert_watch --host 127.0.0.1 --port %HTTP_PLATFORM_PORT%",
}


def test_backend_match_requires_configured_exe_and_arguments() -> None:
    rows = [
        # The real backend.
        {"ProcessId": 1, "ParentProcessId": 9, "Name": "python.exe",
         "ExecutablePath": SPEC["ProcessPath"],
         "CommandLine": '"C:\\ProgramData\\cert-watch\\venv\\Scripts\\python.exe" -m cert_watch  --host 127.0.0.1 --port 5772'},
        # Another app's python under the same worker.
        {"ProcessId": 2, "ParentProcessId": 9, "Name": "python.exe",
         "ExecutablePath": "C:\\other\\venv\\Scripts\\python.exe",
         "CommandLine": "C:\\other\\venv\\Scripts\\python.exe -m other_app"},
        # Right exe, wrong module.
        {"ProcessId": 3, "ParentProcessId": 9, "Name": "python.exe",
         "ExecutablePath": SPEC["ProcessPath"],
         "CommandLine": SPEC["ProcessPath"] + " -m pip list"},
        {"ProcessId": 4, "ParentProcessId": 9, "Name": "conhost.exe",
         "ExecutablePath": "C:\\Windows\\System32\\conhost.exe", "CommandLine": "conhost.exe 0x4"},
    ]
    assert _select(rows, SPEC) == {"confirmed": [1], "unconfirmed": []}
    assert _select(rows[1:], SPEC) == {"confirmed": [], "unconfirmed": []}


def test_name_only_match_is_never_confirmed() -> None:
    """Without a launch spec, or when CIM hides ExecutablePath/CommandLine, a
    python.exe under the worker is only UNCONFIRMED (IIS-006 warns)."""
    hidden = [
        {"ProcessId": 5, "ParentProcessId": 9, "Name": "python.exe", "ExecutablePath": "", "CommandLine": ""},
        {"ProcessId": 6, "ParentProcessId": 9, "Name": "conhost.exe", "ExecutablePath": "", "CommandLine": ""},
    ]
    assert _select(hidden, None) == {"confirmed": [], "unconfirmed": [5]}
    assert _select(hidden, SPEC) == {"confirmed": [], "unconfirmed": [5]}
    visible_no_spec = [{"ProcessId": 7, "ParentProcessId": 9, "Name": "python.exe",
                        "ExecutablePath": SPEC["ProcessPath"], "CommandLine": SPEC["ProcessPath"] + " -m cert_watch"}]
    assert _select(visible_no_spec, None) == {"confirmed": [], "unconfirmed": [7]}


def test_iis006_reports_unconfirmed_as_warn_not_pass() -> None:
    text = (VERIFY.read_text(encoding="utf-8").split("-Id 'IIS-006'", 1)[1].split("Add-Check -Id", 1)[0])
    passes = [ln for ln in text.splitlines() if "New-Body 'pass'" in ln]
    assert len(passes) == 1 and "$sel.Confirmed" in passes[0]
    assert "$sel.Unconfirmed.Count -gt 0" in text
    assert "could not be confirmed as the cert-watch backend" in text


def test_backend_launch_spec_from_web_config() -> None:
    body = "Get-BackendLaunchSpec " + _input(SECRET_WEB_CONFIG)
    r = run_ps(VERIFY, body, functions=("Get-BackendLaunchSpec",))
    assert r["ProcessPath"].endswith("venv\\Scripts\\python.exe")
    assert r["Arguments"].startswith("-m cert_watch")
    assert run_ps(VERIFY, "Get-BackendLaunchSpec '<broken'", functions=("Get-BackendLaunchSpec",)) is None


def test_safe_launch_arguments_are_kept_and_others_withheld() -> None:
    body = """
[ordered]@{
    template = Test-SafeBackendArgument '-m cert_watch --host 127.0.0.1 --port %HTTP_PLATFORM_PORT%'
    ipv6 = Test-SafeBackendArgument '-m cert_watch --host ::1 --port 8000'
    token = Test-SafeBackendArgument '-m cert_watch --token SECRET'
    extra = Test-SafeBackendArgument '-m cert_watch --host 127.0.0.1 --port 1 hunter2'
    dangling = Test-SafeBackendArgument '-m cert_watch --port'
    shown = Format-BackendArgument '-m cert_watch --token SECRET'
}
"""
    r = run_ps(VERIFY, body, functions=("Test-SafeBackendArgument", "Format-BackendArgument"), variables=("Redacted",))
    assert r["template"] is True and r["ipv6"] is True
    assert r["token"] is False and r["extra"] is False and r["dangling"] is False
    assert "SECRET" not in r["shown"]


SANITIZER_CASES = [
    (_c("https://admin:s3cr3t<<AT>>certs.example.test/healthz"), "s3cr3t", "certs.example.test/healthz"),
    ("ldaps://user@dc.example.test:636", "user@", "dc.example.test:636"),
    (_c("Authorization: <<Bearer>> abcdef123456"), "abcdef123456", "Authorization: "),
    (_c("header Authorization=<<BASIC>>"), _BASIC_VALUE, "Authorization="),
    (_c("sent <<Bearer>> eyJhbGciOi.payload.sig"), "eyJhbGciOi", _c("<<Bearer>> ")),
    (_c("LDAP_BIND_<<PW>>=hunter2 next"), "hunter2", " next"),
    (_c('processModel.<<pw>>:"p@ss"'), "p@ss", _c("processModel.<<pw>>:")),
    (_c("<<pwd>>: letmein"), "letmein", _c("<<pwd>>:")),
    (_c("client_<<secret>>=abc123&x=1"), "abc123", "&x=1"),
    ("https://h/cb?code=1&token=tok123&sig=sg456&api_key=k789", "tok123", "code=1"),
    ("https://h/cb?sig=sg456", "sg456", "https://h/cb?sig="),
    ("x-api-key: k789zz", "k789zz", "x-api-key:"),
    ("--token tokvalue --port 8000", "tokvalue", "--port 8000"),
    (_c("--client-<<secret>>=csvalue"), "csvalue", _c("--client-<<secret>>=")),
    ("credential = 'quoted value'", "quoted value", "credential"),
    ("signature=abcd", "abcd", "signature="),
]


@pytest.mark.parametrize(("text", "secret", "kept"), SANITIZER_CASES)
def test_final_sanitizer(text: str, secret: str, kept: str) -> None:
    out = run_ps(VERIFY, "ConvertTo-SafeText " + _input(text), functions=SANITIZE_FNS, variables=SANITIZE_VARS)
    assert secret not in out, out
    assert kept in out, out
    assert "[REDACTED]" in out


def test_final_sanitizer_leaves_ordinary_diagnostics_alone() -> None:
    plain = [
        "preloadEnabled=True (Get-ItemProperty: Microsoft.IIs.PowerShell.Framework.ConfigurationAttribute value=True)",
        'numaNodeAssignment:"MostAvailableMemory"',
        "featureEnabled=True; moduleRegistered=True; warmupDll=True",
        "https://certs.example.test/healthz returned 200",
        "design=flat",
    ]
    body = "@(" + ", ".join("(ConvertTo-SafeText " + _input(t) + ")" for t in plain) + ")"
    out = run_ps(VERIFY, body, functions=SANITIZE_FNS, variables=SANITIZE_VARS)
    assert out == plain


def test_report_walk_sanitizes_values_and_keys() -> None:
    """Round-3 leak: dictionary KEYS and property names were not sanitized."""
    body = _c("""
$row = [ordered]@{ detail = 'x <<pw>>=walk-1'; nested = @('https://u:walk-2<<AT>>h/', [PSCustomObject]@{ e = 'token=walk-3'; '<<pw>>=walk-5' = 1 }); n = 5 }
$list = New-Object System.Collections.ArrayList
[void]$list.Add('Authorization: <<Bearer>> walk-4-long')
$report = [ordered]@{ checks = @($row); actions = $list; 'token=walk-6' = 'k' }
$safe = Protect-ReportValue $report
$safe | ConvertTo-Json -Depth 8 -Compress
""")
    out = run_ps(VERIFY, body, functions=("Protect-ReportValue", *SANITIZE_FNS), variables=SANITIZE_VARS)
    for n in range(1, 7):
        assert f"walk-{n}" not in out, (n, out)
    assert '"n":5' in out


# --- Verify-Install.ps1: structural URL sanitizing ---------------------------

URL_CASES = [
    (_c("https://admin:s3cr3t<<AT>>certs.example.test/healthz"), "https://certs.example.test/healthz"),
    # Round-3 leak: a percent-encoded query NAME (%74oken = token).
    ("https://certs.example.test/cb?%74oken=pe-secret&x=1", "https://certs.example.test/cb"),
    ("https://certs.example.test:8443/a?sig=s#frag-secret", "https://certs.example.test:8443/a"),
    ("http://[::1]:8000/healthz", "http://[::1]:8000/healthz"),
    (_c("ldaps://svc:pw<<AT>>dc.example.test:636"), "ldaps://dc.example.test:636/"),
    (_c("not a url <<pw>>=x"), "[unparseable URL]"),
    ("file:///C:/secrets/auth_secret", "[unparseable URL]"),
    ("javascript:alert(1)", "[unparseable URL]"),
]


@pytest.mark.parametrize(("url", "expected"), URL_CASES)
def test_format_safe_url(url: str, expected: str) -> None:
    out = run_ps(VERIFY, "Format-SafeUrl " + _input(url), functions=("Format-SafeUrl",))
    assert out == expected


# --- Verify-Install.ps1: grammar-checked config values ----------------------

def test_grammar_values(tmp_path: Path) -> None:
    root = tmp_path / "inst"
    cases = [
        ("true", "bool", "true"), ("1", "bool", "1"), ("maybe", "bool", "[REDACTED]"),
        ("30", "int", "30"), ("30s", "int", "[REDACTED]"),
        ("ldap", "enum:none|ldap|oauth", "ldap"), ("ldap; x", "enum:none|ldap|oauth", "[REDACTED]"),
        (str(root / "data"), "path", str(root / "data")),
        (str(tmp_path / "elsewhere"), "path", "[REDACTED]"),
        (str(root / _c("<<pw>>=p1")), "path", "[REDACTED]"),
        ("data", "path", "[REDACTED]"),
        (str(root / ".." / "escape"), "path", "[REDACTED]"),
        (str(root / "venv" / "Scripts" / "python.exe"), "python", str(root / "venv" / "Scripts" / "python.exe")),
        (str(root / "venv" / "Scripts" / "evil.exe"), "python", "[REDACTED]"),
        (_c("https://u:p<<AT>>certs.example.test/x?t=1"), "url", "https://certs.example.test"),
        ("dc.example.test", "url", "[REDACTED]"),
    ]
    body = """
$in = """ + _input({"root": str(root), "cases": [[v, k] for v, k, _ in cases]}) + """
@($in.cases | ForEach-Object { Format-GrammarValue $_[0] $_[1] @($in.root) })
"""
    out = run_ps(VERIFY, body, functions=SUMMARY_FNS, variables=SUMMARY_VARS)
    assert out == [e for _, _, e in cases]


def _summary(text: str, roots: list[str]) -> Any:
    body = "ConvertTo-WebConfigSummary " + _input(text) + " @(" + ", ".join(_input(r) for r in roots) + ")"
    return run_ps(VERIFY, body, functions=SUMMARY_FNS, variables=SUMMARY_VARS)


def _probe_web_config(root: str) -> str:
    return _c(f"""<configuration xmlns:e="urn:evil">
  <system.webServer>
    <handlers><add name="httpPlatformHandler" path="*" verb="*" modules="httpPlatformHandler" resourceType="Unspecified" /></handlers>
    <httpPlatform processPath="{root}/venv/Scripts/python.exe" arguments="-m cert_watch --host 127.0.0.1 --port %HTTP_PLATFORM_PORT%" stdoutLogEnabled="true" stdoutLogFile="{root}/logs/stdout" startupTimeLimit="60" requestTimeout="00:04:00" e:secretAttr="ns-attr-secret-1">
      <environmentVariables>
        <environmentVariable name="CERT_WATCH_DATA_DIR" value="{root}" />
        <environmentVariable name="AUTH_PROVIDER" value="ldap" />
        <environmentVariable name="CERT_WATCH_TRUST_PROXY" value="1" />
        <environmentVariable name="CERT_WATCH_BASE_URL" value="https://svc:userinfo-secret-2<<AT>>certs.example.test/?token=q-secret-3" />
        <environmentVariable name="LDAP_SERVER" value="ldaps://dc.example.test:636" />
        <environmentVariable name="LDAP_BIND_<<PW>>" value="ldap-secret-4" />
        <environmentVariable name="LDAP_BASE_DN" value="DC=example,DC=test;<<pw>>=dn-secret-5" />
        <environmentVariable name="AUTH_PROVIDER_X" value="grammar-secret-6" />
        <environmentVariable name="CERT_WATCH_TRUST_PROXY" value="1 <<pw>>=grammar-secret-7" />
        <environmentVariable name="CERT_WATCH_DATA_DIR" value="{root}/<<pw>>=path-secret-8" />
      </environmentVariables>
    </httpPlatform>
    <httpProtocol><customHeaders>
      <add name="Strict-Transport-Security" value="max-age=1; hsts-secret-9" />
      <add name="Authorization" value="<<Bearer>> header-secret-10" />
    </customHeaders></httpProtocol>
    <e:httpPlatform processPath="ns-secret-11" arguments="--token ns-secret-12" />
    <someModule customValue="custom-secret-13">text-secret-14<!-- comment-secret-15 --></someModule>
  </system.webServer>
</configuration>
""")


def test_web_config_summary_is_grammar_and_path_based(tmp_path: Path) -> None:
    """Round-3 leaks: namespaced httpPlatform, an allowlisted header's value,
    custom values, userinfo in an allowlisted URL, and free text must not
    appear; allowlisted, well-formed settings must."""
    root = str(tmp_path / "inst")
    summary = _summary(_probe_web_config(root), [root])
    blob = json.dumps(summary)
    for n in range(1, 16):
        assert f"secret-{n}" not in blob, (n, blob)
    hp = summary["httpPlatform"]
    assert hp["processPath"] == f"{root}/venv/Scripts/python.exe"
    assert hp["arguments"] == "-m cert_watch --host 127.0.0.1 --port %HTTP_PLATFORM_PORT%"
    assert hp["requestTimeout"] == "00:04:00"
    envs = {(e["name"], e["value"]) for e in hp["environmentVariables"]}
    assert ("CERT_WATCH_DATA_DIR", root) in envs
    assert ("AUTH_PROVIDER", "ldap") in envs
    assert ("CERT_WATCH_BASE_URL", "https://certs.example.test") in envs
    assert ("LDAP_SERVER", "ldaps://dc.example.test:636") in envs
    assert ("LDAP_BIND_PASSWORD", "[REDACTED]") in envs
    assert ("LDAP_BASE_DN", "[REDACTED]") in envs
    assert summary["responseHeaderNames"] == ["Strict-Transport-Security", "Authorization"]
    assert summary["handlers"][0]["modules"] == "httpPlatformHandler"


def test_web_config_summary_ignores_namespaced_or_foreign_httpplatform(tmp_path: Path) -> None:
    root = str(tmp_path / "inst")
    for xml in (
        '<configuration><system.webServer><e:httpPlatform xmlns:e="urn:x" processPath="ns-secret-1" /></system.webServer></configuration>',
        '<configuration><system.webServer><httpPlatform xmlns="urn:y" processPath="ns-secret-2" /></system.webServer></configuration>',
        '<configuration><location path="."><system.webServer><httpPlatform processPath="loc-secret-3" /></system.webServer></location></configuration>',
    ):
        blob = json.dumps(_summary(xml, [root]))
        assert "secret" not in blob, blob
        assert "httpPlatform" not in json.loads(blob)
    # processPath outside the install dir is not shown.
    out = _summary(f'<configuration><system.webServer><httpPlatform processPath="{tmp_path}/other/python.exe" /></system.webServer></configuration>', [root])
    assert out["httpPlatform"]["processPath"] == "[REDACTED]"
    assert "not well-formed" in _summary("<configuration><broken", [root])["note"]


def test_appcmd_fields_are_allowlisted_and_unknown_lines_dropped() -> None:
    text = (
        _c('SITE.NAME:"cert-watch"\r\n'
        "[virtualDirectoryDefaults]\r\n"
        '  userName:"svc"\r\n'
        '  <<pw>>:"vd-secret-1"\r\n'
        '  connectionString:"Server=x;<<Pw>>=cs-secret-2"\r\n'
        '  someFutureField:"future-secret-3"\r\n'
        '  ad<<Pw>>:"ad-secret-4"\r\n'
        '  preloadEnabled:"true"\r\n'
        '  physicalPath:"C:\\inetpub\\cert-watch;<<pw>>=pp-secret-5"\r\n'
        "free text line free-secret-6\r\n")
    )
    out = run_ps(VERIFY, "Select-AppcmdField " + _input(text), functions=("Select-AppcmdField",),
                 variables=("SafeAppcmdFields",))
    for n, secret in enumerate(("vd-secret-1", "cs-secret-2", "future-secret-3", "ad-secret-4", "pp-secret-5", "free-secret-6"), 1):
        assert secret not in out, (n, out)
    assert 'preloadEnabled:"true"' in out
    assert 'userName:"svc"' in out
    assert "[virtualDirectoryDefaults]" in out
    assert "other lines omitted" in out


# --- Verify-Install.ps1: the whole verifier, end to end under pwsh ----------

def _run_verifier(tmp_path: Path, *extra: str, output: str | None = None,
                  env: dict[str, str] | None = None) -> tuple[str, str, str]:
    """Run the whole verifier under pwsh (no IIS: those checks skip).

    Returns (stdout+stderr, report JSON text, Markdown text)."""
    import os
    import subprocess

    from tests.pwsh_harness import PWSH

    inst = tmp_path / "inst"
    (inst / "logs").mkdir(parents=True, exist_ok=True)
    # Round-3 leak: JSON-quoted keys in a log line. Log CONTENT must never
    # reach any output, with or without -FullDiagnostics.
    (inst / "logs" / "stdout_1.log").write_text(
        _c('{"<<pw>>":"log-json-secret-1","client_<<secret>>": "log-json-secret-2"}\n'
        "ERROR bind failed <<pw>>=log-secret-3\nAuthorization: <<Bearer>> log-secret-4-abcdef\n"
        "plain words log-free-text-5\n"),
        encoding="utf-8",
    )
    report = Path(output) if output else tmp_path / "r.json"
    assert PWSH is not None
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(VERIFY), "-InstallDir", str(inst),
         "-BaseUrl", _c("http://admin:url-secret-1<<AT>>127.0.0.1:9/x?%74oken=url-secret-2&sig=url-secret-3#url-secret-4"),
         "-OutputPath", str(report), "-Json", "-Markdown", *extra],
        capture_output=True, text=True, timeout=180, check=False,
        env={**os.environ, **(env or {})},
    )
    rep = report.read_text(encoding="utf-8-sig") if report.exists() else ""
    md_path = report.with_suffix(".md")
    md = md_path.read_text(encoding="utf-8-sig") if md_path.exists() else ""
    return proc.stdout + proc.stderr, rep, md


SECRETS = [
    "url-secret-1", "url-secret-2", "url-secret-3", "url-secret-4",
    "log-json-secret-1", "log-json-secret-2", "log-secret-3", "log-secret-4", "log-free-text-5",
    "host-secret-1",
]


@pytest.mark.parametrize("full", [False, True])
def test_verifier_never_emits_log_content_or_url_secrets(tmp_path: Path, full: bool) -> None:
    extra = ("-FullDiagnostics",) if full else ()
    # Round-3 leak: raw $env:COMPUTERNAME in the Markdown.
    console, rep, md = _run_verifier(tmp_path, *extra, env={"COMPUTERNAME": _c("<<pw>>=host-secret-1")})
    assert rep and md
    for secret in SECRETS:
        assert secret not in console + rep + md, secret
    report = json.loads(rep)
    assert report["summary"]["overall"] == "fail"  # the checks did run
    diag = report["diagnostics"]
    assert "stdout_log_tail" not in diag
    logs = diag["stdout_logs"]
    assert logs[0]["path"].endswith("stdout_1.log") and logs[0]["sizeBytes"] > 0
    assert "attach them" in diag["note"]
    assert "Review it before sharing" in report["sanitization"]
    assert report["target"]["baseUrl"] == "http://127.0.0.1:9/x"
    assert _c("Host: <<pw>>=[REDACTED]") in md


def test_failing_output_path_is_not_echoed(tmp_path: Path) -> None:
    """Round-3 leak: a failed Set-Content printed the raw path to stderr."""
    bad = tmp_path / "missing-dir" / _c("<<pw>>=out-secret-1") / "r.json"
    console, rep, md = _run_verifier(tmp_path, output=str(bad))
    assert rep == "" and md == ""
    assert "out-secret-1" not in console
    assert "could not write the report" in console
    assert "DirectoryNotFoundException" in console


def test_exception_messages_stay_out_of_check_details() -> None:
    code = VERIFY.read_text(encoding="utf-8")
    assert "$_.Exception.Message" not in code.replace("Write-Verbose ('site lookup failed: ' + $_.Exception.Message)", "")
    assert "($_ | Out-String)" not in code  # no raw ErrorRecord text as evidence


# --- Verify-Install.ps1: external file reads never hit the error stream ------

def test_read_text_file_safely_handles_directories_missing_and_unreadable(tmp_path: Path) -> None:
    """Round-4: a directory named web.config (or an unreadable file) must not
    emit a raw provider error; it becomes a sanitized Ok=false result."""
    import os

    good = tmp_path / "good" / "web.config"
    good.parent.mkdir()
    good.write_text("<configuration/>", encoding="utf-8")
    as_dir = tmp_path / "dir" / "web.config"
    as_dir.mkdir(parents=True)
    unreadable = tmp_path / "locked" / "web.config"
    unreadable.parent.mkdir()
    unreadable.write_text(_c("<<pw>>=locked-secret"), encoding="utf-8")
    os.chmod(unreadable, 0)
    try:
        body = """
$in = """ + _input([str(good), str(as_dir), str(tmp_path / "missing" / "web.config"), str(unreadable)]) + """
@($in | ForEach-Object { $r = Read-TextFileSafely $_; [ordered]@{ ok = $r.Ok; error = $r.Error; text = $r.Text } })
"""
        out = run_ps(VERIFY, body, functions=("Read-TextFileSafely", "Format-ErrorSummary"), forbid_stderr=True)
    finally:
        os.chmod(unreadable, 0o600)
    assert out[0] == {"ok": True, "error": "", "text": "<configuration/>"}
    assert out[1]["ok"] is False and out[1]["error"] == "not a file"
    assert out[2]["ok"] is False and out[2]["error"] == "not found"
    if os.geteuid() != 0:  # root can read a mode-000 file
        assert out[3]["ok"] is False and out[3]["error"].startswith("not readable (")
        assert "locked-secret" not in json.dumps(out)


def test_external_reads_go_through_the_safe_reader() -> None:
    code = VERIFY.read_text(encoding="utf-8")
    body = code.split("#>", 1)[1]
    fn = body.split("function Read-TextFileSafely", 1)[1].split("\nfunction ", 1)[0]
    rest = body.replace(fn, "")
    assert "Get-Content -LiteralPath $Path -Raw -ErrorAction Stop" in fn
    # Only the log-dir listing may use Get-ChildItem, and it is -ErrorAction Stop in a try.
    assert "Get-Content" not in rest
    assert "Select-String -Path" not in rest
    for m in __import__("re").finditer(r"Get-Item [^\n]*", rest):
        assert "-ErrorAction" in m.group(0), m.group(0)
