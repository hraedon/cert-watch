# Running cert-watch on Windows / IIS

cert-watch is a standard ASGI (FastAPI/uvicorn) app. IIS does not run Python
natively, so it fronts a Python process. There are two supported hosting
models; both leave the application code unchanged.

| Model | Who supervises uvicorn | Extra software | Best for |
|-------|------------------------|----------------|----------|
| **HttpPlatformHandler** (recommended) | IIS itself | None — a Microsoft-signed IIS module | Regulated/locked-down hosts; one thing (IIS) to manage |
| **Reverse proxy (ARR)** | You (Windows service / scheduled task) | ARR + URL Rewrite modules; a service wrapper such as NSSM | Shops already standardized on ARR |

If you have no strong preference, use **HttpPlatformHandler** — it needs no
third-party service wrapper and IIS manages the process lifecycle for you.

---

## Prerequisites (both models)

1. **Python 3.12+** for Windows (`winget install Python.Python.3.12` or the
   python.org installer). Confirm `py -3.12 --version`.
2. **IIS** with the relevant module:
   - HttpPlatformHandler: install from
     <https://www.iis.net/downloads/microsoft/httpplatformhandler> (or via the
     Web Platform Installer / offline MSI your change process allows).
   - Reverse proxy: install **URL Rewrite** and **Application Request Routing
     (ARR)**, then enable proxying (IIS Manager → server node → *Application
     Request Routing Cache* → *Server Proxy Settings* → check *Enable proxy*).
3. **Unlock the `handlers` config section.** IIS locks `<system.webServer/handlers>`
   by default on some configurations, which blocks the site's `web.config` from
   registering the HttpPlatformHandler module. Unlock it once at the server level:

   ```powershell
   & "$env:windir\system32\inetsrv\appcmd.exe" unlock config -section:system.webServer/handlers
   ```

   Without this, IIS returns error 0x80070021 ("section is locked at a parent
   level"). The reverse-proxy model needs `system.webServer/rewrite/rules`
   unlocked the same way if it's locked.
4. A **TLS certificate** bound to the IIS site (your internal CA or public).

---

## Why a shared Python install

The **Python Install Manager** (the new default for Python 3.14+ on Windows)
installs runtimes **per-user only** — under `%LocalAppData%\Python\`.  The IIS
app pool identity (`IIS AppPool\cert-watch`) is a virtual account with no user
profile, so it cannot traverse the installing user's profile directory tree.
Even granting ACLs on the user-profile path is fragile: the installing user's
profile may be cleaned up, the path changes if the user is different, and
corporate roaming profiles can relocate it.

`install-windows.ps1` detects this and automatically copies the runtime to
`C:\ProgramData\cert-watch\python\` (shared, under the install dir).  The venv
is then built from that shared interpreter.  The IIS app pool only needs access
to `C:\ProgramData\cert-watch\`, which is already granted.

### Alternatives considered (and why they were dismissed)

| Approach | Why not |
|----------|---------|
| **Grant ACLs on the user-profile Python dir** | Fragile: depends on the installing user's profile path surviving. Breaks if a different admin runs the script, if the profile is cleaned up, or under roaming profiles. We tried this first and hit "Access is denied" on the IIS app pool. |
| **`py install --target` to a shared location** | The Python team's recommended approach for per-machine installs. However, `py install --target` does not register the install with the `py` launcher — it's a raw extraction. We use it as a fallback if the `py` launcher is available, but a manual copy works too. |
| **The deprecated full installer (`python-3.14.x-amd64.exe /InstallAllUsers=1`)** | Installs to `C:\Program Files\Python314` (true system-wide). Still works for 3.14 but marked deprecated; 3.15+ may drop it. Ties us to a specific installer format. |
| **NuGet packages** | Minimal, no pip, no venv module. Designed for CI/build, not for running a production app. |
| **Embeddable package** | Stripped-down: no pip, no Tcl/Tk, `._pth` file restricts imports. Suitable for embedding, not for a full web app with dependencies. |
| **winget system-wide install** | `winget install Python.Python.3.14 --scope machine` uses the same deprecated full installer under the hood. Same long-term risk. |

The `--target` copy approach (option 2) is the Python team's own documented
workaround for per-machine installs and has no deprecation risk.

---

## Step 1 — Bootstrap the app (both models)

From an **elevated** PowerShell, in the repo root:

```powershell
# The script is unsigned; bypass the execution policy for this invocation:
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1
```

This creates `C:\ProgramData\cert-watch` (data dir), a virtualenv at
`C:\ProgramData\cert-watch\venv`, installs cert-watch into it, and generates
persistent signing keys at `C:\ProgramData\cert-watch\secrets\` (locked down to
Administrators). See the script for parameters (`-InstallDir`, `-WithAuthExtras`,
etc.).

> **Why generated key files?** cert-watch reads `CERT_WATCH_AUTH_SECRET` /
> `CERT_WATCH_CSRF_SECRET` (or their `*_FILE` variants). Persisting them means
> sessions survive process restarts and app-pool recycles — the same reason the
> Kubernetes deploy wires them from a Secret.

---

## Step 2a — Host with HttpPlatformHandler (recommended)

### 2a.1 — Create the site physical path and web.config

```powershell
New-Item -ItemType Directory -Force -Path "C:\inetpub\cert-watch"
Copy-Item deploy\iis\web.config "C:\inetpub\cert-watch\web.config"
```

Edit the copied `web.config` if your install dir differs from the defaults
(`processPath`, the `*_FILE` paths, `CERT_WATCH_DATA_DIR`).

### 2a.2 — Install HttpPlatformHandler (if not already present)

Download from <https://www.iis.net/downloads/microsoft/httpplatformhandler>
(or via the Web Platform Installer / offline MSI your change process allows).
The module is Microsoft-signed and requires no third-party service wrapper.

### 2a.3 — Create the app pool and IIS site

```powershell
Import-Module WebAdministration

# Create a dedicated app pool (IIS does not auto-create one per site)
New-Item IIS:\AppPools\cert-watch
Set-ItemProperty IIS:\AppPools\cert-watch -Name managedRuntimeVersion -Value ""

# Create the site and assign the pool
New-Item IIS:\Sites\cert-watch `
    -bindings @{protocol="https"; bindingInformation="*:443:certs.example.com"} `
    -physicalPath "C:\inetpub\cert-watch"
Set-ItemProperty IIS:\Sites\cert-watch -Name applicationPool -Value "cert-watch"
```

The `managedRuntimeVersion=""` sets "No Managed Code" — cert-watch is a Python
process, not a .NET app; loading the CLR is unnecessary overhead.

Then bind your TLS certificate to the 443 binding — either via IIS Manager
(*Site Bindings → Edit → SSL certificate*) or:

```powershell
# List available certs and bind one to the catch-all 443 ipport (matches the
# bindingInformation="*:443:certs.example.com" catch-all site binding above, the
# correct single-site default):
netsh http add sslcert ipport=0.0.0.0:443 `
    certhash=<THUMBPRINT> `
    appid="{GUID}"
```

If you run `install-windows.ps1 -ConfigureIIS`, add `-SharePort443` with a
`-HostName` (for example `-HostName certs.example.com -SharePort443`) to use
SNI — the binding becomes `sslFlags=1` and the cert is bound per-host via
`hostnameport=<host>:443`, letting sibling tools share port 443 by hostname.
**Do not mix**: a catch-all `*:443` site binding (`sslFlags=0`) shadows every
SNI `hostnameport` binding, so for co-residency all tools on 443 must use SNI
and none may hold the catch-all. Without `-SharePort443` the installer binds to
the catch-all `0.0.0.0:443`, the correct default for a single cert-watch site.

### 2a.4 — Configure the app pool

The daily scan scheduler runs as a thread *inside* the worker process, so an
idle or auto-recycled pool would stop scanning. Disable idle shutdown and set
the pool to always-running:

```powershell
$pool = "cert-watch"
Set-ItemProperty IIS:\AppPools\$pool -Name processModel.idleTimeout -Value "00:00:00"
Set-ItemProperty IIS:\AppPools\$pool -Name startMode -Value "AlwaysRunning"
Set-ItemProperty IIS:\AppPools\$pool -Name recycling.periodicRestart.time -Value "00:00:00"
```

### 2a.5 — Grant the app-pool identity access to data, secrets, and Python

Now that the app pool exists, re-run the install script with `-AppPool` to set
the ACLs on the data dir and secrets (or set them manually). You also need to
grant access to the Python installation itself — the venv's `python.exe` is a
symlink to the real interpreter, which lives in the user profile by default.

```powershell
# Option A: re-run the install script (idempotent — keeps existing secrets)
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1 -AppPool cert-watch

# Option B: set ACLs manually
$dataDir  = "C:\ProgramData\cert-watch"
$secrets  = "$dataDir\secrets"
$identity = "IIS AppPool\cert-watch"
icacls $dataDir /grant:r "${identity}:(OI)(CI)M" | Out-Null
icacls $secrets    /grant   "${identity}:(OI)(CI)R" | Out-Null

# Both A and B: grant access to the Python installation the venv points to.
# Find the real path from the venv's python.exe:
$pyReal = (Get-Item "C:\ProgramData\cert-watch\venv\Scripts\python.exe").Target
if (-not $pyReal) { $pyReal = "C:\ProgramData\cert-watch\venv\Scripts\python.exe" }
$pyDir = Split-Path $pyReal
icacls $pyDir /grant "${identity}:(OI)(CI)RX" | Out-Null
```

Without the Python-directory ACL, the HttpPlatformHandler logs
`did not find executable at '...python.exe': Access is denied` and IIS hangs
on every request.

### 2a.6 — Browse

Browse `https://certs.example.com/`. Logs land in
`C:\ProgramData\cert-watch\logs\stdout*.log`; `/healthz` should return 200.

## Step 2b — Host as reverse proxy + Windows service (Option A)

1. Run cert-watch as a service bound to loopback. With
   [NSSM](https://nssm.cc/) (or Shawl):

   ```powershell
   $py = "C:\ProgramData\cert-watch\venv\Scripts\cert-watch.exe"
   nssm install cert-watch $py
   nssm set cert-watch AppEnvironmentExtra `
     CERT_WATCH_DATA_DIR=C:\ProgramData\cert-watch `
     CERT_WATCH_HOST=127.0.0.1 `
     CERT_WATCH_PORT=8000 `
     CERT_WATCH_TRUST_PROXY=1 `
     CERT_WATCH_AUTH_SECRET_FILE=C:\ProgramData\cert-watch\secrets\auth_secret `
     CERT_WATCH_CSRF_SECRET_FILE=C:\ProgramData\cert-watch\secrets\csrf_secret
   nssm start cert-watch
   ```

   Binding to `127.0.0.1` keeps uvicorn off the network — only IIS reaches it.

2. Allow-list the forwarded headers and create the proxy site:

   ```powershell
   appcmd set config -section:system.webServer/rewrite/allowedServerVariables /+"[name='HTTP_X_FORWARDED_PROTO']" /commit:apphost
   appcmd set config -section:system.webServer/rewrite/allowedServerVariables /+"[name='HTTP_X_FORWARDED_HOST']" /commit:apphost
   ```

3. Rename [`web.config.reverse-proxy`](web.config.reverse-proxy) to `web.config`
   in the site physical path. Create the HTTPS site + cert binding as in 2a.

---

## Configuration notes

- **First run comes up authenticated.** Both models bind uvicorn to loopback,
  but set `CERT_WATCH_TRUST_PROXY=1` (the web.config / NSSM env already do), which
  tells cert-watch it's network-exposed behind a proxy. So on first run with no
  auth configured it **auto-provisions an `admin`** with a generated password
  rather than serving open. Retrieve it from
  `C:\ProgramData\cert-watch\logs\stdout*.log` or
  `C:\ProgramData\cert-watch\initial-admin-password` (the data dir). For
  production, configure `AUTH_PROVIDER` (LDAP/OAuth) or pin
  `CERT_WATCH_LOCAL_ADMIN_USER` + `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` instead
  of the generated credential, then delete the password file.
- **All config is environment variables** — identical to Linux/Docker (see the
  root `README.md`). Set them in `web.config` `<environmentVariables>`
  (HttpPlatformHandler) or via `nssm set ... AppEnvironmentExtra` (service).
- **`CERT_WATCH_TRUST_PROXY=1` is required** behind IIS so the client IP (rate
  limiting, audit log) comes from the forwarded headers rather than the loopback
  connection. Session/CSRF cookies are always `Secure`-flagged
  (`CERT_WATCH_COOKIE_SECURE` defaults to `1`), so the browser↔IIS HTTPS leg
  keeps them working without the app needing to infer the scheme.
- **OAuth/Entra:** set `CERT_WATCH_BASE_URL=https://certs.example.com` so the
  redirect URI is built with your public host, not the loopback address.
- **Data dir default:** on Windows, with `CERT_WATCH_DATA_DIR` unset, cert-watch
  defaults to `%PROGRAMDATA%\cert-watch`. The SQLite DB, WAL files, and
  generated secrets live there. Back it up like any other app data dir
  (`cert-watch backup <path>` produces a WAL-safe copy).

## Verify the install

After either hosting model, run the verifier from an **elevated** PowerShell to
check the end state — prerequisites, persisted secrets, ACLs, the IIS pool/site
config, and live HTTP health — in one pass:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Verify-Install.ps1 `
    -AppPool cert-watch -BaseUrl https://certs.example.com -SkipCertCheck
```

It is **read-only** (it never modifies the install). It writes a structured JSON
report to `C:\ProgramData\cert-watch\logs\verify-report.json` and **exits
non-zero if any check fails**, so a change-control or CI gate can branch on it.
The JSON bundles each failing check with an explicit remediation plus a
diagnostics dump (stdout-log tail, IIS config, ACLs, recent Application events)
so a failure can be triaged from the report alone, without RDP-ing in to dig.
Add `-Markdown` for a readable report, or `-Json` to stream it to stdout (handy
for feeding the result to an automated triage step). Each remediation string
points back to the relevant step in this document.

## Troubleshooting

- **502.5 / process failed to start:** check `logs\stdout*.log`. Usually a wrong
  `processPath`, a missing venv, or the app-pool identity lacking access to the
  data/secrets dirs.
- **Everyone logged out after a deploy/recycle:** signing keys not persisted —
  confirm the `*_FILE` paths exist and are readable by the app-pool identity.
- **Rate limiting treats everyone as one client:** `CERT_WATCH_TRUST_PROXY` not
  set, or (reverse-proxy model) the forwarded headers weren't allow-listed.
- **Scans never run:** app pool is idling out or recycling — apply the Step 2a.4
  settings.
