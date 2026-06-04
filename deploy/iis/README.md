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
3. A **TLS certificate** bound to the IIS site (your internal CA or public).

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
Administrators + the IIS app-pool identity). See the script for parameters
(`-InstallDir`, `-WithAuthExtras`, etc.).

> **Why generated key files?** cert-watch reads `CERT_WATCH_AUTH_SECRET` /
> `CERT_WATCH_CSRF_SECRET` (or their `*_FILE` variants). Persisting them means
> sessions survive process restarts and app-pool recycles — the same reason the
> Kubernetes deploy wires them from a Secret.

---

## Step 2a — Host with HttpPlatformHandler (recommended)

1. Create a site physical path, e.g. `C:\inetpub\cert-watch`, and copy
   [`web.config`](web.config) into it.
2. Edit the copied `web.config` if your install dir differs from the defaults
   (`processPath`, the `*_FILE` paths, `CERT_WATCH_DATA_DIR`).
3. Create the IIS site (PowerShell `WebAdministration`):

   ```powershell
   Import-Module WebAdministration
   New-Item IIS:\Sites\cert-watch -bindings @{protocol="https";bindingInformation="*:443:certs.example.com"} -physicalPath "C:\inetpub\cert-watch"
   # Bind your TLS cert to the 443 binding via IIS Manager, or:
   # (Get-Item IIS:\Sites\cert-watch).Bindings ... New-WebBinding / netsh http add sslcert
   ```

4. **Make scans reliable.** The daily scan scheduler runs as a thread *inside*
   the worker process, so an idle/auto-recycled app pool would stop scanning.
   Disable idle shutdown and set the pool to always-running:

   ```powershell
   $pool = "cert-watch"   # the pool IIS created for the site
   Set-ItemProperty IIS:\AppPools\$pool -Name processModel.idleTimeout -Value "00:00:00"
   Set-ItemProperty IIS:\AppPools\$pool -Name startMode -Value "AlwaysRunning"
   Set-ItemProperty IIS:\AppPools\$pool -Name recycling.periodicRestart.time -Value "00:00:00"
   ```

   Also grant the app-pool identity (`IIS AppPool\cert-watch`) read/write on the
   data dir and read on the secrets dir — `install-windows.ps1 -AppPool cert-watch`
   does this for you.

5. Browse `https://certs.example.com/`. Logs land in
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
