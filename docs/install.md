# Installing cert-watch

cert-watch is one Python process with one SQLite database file. It runs the
same way everywhere; the platforms differ only in how the process is started,
where its data lives and what sits in front of it.

| Platform | Start here |
|----------|------------|
| Docker or Docker Compose | [Container](#container) |
| Kubernetes | [Kubernetes](#kubernetes) |
| Linux with systemd | [Linux](#linux) |
| Windows Server with IIS | [Windows / IIS](#windows--iis) |

Whatever you choose, read [First start](#first-start) and
[Before you go to production](#before-you-go-to-production).

## Requirements

- Python 3.12 or newer (the container image includes it). On Python 3.12 the
  `openssl` command-line tool must be installed to read full certificate
  chains during scans; Python 3.13 and later don't need it.
- One writable directory for the database, its backups and generated secrets.
- Outbound network access to the hosts you want to scan, your SMTP relay and
  any webhook destinations.
- Optional extras, installed with pip:
  - `cert-watch[auth-ldap]` for LDAP / Active Directory sign-in;
  - `cert-watch[auth-oauth]` for OAuth / OIDC sign-in;
  - `cert-watch[auth]` for both;
  - `cert-watch[windows]` for the Windows Event Log audit sink.

The published container image already includes both sign-in extras.

## Container

Images are published to `ghcr.io/hraedon/cert-watch` for amd64 and arm64:

| Tag | Meaning |
|-----|---------|
| `vX.Y.Z` | A release. Use this. |
| `latest` | The newest build of `main`. |
| short commit SHA | A specific build of `main`. |

### Verifying an image

Every image is signed with a keyless Sigstore signature, and carries an SBOM
and build provenance. Verifying before you deploy tells you it came from this
repository's release workflow, and what is in it, without trusting the
registry:

```bash
cosign verify ghcr.io/hraedon/cert-watch:v1.0.0 \
  --certificate-identity https://github.com/hraedon/cert-watch/.github/workflows/release.yml@refs/tags/v1.0.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Contents and build origin (BuildKit attestations, read with buildx)
docker buildx imagetools inspect ghcr.io/hraedon/cert-watch:v1.0.0 --format '{{ json .SBOM }}'
docker buildx imagetools inspect ghcr.io/hraedon/cert-watch:v1.0.0 --format '{{ json .Provenance }}'
```

Pin the identity to the exact ref, as above. A looser pattern would also accept
a signature from a run of the same workflow on another branch.

Signatures cover digests, not tags. The release job pushes tags a few seconds
before it signs, so when timing matters, verify and deploy by digest
(`ghcr.io/hraedon/cert-watch@sha256:…` from the release run). The Kubernetes
manifests in this repository pin the digest the release job verified. Images
built before signing was introduced have no signature. Failing to verify them
is expected, not a sign of tampering.

Run it with a volume for the data directory:

```bash
docker run -d --name cert-watch -p 8000:8000 \
  -v cert-watch-data:/var/lib/cert-watch \
  ghcr.io/hraedon/cert-watch:v1.0.0
docker exec cert-watch cat /var/lib/cert-watch/initial-admin-password
```

Or with Compose, using `deploy/compose/docker-compose.yml`:

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

Put configuration in the Compose file's `environment:` block or an env file.
See [configuration.md](configuration.md) for every setting.

## Kubernetes

`deploy/k8s/` is a Kustomize base with a Deployment, Service, Ingress,
PersistentVolumeClaim, NetworkPolicy, PodDisruptionBudget and Prometheus rules.
`secret-example.yaml` shows the secrets it expects.

```bash
kubectl apply -k deploy/k8s
```

Three things matter:

- **Run exactly one replica.** SQLite has a single writer. The Deployment uses
  one replica and the `Recreate` strategy; don't change either, and don't
  attach the volume to a second pod.
- **Pin the image.** The checked-in `kustomization.yaml` tracks this
  repository's `main` branch builds for its own lab deployment. For yours, set
  `images:` to a release digest you have verified.
- **Review the NetworkPolicy.** It is permissive towards private ranges so that
  internal scanning works out of the box. Narrow it to the ranges you actually
  monitor, and set `CERT_WATCH_ALLOWED_SUBNETS` to match (see
  [configuration.md](configuration.md#scanning)).

`deploy/argocd/application.yaml` is an Argo CD Application for GitOps
deployments that track this repository. For your own deployment, point it at
your fork or a pinned release instead.

## Linux

```bash
sudo ./scripts/install-linux.sh
```

This installs cert-watch into a virtual environment under `/opt/cert-watch`,
creates a `cert-watch` system user and `/var/lib/cert-watch`, and enables the
`cert-watch.service` unit from `deploy/systemd/`. Put your configuration in a
drop-in (`systemctl edit cert-watch`, then `Environment=` lines, or an
`EnvironmentFile=` of your own); the installer rewrites the unit itself on
upgrade. Put a reverse proxy such as nginx or
Caddy in front of it for TLS, and set the [proxy settings](#behind-a-proxy).

## Windows / IIS

IIS fronts the cert-watch process through HttpPlatformHandler (recommended) or
as a reverse proxy.

```powershell
.\scripts\install-windows.ps1 -ConfigureIIS -WithAuthExtras
```

Without switches, the installer only creates a shared Python runtime and
virtual environment under `C:\ProgramData\cert-watch` and generates persistent
signing keys. `-WithAuthExtras` adds the LDAP and OAuth libraries.
`-ConfigureIIS` also creates the site and application pool, sets the pool to
`AlwaysRunning` and the application to `preloadEnabled`, and installs IIS's
Application Initialization feature if it is missing.

The last three settings matter, so use `-ConfigureIIS` or apply them by hand
(the runbook below says how). Without them IIS starts cert-watch only when the
first web request arrives, so after a reboot or recycle with no traffic the
scheduler never runs and nothing is scanned.

The script is unsigned. Run it with
`powershell -ExecutionPolicy Bypass -File .\scripts\install-windows.ps1`, or
sign it with your own code-signing certificate after review.

[`deploy/iis/README.md`](../deploy/iis/README.md) is the full Windows runbook:
prerequisites, both hosting models, site configuration, TLS binding,
upgrades, removal and troubleshooting. `scripts/Verify-Install.ps1` checks a
finished installation.

To send the audit log to the Windows Event Log, install the extra into the
installer's venv and set `CERT_WATCH_EVENTLOG=1` in the site's environment:

```powershell
& C:\ProgramData\cert-watch\venv\Scripts\python.exe -m pip install "cert-watch[windows]"
```

## First start

What cert-watch does when no sign-in method is configured depends on whether
it can be reached from the network:

| Situation | Behaviour |
|-----------|-----------|
| Listening only on loopback (`127.0.0.1`), not behind a proxy | Opens the `/setup` wizard, where you create the first administrator. |
| Listening on a routable address, or on loopback behind a proxy (`CERT_WATCH_TRUST_PROXY=1`) | Creates an `admin` account with a random password and writes it to `<data dir>/initial-admin-password` (readable only by the service account). The log names the file; it never contains the password. |
| `CERT_WATCH_ALLOW_UNAUTH=1` | Runs with no sign-in at all. Only for development or isolated test systems. |

So a network-exposed instance never comes up without authentication unless you
ask it to. After the first sign-in, either configure LDAP or OAuth, or pin the
break-glass password (`CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH`, generated with
`cert-watch hash-password`), and delete the password file.

## Behind a proxy

When IIS, nginx, an ingress controller or a load balancer terminates TLS:

- set `CERT_WATCH_TRUST_PROXY=1`, and `CERT_WATCH_TRUSTED_PROXIES` to the
  proxy's addresses, so the real client address is used for rate limiting and
  the audit log;
- set `CERT_WATCH_BASE_URL` to the public URL, e.g.
  `https://certs.example.com`. OAuth sign-in refuses to start without it,
  because the redirect address must not come from the request's `Host` header.

## Before you go to production

- [ ] Pin a release tag, and verify its signature.
- [ ] Configure sign-in: LDAP or OAuth for people, plus the break-glass admin.
      Set up role mapping; see [access-control.md](access-control.md).
- [ ] Set `CERT_WATCH_AUTH_SECRET` explicitly, or back up the generated
      `.auth_secret` file in the data directory. Losing it signs everyone out
      and makes stored credentials unreadable.
- [ ] Restrict scanning to the ranges you monitor with
      `CERT_WATCH_ALLOWED_SUBNETS`.
- [ ] Set `CERT_WATCH_METRICS_TOKEN` if `/metrics` is reachable by anyone but
      your monitoring.
- [ ] Configure alert delivery and send a test message; see
      [alerting.md](alerting.md).
- [ ] Schedule backups; see [operations.md](operations.md#backups).
- [ ] Monitor the `CertWatchScanStalled` condition, i.e. no scan for 36 hours;
      see [operations.md](operations.md#monitoring).
