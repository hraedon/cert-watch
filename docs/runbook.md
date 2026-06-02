# cert-watch Operator Runbook

Everything you need to deploy, upgrade, back up, restore, and troubleshoot cert-watch in a single-file reference.

---

## Deploy

### Docker Compose

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

Data persists in the `cert-watch-data` volume (mounted at `/var/lib/cert-watch` inside the container). The SQLite database is at `/var/lib/cert-watch/cert-watch.sqlite3`.

### Kubernetes (Argo CD)

```bash
kubectl apply -f deploy/argocd/application.yaml
```

Argo CD watches `deploy/k8s/` and syncs automatically. CI builds and pushes a multi-arch image to GHCR on every merge to `main`, then commits the new tag to `deploy/k8s/kustomization.yaml`.

### Direct Kubernetes apply

```bash
kubectl apply -k deploy/k8s
```

### Linux + systemd

```bash
sudo ./scripts/install-linux.sh
```

Installs to `/opt/cert-watch`, enables `cert-watch.service`. See `deploy/systemd/cert-watch.service`.

### First run (no auth)

Without `AUTH_PROVIDER` set, cert-watch is fully open — no login required. This is intentional for local development and air-gapped demos. **For any network-reachable deployment, set `AUTH_PROVIDER`.**

---

## Upgrade

cert-watch uses forward-only schema migrations. On startup, the app automatically:

1. Checks the `schema_version` table for applied migrations.
2. Creates a timestamped pre-migration backup: `cert-watch-pre-migration-<timestamp>.sqlite3` in the data directory.
3. Applies any pending migrations.
4. Records each migration in `schema_version`.

**Upgrade procedure (Docker):**

```bash
docker pull ghcr.io/hraedon/cert-watch:latest
docker compose -f deploy/compose/docker-compose.yml up -d
```

The new binary applies migrations on first boot. The pre-migration backup is kept automatically.

**Upgrade procedure (Kubernetes):**

Merge to `main`. CI handles the image build and kustomize tag bump. Argo CD syncs within a minute. The pod restarts with the new image and applies any pending migrations.

**Verify migration status:**

```bash
sqlite3 /var/lib/cert-watch/cert-watch.sqlite3 "SELECT * FROM schema_version ORDER BY id;"
```

---

## Backup and Restore

### Backup

The `cert-watch backup` command creates a WAL-safe copy using `VACUUM INTO`, which works while the app is running:

```bash
cert-watch backup /path/to/backup.sqlite3
```

In Docker:

```bash
docker exec cert-watch cert-watch backup /var/lib/cert-watch/backup-$(date +%Y%m%d).sqlite3
```

Automated pre-migration backups are also created on every upgrade (see Upgrade section).

### Restore

1. **Stop cert-watch.**

   ```bash
   # Docker
   docker compose -f deploy/compose/docker-compose.yml down

   # Kubernetes (scale to 0)
   kubectl scale deployment cert-watch --replicas=0

   # systemd
   sudo systemctl stop cert-watch
   ```

2. **Replace the database file.**

   ```bash
   cp /path/to/backup.sqlite3 /var/lib/cert-watch/cert-watch.sqlite3
   ```

3. **Start cert-watch.**

   The app detects the `schema_version` table and skips already-applied migrations. If restoring into a newer binary, pending migrations run automatically with a fresh pre-migration backup.

**Important:** cert-watch uses a single-writer model with `Recreate` rollout strategy in Kubernetes. Only one instance writes to the database at a time. Do not run multiple instances pointing to the same SQLite file.

---

## Troubleshooting Scans

### A scan is failing

**1. Check the logs.** With `CERT_WATCH_LOG_FORMAT=json`, each log line is structured JSON:

```bash
docker logs cert-watch 2>&1 | grep '"message".*scan'
```

Key fields: `timestamp`, `level`, `message`, and any `extra` context.

With text logs (default):

```bash
docker logs cert-watch 2>&1 | grep scan
```

**2. Common scan failures:**

| Symptom | Cause | Fix |
|---------|-------|-----|
| `connection refused` | Target not listening on 443 | Verify the host and port |
| `connection timed out` | Firewall / network unreachable | Check network path |
| `certificate verify failed` | Self-signed or expired target cert | Expected for internal certs; cert-watch extracts the cert regardless |
| `private IP rejected` | `CERT_WATCH_ALLOW_PRIVATE_IPS=0` | Set to `1` if scanning internal hosts |
| `hostname resolution failed` | DNS can't resolve the host | Set `CERT_WATCH_DNS_SERVERS` for custom DNS |

**3. Scan retry behavior.** `scan_host()` retries transient failures (connection refused, timeout) up to 2 times with exponential backoff. Check logs for retry attempts.

**4. Private IP scanning.** Controlled by `CERT_WATCH_ALLOW_PRIVATE_IPS` (default: `1` — enabled). When set to `0`, RFC 1918 and ULA addresses are rejected. Loopback, link-local, and the cloud metadata endpoint (`169.254.169.254`) are always blocked regardless of this setting.

**4a. Scan allowlist (recommended for sensitive sites).** `CERT_WATCH_ALLOWED_SUBNETS` takes a comma-separated CIDR list (e.g. `10.0.0.0/8,192.168.0.0/16`). When set, a private target is allowed only if it falls inside one of those ranges — everything else private is refused, making internal scanning an explicit, auditable capability. Public hosts remain scannable. The first-run setup wizard prompts for these ranges; you can change them later via the env var. For defence-in-depth, also restrict egress at the network layer (the shipped `deploy/k8s/networkpolicy.yaml` is permissive toward internal ranges by default — tighten it to your approved targets).

**5. Custom DNS.** Set `CERT_WATCH_DNS_SERVERS` to a comma-separated list of DNS server IPs (e.g., `10.0.0.1,10.0.0.2`) for resolving internal hostnames. Queries are sent via UDP port 53 for A/AAAA records. Falls back to system resolver if custom DNS returns no results.

---

## Configuration Reference

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_DATA_DIR` | `/var/lib/cert-watch` | Database directory |
| `CERT_WATCH_HOST` | `0.0.0.0` | Listen address |
| `CERT_WATCH_PORT` | `8000` | Listen port |
| `CERT_WATCH_SCHED_HOUR` | `6` | Daily scan hour (UTC) |
| `CERT_WATCH_SCHED_MIN` | `0` | Daily scan minute |
| `CERT_WATCH_TLS_VERIFY` | `0` | Verify TLS when scanning |
| `CERT_WATCH_ALLOW_PRIVATE_IPS` | `1` | Allow scanning private IPs |
| `CERT_WATCH_ALLOWED_SUBNETS` | — | CIDR allowlist scoping which private ranges may be scanned |
| `CERT_WATCH_DNS_SERVERS` | — | Custom DNS servers (comma-separated) |
| `CERT_WATCH_LOG_FORMAT` | `text` | `text` or `json` |
| `CERT_WATCH_AUTH_SECRET` | random | Session signing key (persist for restart survival) |

### Alerting (SMTP)

| Variable | Default | Description |
|----------|---------|-------------|
| `SMTP_HOST` | — | SMTP server |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password (`SMTP_PASSWORD_FILE` supported) |
| `ALERT_FROM` | — | Sender address |
| `ALERT_RECIPIENTS` | — | Comma-separated recipients |
| `ALERT_WEBHOOK_URL` | — | Webhook URL for JSON alerts |
| `ALERT_WEBHOOK_HEADERS` | — | JSON extra headers |
| `ALERT_WEBHOOK_TEMPLATE` | — | Custom webhook body template |
| `ALERT_DIGEST_ONLY` | `0` | Set `1` for daily digest instead of per-cert alerts |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PROVIDER` | — | `ldap`, `oauth`/`entra`, or unset (no auth) |
| `LDAP_SERVER` | — | LDAP server URL(s), comma-separated for DC failover |
| `LDAP_BASE_DN` | — | Base DN for user search |
| `LDAP_BIND_DN` | — | Service account DN |
| `LDAP_BIND_PASSWORD` | — | Service account password (`LDAP_BIND_PASSWORD_FILE` supported) |
| `LDAP_USER_FILTER` | `(sAMAccountName={username})` | LDAP search filter |
| `LDAP_START_TLS` | `0` | Use StartTLS |
| `LDAP_CA_CERT` | — | CA cert for LDAPS verification (file path or PEM data, `LDAP_CA_CERT_FILE` supported) |
| `LDAP_REQUIRED_GROUPS` | — | Comma-separated group DNs; transitive membership via `LDAP_MATCHING_RULE_IN_CHAIN` |
| `LDAP_CONNECT_TIMEOUT` | `5` | LDAP connection timeout in seconds |
| `OAUTH_CLIENT_ID` | — | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | — | OAuth client secret (`OAUTH_CLIENT_SECRET_FILE` supported) |
| `OAUTH_ISSUER_URL` | — | OIDC issuer URL |
| `OAUTH_SCOPE` | `openid profile email` | OAuth scopes |
| `OAUTH_AUTHORIZATION_ENDPOINT` | — | Override authorization endpoint |
| `OAUTH_TOKEN_ENDPOINT` | — | Override token endpoint |
| `OAUTH_USERINFO_ENDPOINT` | — | Override userinfo endpoint |
| `CERT_WATCH_ALLOWED_GROUPS` | — | Comma-separated group names for authZ gate |
| `CERT_WATCH_ALLOWED_ROLES` | — | Comma-separated role names for authZ gate |
| `CERT_WATCH_LOCAL_ADMIN_USER` | — | Local break-glass admin username |
| `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` | — | Scrypt hash for local admin (`*_FILE` supported) |

### CSRF

| Variable | Default | Description |
|----------|---------|-------------|
| `CERT_WATCH_CSRF_SECRET` | random | HMAC key for CSRF tokens |
| `CERT_WATCH_CSRF_DISABLED` | `0` | Disable CSRF (testing only) |

### Secret file convention

Any credential variable supports a `_FILE` variant (standard Docker/Kubernetes secret mount pattern). For example:

- `LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap_bind_pw` — reads the file contents as the password
- `OAUTH_CLIENT_SECRET_FILE=/run/secrets/oauth_secret`
- `LDAP_CA_CERT_FILE=/run/secrets/ldap_ca.pem` — PEM CA certificate for LDAPS

If both `$NAME` and `$NAME_FILE` are set, `$NAME` takes precedence.

---

## Authentication and Authorization

### LDAP / Active Directory

```bash
AUTH_PROVIDER=ldap
LDAP_SERVER=ldap://dc1.example.com,ldap://dc2.example.com
LDAP_BASE_DN=DC=example,DC=com
LDAP_BIND_DN=CN=cert-watch-svc,OU=ServiceAccounts,DC=example,DC=com
LDAP_BIND_PASSWORD_FILE=/run/secrets/ldap_bind_pw
LDAP_CA_CERT_FILE=/run/secrets/ldap_ca.pem
LDAP_REQUIRED_GROUPS=CN=CertWatchOps,OU=Groups,DC=example,DC=com
LDAP_CONNECT_TIMEOUT=3
```

- Comma-separated `LDAP_SERVER` enables DC failover (tries each server in order).
- `LDAP_CA_CERT` is required for `ldaps://` — cert-watch validates the server cert against this CA. Without it, LDAPS connections will succeed but log a warning about unverified certificates.
- `LDAP_REQUIRED_GROUPS` uses AD's transitive group membership check (`LDAP_MATCHING_RULE_IN_CHAIN` OID 1.2.840.113556.1.4.1941) — nested group membership counts.

### OAuth / Microsoft Entra ID

```bash
AUTH_PROVIDER=entra
OAUTH_CLIENT_ID=<app-registration-id>
OAUTH_CLIENT_SECRET_FILE=/run/secrets/oauth_secret
OAUTH_ISSUER_URL=https://login.microsoftonline.com/<tenant>/v2.0
```

### Local break-glass admin

For when the primary IdP (LDAP/OAuth) is unavailable:

```bash
cert-watch hash-password
# Enter password, get scrypt hash
CERT_WATCH_LOCAL_ADMIN_USER=admin
CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH=scrypt$16384$8$1$<salt>$<hash>
```

- Disabled unless both `CERT_WATCH_LOCAL_ADMIN_USER` and `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` are set.
- Evaluates before the primary provider — works even when LDAP/OAuth is down.
- Bypasses the group/role gate (implicit admin).
- Every login emits a WARNING log and an audit row with `break_glass=true`.
- **Rotate the password after each use.**

### Authorization gate

When `CERT_WATCH_ALLOWED_GROUPS` or `CERT_WATCH_ALLOWED_ROLES` is set, a user must belong to at least one listed group or role. Without these settings, any authenticated user has access.

---

## Secure Deployment Profile

For production, use these settings:

```bash
AUTH_PROVIDER=ldap              # or entra
CERT_WATCH_LOG_FORMAT=json      # structured logs for SIEM
CERT_WATCH_AUTH_SECRET=<stable-key>  # persist sessions across restarts
CERT_WATCH_ALLOWED_SUBNETS=10.0.0.0/8,192.168.0.0/16  # only scan approved internal ranges
CERT_WATCH_COOKIE_SECURE=1      # HTTPS-only cookies (default)
```

Scope `CERT_WATCH_ALLOWED_SUBNETS` to exactly the internal networks you intend
to monitor (or use `CERT_WATCH_ALLOW_PRIVATE_IPS=0` to block all private
scanning). Pair it with a network-layer egress restriction for defence in depth.

Ensure `CERT_WATCH_AUTH_SECRET` is set to a stable value. Without it, a random key is generated on every restart, invalidating all active sessions.

---

## Unauthenticated Paths

The following paths are open even when auth is enabled:

| Path | Purpose |
|------|---------|
| `/healthz` | Liveness probe |
| `/metrics` | Prometheus metrics |
| `/static/*` | CSS, JS, images |
| `/login` | Login form |
| `/auth/callback` | OAuth callback |
| `/auth/logout` | Logout |

All other paths (dashboard, scan history, alerts, host management) require authentication. The `/api/*` data routes return `401` for unauthenticated requests.

### `/metrics` exposure decision

The `/metrics` endpoint is intentionally left unauthenticated for compatibility with standard Prometheus scraping. It exposes aggregate counts (certificate totals, scan counts) but not hostnames, certificate details, or any identifying information.

**Recommendation:** Restrict `/metrics` at the ingress level (network policy, IP allowlist) so only your Prometheus scraper can reach it. If a security review requires auth on metrics, add a reverse proxy that injects a service account token.

---

## Scale Ceiling

cert-watch uses a **single-writer SQLite database** with WAL mode enabled. This is a deliberate tradeoff: zero-ops database management in exchange for a single-instance deployment model.

### Expected capacity

| Metric | Comfortable ceiling |
|--------|---------------------|
| Tracked hosts | ~5,000 |
| Certificates (total, including chain) | ~50,000 |
| Scan history rows | ~200,000 |
| Concurrent users | ~20 (web UI is not a high-throughput API) |

WAL mode allows concurrent reads while a write is in progress. Daily scans are serialized by the scheduler. API reads are fast due to SQLite's in-process architecture.

### When to revisit (BC-031 trigger)

Consider PostgreSQL or MSSQL when any of these become true:

1. **Fleet size exceeds 5,000 hosts** — scan cycle takes longer than the scheduling window.
2. **High-availability requirement** — multiple cert-watch instances need concurrent write access.
3. **Multi-writer need** — more than one process must write to the database simultaneously.
4. **Compliance mandate** — organizational policy requires a managed database service.

The database layer is abstracted into a repository pattern (`database/` package with `schema.py`, `repo.py`, `queries.py`, `connection.py`). Adding a PostgreSQL backend is a matter of implementing the same repository interfaces — see BC-031.

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `cert-watch` | Start web server |
| `cert-watch backup <path>` | Create WAL-safe database backup |
| `cert-watch hash-password` | Generate scrypt hash for `CERT_WATCH_LOCAL_ADMIN_PASSWORD_HASH` |
