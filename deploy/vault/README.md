# Vault wiring for cert-watch

Operational runbook for sourcing every cert-watch secret from Vault — runtime,
CI, and the agentic E2E layer — on one issuance + audit plane. Design rationale
lives in `plans/034-...md` Appendix A.2; this is the how-to.

> **Assumptions** (this cluster): KV v2 mounted at `kv/`, Vault at
> `https://vault.k8s.hraedon.com`, app namespace `cert-watch`, k8s auth mount
> `kubernetes`. For **KV v1**, drop the `/data/` and `/metadata/` path segments
> everywhere below.

## Secret layout

```
kv/cert-watch/entra/app              client_secret=...
kv/cert-watch/entra/cert-watch-admin password=...
kv/cert-watch/entra/cert-watch-user  password=...
kv/cert-watch/ldap/bind              password=...  bind_dn=...   # lab AD service acct
kv/cert-watch/ldap/cw-admin          password=...               # AD test user (admins)
kv/cert-watch/ldap/cw-user           password=...               # AD test user (users)
kv/cert-watch/app                    csrf_secret=... auth_secret=...
totp/keys/entra-cert-watch-admin         (seed; see plan A.1)
totp/keys/entra-cert-watch-user
```

## Provisioned in this cluster (verified 2026-06-05)

Live and proven via the `cert-watch-setup` AppRole:
- **Policies:** `cert-watch-setup`, `cert-watch-app`, `cert-watch-e2e-runner`, `cert-watch-totp-mcp`.
- **AppRoles:** `cert-watch-e2e` (runner), `cert-watch-totp-mcp` (agent) — trust split verified (mcp: codes only; runner: passwords+codes; neither can read seeds).
- **kubernetes auth:** enabled at `kubernetes/`, role `cert-watch` → SA `cert-watch/cert-watch` → `cert-watch-app`; end-to-end login verified.
- **TOTP:** `totp/keys/entra-cert-watch-{admin,user}` live; codes issue correctly.
- **Pending:** `kv/cert-watch/ldap/*` (below), and the deployment cutover to the
  injector (csrf/auth secrets still live in the `cert-watch-secrets` k8s Secret).

## 0. Bootstrap the automation identity (one-time, operator with admin token)

Chicken-and-egg: creating the reusable setup identity needs admin once. After
this, cert-watch automation authenticates as the scoped `cert-watch-setup`
AppRole — never root.

```bash
export VAULT_ADDR=https://vault.k8s.hraedon.com   # + admin VAULT_TOKEN in your shell

# Scoped automation policy (manages only cert-watch policies/TOTP/auth — see the HCL)
vault policy write cert-watch-setup deploy/vault/policies/cert-watch-setup.hcl

# AppRole identity bound to it, short-lived
vault auth enable approle 2>/dev/null || true
vault write auth/approle/role/cert-watch-setup \
    token_policies=cert-watch-setup \
    token_ttl=30m token_max_ttl=2h \
    secret_id_ttl=2h secret_id_num_uses=20

# Mint credentials to hand the agent
vault read  -field=role_id    auth/approle/role/cert-watch-setup/role-id
vault write -field=secret_id -f auth/approle/role/cert-watch-setup/secret-id
```

Then expose to the agent's **shell environment** (not chat):
`VAULT_ADDR`, `VAULT_ROLE_ID`, `VAULT_SECRET_ID`. The agent logs in with
`vault write -field=token auth/approle/login role_id="$VAULT_ROLE_ID" secret_id="$VAULT_SECRET_ID"`
and runs steps 1–4. The secret-id is short-TTL / limited-use, so it self-expires.

## 1. Engines + policies

```bash
vault secrets enable totp           # if not already
vault policy write cert-watch-app        deploy/vault/policies/cert-watch-app.hcl
vault policy write cert-watch-e2e-runner deploy/vault/policies/cert-watch-e2e-runner.hcl
vault policy write cert-watch-totp-mcp   deploy/vault/policies/cert-watch-totp-mcp.hcl
```

Three policies, three trust levels: **app** reads its own KV subtree; **runner**
reads test passwords; **mcp** reads only ephemeral TOTP codes. The split is the
point — agent context never touches a reusable secret.

## 2. Runtime — Vault Agent Injector (no app changes)

cert-watch already honors the `<NAME>_FILE` convention (`config.py:read_secret`),
so the injector renders secrets to files and we point `*_FILE` env at them.

k8s auth role binding the pod ServiceAccount to the app policy:
```bash
vault auth enable kubernetes   # once
vault write auth/kubernetes/role/cert-watch \
    bound_service_account_names=cert-watch \
    bound_service_account_namespaces=cert-watch \
    policies=cert-watch-app ttl=1h
```

Pod annotations (add to `deploy/k8s/deployment.yaml` `spec.template.metadata`):
```yaml
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/role: "cert-watch"
vault.hashicorp.com/agent-inject-secret-auth_secret: "kv/data/cert-watch/app"
vault.hashicorp.com/agent-inject-template-auth_secret: |
  {{- with secret "kv/data/cert-watch/app" -}}{{ .Data.data.auth_secret }}{{- end -}}
vault.hashicorp.com/agent-inject-secret-oauth_client_secret: "kv/data/cert-watch/entra/app"
vault.hashicorp.com/agent-inject-template-oauth_client_secret: |
  {{- with secret "kv/data/cert-watch/entra/app" -}}{{ .Data.data.client_secret }}{{- end -}}
```
Then set the matching env (replace the `secretKeyRef` blocks):
```yaml
- name: CERT_WATCH_AUTH_SECRET_FILE
  value: /vault/secrets/auth_secret
- name: OAUTH_CLIENT_SECRET_FILE
  value: /vault/secrets/oauth_client_secret
# ...repeat for CSRF, LDAP_BIND_PASSWORD, LDAP_CA_CERT, SMTP_PASSWORD as needed
```
(Alternative if you prefer native k8s Secrets / no sidecars: Vault Secrets
Operator or External Secrets Operator syncing the same paths into a Secret.)

## 3. CI — runner credentials (no long-lived token)

AppRole (or GitHub OIDC -> JWT auth) bound to `cert-watch-e2e-runner`:
```bash
vault auth enable approle
vault write auth/approle/role/cert-watch-e2e \
    token_policies=cert-watch-e2e-runner token_ttl=20m token_max_ttl=1h
# role-id in CI config; secret-id from the CI secret store.
```
The Playwright process reads passwords from `kv/cert-watch/entra/*` into
env/files — these never enter the agent's context.

## 4. Agentic layer — TOTP code broker

Give the Vault MCP (or agent) a token/AppRole bound to **only**
`cert-watch-totp-mcp`. At login the agent requests the live code:
```bash
vault read -field=code totp/code/entra-cert-watch-admin
```
Codes are 30s and audit-logged; even in agent context the blast radius is one
expired code. Raw passwords stay on the runner side (policy split above).

## Verify

```bash
vault token capabilities <token> kv/data/cert-watch/entra/app   # runner: read
vault token capabilities <mcp-token> kv/data/cert-watch/entra/app  # expect: deny
vault token capabilities <mcp-token> totp/code/entra-cert-watch-admin  # expect: read
```
