# Plan 032: Pluggable Secrets Provider (Workstream I)

> **Status:** draft for review. Grounded in `config.read_secret()` (the `*_FILE`
> convention), `database/encryption.py` (Fernet at-rest encryption), and the
> auth provider pattern (`auth/protocol.py`, `auth/factory.py`) as a structural
> template. Introduces a `SecretsProvider` abstraction so enterprise vaults can
> be plugged in without changing application code. **Medium; targeted for 0.6.0.**
> Scope (per review): the abstraction + `EnvSecretsProvider` default, plus **three
> reference providers — HashiCorp Vault, Azure Key Vault, and Windows Credential
> Manager**. AWS and others are left to the one-method protocol for operators to add.

## Goal

Let operators fetch secrets from an external vault (HashiCorp Vault, AWS Secrets
Manager, Azure Key Vault, Windows Credential Manager) instead of injecting them
as environment variables — so cert-watch integrates cleanly with enterprise
secret management infrastructure.

The design follows the auth provider pattern exactly: a protocol class, a
factory, a no-op default, and env-var-based selection. This keeps the change
mechanically simple and avoids over-engineering.

## What already exists (build on, don't rebuild)

- **`read_secret(name)`** (`config.py:49`): reads `$name` or `$name_FILE`. This
  is the **single call site** to intercept — every secret in the app flows
  through it (11 call sites across 4 files).
- **`*_FILE` convention**: Docker/K8s secret mounts. This remains the default
  and the no-op provider's implementation.
- **Fernet at-rest encryption** (`database/encryption.py`): encrypts sensitive
  `kv_store` values. The encryption key is derived from the signing key. This
  is orthogonal to vault integration — the vault provides the secret *value*;
  at-rest encryption protects it *after* it's in the DB.
- **Auth provider pattern** (`auth/protocol.py` + `auth/factory.py`):
  - Protocol class with `@abstractmethod` methods
  - `build_auth_provider(provider: str, ...)` factory
  - `NoAuthProvider` as the default
  - `_CompositeProvider` for layered concerns
  - Env-var selection (`AUTH_PROVIDER=ldap`)
  - This is the structural template.

## Design

### Protocol: `SecretsProvider`

```python
class SecretsProvider(ABC):
    @abstractmethod
    def get_secret(self, name: str) -> str | None:
        """Return the secret value for `name`, or None if not found."""
        ...

    @property
    @abstractmethod
    def provider_name(self) -> str: ...
```

One method. Minimal surface. The provider either has the secret or it doesn't.

### Implementations

**`EnvSecretsProvider`** (default, replaces current `read_secret` logic):
```python
class EnvSecretsProvider:
    def get_secret(self, name: str) -> str | None:
        val = os.environ.get(name)
        if val is not None:
            return val
        path = os.environ.get(f"{name}_FILE")
        if path:
            return Path(path).read_text().strip()
        return None
```

**`VaultSecretsProvider`** (HashiCorp Vault KV v2):
- Auth via token (`VAULT_TOKEN` or `VAULT_TOKEN_FILE`) or AppRole
  (`VAULT_ROLE_ID` + `VAULT_SECRET_ID`).
- Reads from KV v2 mount at `secret/data/cert-watch/{name}`.
- TTL-based caching (default 5 min) to avoid a vault call per `get_secret`.
- Falls back to env/`_FILE` if the vault path doesn't have the secret (so
  operators can mix vault + env for secrets not yet migrated).

**`AzureKeyVaultProvider`** (Azure Key Vault):
- Auth via `DefaultAzureCredential` (managed identity, env vars, CLI).
- Reads from `https://{vault-name}.vault.azure.net/secrets/{name}`.
- TTL-based caching.

**`WindowsCredentialManagerProvider`**:
- Reads from Windows Credential Manager via `win32cred` (pywin32).
- Only available on Windows (same pattern as the Event Log sink).

### Factory: `build_secrets_provider`

```python
def build_secrets_provider(provider: str = "", **kwargs) -> SecretsProvider:
    provider = provider.lower().strip()
    if not provider or provider == "none":
        return EnvSecretsProvider()
    if provider == "vault":
        return VaultSecretsProvider(...)
    if provider == "azure":
        return AzureKeyVaultProvider(...)
    if provider == "windows":
        return WindowsCredentialManagerProvider(...)
    raise ValueError(f"Unknown SECRETS_PROVIDER={provider!r}")
```

### Wiring

1. `Settings` gains a `secrets_provider` field (from `SECRETS_PROVIDER` env var).
2. The lifespan calls `build_secrets_provider()` and stores the result on
   `app.state.secrets_provider`.
3. `read_secret(name)` gains an optional `provider: SecretsProvider | None = None`
   parameter. When provided, delegates to `provider.get_secret(name)`. When
   `None` (direct unit-test calls, import-time fallbacks), uses the current
   env/`_FILE` logic.
4. The `Settings.from_env()` and `Settings.from_env_with_kv()` paths use the
   provider to resolve all secrets.

### Migration path

- **Default behavior is unchanged.** `SECRETS_PROVIDER` unset =
  `EnvSecretsProvider` = current `read_secret` logic. Zero new dependencies.
- **Each vault provider is an optional extra** in `pyproject.toml`:
  `[vault]` → `hvac`, `[azure]` → `azure-identity` + `azure-keyvault-secrets`,
  `[windows]` → `pywin32` (already present for the Event Log sink).
- **Operators can migrate incrementally.** The `VaultSecretsProvider` falls
  back to env/`_FILE` for secrets not in the vault, so operators can move
  secrets one at a time.

## Non-goals

- Not auto-rotating secrets. The provider reads secrets; it doesn't write or
  rotate them.
- Not a generic secrets SDK. The provider is specific to cert-watch's config
  model (flat key-value, `read_secret` call sites).
- Not supporting every vault product. Ship **three reference implementations** —
  Vault (most common in the self-hosted space), Azure Key Vault, and Windows
  Credential Manager — plus the Env default. AWS, GCP, 1Password, CyberArk, etc.
  are deliberately out of scope: the one-method protocol makes it
  straightforward for an operator to add their own.
- Not replacing at-rest encryption. The vault provides the secret value; Fernet
  encryption protects it in the `kv_store` after retrieval. They are
  complementary layers.

## Slices

1. **Protocol + env provider**: `SecretsProvider` ABC in a new
   `secrets_provider.py` module. `EnvSecretsProvider` implements the current
   `read_secret` logic. Wire into `read_secret()` as an optional parameter.
   No behavior change when `SECRETS_PROVIDER` is unset.
2. **Factory**: `build_secrets_provider(provider, **kwargs)` in the same module.
   Wire into `Settings` and the app lifespan.
3. **Vault provider** (optional extra `[vault]`): `VaultSecretsProvider` using
   `hvac`. Token auth, AppRole auth, KV v2 read, TTL cache. Falls back to
   env/`_FILE`.
4. **Azure provider** (optional extra `[azure]`): `AzureKeyVaultProvider` using
   `azure-identity` + `azure-keyvault-secrets`. Managed identity auth, TTL cache.
5. **Windows provider** (optional extra `[windows]`): `WindowsCredentialManagerProvider`
   using `win32cred` (pywin32). Windows-only; no-ops/raises a clear error
   off-Windows, matching the Event Log sink pattern.
6. **UI (small)**: surface the active provider name on the Settings page
   (read-only). Show which secrets are resolved from vault vs. env.

## Testing

- **Env provider**: assert `FOO` env var → returns value. Assert `FOO_FILE`
  pointing to a temp file → returns file contents. Assert neither → returns
  None. (These are the existing `read_secret` tests, re-homed.)
- **Factory**: assert `SECRETS_PROVIDER=""` → `EnvSecretsProvider`. Assert
  `SECRETS_PROVIDER=vault` → `VaultSecretsProvider`. Assert unknown →
  `ValueError`.
- **Vault provider**: mock `hvac.Client`; assert `get_secret("SMTP_PASSWORD")`
  reads from `secret/data/cert-watch/SMTP_PASSWORD`; assert cache hit on
  second call within TTL; assert fallback to env when vault returns 404.
- **No-config regression**: with `SECRETS_PROVIDER` unset, the entire secret
  resolution path is byte-for-byte identical to today (no new imports, no new
  dependencies, no new call paths).

## Risks / decisions

- **`read_secret` is called at import time** (`auth/session.py:34`) — before
  the app lifespan runs. The import-time fallback must remain env/`_FILE` (the
  current behavior). The provider is only available after the lifespan resolves
  it. This is acceptable because the import-time call is a fallback for a
  fallback (the real signing key is resolved in the lifespan via
  `resolve_or_persist_secret`).
- **Cache staleness** — if an operator rotates a secret in the vault, the
  cached value is stale for up to `TTL` minutes. This is the standard trade-off
  for vault caching. Document it; operators who need instant rotation can set
  TTL to 0 (every call hits the vault).
- **Optional dependency isolation** — each vault provider imports its SDK
  lazily (inside the class, not at module level). The `[vault]`/`[aws]`/`[azure]`
  extras are only needed at install time if the operator wants that provider.
  The core package remains dependency-free.
- **The `_SENSITIVE` / `_SENSITIVE_KEYS` lists** (`config.py:427`,
  `routes/settings.py:113`) must stay in sync. This plan does not change that
  contract — the vault provider just provides the secret *value*; the
  encryption-at-rest decision is still governed by these lists.
- **Latent bug**: `routes/settings.py:113` `_SENSITIVE_KEYS` is missing
  `pagerduty_routing_key` (present in `config.py:427` `_SENSITIVE`). Fix as
  part of slice 1.
