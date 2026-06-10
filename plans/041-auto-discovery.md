# Plan 041 — Auto-Discovery / Cloud Inventory Sync

**Status:** declined 2026-06-10
**Author:** Opus 4.8 (portfolio review)
**Declination rationale:** Contradicts `docs/positioning.md` — cloud API
discovery introduces external SaaS dependencies the positioning explicitly
declines. Exceptions retained: `static` file source (air-gap-friendly) and
k8s Ingress discovery (inside the trust boundary, self-hosted). If k8s
discovery is built, ensure the `DiscoverySource` seam remains modular so
future cloud ingest sources could slot in without rearchitecting.
**Strategic role:** Eliminate the toil of keeping the cert-watch inventory in sync with live infrastructure. The repository pattern already supports abstract sources; this plan adds a `DiscoverySource` seam.

## Why now

cert-watch currently requires manual host entry: the user adds a hostname/port CSV or clicks "Add Host" in the UI. In a real environment with AWS ALBs, GCP load balancers, Kubernetes Ingress objects, or Azure Front Doors, the inventory is always slightly out of date. The `database/` package already uses the repository pattern (`SqliteHostRepository`, `SqliteCertificateRepository`), so adding a periodic sync from external sources is a clean extension rather than a refactor.

## Scope

### WI-1 — `DiscoverySource` protocol and registry
- `cert_watch.discovery` package with a `DiscoverySource` protocol:
  - `discover() -> list[DiscoveredHost]` where `DiscoveredHost` has `hostname`, `port`, `source`, `metadata` (dict), `owner`.
- Registry mapping `kind` → adapter class:
  - `aws` — discovers ALB/ELB listeners via `boto3` (describe load balancers + describe listeners).
  - `gcp` — discovers load balancer backends via `google-cloud-compute` (list backend services).
  - `k8s` — discovers Ingress hosts + ports via `kubernetes` client (list ingresses in all namespaces).
  - `azure` — discovers Front Door / App Gateway endpoints via `azure-mgmt-network`.
  - `static` — reads from a JSON/YAML file (for air-gapped or custom environments).

### WI-2 — Sync engine
- `discovery.sync.sync_hosts(discovery_sources, host_repo, cert_repo)`:
  - For each source, call `discover()`.
  - Merge discovered hosts with the existing DB inventory:
    - **New host:** insert with `source="discovered:<kind>"`.
    - **Existing host:** update `metadata` and `owner` if changed; leave manual overrides untouched.
    - **Missing host:** if the host was previously discovered from the same source and no longer appears, mark it `status="missing"` (do not auto-delete to avoid data loss).
  - Idempotent: running sync twice yields the same DB state.

### WI-3 — UI and API
- `GET /api/insights/discovery` — list configured sources and last sync results.
- `POST /api/insights/discovery/sync` — trigger a manual sync (write scope required).
- Settings page (`/settings`) adds a "Discovery Sources" panel:
  - Dropdown to add a source (AWS, GCP, K8s, Azure, Static File).
  - Per-source config form (region, credentials, filter tags, etc.).
  - Config persisted in `kv_store` (encrypted for credentials).

### WI-4 — Scheduler integration
- `scheduler.py` adds a `discovery_fn` parameter to `_run_cycle`.
- Runs **before** the scan cycle so newly discovered hosts are scanned immediately in the same window.
- Honor `CERT_WATCH_DISCOVERY_SYNC_INTERVAL_HOURS` (default 24).

### WI-5 — AWS adapter (first-class)
- The AWS adapter is implemented as the reference implementation:
  - Uses `boto3` (optional extra `cert-watch[discovery-aws]`).
  - Scans all regions or a configurable region list.
  - Filters by ALB tags (e.g., `Environment=production`).
  - Extracts the HTTPS listener port (usually 443) and the ALB DNS name.
  - Optionally resolves the ALB DNS name to the backend target group instances (configurable depth).

## Acceptance

- A mocked AWS ALB response yields 3 discovered hosts inserted into the DB with `source="discovered:aws"`.
- Re-running sync with the same mock response is idempotent (no duplicate hosts).
- Removing a host from the mock response marks it `status="missing"` in the DB.
- The settings page can add, edit, and remove discovery sources.
- A manual sync triggered via API returns a summary of `added`, `updated`, `missing` counts.
- The scheduler runs discovery before scanning without blocking.
- 0 lint errors; unit tests cover the sync engine, AWS adapter, and registry; full suite passes.

## Non-goals

- Real-time event-driven discovery (AWS EventBridge, K8s watch API); polling is sufficient for v1.
- Automatic deletion of missing hosts; manual review is safer.
- Credential rotation / IAM role chaining; the operator provides static credentials or instance profiles.
- Non-cloud sources (SNMP, network scanning); these are a follow-up plan.
