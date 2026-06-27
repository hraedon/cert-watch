# Plan: Certify the Web Integration

## Status: Deferred (waiting for CTW Management Hub GA)
## Date: 2026-06-26
## Depends on: Renewal webhook (implemented this session)

## Goal

Surface Certify the Web (CTW) managed-certificate issues in the cert-watch GUI, giving operators a single pane showing both the external TLS posture (cert-watch's scans) and the internal renewal-management status (CTW's state).

## Background

### What CTW is

Certify the Web is a Windows-first ACME certificate manager (desktop app + Management Hub web UI/API). It handles ACME renewal, deployment to IIS/Exchange/Apache/nginx, and DNS challenge automation. Many cert-watch target users (SMBs on Windows/IIS) already run CTW for renewal.

### What CTW exposes

**Certify Management Hub** (the web API product, currently RC) has:
- `GET /api/v1/certificate` — list managed certificates with status, health, domains, expiry
- `POST /api/v1/certificate` — add a managed certificate (managed challenges by default)
- Auth via JWT (OIDC or local admin)
- Docker image: `certifytheweb/management-hub`

**Certify Certificate Manager** (the desktop product) has:
- An internal API (used by the desktop UI) that is **not stable for external use
- A CLI (`certify list`, `certify deploy`, `certify add`, etc.) that is stable
- No public HTTP API

### Integration viability

| Path | Viable? | Notes |
|------|---------|-------|
| cert-watch → CTW Hub API (poll managed certs) | **Yes** | Hub has a public REST API with JWT auth. cert-watch can poll `GET /api/v1/certificate` periodically and surface issues. |
| cert-watch → CTW Desktop API | **No** | Internal API, unstable, Windows-auth only. |
| cert-watch → CTW CLI | **Partial** | Could shell out to `certify list --json` on the same host. Fragile (path/version dependent). Only works when co-located. |
| CTW → cert-watch webhook | **Yes (done)** | The renewal webhook implemented this session sends a structured `renewal_needed` payload. CTW Hub or a script wrapping the CLI can consume it and trigger renewal. |
| CTW → cert-watch (push issues) | **No** | CTW has no outbound webhook for issue events. |

## Design

### Phase 1: CTW Hub API poller (read-only)

A background poller (similar to the scan scheduler) that periodically fetches the CTW Hub's managed certificate list and stores the results. The cert-watch GUI surfaces CTW issues alongside scan results.

**Config (env vars):**
```
CERT_WATCH_CTW_API_URL=https://ctw.internal/api/v1
CERT_WATCH_CTW_API_TOKEN=<JWT or API key>
CERT_WATCH_CTW_POLL_INTERVAL=3600   # seconds (default: hourly)
```

**New module: `ctw_integration.py`**
- `CTWConfig` dataclass (api_url, token, poll_interval)
- `fetch_ctw_certificates(config)` → `list[CTWManagedCert]`
- `store_ctw_state(db_path, certs)` — upsert into a new `ctw_managed_certs` table
- `get_ctw_issues(db_path)` → list of certs with issues (failed renewal, expiring, etc.)

**New DB table (migration 0029):**
```sql
CREATE TABLE ctw_managed_certs (
    id TEXT PRIMARY KEY,           -- CTW managed cert ID
    name TEXT,
    primary_domain TEXT,
    status TEXT,                    -- "healthy", "renewal_due", "failed", "unknown"
    health_message TEXT,
    expiry_date TEXT,              -- ISO
    last_renewal_attempt TEXT,     -- ISO
    cert_id TEXT,                  -- FK to certificates.id (nullable, matched by domain)
    updated_at TEXT                -- ISO
);
```

**GUI integration:**
- Dashboard: a "CTW Issues" stat card showing count of unhealthy CTW-managed certs
- Certificate detail page: if the cert's hostname matches a CTW-managed cert, show a "Managed by Certify the Web" banner with CTW status
- New page `/ctw` (or a tab on Insights): CTW managed cert inventory with health status

**Matching logic:**
- Match by primary_domain → hostname
- If multiple CTW certs match, show all
- If no match, show in a separate "Unmatched CTW certs" section (certs CTW manages that cert-watch doesn't scan)

### Phase 2: Cross-referencing (post-1.0)

- When cert-watch detects a cert change (scan), cross-reference with CTW state
- If cert-watch sees a new cert that CTW doesn't know about → alert "unmanaged cert"
- If CTW reports a failed renewal → surface in cert-watch alerts with a link to the CTW cert
- If cert-watch's renewal-overdue webhook fires AND CTW manages that host → note that CTW should have handled it (possible CTW failure)

## Effort estimate

| Phase | Effort | Depends on |
|-------|--------|------------|
| Phase 1: API poller + DB + GUI | 2-3 days | CTW Hub deployed (RC) |
| Phase 2: Cross-referencing | 1-2 days | Phase 1 |

## Risks

1. **CTW Hub is RC** — the API may change. Pin to a specific version and handle 404s gracefully.
2. **Auth complexity** — CTW Hub uses JWT with OIDC or local admin. cert-watch would need to store and refresh a JWT token, or use a long-lived API key if CTW adds one.
3. **Co-existence** — if cert-watch and CTW are on the same host, the operator needs to understand which tool is responsible for what. Clear UI labeling ("Managed by CTW" vs "Monitored by cert-watch") is essential.
4. **SSRF** — the CTW API URL must go through the same SSRF validation as scan targets.

## What this plan does NOT include

- **Triggering CTW renewals from cert-watch** — that's the renewal webhook's job (already implemented). cert-watch detects and notifies; CTW acts.
- **Importing CTW-managed certs into cert-watch's scan list** — that's a Phase 3+ consideration (auto-registration of CTW-managed domains as scan targets).
- **CTW Desktop integration** — the desktop API is not public. If there's demand, a CLI-based integration (shelling out to `certify list --json`) could be added as a fallback for Desktop users who don't run the Hub.

## Decision needed from human

1. Is the CTW Hub deployed in the test estate? If not, Phase 1 can't be validated against a real instance.
2. Is the GUI surface (dashboard card + cert detail banner + /ctw page) the right scope, or is a lighter touch (just the dashboard card) sufficient?
3. Should we proceed now, or defer until CTW Hub is GA?
