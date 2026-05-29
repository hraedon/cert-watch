# Handoff: cert-watch front-end redesign

## Overview
A full visual + UX redesign of the cert-watch web UI: the certificate dashboard, the
certificate detail view, the Alerts page, the Scan history page, and the "Add host /
upload / bulk import" flow. The aesthetic is a modern infra-tool dark theme (Grafana /
Linear / Vercel lineage) with a matching light theme, built on IBM Plex Sans + IBM Plex
Mono. It replaces the current browser-default styling.

The single most important change is **the certificate table**: the old table dumped the
full Distinguished Name (`CN=apple.com,O=Apple Inc.,L=Cupertino,...`) into a column and
never showed the Subject Alternative Names. The redesign leads each row with a clean
common name + SAN chips, collapses the issuer to a friendly label, and moves the raw DN /
serial / fingerprint to the detail view where there's room.

## About the design files
The files in `prototype/` are **design references built in HTML/React** — prototypes that
show the intended look and behavior. They are **not** production code to copy directly.
The task is to **recreate these designs in cert-watch's existing environment**: FastAPI +
**Jinja2 templates** (`src/cert_watch/templates/`) + a plain CSS stylesheet
(`src/cert_watch/static/`). Do **not** introduce React — the prototype only uses it as a
convenient rendering medium. Everything here maps cleanly to server-rendered HTML plus a
small amount of vanilla JS (theme toggle, the slide-over open/close, optional client-side
table sort).

A ready-to-use, framework-agnostic stylesheet is included: **`tokens.css`**. Drop it into
`static/css/` and link it from your base template — it contains every design token and the
core component classes (`.cw-btn`, `.cw-panel`, `.cw-pill`, `.cw-table`, `.cw-chip`,
`.cw-seg`, `.cw-slide`, etc.) used below. The class names in this README match that file.

## Fidelity
**High-fidelity.** Colors, typography, spacing, and interactions are final. Recreate the UI
to match. Exact values are in `tokens.css` and the Design Tokens section below.

---

## Design tokens (summary — full values in `tokens.css`)

**Type**
- UI font: `IBM Plex Sans` (weights 400/500/600/700)
- Mono font: `IBM Plex Mono` (400/500/600) — used for **every cert identity, hostname,
  date, serial, fingerprint, and number**. This is a deliberate, load-bearing choice: mono
  makes hostnames and hex scannable and column-aligned. Class `.mono`.
- Scale: page title 21px/600; section title 13.5px/600; body 13px; table cell 12.5–13.5px;
  labels/sub 11–12px; stat value 30px/600. Never below 11px.

**Color** (dark default; light values in `tokens.css` under `[data-theme="light"]`)
| Token | Dark | Meaning |
|---|---|---|
| `--bg` | `#0c0e12` | app background |
| `--panel` | `#14171d` | cards, top bar, table container |
| `--panel-2` / `--panel-3` | `#191d25` / `#1f242e` | raised / hover surfaces |
| `--inset` | `#0e1116` | inputs, bars, insets |
| `--border` / `--border-2` | `#232934` / `#2d3440` | hairlines / stronger borders |
| `--text` / `--text-2` / `--text-3` | `#e9ecf2` / `#a3acbc` / `#69727f` | primary / secondary / muted |
| `--accent` | `#7c8cff` | indigo accent (primary buttons, links, focus) |
| `--ok` | `#34d399` | healthy |
| `--warn` | `#fbbf24` | warning |
| `--crit` | `#f87171` | critical |
| `--expired` | `#fb6f92` | expired |
Each status color has a matching `--*-soft` translucent fill for pill/zone backgrounds.

**Radius:** 6 / 8 / 9 / 12px. **Spacing:** multiples used throughout — 4 6 8 10 12 14 16 18 22 26px.
**Shadow:** `--shadow` (see tokens). **Row hover:** `--row-hover`.

---

## Urgency model (drives all color coding)
Compute days-until-expiry, then bucket. Thresholds mirror the app's existing per-host
defaults (14/7/3/1):
```
days < 0   → "expired"   (--expired)
days <= 7  → "critical"  (--crit)
days <= 14 → "warning"   (--warn)
else       → "healthy"   (--ok)
```
Render as a `.cw-pill` with the bucket name as a class: `<span class="cw-pill critical">`.
The relative-time string ("in 4 days", "3 days ago", "in 2 months") is shown under the
expiry date. (Reference impl: `prototype/cw-data.js` → `urgency()` and `relExpiry()`.)

---

## Screens / views

### 1. Dashboard — certificate list (`GET /`)
**Purpose:** the home view; see every tracked certificate and triage by urgency.

**Layout (top to bottom), max content width full, page padding 22px 26px:**
1. **Top bar** (`.cw-topbar`, height 58, `--panel` bg, bottom border): wordmark left
   (shield mark + "cert·watch" + version pill), nav (`Dashboard` / `Alerts` /
   `Scan history`), spacer, alert bell (with unread count badge), theme toggle, primary
   **Add host** button.
2. **Page header**: H1 "Certificates" + muted subtitle, right-aligned **Export CSV** /
   **Export JSON** buttons (`.cw-btn`).
3. **Summary stat cards** (`.cw-stats`, 4-up grid): Tracked certificates (default/accent
   rail), Expired (`--crit` rail+value), Expiring ≤ 14 days (`--warn`), Healthy (`--ok`).
   Each card: left color rail (3px), icon + label, big value, muted sub-line. Values come
   from counting certs per urgency bucket.
4. **Toolbar** (`.cw-toolbar`): search input (`.cw-search`, magnifier icon, placeholder
   "Search subject, issuer, host…"), segmented urgency filter (`.cw-seg` with per-segment
   counts: All / Expired / Critical / Warning / Healthy), spacer, "Source: All" filter
   button.
5. **Table** (`.cw-table` inside `.cw-panel`), columns:
   - **Certificate**: common name in `.cw-host` (mono); a "CA" chip if it's a CA cert;
     below it, up to 2 SAN chips (`.cw-chip.san`) + a "+N more" chip. **This is the key
     redesign — lead with CN + SANs, not the DN.**
   - **Issuer**: friendly org name ("Let's Encrypt") on line 1; mono sub-line with the
     intermediate CA + key type ("R11 · ECDSA P-256"). Parse from the issuer DN — show the
     `O=` value (or a known-CA friendly name) as the headline and the issuer `CN=` as the
     sub-detail. **Do not show the full issuer DN here.**
   - **Source**: a `.cw-chip` ("Scanned" / "Uploaded" / "Public CT") with an icon, plus a
     chain-status chip below ("full chain" muted, or "chain incomplete" in `--warn` when
     the server didn't return intermediates).
   - **Expires**: ISO date (mono), relative string below (colored `--expired`/`--crit` when
     urgent), and a thin `.cw-bar` showing proportion of a 90-day horizon remaining,
     filled with the urgency color.
   - **Status**: `.cw-pill` for the urgency bucket.
   - **Actions** (hover-revealed, `.cw-rowact`): "Scan now" icon-button (spins while
     scanning), "Details" chevron.
   - Sortable headers: Certificate (cn), Issuer, Expires (days). Default sort = soonest
     expiry first. Clicking a row navigates to the detail view.

**States:**
- **Loading**: 6 skeleton rows (`.sk` shimmer blocks) while the first data load resolves.
- **Empty (filtered)**: centered icon + "No matching certificates" + hint when search/filter
  yields nothing.
- **Scanning a row**: the row's refresh icon gets `.spin` until the scan completes.

### 2. Certificate detail (`GET` a per-cert page, e.g. `/certificates/{id}`)
**Purpose:** everything about one certificate; this is where the verbose data lives.

**Layout:** breadcrumb ("Certificates › {cn}", first crumb links back), header row (cn as
mono H1 + status pill; source badge + "scanned from host:port" / "uploaded · file" /
"discovered via CT" sub-line; right-aligned **Scan now** primary / **Download** / delete
icon). Then a 2-column grid (`1.6fr / 1fr`):
- **Left column:**
  - **Validity meter** (`.cw-panel`): "TIME REMAINING", big day count in urgency color,
    status pill; a progress bar showing elapsed fraction of the cert's lifetime
    (issued→expires) with a green→urgency gradient; issued/expires dates beneath.
  - **Subject Alternative Names** (`.cw-panel`): every SAN as a `.cw-chip.san` with a globe
    icon + a count badge. (The data the old UI omitted.)
  - **Certificate details** (`.cw-panel`): 2-col grid of labeled fields — **Subject** (full
    DN), **Issuer** (full DN), **Key**, **Signature**, **Serial number**, **SHA-256
    fingerprint**, **Issued**, **Last scanned**. Values in mono, labels in 11px uppercase
    muted. **This is where the full DN belongs.**
  - **Notes & procedures** (`.cw-panel`): an editable free-text field (click or "Edit" →
    textarea; "Save" persists). Seeded with an example renewal runbook. Footer note
    "Markdown supported · saved to this certificate". Intended to grow into automation
    documentation / change-procedure storage — **needs a backing column** (e.g. a
    `notes TEXT` field on the certificate/host row + a small save endpoint).
- **Right column — Certificate chain** (`.cw-panel`): the chain as a vertical connected
  list, leaf → intermediate → root. Each node: cn (mono) + role tag ("Leaf · end-entity" /
  "Intermediate CA" / "Root CA"), a key-type chip, expiry date, and a colored days-left
  indicator. A footer banner: green "Chain verified to trusted root" when complete, or a
  `--warn` "Server did not send intermediate(s)" note when incomplete.

### 3. Alerts (`GET /` Alerts tab; data from `/api/alerts`)
**Purpose:** expiry & scan notifications sent via email/webhook.

**Layout:** header (H1 "Alerts" + subtitle; right: channel-status chips "Email · N
recipients", "Webhook · configured", and an "Alert settings" button); a `.cw-seg` filter
(All / Unread / Critical with counts); then a vertical list of alert cards. Each card
(`.cw-panel`, 3px left border in the severity color when unread): a severity icon tile
(soft-tinted bg), cert name (mono) + "NEW" tag if unread, the message line, channel chips
(email/webhook), and a right block with send status ("sent" green / "pending" amber) + a
mono timestamp.
**Empty state:** centered green check tile + "You're all caught up" + "No alerts match this
filter."

### 4. Scan history (`GET /` Scan history tab; data from scan records)
**Purpose:** audit of TLS handshakes, scheduled and manual.

**Layout:** header (H1 + subtitle; right: **Run scan now** primary). A 3-up stat row (Last
scan / Next scheduled / Failures (7d)). Then a table: **When** (mono), **Trigger** (chip:
scheduled/manual), **Scope** (mono — "All hosts" or a hostname), **Hosts** ("9/9", with
"· N failed" in `--crit` and "· N changed" in `--warn`), **Result** (pill: Success /
Cert changed / Failed), **Duration** (mono), and a details chevron.

### 5. Add host / upload / bulk import — slide-over
**Purpose:** the three intake methods. In the old UI these were four cards across the top of
the dashboard; the redesign consolidates them into one right-side slide-over panel opened
by the **Add host** button, keeping the dashboard clean.

**Layout** (`.cw-slide`, 452px, slides in from right over a dimmed `.cw-slide-bg`): header
("Add certificates" + subtitle + close), a full-width 3-tab `.cw-seg` (Scan host / Upload
file / Bulk import), tab body, and a sticky footer (Cancel + a primary action whose label
changes per tab: "Add & scan" / "Upload" / "Import").
- **Scan host:** Hostname, Port (default 443), Alert thresholds (placeholder "14, 7, 3, 1"),
  checkbox "Scan common TLS ports", checkbox "Verify certificate chain on scan". → `POST /hosts`
- **Upload file:** a dashed drop zone (PEM · DER · CER · CRT · PKCS#12 · PKCS#7 · chain
  bundles) + a Password field (PKCS#12 only). → `POST /upload`
- **Bulk import:** a dashed CSV drop zone, an inline example (hostname,port,threshold_days),
  and a "Download CSV template" link. → `POST /hosts/import`

---

## Interactions & behavior
- **Navigation:** top-bar nav switches pages. In the prototype this is client state; in
  Jinja these are normal routes/links (`/`, `/alerts`, `/scans`, `/certificates/{id}`). The
  active tab gets `.active`.
- **Theme toggle:** flips `data-theme` between `dark`/`light` on the root element. Persist
  to `localStorage` and apply before paint (see snippet below). Transition: instant token
  swap (no animation needed).
- **Add-host slide-over:** toggling a class `on` on `.cw-slide` (translateX 0) and
  `.cw-slide-bg` (opacity 1, pointer-events auto). Backdrop click or Cancel closes. ~260ms
  cubic-bezier(.3,.8,.3,1) transform.
- **Tabs in slide-over:** swap the active `.cw-seg button.on` and show the matching body.
- **Table sort:** clicking a sortable `th` toggles asc/desc on that key. Can be done
  server-side (querystring `?sort=expires&dir=asc`) or with a tiny client script.
- **Table filter/search:** segmented urgency filter + search box. Server-side via
  querystring is fine and matches the existing `?urgency=&source=&q=` pattern.
- **Scan now:** posts to `/hosts/{id}/scan`; spin the row icon until the response returns,
  then refresh the row.
- **Row click → detail:** navigates to the cert detail page. Action-cell clicks must not
  bubble to the row navigation (`stopPropagation` / separate links).

**Theme-before-paint snippet** (put in `<head>` of `base.html`, before the stylesheet):
```html
<script>
  try {
    var t = localStorage.getItem('cw-theme') || 'dark';
    document.documentElement.setAttribute('data-theme', t);
  } catch (e) { document.documentElement.setAttribute('data-theme', 'dark'); }
</script>
```
Toggle handler: read current `data-theme`, set the other, write to `localStorage`.

---

## State / data mapping (to existing cert-watch fields)
The prototype's per-cert object (see `prototype/cw-data.js`) maps to your X.509 model:
- `cn` ← subject CN. `sans` ← Subject Alternative Names list (currently parsed but not
  surfaced — surface it).
- `issuerOrg` ← issuer `O=` (or a friendly name for known CAs); `issuerCa` ← issuer `CN=`;
  `key` ← public-key type + size; `sigAlg` ← signature algorithm.
- `subjectDN` / `issuerDN` ← the full RFC 4514 strings (detail view only).
- `serial`, `fp` (SHA-256 fingerprint), `issued`, `expires`, `lastScan` ← as stored.
- `source` ∈ {`scan`,`upload`,`public`}; `chainComplete` ← whether intermediates were
  returned; `isCa` ← basicConstraints CA flag.
- `days` ← computed (expires − today); `urgency`/`rel` ← derived (see Urgency model).
- **New:** a `notes` text field (for the Notes & procedures panel) — not in the current
  schema; add a column + save endpoint.

Alerts use: severity, kind (expired / expiring / scan-failed), cert, message, channels,
status (sent/pending), timestamp, unread flag. Scan records use: timestamp, trigger
(scheduled/manual), scope, hosts/ok/failed/changed counts, duration, result.

---

## Assets
- **Fonts:** IBM Plex Sans + IBM Plex Mono via Google Fonts (`@import` at top of
  `tokens.css`). For an offline/self-hosted deploy, vendor the woff2 files into
  `static/fonts/` and replace the `@import` with `@font-face` rules.
- **Icons:** simple line icons drawn inline as SVG `<path>` data (no icon library). The full
  set used (shield, clock, alert-triangle, check-circle, search, plus, upload, refresh,
  server, file, globe, chevrons, sun, moon, bell, link, key, download, trash, filter) is in
  `prototype/cw-shared.jsx` in the `I = {…}` path map — copy the path strings into a Jinja
  macro or partial. Stroke width 1.7, 24×24 viewBox, `stroke="currentColor"`, no fill.
- **Wordmark:** the shield+check "cert·watch" mark is the `.cw-mark` gradient tile + inline
  SVG (also in `cw-shared.jsx`). No external logo file.

---

## Files in this bundle
- **`tokens.css`** — production-ready CSS: all tokens (dark + light via `data-theme`) and
  every core component class. **Start here.** Link it from your base template.
- **`prototype/cw-app.html`** — the full working app (open in a browser to click through
  every screen, theme toggle, slide-over, detail view).
- **`prototype/index.html`** — the original exploration canvas (3 dashboard directions +
  detail + light mode), for context on why Direction A was chosen.
- **`prototype/cw-data.js`** — sample data + the urgency / relative-time helper logic to
  port server-side.
- **`prototype/cw-shared.jsx`** — source of truth for component markup, the SVG icon path
  map, and the wordmark.
- **`prototype/cw-app.jsx`** — the app shell: page layouts, the table, alerts, scan history,
  and the add-host slide-over. The clearest reference for each screen's structure.
- **`prototype/cw-dashboards.jsx`** — the dashboard table + stat cards + the timeline/board
  directions (B/C) that were explored but not chosen.
- **`prototype/cw-detail.jsx`** — the certificate detail view (validity meter, SANs, details,
  chain, notes).
- **`prototype/design-canvas.jsx`** — canvas harness for `index.html` only; not part of the
  app design.

## Suggested implementation order
1. Add `tokens.css` + the theme snippet to `base.html`; confirm fonts + dark/light work.
2. Build a Jinja macro/partial for the top bar + nav + wordmark + icon set.
3. Rebuild the **dashboard table** (the highest-value change) — CN+SAN cell, friendly
   issuer, source/chain chips, expiry cell, status pill, stat cards, toolbar.
4. Build the **certificate detail** page (SANs + chain + details + notes field; add the
   `notes` column + save route).
5. Alerts + Scan history pages.
6. Convert the four intake cards into the **Add-host slide-over**.
7. Wire sort/filter/search (server-side querystring is fine) and the Scan-now spinner.
