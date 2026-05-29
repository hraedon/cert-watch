/* cert-watch shared design tokens + UI primitives.
   Exports primitives to window for the dashboard/detail files. */

/* ---- one-time CSS injection (tokens + component styles) ---- */
if (typeof document !== 'undefined' && !document.getElementById('cw-styles')) {
  const s = document.createElement('style');
  s.id = 'cw-styles';
  s.textContent = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

  .cw, .cw * { box-sizing: border-box; }
  .cw {
    --font-sans: 'IBM Plex Sans', system-ui, -apple-system, sans-serif;
    --font-mono: 'IBM Plex Mono', ui-monospace, 'SF Mono', Menlo, monospace;
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
    text-rendering: optimizeLegibility;
    width: 100%; height: 100%;
    background: var(--bg);
    color: var(--text);
    overflow: hidden;
  }

  /* ---------- DARK (primary) ---------- */
  .cw.cw-dark {
    --bg: #0c0e12;
    --bg-soft: #0f1217;
    --panel: #14171d;
    --panel-2: #191d25;
    --panel-3: #1f242e;
    --inset: #0e1116;
    --border: #232934;
    --border-2: #2d3440;
    --text: #e9ecf2;
    --text-2: #a3acbc;
    --text-3: #69727f;
    --accent: #7c8cff;
    --accent-2: #a78bfa;
    --accent-soft: rgba(124,140,255,0.15);
    --accent-line: rgba(124,140,255,0.4);
    --ok: #34d399;     --ok-soft: rgba(52,211,153,0.14);
    --warn: #fbbf24;   --warn-soft: rgba(251,191,36,0.15);
    --crit: #f87171;   --crit-soft: rgba(248,113,113,0.15);
    --expired: #fb6f92; --expired-soft: rgba(251,111,146,0.15);
    --shadow: 0 1px 2px rgba(0,0,0,.4), 0 8px 28px rgba(0,0,0,.28);
    --row-hover: rgba(255,255,255,0.022);
  }
  /* ---------- LIGHT ---------- */
  .cw.cw-light {
    --bg: #f3f4f7;
    --bg-soft: #eceef2;
    --panel: #ffffff;
    --panel-2: #fafbfc;
    --panel-3: #f2f4f7;
    --inset: #f6f7f9;
    --border: #e5e8ed;
    --border-2: #d6dae1;
    --text: #181c24;
    --text-2: #58616f;
    --text-3: #8b94a3;
    --accent: #5868f0;
    --accent-2: #7c5cf0;
    --accent-soft: rgba(88,104,240,0.10);
    --accent-line: rgba(88,104,240,0.35);
    --ok: #15a34a;     --ok-soft: rgba(21,163,74,0.10);
    --warn: #c2740a;   --warn-soft: rgba(194,116,10,0.11);
    --crit: #dc3030;   --crit-soft: rgba(220,48,48,0.10);
    --expired: #c41d6f; --expired-soft: rgba(196,29,111,0.10);
    --shadow: 0 1px 2px rgba(20,24,40,.06), 0 6px 22px rgba(20,24,40,.07);
    --row-hover: rgba(20,30,60,0.025);
  }

  .cw .mono { font-family: var(--font-mono); font-feature-settings: 'zero' 1; }
  .cw .tnum { font-variant-numeric: tabular-nums; }

  /* scrollbars (kept subtle; canvas hides them anyway) */
  .cw ::-webkit-scrollbar { width: 9px; height: 9px; }
  .cw ::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 6px; }

  /* ---- app chrome ---- */
  .cw-app { display: flex; flex-direction: column; height: 100%; }
  .cw-topbar {
    display: flex; align-items: center; gap: 22px;
    padding: 0 26px; height: 58px; flex: 0 0 auto;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  .cw-wordmark { display: flex; align-items: center; gap: 10px; }
  .cw-mark {
    width: 28px; height: 28px; border-radius: 7px; flex: 0 0 auto;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(150deg, var(--accent), var(--accent-2));
    color: #fff; box-shadow: 0 2px 8px var(--accent-soft);
  }
  .cw-name { font-size: 16px; font-weight: 600; letter-spacing: -.3px; }
  .cw-name b { font-weight: 600; }
  .cw-ver {
    font-family: var(--font-mono); font-size: 10.5px; color: var(--text-3);
    border: 1px solid var(--border-2); border-radius: 5px; padding: 1px 5px; margin-left: 2px;
  }
  .cw-nav { display: flex; gap: 2px; margin-left: 8px; }
  .cw-nav a {
    font-size: 13.5px; font-weight: 500; color: var(--text-2);
    padding: 7px 12px; border-radius: 7px; text-decoration: none; cursor: pointer;
    transition: background .12s, color .12s;
  }
  .cw-nav a:hover { background: var(--panel-2); color: var(--text); }
  .cw-nav a.active { color: var(--text); background: var(--panel-3); }
  .cw-spacer { flex: 1 1 auto; }

  .cw-iconbtn {
    width: 34px; height: 34px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--panel-2); color: var(--text-2); cursor: pointer;
    display: flex; align-items: center; justify-content: center; transition: all .12s;
  }
  .cw-iconbtn:hover { color: var(--text); border-color: var(--border-2); }

  /* ---- buttons ---- */
  .cw-btn {
    font-family: var(--font-sans); font-size: 13px; font-weight: 500;
    display: inline-flex; align-items: center; gap: 7px; cursor: pointer;
    padding: 8px 13px; border-radius: 8px; border: 1px solid var(--border-2);
    background: var(--panel-2); color: var(--text); transition: all .12s; white-space: nowrap;
  }
  .cw-btn:hover { background: var(--panel-3); border-color: var(--text-3); }
  .cw-btn.primary {
    background: var(--accent); border-color: transparent; color: #fff;
    box-shadow: 0 1px 0 rgba(255,255,255,.12) inset, 0 4px 14px var(--accent-soft);
  }
  .cw-btn.primary:hover { filter: brightness(1.06); }
  .cw-btn.ghost { background: transparent; border-color: transparent; color: var(--text-2); padding: 6px 9px; }
  .cw-btn.ghost:hover { background: var(--panel-2); color: var(--text); }
  .cw-btn.sm { padding: 5px 10px; font-size: 12px; }

  /* ---- inputs ---- */
  .cw-field { display: flex; flex-direction: column; gap: 6px; }
  .cw-label { font-size: 11.5px; font-weight: 500; color: var(--text-2); letter-spacing: .02em; }
  .cw-input, .cw-select {
    font-family: var(--font-sans); font-size: 13px; color: var(--text);
    background: var(--inset); border: 1px solid var(--border); border-radius: 8px;
    padding: 8px 11px; outline: none; transition: border-color .12s, box-shadow .12s; width: 100%;
  }
  .cw-input::placeholder { color: var(--text-3); }
  .cw-input:focus, .cw-select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-soft); }
  .cw-input.mono { font-family: var(--font-mono); }

  /* ---- panels / cards ---- */
  .cw-panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  }

  /* ---- stat cards ---- */
  .cw-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  .cw-stat {
    position: relative; overflow: hidden;
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 15px 16px 14px;
  }
  .cw-stat-rail { position: absolute; left: 0; top: 0; bottom: 0; width: 3px; }
  .cw-stat-top { display: flex; align-items: center; gap: 8px; color: var(--text-2); }
  .cw-stat-label { font-size: 12px; font-weight: 500; }
  .cw-stat-val { font-size: 30px; font-weight: 600; letter-spacing: -1px; margin-top: 8px; line-height: 1; }
  .cw-stat-sub { font-size: 11.5px; color: var(--text-3); margin-top: 7px; }

  /* ---- status pill / dot ---- */
  .cw-pill {
    display: inline-flex; align-items: center; gap: 6px; white-space: nowrap;
    font-size: 11.5px; font-weight: 600; padding: 3px 9px 3px 7px; border-radius: 999px;
    border: 1px solid transparent; line-height: 1.4;
  }
  .cw-pill .dot { width: 6px; height: 6px; border-radius: 50%; flex: 0 0 auto; }
  .cw-pill.expired  { color: var(--expired); background: var(--expired-soft); border-color: color-mix(in srgb, var(--expired) 28%, transparent); }
  .cw-pill.expired .dot  { background: var(--expired); }
  .cw-pill.critical { color: var(--crit); background: var(--crit-soft); border-color: color-mix(in srgb, var(--crit) 28%, transparent); }
  .cw-pill.critical .dot { background: var(--crit); }
  .cw-pill.warning  { color: var(--warn); background: var(--warn-soft); border-color: color-mix(in srgb, var(--warn) 28%, transparent); }
  .cw-pill.warning .dot  { background: var(--warn); }
  .cw-pill.healthy  { color: var(--ok); background: var(--ok-soft); border-color: color-mix(in srgb, var(--ok) 26%, transparent); }
  .cw-pill.healthy .dot  { background: var(--ok); }

  /* ---- source / chip ---- */
  .cw-chip {
    display: inline-flex; align-items: center; gap: 5px; font-size: 11px; font-weight: 500;
    padding: 2px 8px; border-radius: 6px; border: 1px solid var(--border-2);
    color: var(--text-2); background: var(--panel-2); font-family: var(--font-mono); white-space: nowrap;
  }
  .cw-chip.san { color: var(--text-2); background: var(--inset); }
  .cw-chip.more { color: var(--text-3); }

  /* ---- expiry bar ---- */
  .cw-bar { height: 5px; border-radius: 3px; background: var(--inset); overflow: hidden; position: relative; }
  .cw-bar > i { display: block; height: 100%; border-radius: 3px; }

  /* ---- table ---- */
  .cw-table { width: 100%; border-collapse: separate; border-spacing: 0; }
  .cw-table th {
    text-align: left; font-size: 11px; font-weight: 600; color: var(--text-3);
    letter-spacing: .04em; text-transform: uppercase; padding: 0 14px 10px;
    border-bottom: 1px solid var(--border); white-space: nowrap; user-select: none;
  }
  .cw-table th.sortable { cursor: pointer; }
  .cw-table th.sortable:hover { color: var(--text-2); }
  .cw-table td { padding: 13px 14px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  .cw-table tr:last-child td { border-bottom: none; }
  .cw-table tbody tr { transition: background .1s; }
  .cw-table tbody tr:hover { background: var(--row-hover); }
  .cw-num { font-family: var(--font-mono); font-variant-numeric: tabular-nums; }

  .cw-host { font-family: var(--font-mono); font-size: 13.5px; font-weight: 500; color: var(--text); letter-spacing: -.2px; }
  .cw-sub { font-size: 11.5px; color: var(--text-3); margin-top: 3px; }

  /* ---- toolbar / filter row ---- */
  .cw-toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .cw-search { position: relative; flex: 0 0 auto; }
  .cw-search svg { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--text-3); pointer-events: none; }
  .cw-search input { padding-left: 33px; width: 260px; }

  .cw-seg { display: inline-flex; background: var(--inset); border: 1px solid var(--border); border-radius: 9px; padding: 3px; gap: 2px; }
  .cw-seg button {
    font-family: var(--font-sans); font-size: 12.5px; font-weight: 500; color: var(--text-2);
    border: none; background: transparent; padding: 5px 11px; border-radius: 6px; cursor: pointer; transition: all .12s;
    display: inline-flex; align-items: center; gap: 6px;
  }
  .cw-seg button:hover { color: var(--text); }
  .cw-seg button.on { background: var(--panel); color: var(--text); box-shadow: var(--shadow); }
  .cw-seg button .cnt { font-family: var(--font-mono); font-size: 11px; opacity: .65; }

  .cw-rowact { display: flex; gap: 4px; opacity: 0; transition: opacity .12s; justify-content: flex-end; }
  .cw-table tbody tr:hover .cw-rowact { opacity: 1; }

  .cw-divider { height: 1px; background: var(--border); }
  .cw-muted { color: var(--text-3); }
  .cw-link { color: var(--accent); cursor: pointer; text-decoration: none; }
  .cw-link:hover { text-decoration: underline; }
  `;
  document.head.appendChild(s);
}

/* ---- JS palette (for SVG/timeline that can't read CSS vars conveniently) ---- */
const CW_PALETTE = {
  dark: {
    ok: '#34d399', warn: '#fbbf24', crit: '#f87171', expired: '#fb6f92',
    accent: '#7c8cff', text: '#e9ecf2', text2: '#a3acbc', text3: '#69727f',
    border: '#232934', border2: '#2d3440', panel: '#14171d', inset: '#0e1116', bg: '#0c0e12',
  },
  light: {
    ok: '#15a34a', warn: '#c2740a', crit: '#dc3030', expired: '#c41d6f',
    accent: '#5868f0', text: '#181c24', text2: '#58616f', text3: '#8b94a3',
    border: '#e5e8ed', border2: '#d6dae1', panel: '#ffffff', inset: '#f6f7f9', bg: '#f3f4f7',
  },
};
const cwColor = (theme, u) => CW_PALETTE[theme][u === 'healthy' ? 'ok' : u === 'warning' ? 'warn' : u === 'critical' ? 'crit' : 'expired'];

/* ---------------- Icons ---------------- */
const I = {
  shield: 'M12 2l7 3v6c0 4.5-3 8.3-7 9.5C8 19.3 5 15.5 5 11V5l7-3z',
  clock: 'M12 7v5l3 2 M12 21a9 9 0 100-18 9 9 0 000 18z',
  alert: 'M12 9v4 M12 17h.01 M10.3 3.9L2.4 18a2 2 0 001.7 3h15.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z',
  check: 'M20 6L9 17l-5-5',
  checkCircle: 'M9 12l2 2 4-4 M12 21a9 9 0 100-18 9 9 0 000 18z',
  search: 'M21 21l-4.3-4.3 M11 19a8 8 0 100-16 8 8 0 000 16z',
  plus: 'M12 5v14 M5 12h14',
  upload: 'M12 16V4 M7 9l5-5 5 5 M4 20h16',
  refresh: 'M21 12a9 9 0 11-3-6.7L21 8 M21 3v5h-5',
  server: 'M3 6a2 2 0 012-2h14a2 2 0 012 2v3a2 2 0 01-2 2H5a2 2 0 01-2-2V6z M3 15a2 2 0 012-2h14a2 2 0 012 2v3a2 2 0 01-2 2H5a2 2 0 01-2-2v-3z M7 7.5h.01 M7 16.5h.01',
  file: 'M14 3v5h5 M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z',
  globe: 'M12 21a9 9 0 100-18 9 9 0 000 18z M3 12h18 M12 3a14 14 0 000 18 14 14 0 000-18z',
  chevDown: 'M5 8l5 5 5-5',
  chevRight: 'M8 5l5 5-5 5',
  sun: 'M12 17a5 5 0 100-10 5 5 0 000 10z M12 1v2 M12 21v2 M4.2 4.2l1.4 1.4 M18.4 18.4l1.4 1.4 M1 12h2 M21 12h2 M4.2 19.8l1.4-1.4 M18.4 5.6l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z',
  ext: 'M15 3h6v6 M10 14L21 3 M21 14v5a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h5',
  dots: 'M12 6h.01 M12 12h.01 M12 18h.01',
  x: 'M18 6L6 18 M6 6l12 12',
  trash: 'M3 6h18 M8 6V4a1 1 0 011-1h6a1 1 0 011 1v2 M19 6l-1 14a2 2 0 01-2 2H8a2 2 0 01-2-2L5 6',
  bell: 'M18 8a6 6 0 10-12 0c0 7-3 9-3 9h18s-3-2-3-9 M13.7 21a2 2 0 01-3.4 0',
  link: 'M10 13a5 5 0 007.5.5l3-3a5 5 0 00-7-7l-1.7 1.7 M14 11a5 5 0 00-7.5-.5l-3 3a5 5 0 007 7l1.7-1.7',
  key: 'M21 2l-2 2 M15 7a4 4 0 11-6 6l-6 6v3h3l6-6a4 4 0 016-6l1-1-3-3z',
  download: 'M12 3v12 M7 10l5 5 5-5 M5 21h14',
  filter: 'M3 5h18 M6 12h12 M10 19h4',
};
function Icon({ name, size = 16, sw = 1.7, fill = false, style }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill={fill ? 'currentColor' : 'none'}
      stroke={fill ? 'none' : 'currentColor'} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
      style={{ flex: '0 0 auto', ...style }}>
      <path d={I[name]} />
    </svg>
  );
}

/* ---------------- Wordmark ---------------- */
function Wordmark({ version = 'v0.3.0' }) {
  return (
    <div className="cw-wordmark">
      <div className="cw-mark">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d={I.shield} /><path d="M9 12l2 2 4-4" />
        </svg>
      </div>
      <span className="cw-name">cert<span style={{ color: 'var(--text-3)' }}>·</span>watch</span>
      <span className="cw-ver">{version}</span>
    </div>
  );
}

/* ---------------- StatusPill ---------------- */
const URG_LABEL = { expired: 'Expired', critical: 'Critical', warning: 'Warning', healthy: 'Healthy' };
function StatusPill({ urgency, label }) {
  return (
    <span className={`cw-pill ${urgency}`}>
      <span className="dot" />{label || URG_LABEL[urgency]}
    </span>
  );
}

/* ---------------- SourceBadge ---------------- */
function SourceBadge({ source }) {
  const map = { scan: { icon: 'server', t: 'Scanned' }, upload: { icon: 'file', t: 'Uploaded' }, public: { icon: 'globe', t: 'Public CT' } };
  const m = map[source] || map.scan;
  return <span className="cw-chip"><Icon name={m.icon} size={12} sw={1.6} />{m.t}</span>;
}

/* ---------------- SAN chips ---------------- */
function SanChips({ sans, max = 3 }) {
  if (!sans || !sans.length) return <span className="cw-sub">no SAN entries</span>;
  const shown = sans.slice(0, max);
  const extra = sans.length - shown.length;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 5 }}>
      {shown.map((s) => <span key={s} className="cw-chip san">{s}</span>)}
      {extra > 0 && <span className="cw-chip more">+{extra} more</span>}
    </div>
  );
}

/* ---------------- ExpiryBar (proportion of validity remaining toward a 90d horizon) ---------------- */
function ExpiryBar({ days, urgency, theme = 'dark', horizon = 90 }) {
  const pct = Math.max(2, Math.min(100, (days / horizon) * 100));
  const c = days < 0 ? cwColor(theme, 'expired') : cwColor(theme, urgency);
  return (
    <div className="cw-bar" title={`${days} days`}>
      <i style={{ width: `${days < 0 ? 100 : pct}%`, background: days < 0 ? c : `linear-gradient(90deg, ${c}, ${c})`, opacity: days < 0 ? .5 : 1 }} />
    </div>
  );
}

/* ---------------- StatCard ---------------- */
function StatCard({ tone, icon, label, value, sub }) {
  const cvar = tone === 'attention' ? 'var(--crit)' : tone === 'warning' ? 'var(--warn)' : tone === 'ok' ? 'var(--ok)' : 'var(--accent)';
  return (
    <div className="cw-stat">
      <div className="cw-stat-rail" style={{ background: cvar }} />
      <div className="cw-stat-top" style={{ color: cvar }}>
        <Icon name={icon} size={15} sw={1.8} />
        <span className="cw-stat-label" style={{ color: 'var(--text-2)' }}>{label}</span>
      </div>
      <div className="cw-stat-val" style={{ color: tone === 'default' ? 'var(--text)' : cvar }}>{value}</div>
      {sub && <div className="cw-stat-sub">{sub}</div>}
    </div>
  );
}

/* ---------------- ThemeToggle ---------------- */
function ThemeToggle({ theme, onToggle }) {
  return (
    <button className="cw-iconbtn" onClick={onToggle} title={theme === 'dark' ? 'Switch to light' : 'Switch to dark'}>
      <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={16} />
    </button>
  );
}

Object.assign(window, {
  CW_PALETTE, cwColor, Icon, Wordmark, StatusPill, SourceBadge, SanChips, ExpiryBar, StatCard, ThemeToggle, URG_LABEL,
});
