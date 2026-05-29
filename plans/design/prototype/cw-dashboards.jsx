/* cert-watch dashboard directions A / B / C.
   Each is a self-contained, themeable, lightly-interactive frame.
   Relies on window.CW (data) + cw-shared primitives. */

const { CERTS, summary } = window.CW;
const { Icon, Wordmark, StatusPill, SourceBadge, SanChips, ExpiryBar, StatCard, ThemeToggle, cwColor } = window;

/* ---------- shared bits ---------- */

function shortLabel(c) {
  if (c.source === 'upload') return 'root-ca';
  if (c.cn.startsWith('*.')) return '*.' + c.cn.split('.')[1];
  return c.cn.split('.')[0];
}

function AppFrame({ theme, setTheme, active = 'Dashboard', alerts = 5, children }) {
  return (
    <div className={`cw cw-${theme}`}>
      <div className="cw-app">
        <header className="cw-topbar">
          <Wordmark />
          <nav className="cw-nav">
            {['Dashboard', 'Alerts', 'Scan history'].map((n) => (
              <a key={n} className={active === n ? 'active' : ''}>{n}</a>
            ))}
          </nav>
          <div className="cw-spacer" />
          <button className="cw-iconbtn" style={{ position: 'relative' }} title="Alerts">
            <Icon name="bell" size={16} />
            {alerts > 0 && (
              <span style={{ position: 'absolute', top: 5, right: 5, width: 7, height: 7, borderRadius: 4, background: 'var(--crit)', boxShadow: '0 0 0 2px var(--panel)' }} />
            )}
          </button>
          <ThemeToggle theme={theme} onToggle={() => setTheme(theme === 'dark' ? 'light' : 'dark')} />
          <button className="cw-btn primary"><Icon name="plus" size={15} sw={2} />Add host</button>
        </header>
        <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>{children}</div>
      </div>
    </div>
  );
}

function PageHead({ title, sub }) {
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 18 }}>
      <div>
        <h1 style={{ margin: 0, fontSize: 21, fontWeight: 600, letterSpacing: '-.4px' }}>{title}</h1>
        <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>{sub}</div>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button className="cw-btn"><Icon name="upload" size={14} />Upload certificate</button>
        <button className="cw-btn"><Icon name="download" size={14} />Export</button>
      </div>
    </div>
  );
}

function StatRow() {
  const s = summary();
  const soonest = [...CERTS].filter((c) => c.days >= 0).sort((a, b) => a.days - b.days)[0];
  return (
    <div className="cw-stats" style={{ marginBottom: 18 }}>
      <StatCard tone="default" icon="shield" label="Tracked certificates" value={s.total} sub={`${s.hosts} hosts · 1 uploaded`} />
      <StatCard tone="attention" icon="alert" label="Expired" value={s.expired} sub={s.expired ? 'vault.k8s.hraedon.com' : 'none'} />
      <StatCard tone="warning" icon="clock" label="Expiring ≤ 14 days" value={s.critical + s.warning} sub={`soonest: ${shortLabel(soonest)} · ${soonest.days}d`} />
      <StatCard tone="ok" icon="checkCircle" label="Healthy" value={s.healthy} sub="no action needed" />
    </div>
  );
}

/* issuer cell content */
function IssuerCell({ c }) {
  return (
    <div>
      <div style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{c.issuerOrg}</div>
      <div className="cw-sub mono">{c.issuerCa} · {c.key}</div>
    </div>
  );
}

function ChainNote({ c }) {
  if (c.source !== 'scan') return null;
  return c.chainComplete
    ? <span className="cw-chip" style={{ color: 'var(--text-3)', borderColor: 'var(--border)' }}><Icon name="link" size={11} sw={1.6} />full chain</span>
    : <span className="cw-chip" style={{ color: 'var(--warn)', borderColor: 'color-mix(in srgb, var(--warn) 30%, transparent)', background: 'var(--warn-soft)' }}><Icon name="alert" size={11} sw={1.7} />chain incomplete</span>;
}

/* ============================================================= */
/* DIRECTION A — Refined table                                    */
/* ============================================================= */
function DirectionA({ initialTheme = 'dark' }) {
  const [theme, setTheme] = React.useState(initialTheme);
  const [filter, setFilter] = React.useState('all');
  const [q, setQ] = React.useState('');
  const [sort, setSort] = React.useState({ key: 'days', dir: 1 });

  const s = summary();
  const segs = [
    ['all', 'All', s.total], ['expired', 'Expired', s.expired], ['critical', 'Critical', s.critical],
    ['warning', 'Warning', s.warning], ['healthy', 'Healthy', s.healthy],
  ];

  let list = CERTS.filter((c) => (filter === 'all' || c.urgency === filter)
    && (!q || (c.cn + ' ' + c.issuerOrg + ' ' + (c.host || '') + ' ' + c.sans.join(' ')).toLowerCase().includes(q.toLowerCase())));
  list = [...list].sort((a, b) => {
    let r = 0;
    if (sort.key === 'days') r = a.days - b.days;
    else if (sort.key === 'cn') r = a.cn.localeCompare(b.cn);
    else if (sort.key === 'issuer') r = a.issuerOrg.localeCompare(b.issuerOrg);
    return r * sort.dir;
  });
  const setSortKey = (key) => setSort((p) => ({ key, dir: p.key === key ? -p.dir : 1 }));
  const Arrow = ({ k }) => sort.key === k ? <span style={{ marginLeft: 4, opacity: .7 }}>{sort.dir === 1 ? '↑' : '↓'}</span> : null;

  return (
    <AppFrame theme={theme} setTheme={setTheme}>
      <div style={{ padding: '22px 26px' }}>
        <PageHead title="Certificates" sub="All tracked certificates from scanned hosts and uploaded files." />
        <StatRow />

        <div className="cw-toolbar" style={{ marginBottom: 14 }}>
          <div className="cw-search">
            <Icon name="search" size={15} />
            <input className="cw-input" placeholder="Search subject, issuer, host…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <div className="cw-seg">
            {segs.map(([k, lab, n]) => (
              <button key={k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>
                {lab}<span className="cnt">{n}</span>
              </button>
            ))}
          </div>
          <div className="cw-spacer" />
          <button className="cw-btn"><Icon name="filter" size={14} />Source: All</button>
        </div>

        <div className="cw-panel" style={{ overflow: 'hidden' }}>
          <table className="cw-table">
            <thead>
              <tr>
                <th className="sortable" style={{ paddingTop: 14 }} onClick={() => setSortKey('cn')}>Certificate<Arrow k="cn" /></th>
                <th className="sortable" onClick={() => setSortKey('issuer')}>Issuer<Arrow k="issuer" /></th>
                <th>Source</th>
                <th className="sortable" onClick={() => setSortKey('days')}>Expires<Arrow k="days" /></th>
                <th style={{ width: 120 }}>Status</th>
                <th style={{ width: 96 }}></th>
              </tr>
            </thead>
            <tbody>
              {list.map((c) => (
                <tr key={c.id}>
                  <td style={{ maxWidth: 360 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="cw-host">{c.cn}</span>
                      {c.isCa && <span className="cw-chip" style={{ color: 'var(--accent)', borderColor: 'var(--accent-line)' }}>CA</span>}
                    </div>
                    <SanChips sans={c.sans} max={2} />
                  </td>
                  <td><IssuerCell c={c} /></td>
                  <td>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
                      <SourceBadge source={c.source} />
                      <ChainNote c={c} />
                    </div>
                  </td>
                  <td style={{ minWidth: 150 }}>
                    <div className="mono" style={{ fontSize: 12.5, color: 'var(--text)', fontWeight: 500 }}>{c.expires}</div>
                    <div className="cw-sub" style={{ color: c.days < 0 ? 'var(--expired)' : c.days <= 7 ? 'var(--crit)' : 'var(--text-3)', marginBottom: 6 }}>{c.rel}</div>
                    <div style={{ width: 130 }}><ExpiryBar days={c.days} urgency={c.urgency} theme={theme} /></div>
                  </td>
                  <td><StatusPill urgency={c.urgency} /></td>
                  <td>
                    <div className="cw-rowact">
                      <button className="cw-iconbtn" title="Scan now" style={{ width: 30, height: 30 }}><Icon name="refresh" size={14} /></button>
                      <button className="cw-iconbtn" title="Details" style={{ width: 30, height: 30 }}><Icon name="chevRight" size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppFrame>
  );
}

/* ============================================================= */
/* DIRECTION B — Timeline-forward                                 */
/* ============================================================= */
function TimelinePanel({ theme }) {
  const HOR = 90;
  const ticks = [0, 7, 14, 30, 60, 90];
  // place certs along 0..90; expired in left gutter; >90 clamp to far right
  const plotted = CERTS.map((c) => ({ c, x: c.days < 0 ? -1 : Math.min(HOR, c.days), over: c.days > HOR }));
  // lane assignment greedy by x
  const sorted = [...plotted].filter((p) => p.x >= 0).sort((a, b) => a.x - b.x);
  const expiredOnes = plotted.filter((p) => p.x < 0);
  const laneLast = [];
  sorted.forEach((p) => {
    let lane = 0;
    for (; lane < laneLast.length; lane++) { if (p.x - laneLast[lane] > 9) break; }
    p.lane = lane; laneLast[lane] = p.x;
  });
  const lanes = Math.max(1, laneLast.length);
  const laneH = 30;
  const trackTop = 20, trackH = lanes * laneH + 14;
  const pct = (x) => `${(x / HOR) * 100}%`;

  return (
    <div className="cw-panel" style={{ padding: '16px 20px 14px', marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
          <Icon name="clock" size={16} style={{ color: 'var(--accent)' }} />
          <span style={{ fontSize: 14, fontWeight: 600 }}>Expiration timeline</span>
          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>next 90 days</span>
        </div>
        <div style={{ display: 'flex', gap: 14, fontSize: 11.5, color: 'var(--text-2)' }}>
          {[['expired', 'Expired'], ['critical', 'Critical'], ['warning', 'Warning'], ['healthy', 'Healthy']].map(([u, l]) => (
            <span key={u} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <span style={{ width: 8, height: 8, borderRadius: 4, background: cwColor(theme, u) }} />{l}
            </span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10, marginTop: 10 }}>
        {/* expired gutter */}
        <div style={{ flex: '0 0 88px', position: 'relative', borderRight: '1px dashed var(--border-2)', paddingRight: 10 }}>
          <div style={{ fontSize: 10.5, color: 'var(--expired)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 6 }}>Expired</div>
          {expiredOnes.map((p) => (
            <div key={p.c.id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span style={{ width: 7, height: 7, borderRadius: 4, background: cwColor(theme, 'expired') }} />
              <span className="mono" style={{ fontSize: 11.5, color: 'var(--text)' }}>{shortLabel(p.c)}</span>
              <span className="mono" style={{ fontSize: 10.5, color: 'var(--text-3)' }}>{p.c.days}d</span>
            </div>
          ))}
        </div>

        {/* track */}
        <div style={{ flex: 1, position: 'relative', height: trackTop + trackH + 22 }}>
          {/* threshold zones */}
          <div style={{ position: 'absolute', left: 0, top: trackTop, height: trackH, width: pct(7), background: 'var(--crit-soft)', borderRadius: 4 }} />
          <div style={{ position: 'absolute', left: pct(7), top: trackTop, height: trackH, width: `calc(${pct(14)} - ${pct(7)})`, background: 'var(--warn-soft)', borderRadius: 4 }} />
          {/* gridlines */}
          {ticks.map((t) => (
            <div key={t} style={{ position: 'absolute', left: pct(t), top: trackTop, height: trackH }}>
              <div style={{ width: 1, height: '100%', background: 'var(--border)' }} />
              <div className="mono" style={{ position: 'absolute', top: -16, left: 0, transform: t === 90 ? 'translateX(-100%)' : 'translateX(-50%)', fontSize: 10.5, color: 'var(--text-3)', whiteSpace: 'nowrap' }}>{t === 0 ? 'today' : t + 'd'}</div>
            </div>
          ))}
          {/* markers */}
          {sorted.map((p) => (
            <div key={p.c.id} style={{ position: 'absolute', left: pct(p.x), top: trackTop + p.lane * laneH }}>
              <div style={{ position: 'absolute', left: 0, top: 9, width: 1, height: (lanes - p.lane) * laneH - 4, background: cwColor(theme, p.c.urgency), opacity: .35 }} />
              <div style={{ display: 'flex', alignItems: 'center', gap: 5, transform: 'translateX(-3px)', background: 'var(--panel)', padding: '1px 5px 1px 2px', borderRadius: 999, position: 'relative' }}>
                <span style={{ width: 8, height: 8, borderRadius: 4, background: cwColor(theme, p.c.urgency), boxShadow: `0 0 0 3px ${theme === 'dark' ? 'var(--panel)' : 'var(--panel)'}` }} />
                <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)', whiteSpace: 'nowrap' }}>{shortLabel(p.c)} {p.over ? '90+' : p.c.days + 'd'}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DirectionB({ initialTheme = 'dark' }) {
  const [theme, setTheme] = React.useState(initialTheme);
  const list = [...CERTS].sort((a, b) => a.days - b.days);
  return (
    <AppFrame theme={theme} setTheme={setTheme}>
      <div style={{ padding: '22px 26px' }}>
        <PageHead title="Dashboard" sub="Certificate expirations across all tracked hosts, plotted by urgency." />
        <StatRow />
        <TimelinePanel theme={theme} />

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, margin: '4px 2px 12px' }}>
          <span style={{ fontSize: 13, fontWeight: 600 }}>All certificates</span>
          <span style={{ fontSize: 12, color: 'var(--text-3)' }}>sorted by soonest expiry</span>
        </div>
        <div className="cw-panel" style={{ overflow: 'hidden' }}>
          <table className="cw-table">
            <thead>
              <tr>
                <th style={{ paddingTop: 14 }}>Certificate</th>
                <th>Issuer</th>
                <th>Source</th>
                <th>Expires</th>
                <th style={{ width: 120 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {list.map((c) => (
                <tr key={c.id}>
                  <td style={{ maxWidth: 340 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="cw-host">{c.cn}</span>
                      {c.isCa && <span className="cw-chip" style={{ color: 'var(--accent)', borderColor: 'var(--accent-line)' }}>CA</span>}
                    </div>
                    <SanChips sans={c.sans} max={2} />
                  </td>
                  <td><IssuerCell c={c} /></td>
                  <td><SourceBadge source={c.source} /></td>
                  <td style={{ minWidth: 140 }}>
                    <div className="mono" style={{ fontSize: 12.5, fontWeight: 500 }}>{c.expires}</div>
                    <div className="cw-sub" style={{ color: c.days < 0 ? 'var(--expired)' : c.days <= 7 ? 'var(--crit)' : 'var(--text-3)' }}>{c.rel}</div>
                  </td>
                  <td><StatusPill urgency={c.urgency} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppFrame>
  );
}

/* ============================================================= */
/* DIRECTION C — Urgency board                                    */
/* ============================================================= */
function CertCard({ c, theme }) {
  return (
    <div className="cw-panel" style={{ padding: '12px 13px', background: 'var(--panel-2)', cursor: 'pointer', transition: 'transform .12s, box-shadow .12s' }}
      onMouseEnter={(e) => { e.currentTarget.style.transform = 'translateY(-2px)'; e.currentTarget.style.boxShadow = 'var(--shadow)'; }}
      onMouseLeave={(e) => { e.currentTarget.style.transform = ''; e.currentTarget.style.boxShadow = ''; }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
        <span className="cw-host" style={{ fontSize: 13, lineHeight: 1.3 }}>{c.cn}</span>
        <span style={{ width: 8, height: 8, borderRadius: 4, flex: '0 0 auto', marginTop: 4, background: cwColor(theme, c.urgency) }} />
      </div>
      <div className="cw-sub mono" style={{ marginTop: 5 }}>{c.issuerOrg} · {c.issuerCa}</div>
      <div style={{ margin: '11px 0 8px', display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 12.5, fontWeight: 600, color: c.days < 0 ? 'var(--expired)' : c.days <= 7 ? 'var(--crit)' : c.days <= 14 ? 'var(--warn)' : 'var(--text-2)' }}>{c.rel}</span>
        <span className="mono cw-sub">{c.expires}</span>
      </div>
      <ExpiryBar days={c.days} urgency={c.urgency} theme={theme} />
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 11 }}>
        <SourceBadge source={c.source} />
        <ChainNote c={c} />
      </div>
    </div>
  );
}

function DirectionC({ initialTheme = 'dark' }) {
  const [theme, setTheme] = React.useState(initialTheme);
  const lanes = [
    { key: 'expired', title: 'Expired', icon: 'alert' },
    { key: 'critical', title: 'Critical', sub: '≤ 7 days', icon: 'alert' },
    { key: 'warning', title: 'Warning', sub: '≤ 14 days', icon: 'clock' },
    { key: 'healthy', title: 'Healthy', icon: 'checkCircle' },
  ];
  const byLane = (k) => [...CERTS].filter((c) => c.urgency === k).sort((a, b) => a.days - b.days);
  return (
    <AppFrame theme={theme} setTheme={setTheme}>
      <div style={{ padding: '22px 26px' }}>
        <PageHead title="Monitor" sub="Certificates grouped by how urgently they need attention." />
        <StatRow />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, alignItems: 'start' }}>
          {lanes.map((ln) => {
            const items = byLane(ln.key);
            return (
              <div key={ln.key}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '0 2px 12px' }}>
                  <span style={{ width: 9, height: 9, borderRadius: 5, background: cwColor(theme, ln.key) }} />
                  <span style={{ fontSize: 13.5, fontWeight: 600 }}>{ln.title}</span>
                  {ln.sub && <span style={{ fontSize: 11.5, color: 'var(--text-3)' }}>{ln.sub}</span>}
                  <span className="cw-spacer" />
                  <span className="mono" style={{ fontSize: 12, color: 'var(--text-2)', background: 'var(--inset)', border: '1px solid var(--border)', borderRadius: 6, padding: '1px 7px' }}>{items.length}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, minHeight: 80, background: 'var(--bg-soft)', border: '1px solid var(--border)', borderRadius: 12, padding: 10 }}>
                  {items.length ? items.map((c) => <CertCard key={c.id} c={c} theme={theme} />)
                    : <div style={{ padding: '22px 0', textAlign: 'center', fontSize: 12, color: 'var(--text-3)' }}>nothing here</div>}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </AppFrame>
  );
}

Object.assign(window, { DirectionA, DirectionB, DirectionC, AppFrame, PageHead, StatRow, IssuerCell, ChainNote, shortLabel });
