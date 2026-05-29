/* cert-watch — full Direction A application shell.
   Working nav, theme toggle, row→detail, add-host slide-over,
   Alerts, Scan history, plus loading + empty states.
   Reuses window.CW data + cw-shared primitives + DetailBody. */

const { CERTS, ALERTS, SCANS, summary } = window.CW;
const {
  Icon, Wordmark, StatusPill, SourceBadge, SanChips, ExpiryBar, StatCard, ThemeToggle,
  cwColor, IssuerCell, ChainNote, StatRow, DetailBody,
} = window;

/* skeleton shimmer */
if (!document.getElementById('cw-app-styles')) {
  const s = document.createElement('style');
  s.id = 'cw-app-styles';
  s.textContent = `
  @keyframes cw-shimmer { 0% { background-position: -300px 0; } 100% { background-position: 300px 0; } }
  @keyframes cw-spin { to { transform: rotate(360deg); } }
  .cw .sk { border-radius: 6px; background: var(--panel-2); background-image: linear-gradient(90deg, transparent, var(--row-hover), transparent); background-size: 300px 100%; background-repeat: no-repeat; animation: cw-shimmer 1.2s infinite linear; }
  .cw-slide-bg { position: absolute; inset: 0; background: rgba(4,6,10,.55); backdrop-filter: blur(2px); opacity: 0; transition: opacity .22s; pointer-events: none; z-index: 40; }
  .cw-slide-bg.on { opacity: 1; pointer-events: auto; }
  .cw-slide { position: absolute; top: 0; right: 0; bottom: 0; width: 452px; max-width: 92vw; background: var(--panel); border-left: 1px solid var(--border); box-shadow: -16px 0 48px rgba(0,0,0,.4); transform: translateX(100%); transition: transform .26s cubic-bezier(.3,.8,.3,1); z-index: 41; display: flex; flex-direction: column; }
  .cw-slide.on { transform: translateX(0); }
  .cw-drop { border: 1.5px dashed var(--border-2); border-radius: 11px; padding: 26px 18px; text-align: center; background: var(--inset); transition: border-color .14s, background .14s; cursor: pointer; }
  .cw-drop:hover { border-color: var(--accent); background: var(--accent-soft); }
  `;
  document.head.appendChild(s);
}

/* ---------------- Topbar ---------------- */
function Topbar({ theme, setTheme, page, setPage, onAdd, unread }) {
  const tabs = [['dashboard', 'Dashboard'], ['alerts', 'Alerts'], ['scans', 'Scan history']];
  const cur = page === 'detail' ? 'dashboard' : page;
  return (
    <header className="cw-topbar">
      <div onClick={() => setPage('dashboard')} style={{ cursor: 'pointer' }}><Wordmark /></div>
      <nav className="cw-nav">
        {tabs.map(([k, l]) => (
          <a key={k} className={cur === k ? 'active' : ''} onClick={() => setPage(k)}>{l}</a>
        ))}
      </nav>
      <div className="cw-spacer" />
      <button className="cw-iconbtn" style={{ position: 'relative' }} title="Alerts" onClick={() => setPage('alerts')}>
        <Icon name="bell" size={16} />
        {unread > 0 && <span style={{ position: 'absolute', top: 4, right: 4, minWidth: 14, height: 14, padding: '0 3px', borderRadius: 7, background: 'var(--crit)', color: '#fff', fontSize: 9, fontWeight: 700, display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: '0 0 0 2px var(--panel)' }}>{unread}</span>}
      </button>
      <ThemeToggle theme={theme} onToggle={() => setTheme(theme === 'dark' ? 'light' : 'dark')} />
      <button className="cw-btn primary" onClick={onAdd}><Icon name="plus" size={15} sw={2} />Add host</button>
    </header>
  );
}

/* ---------------- Dashboard ---------------- */
function SkeletonRows() {
  return (
    <tbody>
      {Array.from({ length: 6 }).map((_, i) => (
        <tr key={i}>
          <td><div className="sk" style={{ height: 14, width: '60%' }} /><div className="sk" style={{ height: 10, width: '38%', marginTop: 8 }} /></td>
          <td><div className="sk" style={{ height: 12, width: 90 }} /><div className="sk" style={{ height: 9, width: 60, marginTop: 7 }} /></td>
          <td><div className="sk" style={{ height: 20, width: 80, borderRadius: 6 }} /></td>
          <td><div className="sk" style={{ height: 12, width: 80 }} /><div className="sk" style={{ height: 5, width: 120, marginTop: 9, borderRadius: 3 }} /></td>
          <td><div className="sk" style={{ height: 20, width: 70, borderRadius: 999 }} /></td>
          <td></td>
        </tr>
      ))}
    </tbody>
  );
}

function DashboardPage({ theme, loading, onOpen, scanning, onScan }) {
  const [filter, setFilter] = React.useState('all');
  const [q, setQ] = React.useState('');
  const [sort, setSort] = React.useState({ key: 'days', dir: 1 });
  const s = summary();
  const segs = [['all', 'All', s.total], ['expired', 'Expired', s.expired], ['critical', 'Critical', s.critical], ['warning', 'Warning', s.warning], ['healthy', 'Healthy', s.healthy]];

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
    <div style={{ padding: '22px 26px' }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 21, fontWeight: 600, letterSpacing: '-.4px' }}>Certificates</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>All tracked certificates from scanned hosts and uploaded files.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="cw-btn"><Icon name="download" size={14} />Export CSV</button>
          <button className="cw-btn"><Icon name="download" size={14} />Export JSON</button>
        </div>
      </div>

      <StatRow />

      <div className="cw-toolbar" style={{ marginBottom: 14 }}>
        <div className="cw-search"><Icon name="search" size={15} /><input className="cw-input" placeholder="Search subject, issuer, host…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <div className="cw-seg">{segs.map(([k, lab, n]) => <button key={k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>{lab}<span className="cnt">{n}</span></button>)}</div>
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
          {loading ? <SkeletonRows /> : (
            <tbody>
              {list.map((c) => (
                <tr key={c.id} style={{ cursor: 'pointer' }} onClick={() => onOpen(c)}>
                  <td style={{ maxWidth: 360 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="cw-host">{c.cn}</span>
                      {c.isCa && <span className="cw-chip" style={{ color: 'var(--accent)', borderColor: 'var(--accent-line)' }}>CA</span>}
                    </div>
                    <SanChips sans={c.sans} max={2} />
                  </td>
                  <td><IssuerCell c={c} /></td>
                  <td><div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}><SourceBadge source={c.source} /><ChainNote c={c} /></div></td>
                  <td style={{ minWidth: 150 }}>
                    <div className="mono" style={{ fontSize: 12.5, color: 'var(--text)', fontWeight: 500 }}>{c.expires}</div>
                    <div className="cw-sub" style={{ color: c.days < 0 ? 'var(--expired)' : c.days <= 7 ? 'var(--crit)' : 'var(--text-3)', marginBottom: 6 }}>{c.rel}</div>
                    <div style={{ width: 130 }}><ExpiryBar days={c.days} urgency={c.urgency} theme={theme} /></div>
                  </td>
                  <td><StatusPill urgency={c.urgency} /></td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <div className="cw-rowact">
                      <button className="cw-iconbtn" title="Scan now" style={{ width: 30, height: 30 }} onClick={() => onScan(c.id)}>
                        <Icon name="refresh" size={14} style={scanning === c.id ? { animation: 'cw-spin 0.8s linear infinite' } : null} />
                      </button>
                      <button className="cw-iconbtn" title="Details" style={{ width: 30, height: 30 }} onClick={() => onOpen(c)}><Icon name="chevRight" size={14} /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          )}
        </table>
        {!loading && list.length === 0 && (
          <div style={{ padding: '54px 0', textAlign: 'center' }}>
            <div style={{ width: 44, height: 44, borderRadius: 12, background: 'var(--inset)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-3)', marginBottom: 12 }}><Icon name="search" size={20} /></div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>No matching certificates</div>
            <div style={{ fontSize: 12.5, color: 'var(--text-3)', marginTop: 4 }}>Try a different search or filter.</div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------------- Alerts ---------------- */
function channelChip(ch) {
  return ch.map((c) => <span key={c} className="cw-chip"><Icon name={c === 'email' ? 'bell' : 'link'} size={11} sw={1.6} />{c}</span>);
}
function AlertsPage({ theme }) {
  const [filter, setFilter] = React.useState('all');
  const sevColor = (sev) => sev === 'error' ? 'var(--crit)' : sev === 'critical' ? 'var(--crit)' : sev === 'warning' ? 'var(--warn)' : 'var(--accent)';
  const tabs = [['all', 'All', ALERTS.length], ['unread', 'Unread', ALERTS.filter((a) => a.unread).length], ['critical', 'Critical', ALERTS.filter((a) => a.sev === 'critical' || a.sev === 'error').length]];
  const list = ALERTS.filter((a) => filter === 'all' || (filter === 'unread' ? a.unread : (a.sev === 'critical' || a.sev === 'error')));
  return (
    <div style={{ padding: '22px 26px', maxWidth: 1080 }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 21, fontWeight: 600, letterSpacing: '-.4px' }}>Alerts</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>Expiry &amp; scan notifications sent via email and webhook.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <span className="cw-chip" style={{ padding: '6px 10px' }}><Icon name="bell" size={12} />Email · 2 recipients</span>
          <span className="cw-chip" style={{ padding: '6px 10px' }}><Icon name="link" size={12} />Webhook · configured</span>
          <button className="cw-btn"><Icon name="key" size={14} />Alert settings</button>
        </div>
      </div>

      <div className="cw-seg" style={{ marginBottom: 14 }}>{tabs.map(([k, l, n]) => <button key={k} className={filter === k ? 'on' : ''} onClick={() => setFilter(k)}>{l}<span className="cnt">{n}</span></button>)}</div>

      {list.length === 0 ? (
        <div className="cw-panel" style={{ padding: '64px 0', textAlign: 'center' }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, background: 'var(--ok-soft)', color: 'var(--ok)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', marginBottom: 14 }}><Icon name="checkCircle" size={24} /></div>
          <div style={{ fontSize: 15, fontWeight: 600 }}>You're all caught up</div>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 5 }}>No alerts match this filter.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {list.map((a) => (
            <div key={a.id} className="cw-panel" style={{ padding: '14px 16px', display: 'flex', gap: 14, alignItems: 'center', borderLeft: `3px solid ${a.unread ? sevColor(a.sev) : 'transparent'}` }}>
              <div style={{ width: 34, height: 34, borderRadius: 9, flex: '0 0 auto', display: 'flex', alignItems: 'center', justifyContent: 'center', color: sevColor(a.sev), background: a.sev === 'warning' ? 'var(--warn-soft)' : a.sev === 'info' ? 'var(--accent-soft)' : 'var(--crit-soft)' }}>
                <Icon name={a.kind === 'scan-failed' ? 'server' : a.kind === 'expired' ? 'alert' : 'clock'} size={17} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
                  <span className="cw-host" style={{ fontSize: 13 }}>{a.cert}</span>
                  {a.unread && <span style={{ fontSize: 10, fontWeight: 700, color: sevColor(a.sev), background: 'var(--inset)', borderRadius: 5, padding: '1px 6px', textTransform: 'uppercase', letterSpacing: '.04em' }}>new</span>}
                </div>
                <div style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 3 }}>{a.msg}</div>
              </div>
              <div style={{ display: 'flex', gap: 5 }}>{channelChip(a.channel)}</div>
              <div style={{ textAlign: 'right', minWidth: 110 }}>
                <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, fontWeight: 500, color: a.status === 'sent' ? 'var(--ok)' : 'var(--warn)' }}>
                  <span style={{ width: 6, height: 6, borderRadius: 3, background: a.status === 'sent' ? 'var(--ok)' : 'var(--warn)' }} />{a.status}
                </div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 4 }}>{a.when}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ---------------- Scan history ---------------- */
function ScanHistoryPage({ theme, onScan, scanning }) {
  const resultPill = (r) => {
    const map = { ok: ['healthy', 'Success'], changed: ['warning', 'Cert changed'], failed: ['critical', 'Failed'] };
    const [u, l] = map[r];
    return <StatusPill urgency={u} label={l} />;
  };
  return (
    <div style={{ padding: '22px 26px', maxWidth: 1080 }}>
      <div style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', marginBottom: 18 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 21, fontWeight: 600, letterSpacing: '-.4px' }}>Scan history</h1>
          <div style={{ fontSize: 13, color: 'var(--text-3)', marginTop: 4 }}>TLS handshakes performed on tracked hosts, scheduled and on-demand.</div>
        </div>
        <button className="cw-btn primary" onClick={() => onScan('all')}><Icon name="refresh" size={14} style={scanning === 'all' ? { animation: 'cw-spin 0.8s linear infinite' } : null} />Run scan now</button>
      </div>

      <div className="cw-stats" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 18 }}>
        <StatCard tone="default" icon="clock" label="Last scan" value="3h ago" sub="2026-05-28 06:00 UTC · scheduled" />
        <StatCard tone="ok" icon="refresh" label="Next scheduled" value="06:00" sub="daily · UTC" />
        <StatCard tone="attention" icon="alert" label="Failures (7d)" value="2" sub="old-nas.hraedon.com · timeout" />
      </div>

      <div className="cw-panel" style={{ overflow: 'hidden' }}>
        <table className="cw-table">
          <thead>
            <tr>
              <th style={{ paddingTop: 14 }}>When</th><th>Trigger</th><th>Scope</th><th>Hosts</th><th>Result</th><th>Duration</th><th style={{ width: 60 }}></th>
            </tr>
          </thead>
          <tbody>
            {SCANS.map((s) => (
              <tr key={s.id}>
                <td className="mono" style={{ fontSize: 12.5, color: 'var(--text)' }}>{s.when}</td>
                <td><span className="cw-chip"><Icon name={s.trigger === 'scheduled' ? 'clock' : 'refresh'} size={11} sw={1.6} />{s.trigger}</span></td>
                <td className="mono" style={{ fontSize: 12.5, color: 'var(--text-2)' }}>{s.scope}</td>
                <td className="cw-num" style={{ fontSize: 12.5 }}>
                  <span style={{ color: 'var(--text)' }}>{s.ok}/{s.hosts}</span>
                  {s.failed > 0 && <span style={{ color: 'var(--crit)' }}> · {s.failed} failed</span>}
                  {s.changed > 0 && <span style={{ color: 'var(--warn)' }}> · {s.changed} changed</span>}
                </td>
                <td>{resultPill(s.result)}</td>
                <td className="cw-num" style={{ fontSize: 12.5, color: 'var(--text-2)' }}>{s.dur}</td>
                <td><button className="cw-iconbtn" style={{ width: 30, height: 30 }} title="View details"><Icon name="chevRight" size={14} /></button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ---------------- Add-host slide-over ---------------- */
function AddHostPanel({ open, onClose }) {
  const [tab, setTab] = React.useState('scan');
  const tabs = [['scan', 'Scan host', 'server'], ['upload', 'Upload file', 'file'], ['bulk', 'Bulk import', 'upload']];
  return (
    <React.Fragment>
      <div className={`cw-slide-bg ${open ? 'on' : ''}`} onClick={onClose} />
      <div className={`cw-slide ${open ? 'on' : ''}`}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 20px', borderBottom: '1px solid var(--border)' }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>Add certificates</div>
            <div style={{ fontSize: 12, color: 'var(--text-3)', marginTop: 2 }}>Scan a host, upload a file, or import in bulk.</div>
          </div>
          <button className="cw-iconbtn" onClick={onClose}><Icon name="x" size={16} /></button>
        </div>

        <div style={{ padding: '16px 20px 0' }}>
          <div className="cw-seg" style={{ width: '100%', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr' }}>
            {tabs.map(([k, l, ic]) => <button key={k} className={tab === k ? 'on' : ''} onClick={() => setTab(k)} style={{ justifyContent: 'center' }}><Icon name={ic} size={13} />{l}</button>)}
          </div>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '20px' }}>
          {tab === 'scan' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="cw-field"><label className="cw-label">Hostname</label><input className="cw-input mono" placeholder="example.com" /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="cw-field"><label className="cw-label">Port</label><input className="cw-input mono" defaultValue="443" /></div>
                <div className="cw-field"><label className="cw-label">Alert thresholds (days)</label><input className="cw-input mono" placeholder="14, 7, 3, 1" /></div>
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 13, color: 'var(--text-2)', cursor: 'pointer' }}><input type="checkbox" /> Scan common TLS ports (443, 8443, 993, 995…)</label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 9, fontSize: 13, color: 'var(--text-2)', cursor: 'pointer' }}><input type="checkbox" /> Verify certificate chain on scan</label>
            </div>
          )}
          {tab === 'upload' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="cw-drop">
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'var(--panel-2)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', marginBottom: 10 }}><Icon name="upload" size={18} /></div>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>Drop a certificate, or <span className="cw-link">browse</span></div>
                <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 6 }}>PEM · DER · CER · CRT · PKCS#12 · PKCS#7 · chain bundles</div>
              </div>
              <div className="cw-field"><label className="cw-label">Password <span style={{ color: 'var(--text-3)' }}>(PKCS#12 only, optional)</span></label><input className="cw-input" type="password" placeholder="optional" /></div>
            </div>
          )}
          {tab === 'bulk' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div className="cw-drop">
                <div style={{ width: 38, height: 38, borderRadius: 10, background: 'var(--panel-2)', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', marginBottom: 10 }}><Icon name="file" size={18} /></div>
                <div style={{ fontSize: 13.5, fontWeight: 600 }}>Drop a CSV, or <span className="cw-link">browse</span></div>
                <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 6 }}>Needs a <span className="mono">hostname</span> column · optional <span className="mono">port</span>, <span className="mono">threshold_days</span></div>
              </div>
              <div style={{ fontSize: 12.5, color: 'var(--text-2)', background: 'var(--inset)', border: '1px solid var(--border)', borderRadius: 9, padding: '11px 13px', lineHeight: 1.5 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 6, color: 'var(--text)' }}><Icon name="file" size={13} /><b style={{ fontWeight: 600 }}>Example</b></div>
                <code className="mono" style={{ fontSize: 11.5, color: 'var(--text-3)' }}>hostname,port,threshold_days<br />api.example.com,443,30<br />vpn.example.com,4443,14</code>
              </div>
              <span className="cw-link" style={{ fontSize: 12.5, display: 'inline-flex', alignItems: 'center', gap: 6 }}><Icon name="download" size={13} />Download CSV template</span>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', gap: 10, padding: '16px 20px', borderTop: '1px solid var(--border)' }}>
          <button className="cw-btn" style={{ flex: 1, justifyContent: 'center' }} onClick={onClose}>Cancel</button>
          <button className="cw-btn primary" style={{ flex: 1, justifyContent: 'center' }} onClick={onClose}>
            <Icon name={tab === 'scan' ? 'refresh' : tab === 'upload' ? 'upload' : 'plus'} size={14} />
            {tab === 'scan' ? 'Add & scan' : tab === 'upload' ? 'Upload' : 'Import'}
          </button>
        </div>
      </div>
    </React.Fragment>
  );
}

/* ---------------- App shell ---------------- */
function CertWatchApp({ initialTheme = 'dark' }) {
  const [theme, setTheme] = React.useState(initialTheme);
  const [page, setPage] = React.useState('dashboard');
  const [sel, setSel] = React.useState(null);
  const [addOpen, setAddOpen] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [scanning, setScanning] = React.useState(null);
  const unread = ALERTS.filter((a) => a.unread).length;

  React.useEffect(() => { const t = setTimeout(() => setLoading(false), 950); return () => clearTimeout(t); }, []);
  const onScan = (id) => { setScanning(id); setTimeout(() => setScanning(null), 1400); };
  const openDetail = (c) => { setSel(c); setPage('detail'); };

  return (
    <div className={`cw cw-${theme}`} style={{ position: 'relative' }}>
      <div className="cw-app">
        <Topbar theme={theme} setTheme={setTheme} page={page} setPage={setPage} onAdd={() => setAddOpen(true)} unread={unread} />
        <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
          {page === 'dashboard' && <DashboardPage theme={theme} loading={loading} onOpen={openDetail} scanning={scanning} onScan={onScan} />}
          {page === 'alerts' && <AlertsPage theme={theme} />}
          {page === 'scans' && <ScanHistoryPage theme={theme} onScan={onScan} scanning={scanning} />}
          {page === 'detail' && sel && <DetailBody c={sel} theme={theme} onBack={() => setPage('dashboard')} />}
        </div>
      </div>
      <AddHostPanel open={addOpen} onClose={() => setAddOpen(false)} />
    </div>
  );
}

Object.assign(window, { CertWatchApp });
