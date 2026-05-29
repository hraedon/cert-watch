/* cert-watch — certificate detail view (SANs + chain visualization).
   Uses the grafana cert (id 3) + window.CW.CHAIN_LE. */

const { Icon, StatusPill, SourceBadge, ExpiryBar, AppFrame, cwColor } = window;

function Field({ label, children, mono = true, span = 1 }) {
  return (
    <div style={{ gridColumn: `span ${span}` }}>
      <div style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 500, letterSpacing: '.03em', marginBottom: 5 }}>{label}</div>
      <div className={mono ? 'mono' : ''} style={{ fontSize: 12.5, color: 'var(--text)', lineHeight: 1.5, wordBreak: 'break-word' }}>{children}</div>
    </div>
  );
}

function ValidityMeter({ c, theme }) {
  const issued = window.CW.daysFromNow(c.issued);   // negative (past)
  const total = c.days - issued;                    // full validity in days
  const elapsed = -issued;
  const pct = Math.max(0, Math.min(100, (elapsed / total) * 100));
  const col = cwColor(theme, c.urgency);
  return (
    <div className="cw-panel" style={{ padding: '16px 18px', marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: 12 }}>
        <div>
          <div style={{ fontSize: 11, color: 'var(--text-3)', fontWeight: 500, marginBottom: 4 }}>TIME REMAINING</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
            <span style={{ fontSize: 30, fontWeight: 600, letterSpacing: '-1px', color: col }}>{c.days < 0 ? 'Expired' : c.days}</span>
            {c.days >= 0 && <span style={{ fontSize: 14, color: 'var(--text-2)' }}>days</span>}
          </div>
        </div>
        <StatusPill urgency={c.urgency} />
      </div>
      <div style={{ position: 'relative', height: 8, borderRadius: 5, background: 'var(--inset)', overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, width: `${pct}%`, background: `linear-gradient(90deg, ${cwColor(theme, 'healthy')}, ${col})`, borderRadius: 5 }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, fontSize: 11.5 }} className="mono">
        <span style={{ color: 'var(--text-3)' }}>{c.issued} · issued</span>
        <span style={{ color: 'var(--text-3)' }}>{c.expires} · expires</span>
      </div>
    </div>
  );
}

function ChainNode({ node, theme, isLast }) {
  const roleMap = {
    leaf: { t: 'Leaf · end-entity', c: 'var(--accent)' },
    intermediate: { t: 'Intermediate CA', c: 'var(--text-2)' },
    root: { t: 'Root CA', c: 'var(--text-2)' },
  };
  const r = roleMap[node.role];
  const u = node.days < 0 ? 'expired' : node.days <= 7 ? 'critical' : node.days <= 14 ? 'warning' : 'healthy';
  return (
    <div style={{ position: 'relative', paddingLeft: 30 }}>
      {/* connector */}
      <div style={{ position: 'absolute', left: 9, top: 6, width: 14, height: 14, borderRadius: '50%', border: `2px solid ${r.c}`, background: 'var(--panel)', zIndex: 2 }} />
      {!isLast && <div style={{ position: 'absolute', left: 15, top: 18, bottom: -14, width: 2, background: 'var(--border-2)' }} />}
      <div className="cw-panel" style={{ padding: '11px 13px', marginBottom: 14, background: 'var(--panel-2)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8 }}>
          <span className="cw-host" style={{ fontSize: 13 }}>{node.cn}</span>
          <span style={{ fontSize: 10.5, fontWeight: 600, color: r.c, textTransform: 'uppercase', letterSpacing: '.03em', whiteSpace: 'nowrap' }}>{r.t}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8, fontSize: 11.5 }}>
          <span className="cw-chip"><Icon name="key" size={11} sw={1.6} />{node.key}</span>
          <span className="mono" style={{ color: 'var(--text-3)' }}>exp {node.expires}</span>
          <span className="cw-spacer" />
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: cwColor(theme, u) }}>
            <span style={{ width: 6, height: 6, borderRadius: 3, background: cwColor(theme, u) }} />
            <span style={{ fontSize: 11.5, fontWeight: 500 }}>{node.days < 0 ? 'expired' : node.days + 'd'}</span>
          </span>
        </div>
      </div>
    </div>
  );
}

function NotesPanel() {
  const seed = 'Renewal: managed by cert-manager (ClusterIssuer letsencrypt-prod).\nIf auto-renew fails, check the Ingress annotation and re-run:\n  kubectl -n monitoring delete certificate grafana-tls\n\nOwner: platform-team · escalation: #infra-oncall';
  const [val, setVal] = React.useState(seed);
  const [editing, setEditing] = React.useState(false);
  return (
    <div className="cw-panel" style={{ padding: '15px 18px', marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <Icon name="file" size={15} style={{ color: 'var(--accent)' }} />
        <span style={{ fontSize: 13.5, fontWeight: 600 }}>Notes &amp; procedures</span>
        <span className="cw-spacer" />
        <button className="cw-btn ghost sm" onClick={() => setEditing((e) => !e)}>
          <Icon name={editing ? 'check' : 'key'} size={13} />{editing ? 'Save' : 'Edit'}
        </button>
      </div>
      {editing ? (
        <textarea
          autoFocus value={val} onChange={(e) => setVal(e.target.value)}
          spellCheck={false}
          style={{
            width: '100%', minHeight: 132, resize: 'vertical', fontFamily: 'var(--font-mono)',
            fontSize: 12.5, lineHeight: 1.6, color: 'var(--text)', background: 'var(--inset)',
            border: '1px solid var(--accent)', borderRadius: 9, padding: '11px 13px', outline: 'none',
            boxShadow: '0 0 0 3px var(--accent-soft)',
          }}
        />
      ) : (
        <pre
          onClick={() => setEditing(true)}
          className="mono"
          style={{
            margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word', cursor: 'text',
            fontSize: 12.5, lineHeight: 1.6, color: 'var(--text-2)', background: 'var(--inset)',
            border: '1px solid var(--border)', borderRadius: 9, padding: '11px 13px', minHeight: 60,
          }}
        >{val || 'Add a renewal procedure, automation runbook, or owner…'}</pre>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 9, fontSize: 11, color: 'var(--text-3)' }}>
        <Icon name="clock" size={11} sw={1.6} />
        <span>Markdown supported · saved to this certificate · last edited 2026-05-28</span>
      </div>
    </div>
  );
}

function buildChain(c) {
  if (c.id === 3) return window.CW.CHAIN_LE;
  if (c.isCa) return [{ role: 'root', cn: c.cn, issuer: c.cn, expires: c.expires, days: c.days, key: c.key }];
  const D = window.CW.daysFromNow;
  if (c.source === 'public') return [
    { role: 'leaf', cn: c.cn, issuer: c.issuerOrg, expires: c.expires, days: c.days, key: c.key },
    { role: 'intermediate', cn: c.issuerOrg, issuer: 'Apple Root CA - G3', expires: '2031-04-14', days: D('2031-04-14'), key: 'ECDSA P-384' },
    { role: 'root', cn: 'Apple Root CA - G3', issuer: 'Apple Root CA - G3', expires: '2039-04-30', days: D('2039-04-30'), key: 'ECDSA P-384' },
  ];
  // Let's Encrypt-style
  return [
    { role: 'leaf', cn: c.cn, issuer: "Let's Encrypt " + c.issuerCa, expires: c.expires, days: c.days, key: c.key },
    { role: 'intermediate', cn: c.issuerCa, issuer: 'ISRG Root X1', expires: '2027-03-12', days: D('2027-03-12'), key: 'RSA 2048' },
    { role: 'root', cn: 'ISRG Root X1', issuer: 'ISRG Root X1', expires: '2035-06-04', days: D('2035-06-04'), key: 'RSA 4096' },
  ];
}

function DetailBody({ c, theme, onBack }) {
  const chain = buildChain(c);
  return (
      <div style={{ padding: '20px 26px' }}>
        {/* breadcrumb */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12.5, color: 'var(--text-3)', marginBottom: 16 }}>
          <span className="cw-link" onClick={onBack}>Certificates</span>
          <Icon name="chevRight" size={13} />
          <span className="mono" style={{ color: 'var(--text-2)' }}>{c.cn}</span>
        </div>

        {/* header */}
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <h1 className="mono" style={{ margin: 0, fontSize: 22, fontWeight: 600, letterSpacing: '-.5px' }}>{c.cn}</h1>
              <StatusPill urgency={c.urgency} />
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 9 }}>
              <SourceBadge source={c.source} />
              <span style={{ fontSize: 12.5, color: 'var(--text-3)' }} className="mono">{c.source === 'scan' ? `scanned from ${c.host}:${c.port}` : c.source === 'upload' ? `uploaded · ${c.fileName}` : 'discovered via Certificate Transparency'}</span>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="cw-btn primary"><Icon name="refresh" size={14} />Scan now</button>
            <button className="cw-btn"><Icon name="download" size={14} />Download</button>
            <button className="cw-iconbtn"><Icon name="trash" size={15} /></button>
          </div>
        </div>

        {/* two columns */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 18, alignItems: 'start' }}>
          {/* LEFT */}
          <div>
            <ValidityMeter c={c} theme={theme} />

            {/* SANs — front and center, the previously-missing data */}
            <div className="cw-panel" style={{ padding: '15px 18px', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <Icon name="globe" size={15} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 13.5, fontWeight: 600 }}>Subject Alternative Names</span>
                <span className="mono" style={{ fontSize: 11.5, color: 'var(--text-3)', background: 'var(--inset)', borderRadius: 5, padding: '1px 6px' }}>{c.sans.length}</span>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 7 }}>
                {c.sans.map((s) => (
                  <span key={s} className="cw-chip san" style={{ fontSize: 12, padding: '4px 10px' }}>
                    <Icon name="globe" size={11} sw={1.5} style={{ opacity: .6 }} />{s}
                  </span>
                ))}
              </div>
            </div>

            {/* raw details — full DN lives HERE, not in the table */}
            <div className="cw-panel" style={{ padding: '16px 18px' }}>
              <div style={{ fontSize: 13.5, fontWeight: 600, marginBottom: 15 }}>Certificate details</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px 22px' }}>
                <Field label="SUBJECT" span={2}>{c.subjectDN}</Field>
                <Field label="ISSUER" span={2}>{c.issuerDN}</Field>
                <Field label="KEY">{c.key}</Field>
                <Field label="SIGNATURE">{c.sigAlg}</Field>
                <Field label="SERIAL NUMBER" span={2}>{c.serial}</Field>
                <Field label="SHA-256 FINGERPRINT" span={2}>{c.fp}</Field>
                <Field label="ISSUED">{c.issued}</Field>
                <Field label="LAST SCANNED">{c.lastScan}</Field>
              </div>
            </div>

            <NotesPanel />
          </div>

          {/* RIGHT — chain */}
          <div className="cw-panel" style={{ padding: '16px 18px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <Icon name="link" size={15} style={{ color: 'var(--accent)' }} />
              <span style={{ fontSize: 13.5, fontWeight: 600 }}>Certificate chain</span>
            </div>
            {chain.map((n, i) => <ChainNode key={i} node={n} theme={theme} isLast={i === chain.length - 1} />)}
            {c.chainComplete ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 4, padding: '9px 11px', borderRadius: 8, background: 'var(--ok-soft)', color: 'var(--ok)' }}>
                <Icon name="checkCircle" size={14} />
                <span style={{ fontSize: 12, fontWeight: 500 }}>Chain verified to trusted root</span>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginTop: 4, padding: '9px 11px', borderRadius: 8, background: 'var(--warn-soft)', color: 'var(--warn)' }}>
                <Icon name="alert" size={14} />
                <span style={{ fontSize: 12, fontWeight: 500 }}>Server did not send intermediate(s) — chain rebuilt from known CAs</span>
              </div>
            )}
          </div>
        </div>
      </div>
  );
}

function CertDetail({ initialTheme = 'dark' }) {
  const [theme, setTheme] = React.useState(initialTheme);
  const c = window.CW.CERTS.find((x) => x.id === 3);
  return (
    <AppFrame theme={theme} setTheme={setTheme}>
      <DetailBody c={c} theme={theme} />
    </AppFrame>
  );
}

Object.assign(window, { CertDetail, DetailBody, buildChain });
