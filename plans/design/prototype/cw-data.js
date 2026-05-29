/* cert-watch sample data + helpers — plain JS, attaches to window.
   "Now" is pinned to 2026-05-28 to match the source screenshot. */
(function () {
  const NOW = new Date('2026-05-28T12:00:00Z');

  function daysFromNow(dateStr) {
    const d = new Date(dateStr + 'T12:00:00Z');
    return Math.round((d - NOW) / 86400000);
  }

  // Urgency buckets mirror the app's per-host thresholds (14/7/3/1).
  // expired < 0 ; critical <= 7 ; warning <= 14 ; healthy otherwise.
  function urgency(days) {
    if (days < 0) return 'expired';
    if (days <= 7) return 'critical';
    if (days <= 14) return 'warning';
    return 'healthy';
  }

  // Human "in 27 days" / "3 days ago" / "in 2 months".
  function relExpiry(days) {
    if (days === 0) return 'today';
    if (days < 0) {
      const a = -days;
      return a === 1 ? '1 day ago' : `${a} days ago`;
    }
    if (days < 45) return `in ${days} day${days === 1 ? '' : 's'}`;
    if (days < 365) return `in ${Math.round(days / 30)} months`;
    const y = (days / 365);
    return `in ${y.toFixed(y < 2 ? 1 : 0)} year${y >= 2 ? 's' : ''}`;
  }

  // source: 'scan' (TLS handshake), 'upload' (file), 'public' (CT lookup)
  const RAW = [
    {
      id: 1, source: 'scan', host: 'vault.k8s.hraedon.com', port: 443,
      cn: 'vault.k8s.hraedon.com',
      sans: ['vault.k8s.hraedon.com', 'vault.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R10',
      issuerDN: "CN=R10,O=Let's Encrypt,C=US",
      subjectDN: 'CN=vault.k8s.hraedon.com',
      issued: '2026-02-23', lastScan: '2026-05-28', expires: '2026-05-25',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '04:A1:9F:2C:88:1B:E3:77:0D:55:AC:91:6E:42:F0:B8',
      fp: 'C1:7A:42:9E:0B:F5:38:AA:91:6D:2C:E4:77:80:1F:B3:5A:90:CC:12',
      chainComplete: true,
    },
    {
      id: 2, source: 'scan', host: 'registry.k8s.hraedon.com', port: 443,
      cn: 'registry.k8s.hraedon.com',
      sans: ['registry.k8s.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R11',
      issuerDN: "CN=R11,O=Let's Encrypt,C=US",
      subjectDN: 'CN=registry.k8s.hraedon.com',
      issued: '2026-03-01', lastScan: '2026-05-28', expires: '2026-06-01',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '03:5B:71:9A:42:CC:18:0E:F7:21:64:9D:B0:3A:77:1C',
      fp: '88:0C:51:A2:6F:90:34:DE:7B:11:F2:88:4A:0C:99:E1:2D:74:B6:03',
      chainComplete: true,
    },
    {
      id: 3, source: 'scan', host: 'grafana.hraedon.com', port: 443,
      cn: 'grafana.hraedon.com',
      sans: ['grafana.hraedon.com', 'metrics.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R11',
      issuerDN: "CN=R11,O=Let's Encrypt,C=US",
      subjectDN: 'CN=grafana.hraedon.com',
      issued: '2026-03-04', lastScan: '2026-05-28', expires: '2026-06-03',
      key: 'RSA 2048', sigAlg: 'sha256WithRSAEncryption',
      serial: '06:E2:14:7B:3C:91:5A:0D:88:42:1F:6C:99:B7:20:E4',
      fp: '5F:91:2C:7A:44:E0:18:BB:6D:90:3A:F1:2C:88:0E:55:71:9A:C4:30',
      chainComplete: true,
    },
    {
      id: 4, source: 'scan', host: 'mail.hraedon.com', port: 443,
      cn: 'mail.hraedon.com',
      sans: ['mail.hraedon.com', 'smtp.hraedon.com', 'imap.hraedon.com', 'autodiscover.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R12',
      issuerDN: "CN=R12,O=Let's Encrypt,C=US",
      subjectDN: 'CN=mail.hraedon.com',
      issued: '2026-03-08', lastScan: '2026-05-28', expires: '2026-06-06',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '07:14:9C:2A:55:E1:0B:7D:33:90:6F:1C:A2:48:B0:77',
      fp: '2A:6C:90:14:7F:E3:55:0B:91:2D:8A:F0:1C:44:77:90:6E:33:B1:08',
      chainComplete: true,
    },
    {
      id: 5, source: 'scan', host: 'hraedon.com', port: 443,
      cn: '*.hraedon.com',
      sans: ['*.hraedon.com', 'hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R12',
      issuerDN: "CN=R12,O=Let's Encrypt,C=US",
      subjectDN: 'CN=*.hraedon.com',
      issued: '2026-03-27', lastScan: '2026-05-28', expires: '2026-06-10',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '05:3A:88:1C:90:4B:E2:77:0D:6F:21:AC:55:90:1B:E4',
      fp: 'A1:5F:90:2C:7B:E0:44:18:6D:90:3A:F1:2C:88:0E:55:71:9A:C4:31',
      chainComplete: false,
    },
    {
      id: 6, source: 'public', host: 'apple.com', port: 443,
      cn: 'apple.com', org: 'Apple Inc.', ev: true,
      sans: ['apple.com', 'www.apple.com'],
      issuerOrg: 'Apple Public EV Server ECC CA 1 - G1', issuerCa: 'G1',
      issuerDN: 'CN=Apple Public EV Server ECC CA 1 - G1,O=Apple Inc.,C=US',
      subjectDN: 'CN=apple.com,O=Apple Inc.,L=Cupertino,ST=California,C=US',
      issued: '2026-04-23', lastScan: '2026-05-28', expires: '2026-07-16',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '0C:08:06:59:2A:1B:3C:6E:90:44:7F:E1:2D:88:0B:55',
      fp: '4E:90:2C:7A:55:E1:0B:88:6D:91:3A:F0:1C:44:77:90:6E:33:B1:0C',
      chainComplete: true,
    },
    {
      id: 7, source: 'scan', host: 'argocd.k8s.hraedon.com', port: 443,
      cn: 'argocd.k8s.hraedon.com',
      sans: ['argocd.k8s.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R13',
      issuerDN: "CN=R13,O=Let's Encrypt,C=US",
      subjectDN: 'CN=argocd.k8s.hraedon.com',
      issued: '2026-05-08', lastScan: '2026-05-28', expires: '2026-08-08',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '08:71:2C:9A:44:E0:1B:55:90:6D:3A:F1:2C:88:0E:77',
      fp: '6D:90:3A:F1:2C:88:0E:55:71:9A:C4:30:4E:90:2C:7A:55:E1:0B:88',
      chainComplete: false,
    },
    {
      id: 8, source: 'scan', host: 'cert-watch.k8s.hraedon.com', port: 443,
      cn: 'cert-watch.k8s.hraedon.com',
      sans: ['cert-watch.k8s.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R13',
      issuerDN: "CN=R13,O=Let's Encrypt,C=US",
      subjectDN: 'CN=cert-watch.k8s.hraedon.com',
      issued: '2026-05-27', lastScan: '2026-05-28', expires: '2026-08-25',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '09:6F:21:AC:55:90:1B:E4:05:3A:88:1C:90:4B:E2:77',
      fp: 'F1:2C:88:0E:55:71:9A:C4:30:4E:90:2C:7A:55:E1:0B:88:6D:91:3A',
      chainComplete: false,
    },
    {
      id: 9, source: 'scan', host: 'longhorn.k8s.hraedon.com', port: 443,
      cn: 'longhorn.k8s.hraedon.com',
      sans: ['longhorn.k8s.hraedon.com'],
      issuerOrg: "Let's Encrypt", issuerCa: 'R12',
      issuerDN: "CN=R12,O=Let's Encrypt,C=US",
      subjectDN: 'CN=longhorn.k8s.hraedon.com',
      issued: '2026-04-24', lastScan: '2026-05-28', expires: '2026-07-23',
      key: 'ECDSA P-256', sigAlg: 'ecdsa-with-SHA384',
      serial: '0A:55:90:1B:E4:05:3A:88:1C:90:4B:E2:77:0D:6F:21',
      fp: '0E:55:71:9A:C4:30:4E:90:2C:7A:55:E1:0B:88:6D:91:3A:F0:1C:44',
      chainComplete: false,
    },
    {
      id: 10, source: 'upload', host: null, fileName: 'hraedon-root-ca.pem',
      cn: 'Hraedon Internal Root CA', isCa: true,
      sans: [],
      issuerOrg: 'Hraedon Internal Root CA', issuerCa: 'self-signed',
      issuerDN: 'CN=Hraedon Internal Root CA,O=Hraedon Labs,C=US',
      subjectDN: 'CN=Hraedon Internal Root CA,O=Hraedon Labs,C=US',
      issued: '2024-01-15', lastScan: '2026-05-28', expires: '2029-01-13',
      key: 'RSA 4096', sigAlg: 'sha384WithRSAEncryption',
      serial: '01',
      fp: '9A:C4:30:4E:90:2C:7A:55:E1:0B:88:6D:91:3A:F0:1C:44:77:90:6E',
      chainComplete: true,
    },
  ];

  const CERTS = RAW.map((c) => {
    const days = daysFromNow(c.expires);
    return { ...c, days, urgency: urgency(days), rel: relExpiry(days) };
  });

  // Chain for the detail view (leaf -> intermediate -> root).
  const CHAIN_LE = [
    { role: 'leaf', cn: 'grafana.hraedon.com', issuer: "Let's Encrypt R11", expires: '2026-06-03', days: daysFromNow('2026-06-03'), key: 'RSA 2048' },
    { role: 'intermediate', cn: "R11", issuer: 'ISRG Root X1', expires: '2027-03-12', days: daysFromNow('2027-03-12'), key: 'RSA 2048' },
    { role: 'root', cn: 'ISRG Root X1', issuer: 'ISRG Root X1', expires: '2035-06-04', days: daysFromNow('2035-06-04'), key: 'RSA 4096' },
  ];

  function summary() {
    const s = { total: CERTS.length, expired: 0, critical: 0, warning: 0, healthy: 0, hosts: 0, scanFails: 0 };
    const hosts = new Set();
    CERTS.forEach((c) => {
      s[c.urgency] += 1;
      if (c.host) hosts.add(c.host);
      if (!c.chainComplete && c.source === 'scan') s.scanFails += 0; // chain-incomplete is a note, not a failure
    });
    s.hosts = hosts.size;
    s.attention = s.expired + s.critical + s.warning;
    return s;
  }

  // ---- alerts ----
  const ALERTS = [
    { id: 'a1', sev: 'critical', kind: 'expired', cert: 'vault.k8s.hraedon.com', msg: 'Certificate has expired', channel: ['email'], status: 'sent', when: '2026-05-25 06:00', unread: true },
    { id: 'a2', sev: 'critical', kind: 'expiring', cert: 'registry.k8s.hraedon.com', msg: 'Expires in 4 days (≤ 7d threshold)', channel: ['email', 'webhook'], status: 'sent', when: '2026-05-28 06:00', unread: true },
    { id: 'a3', sev: 'critical', kind: 'expiring', cert: 'grafana.hraedon.com', msg: 'Expires in 6 days (≤ 7d threshold)', channel: ['email', 'webhook'], status: 'sent', when: '2026-05-28 06:00', unread: true },
    { id: 'a4', sev: 'warning', kind: 'expiring', cert: 'mail.hraedon.com', msg: 'Expires in 9 days (≤ 14d threshold)', channel: ['email'], status: 'pending', when: '2026-05-28 06:00', unread: false },
    { id: 'a5', sev: 'warning', kind: 'expiring', cert: '*.hraedon.com', msg: 'Expires in 13 days (≤ 14d threshold)', channel: ['email'], status: 'sent', when: '2026-05-28 06:00', unread: false },
    { id: 'a6', sev: 'error', kind: 'scan-failed', cert: 'old-nas.hraedon.com:443', msg: 'Scan failed — connection timed out', channel: ['email'], status: 'sent', when: '2026-05-27 06:01', unread: false },
  ];

  // ---- scan history ----
  const SCANS = [
    { id: 's1', when: '2026-05-28 06:00', trigger: 'scheduled', scope: 'All hosts', hosts: 9, ok: 9, failed: 0, changed: 1, dur: '14.2s', result: 'ok' },
    { id: 's2', when: '2026-05-28 09:12', trigger: 'manual', scope: 'grafana.hraedon.com', hosts: 1, ok: 1, failed: 0, changed: 1, dur: '0.8s', result: 'changed' },
    { id: 's3', when: '2026-05-27 06:00', trigger: 'scheduled', scope: 'All hosts', hosts: 9, ok: 8, failed: 1, changed: 0, dur: '38.6s', result: 'failed' },
    { id: 's4', when: '2026-05-26 14:31', trigger: 'manual', scope: 'old-nas.hraedon.com', hosts: 1, ok: 0, failed: 1, changed: 0, dur: '30.0s', result: 'failed' },
    { id: 's5', when: '2026-05-26 06:00', trigger: 'scheduled', scope: 'All hosts', hosts: 9, ok: 9, failed: 0, changed: 0, dur: '12.9s', result: 'ok' },
    { id: 's6', when: '2026-05-25 06:00', trigger: 'scheduled', scope: 'All hosts', hosts: 9, ok: 9, failed: 0, changed: 2, dur: '15.4s', result: 'changed' },
  ];

  window.CW = {
    NOW, CERTS, CHAIN_LE, ALERTS, SCANS, summary, daysFromNow, urgency, relExpiry,
    // Source labels
    sourceLabel: { scan: 'Scanned', upload: 'Uploaded', public: 'Public CT' },
  };
})();
