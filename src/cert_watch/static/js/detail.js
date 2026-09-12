/* Certificate detail — on-demand OCSP/CRL endpoint reachability. */
(function () {
  'use strict';
  var btn = document.getElementById('check-revocation');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var certId = btn.getAttribute('data-cert-id');
    var status = document.getElementById('revocation-status');
    var results = document.getElementById('revocation-results');
    if (!certId || !status || !results) return;
    status.textContent = 'Checking…';
    fetch('/api/certificates/' + encodeURIComponent(certId) + '/revocation')
      .then(function (r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
      .then(function (data) {
        status.textContent = '';
        results.textContent = '';
        results.classList.remove('cw-hidden');
        (data.findings || []).forEach(function (f) {
          var row = document.createElement('div');
          row.className = 'cw-finding';
          var icon = document.createElement('span');
          icon.className = f.status === 'pass' ? 't-ok' : f.status === 'warn' ? 't-warn' : 'cw-muted';
          icon.textContent = f.status === 'pass' ? '✓' : f.status === 'warn' ? '⚠' : '—';
          var msg = document.createElement('span');
          msg.textContent = f.message || '';
          row.appendChild(icon);
          row.appendChild(msg);
          results.appendChild(row);
        });
      })
      .catch(function () {
        status.textContent = 'Failed to check endpoint reachability';
        results.classList.add('cw-hidden');
      });
  });
})();
