/* Settings-section behavior (auth + channels pages).
 *
 * Loaded only by settings/auth.html and settings/channels.html; every binding
 * is existence-guarded so the one file serves both pages. ES5, CSP-nonce'd,
 * no inline handlers. */
(function () {
  'use strict';

  function byId(id) { return document.getElementById(id); }

  // CSRF token for the async test endpoints — read from any rendered form.
  function csrfToken() {
    var el = document.querySelector('input[name="_csrf_token"]');
    return el ? el.value : '';
  }

  // Parse a test-endpoint response defensively. The handlers normally return
  // JSON, but an unexpected 500 yields a plain-text body ("Internal Server
  // Error") that JSON.parse() would choke on, surfacing a cryptic
  // "Unexpected token 'I'" instead of a usable message. Fall back to a
  // readable error keyed on the HTTP status.
  function parseTestResponse(r) {
    return r.text().then(function (t) {
      try {
        return JSON.parse(t);
      } catch (e) {
        return { ok: false, error: 'Server error (HTTP ' + r.status + ')' };
      }
    });
  }

  function setResult(el, ok, text) {
    el.className = 'cw-testres ' + (ok ? 't-ok' : 't-crit');
    el.textContent = text;
  }

  /* ---------- Auth page: provider toggle ---------- */

  var providerSelect = byId('auth_provider');

  function toggleProvider() {
    var provider = providerSelect.value;
    byId('ldap-section').classList.toggle('cw-hidden', provider !== 'ldap');
    byId('oauth-section').classList.toggle('cw-hidden', provider !== 'oauth');
  }

  if (providerSelect) {
    toggleProvider();
    providerSelect.addEventListener('change', toggleProvider);
  }

  /* ---------- Auth page: LDAP test + TOFU CA pinning ---------- */

  var capturedLdapCaPem = '';

  // One TOFU chain entry, built with DOM nodes (never innerHTML) so untrusted
  // subject/issuer strings cannot inject markup.
  function tofuCertNode(cert) {
    var wrap = document.createElement('div');
    wrap.className = 'cw-note';
    var body = document.createElement('div');
    var subject = document.createElement('div');
    subject.className = 'cw-id';
    subject.textContent = cert.subject;
    var issuer = document.createElement('div');
    issuer.className = 'cw-hint';
    issuer.textContent = 'Issuer: ' + cert.issuer;
    var sha = document.createElement('div');
    sha.className = 'cw-hint mono';
    sha.textContent = 'SHA-256: ' + cert.sha256;
    body.appendChild(subject);
    body.appendChild(issuer);
    body.appendChild(sha);
    wrap.appendChild(body);
    return wrap;
  }

  function testLdap(btn) {
    var result = byId('ldap-test-result');
    var tofuPanel = byId('ldap-tofu-panel');
    var tofuChain = byId('ldap-tofu-chain');
    btn.disabled = true;
    btn.textContent = 'Testing...';
    result.className = 'cw-testres';
    result.textContent = '';
    tofuPanel.classList.add('cw-hidden');
    while (tofuChain.firstChild) { tofuChain.removeChild(tofuChain.firstChild); }
    capturedLdapCaPem = '';

    var form = new FormData();
    form.append('_csrf_token', csrfToken());
    form.append('ldap_server', byId('ldap_server').value);
    form.append('ldap_base_dn', byId('ldap_base_dn').value);
    form.append('ldap_bind_dn', byId('ldap_bind_dn').value);
    form.append('ldap_bind_password', byId('ldap_bind_password').value);
    form.append('ldap_start_tls', byId('ldap_start_tls').value);
    form.append('ldap_ca_cert', byId('ldap_ca_cert').value);
    form.append('ldap_connect_timeout', byId('ldap_connect_timeout').value);

    fetch('/settings/test-ldap', { method: 'POST', body: form })
      .then(parseTestResponse)
      .then(function (data) {
        if (data.tofu) {
          capturedLdapCaPem = data.tofu.pem;
          data.tofu.chain.forEach(function (cert) {
            tofuChain.appendChild(tofuCertNode(cert));
          });
          tofuPanel.classList.remove('cw-hidden');
          setResult(result, false, 'Error: ' + data.error);
        } else {
          setResult(result, data.ok, data.ok ? data.message : 'Error: ' + data.error);
        }
      })
      .catch(function (e) {
        setResult(result, false, 'Request failed: ' + e);
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = 'Test Connection';
      });
  }

  function pinLdapCa(btn) {
    if (!capturedLdapCaPem) return;
    var result = byId('ldap-test-result');
    btn.disabled = true;
    var form = new FormData();
    form.append('_csrf_token', csrfToken());
    form.append('ldap_ca_cert', capturedLdapCaPem);
    fetch('/settings/pin-ldap-ca', { method: 'POST', body: form })
      .then(parseTestResponse)
      .then(function (data) {
        if (data.ok) {
          byId('ldap_ca_cert').value = capturedLdapCaPem;
          byId('ldap-tofu-panel').classList.add('cw-hidden');
        }
        setResult(result, data.ok, data.ok ? data.message : 'Error: ' + data.error);
      })
      .catch(function (e) {
        setResult(result, false, 'Request failed: ' + e);
      })
      .finally(function () {
        btn.disabled = false;
      });
  }

  function copyLdapCa() {
    if (!capturedLdapCaPem) return;
    var done = function () {
      setResult(byId('ldap-test-result'), true, 'PEM copied to clipboard');
    };
    if (navigator.clipboard) {
      navigator.clipboard.writeText(capturedLdapCaPem).then(done);
    } else {
      var ta = document.createElement('textarea');
      ta.value = capturedLdapCaPem;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      done();
    }
  }

  var ldapTestBtn = byId('ldap-test-btn');
  if (ldapTestBtn) {
    ldapTestBtn.addEventListener('click', function (e) {
      e.preventDefault();
      testLdap(e.currentTarget);
    });
  }
  var ldapPinBtn = byId('ldap-pin-btn');
  if (ldapPinBtn) {
    ldapPinBtn.addEventListener('click', function (e) {
      e.preventDefault();
      pinLdapCa(e.currentTarget);
    });
  }
  var ldapCopyBtn = byId('ldap-copy-btn');
  if (ldapCopyBtn) {
    ldapCopyBtn.addEventListener('click', function (e) {
      e.preventDefault();
      copyLdapCa();
    });
  }

  /* ---------- Channels page: SMTP test ---------- */

  function testSmtp(btn) {
    var result = byId('smtp-test-result');
    btn.disabled = true;
    btn.textContent = 'Sending...';
    result.className = 'cw-testres';
    result.textContent = '';

    var form = new FormData();
    form.append('_csrf_token', csrfToken());
    form.append('smtp_host', byId('smtp_host').value);
    form.append('smtp_port', byId('smtp_port').value);
    form.append('smtp_user', byId('smtp_user').value);
    form.append('smtp_password', byId('smtp_password').value);
    form.append('alert_from', byId('alert_from').value);
    form.append('alert_recipients', byId('alert_recipients').value);

    fetch('/settings/test-smtp', { method: 'POST', body: form })
      .then(parseTestResponse)
      .then(function (data) {
        setResult(result, data.ok, data.ok ? data.message : 'Error: ' + data.error);
      })
      .catch(function (e) {
        setResult(result, false, 'Request failed: ' + e);
      })
      .finally(function () {
        btn.disabled = false;
        btn.textContent = 'Send test email';
      });
  }

  var smtpTestBtn = byId('smtp-test-btn');
  if (smtpTestBtn) {
    smtpTestBtn.addEventListener('click', function (e) {
      e.preventDefault();
      testSmtp(e.currentTarget);
    });
  }

  /* ---------- Channels page: webhook presets ---------- */

  var WEBHOOK_PRESETS = {
    slack: {
      kind: 'slack',
      url: '',
      template: '{"text": "Certificate alert: {{subject}} ({{host}}) expires in {{days_remaining}} days — grade {{grade}}"}'
    },
    teams: {
      kind: 'teams',
      url: '',
      template: '{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {"type": "AdaptiveCard", "body": [{"type": "TextBlock", "text": "Certificate alert: {{subject}} ({{host}}) expires in {{days_remaining}} days — grade {{grade}}", "weight": "bolder"}], "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "version": "1.0"}}]}'
    },
    pagerduty: {
      kind: 'pagerduty',
      url: '',
      template: '{"routing_key": "YOUR_ROUTING_KEY", "event_action": "trigger", "payload": {"summary": "Certificate alert: {{subject}} ({{host}}) expires in {{days_remaining}} days", "severity": "warning", "source": "cert-watch"}}'
    },
    alertmanager: {
      kind: 'generic',
      url: '',
      template: '[{"labels": {"alertname": "CertificateExpiry", "host": "{{host}}", "subject": "{{subject}}"}, "annotations": {"summary": "Certificate expires in {{days_remaining}} days", "grade": "{{grade}}"}}]'
    }
  };

  function templateMatchesAnyPreset(text) {
    for (var k in WEBHOOK_PRESETS) {
      if (WEBHOOK_PRESETS[k].template === text) { return true; }
    }
    return false;
  }

  function applyWebhookPreset(preset) {
    var kindEl = byId('webhook_kind');
    var urlEl = byId('webhook_url');
    var ta = byId('webhook_template');
    var cfg = WEBHOOK_PRESETS[preset];
    // Switching presets should replace the template. Only guard a template the
    // user hand-wrote (one that does not match any known preset) so an
    // accidental dropdown change cannot silently discard real work.
    var cur = ta.value.trim();
    if (cur && !templateMatchesAnyPreset(ta.value) &&
        !confirm('Replace the current webhook template with the selected preset?')) {
      return;
    }
    if (!cfg) {
      kindEl.value = preset;
      urlEl.placeholder = 'https://...';
      ta.value = '';
      return;
    }
    kindEl.value = cfg.kind;
    urlEl.placeholder = cfg.url || 'https://...';
    ta.value = cfg.template;
  }

  var presetSelect = byId('webhook_preset');
  if (presetSelect) {
    presetSelect.addEventListener('change', function () {
      applyWebhookPreset(this.value);
    });
  }
})();
