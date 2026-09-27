/* Certificates page — pivot lazy-loading (BC-048).
 * Inline host-note editing was removed (UI-INVENTORY V2): the single notes
 * editing surface is the Notes panel on the endpoint detail page. */
(function () {
  'use strict';

  /* ---- pivot group lazy expansion (BC-048) ----
   * The expansion row itself is toggled by core.js via data-expand;
   * this hook fills it with fetched entries on first open.          */
  function textSpan(className, value) {
    var span = document.createElement('span');
    span.className = className;
    span.textContent = value;
    return span;
  }

  function conditionDisplay(entry) {
    var status = entry.status || {};
    var condition = status.condition || {};
    var state = condition.state || entry.condition;
    var days = condition.effective_days;
    if (days == null) days = entry.effective_days;
    if (state == null || days == null) return { label: 'No certificate', tone: 't-muted' };
    if (state === 'expired') {
      var ago = Math.abs(days);
      return { label: 'Expired ' + ago + ' day' + (ago === 1 ? '' : 's') + ' ago', tone: 't-expired' };
    }
    if (days === 0) return { label: 'Expires today', tone: 't-crit' };
    return {
      label: days + ' day' + (days === 1 ? '' : 's') + ' left',
      tone: { le7: 't-crit', '8to30': 't-warn', ok: 't-ok' }[state] || 't-muted'
    };
  }

  function utcLabel(value) {
    if (!value) return '';
    var date = new Date(value);
    if (isNaN(date.getTime())) return '';
    return date.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }

  function addFact(flags, label, tone) {
    if (!label) return;
    flags.appendChild(textSpan('cw-chip ' + tone, label));
  }

  function factFlags(entry) {
    var flags = document.createElement('div');
    flags.className = 'cw-fact-flags';
    var status = entry.status || {};
    var monitoring = status.monitoring || {};
    var monitoringState = monitoring.state || entry.monitoring;
    var monitoringLabel = '';
    if (monitoringState === 'never_scanned') monitoringLabel = 'Never scanned';
    if (monitoringState === 'failing') {
      if (entry.monitoring_attempt_status === 'success' && !monitoring.raw_error) {
        monitoringLabel = 'Monitoring overdue';
      } else {
        var since = utcLabel(monitoring.since);
        monitoringLabel = since ? 'Failing since ' + since : 'Monitoring failing';
      }
    }
    addFact(flags, monitoringLabel, 't-warn');
    if (status.chain_trust_problem) {
      addFact(flags, {
        incomplete: 'Chain incomplete', invalid: 'Chain invalid',
        unknown: 'Chain not verified', unverified: 'Chain not verified',
        'self-signed': 'Self-signed chain'
      }[status.chain_status || entry.chain_status] || 'Chain problem', 't-warn');
    }
    var renewal = (status.renewal || {}).state || entry.renewal;
    addFact(flags, { stalled: 'Renewal stalled', in_progress: 'Renewal in progress' }[renewal],
      renewal === 'stalled' ? 't-warn' : 't-ink');
    var delivery = (status.delivery || {}).state || entry.delivery;
    addFact(flags, { failing: "Can't be delivered", unrouted: 'Unrouted' }[delivery],
      delivery === 'failing' ? 't-crit' : 't-muted');
    if (!flags.children.length) flags.appendChild(textSpan('cw-sr', 'No exceptions'));
    return flags;
  }

  document.addEventListener('click', function (e) {
    var trigger = e.target.closest('[data-expand^="pivot-detail-"]');
    if (!trigger) return;
    var row = document.getElementById(trigger.getAttribute('data-expand'));
    if (!row || row.getAttribute('data-loaded') === '1' || row.classList.contains('cw-hidden')) return;
    row.setAttribute('data-loaded', '1');
    var cell = row.querySelector('td');
    var pivot = row.getAttribute('data-pivot');
    var key = row.getAttribute('data-group-key');
    cell.textContent = 'Loading…';

    function entryRow(entry) {
      var div = document.createElement('div');
      div.className = 'row cw-browse-subrow';
      var name = entry.name || entry.host || '—';
      var subject = document.createElement('div');
      subject.className = 'cw-browse-subject';
      var link;
      if (entry.id) {
        link = document.createElement('a');
        link.href = '/certificates/' + encodeURIComponent(entry.id);
        link.className = 'cw-id';
        link.textContent = name;
      } else {
        link = document.createElement('span');
        link.className = 'cw-id';
        link.textContent = name;
      }
      subject.appendChild(link);
      if (entry.source === 'uploaded') subject.appendChild(textSpan('cw-chip', 'Uploaded'));
      div.appendChild(subject);
      var condition = conditionDisplay(entry);
      var conditionCell = document.createElement('div');
      conditionCell.className = 'cw-condition';
      var pill = textSpan('cw-status ' + condition.tone, condition.label);
      var dot = document.createElement('span');
      dot.className = 'dot';
      dot.setAttribute('aria-hidden', 'true');
      pill.insertBefore(dot, pill.firstChild);
      conditionCell.appendChild(pill);
      div.appendChild(conditionCell);
      div.appendChild(factFlags(entry));
      return div;
    }

    /* A large group is paged (#113 review): show the first page and offer
     * the rest a page at a time instead of loading thousands of rows. */
    function load(page, more) {
      fetch('/api/pivot/' + encodeURIComponent(pivot) + '/' + encodeURIComponent(key) +
            '?page=' + page)
        .then(function (r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
        .then(function (data) {
          var frag = document.createDocumentFragment();
          (data.entries || []).forEach(function (entry) { frag.appendChild(entryRow(entry)); });
          if (more) { more.remove(); } else { cell.textContent = ''; }
          cell.appendChild(frag);
          if (data.has_more) {
            var shown = cell.querySelectorAll('.row').length;
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'cw-btn ghost sm';
            btn.textContent = 'Show more (' + (data.total - shown) + ' more)';
            btn.addEventListener('click', function (ev) {
              ev.stopPropagation();
              btn.disabled = true;
              load(page + 1, btn);
            });
            cell.appendChild(btn);
          }
        })
        .catch(function (err) {
          if (more) { more.disabled = false; more.textContent = 'Failed to load: ' + err.message; return; }
          cell.textContent = 'Failed to load: ' + err.message;
          row.removeAttribute('data-loaded');
        });
    }
    load(1, null);
  });
})();
