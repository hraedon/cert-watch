/* Certificates page — pivot lazy-loading (BC-048).
 * Inline host-note editing was removed (UI-INVENTORY V2): the single notes
 * editing surface is the Notes panel on the endpoint detail page. */
(function () {
  'use strict';

  /* ---- pivot group lazy expansion (BC-048) ----
   * The expansion row itself is toggled by core.js via data-expand;
   * this hook fills it with fetched entries on first open.          */
  var VALID_URGENCY = { expired: 1, critical: 1, warning: 1, healthy: 1, gray: 1 };

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

    fetch('/api/pivot/' + encodeURIComponent(pivot) + '/' + encodeURIComponent(key))
      .then(function (r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
      .then(function (data) {
        var frag = document.createDocumentFragment();
        (data.entries || []).forEach(function (entry) {
          var div = document.createElement('div');
          div.className = 'row';
          var name = entry.name || entry.host || '—';
          var urg = VALID_URGENCY[entry.urgency] ? entry.urgency : 'gray';
          var tone = { expired: 't-expired', critical: 't-crit', warning: 't-warn', healthy: 't-ok', gray: 't-muted' }[urg];
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
          div.appendChild(link);
          var pill = document.createElement('span');
          pill.className = 'cw-status ' + tone;
          pill.innerHTML = '<span class="dot" aria-hidden="true"></span>';
          pill.appendChild(document.createTextNode(entry.urgency_label || 'Unknown'));
          div.appendChild(pill);
          if (entry.days_remaining != null) {
            var days = document.createElement('span');
            days.className = 'cw-muted mono';
            days.textContent = entry.days_remaining + ' days';
            div.appendChild(days);
          }
          frag.appendChild(div);
        });
        cell.textContent = '';
        cell.appendChild(frag);
      })
      .catch(function (err) {
        cell.textContent = 'Failed to load: ' + err.message;
        row.removeAttribute('data-loaded');
      });
  });
})();
