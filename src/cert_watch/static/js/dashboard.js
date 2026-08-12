/* Certificates page — pivot lazy-loading and inline host-note editing. */
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

  /* ---- inline host-note editing (BC-021) ---- */
  document.addEventListener('click', function (e) {
    var btn = e.target.closest('[data-edit-note]');
    if (!btn) return;
    var hostId = btn.getAttribute('data-edit-note');
    var csrf = btn.getAttribute('data-csrf');
    var scopeRow = btn.closest('tr') || btn.parentElement;
    var existing = scopeRow.querySelector('.cw-note-form[data-host-id="' + hostId + '"]');
    if (existing) { existing.remove(); return; }

    var form = document.createElement('form');
    form.className = 'cw-inline cw-note-form';
    form.setAttribute('data-host-id', hostId);
    var input = document.createElement('input');
    input.type = 'text';
    input.name = 'notes';
    input.className = 'cw-input sm';
    input.placeholder = 'Add note…';
    input.value = btn.getAttribute('data-note') || '';
    var save = document.createElement('button');
    save.type = 'submit';
    save.className = 'cw-btn sm';
    save.textContent = 'Save';
    form.appendChild(input);
    form.appendChild(save);
    btn.parentNode.insertBefore(form, btn.nextSibling);
    input.focus();

    form.addEventListener('submit', function (ev) {
      ev.preventDefault();
      var note = input.value;
      fetch('/api/hosts/' + hostId + '/notes', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
        body: JSON.stringify({ notes: note }),
      }).then(function (r) {
        if (!r.ok) throw new Error('failed to save note');
        return r.json();
      }).then(function () {
        form.remove();
        btn.setAttribute('data-note', note);
        // WI-105: scope chip lookup to this row (host_id is not unique per row).
        var chip = scopeRow.querySelector('.cw-note-chip[data-host-id="' + hostId + '"]');
        if (note.trim()) {
          if (chip) {
            chip.setAttribute('title', note);
            chip.classList.remove('cw-hidden');
          }
        } else if (chip) {
          chip.classList.add('cw-hidden');
        }
      }).catch(function (err) {
        input.setCustomValidity('Error saving note: ' + err.message);
        input.reportValidity();
        input.setCustomValidity('');
      });
    });
  });
})();
