/* cert-watch Activity page — alerts tab behavior.
 *
 * Owns the per-alert "Mark read" action. Generic chrome behavior
 * (tabs, dismissables, row expansion) lives in core.js.
 */
(function () {
  'use strict';

  document.addEventListener('click', function (e) {
    var el = e.target.closest('[data-mark-read]');
    if (!el) return;
    var alertId = el.getAttribute('data-mark-read');
    if (!alertId) return;
    e.preventDefault();
    fetch('/api/alerts/' + encodeURIComponent(alertId) + '/read', {
      method: 'POST',
      headers: { 'x-csrf-token': el.getAttribute('data-csrf') || '' }
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.ok) {
          var item = document.querySelector('[data-alert-id="' + alertId + '"]');
          if (item) {
            var badge = item.querySelector('.cw-badge-new');
            if (badge) badge.remove();
          }
          el.remove();
        }
      })
      .catch(function () {});
  });
})();
