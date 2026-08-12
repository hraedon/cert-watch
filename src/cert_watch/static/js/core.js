/* cert-watch UI core — shared behaviors, wired by data-attributes.
 *
 * Contract: this file owns generic chrome behavior (theme, health
 * strip, confirmations, row links, drawers, menus, drawer tabs,
 * dismissables). Page-specific logic lives in its own static/js/
 * file and binds to ids — nothing in here calls page globals.
 */
(function () {
  'use strict';

  /* ---------- helpers ---------- */
  function esc(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s == null ? '' : String(s)));
    return d.innerHTML;
  }
  // Exposed for page scripts.
  window.cw = { esc: esc };

  /* ---------- theme toggle ---------- */
  var themeBtn = document.getElementById('theme-toggle');
  if (themeBtn) {
    var updateIcons = function () {
      var dark = document.documentElement.getAttribute('data-theme') === 'dark';
      var d = document.getElementById('theme-icon-dark');
      var l = document.getElementById('theme-icon-light');
      if (d) d.classList.toggle('cw-hidden', dark);
      if (l) l.classList.toggle('cw-hidden', !dark);
    };
    updateIcons();
    themeBtn.addEventListener('click', function () {
      var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      try { localStorage.setItem('cw-theme', next); } catch (e) { /* private mode */ }
      updateIcons();
    });
  }

  /* ---------- confirmed forms ---------- */
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (form.classList && form.classList.contains('confirm-form')) {
      var msg = form.getAttribute('data-confirm') || 'Are you sure?';
      if (!window.confirm(msg)) e.preventDefault();
    }
  });

  /* ---------- generic delegated click behaviors ---------- */
  document.addEventListener('click', function (e) {
    var el;

    // data-dismiss="<id>" — hide an element (flash, banner).
    el = e.target.closest('[data-dismiss]');
    if (el) {
      var t = document.getElementById(el.getAttribute('data-dismiss'));
      if (t) t.classList.add('cw-hidden');
      var key = el.getAttribute('data-dismiss-key');
      if (key) { try { sessionStorage.setItem(key, '1'); } catch (err) { /* ignore */ } }
      return;
    }

    // data-href on a row — navigate, unless the click hit an interactive child.
    el = e.target.closest('[data-href]');
    if (el && !e.target.closest('a, button, form, input, select, textarea, details, label')) {
      var href = el.getAttribute('data-href');
      if (href && (href.charAt(0) === '/' || /^https?:\/\//.test(href))) window.location = href;
      return;
    }

    // data-drawer-open / data-drawer-close
    el = e.target.closest('[data-drawer-open]');
    if (el) { openDrawer(el.getAttribute('data-drawer-open')); return; }
    el = e.target.closest('[data-drawer-close]');
    if (el) { closeDrawer(el.getAttribute('data-drawer-close')); return; }

    // data-menu="<id>" — toggle a dropdown menu.
    el = e.target.closest('[data-menu]');
    if (el) { toggleMenu(el); return; }
    // click outside an open menu closes it
    closeAllMenus(e.target);

    // data-expand="<id>" — toggle a table expansion row (.cw-subrow).
    // The one row-expansion mechanism (tables can't host <details>).
    el = e.target.closest('[data-expand]');
    if (el && !e.target.closest('a, button, form, input')) {
      var row = document.getElementById(el.getAttribute('data-expand'));
      if (row) {
        var hidden = row.classList.toggle('cw-hidden');
        el.setAttribute('aria-expanded', hidden ? 'false' : 'true');
        var chev = el.querySelector('.chev');
        if (chev) chev.classList.toggle('open', !hidden);
      }
      return;
    }

    // data-tab-target — drawer/section tab switching within a tabset.
    el = e.target.closest('[data-tab-target]');
    if (el) {
      var setEl = el.closest('[data-tabset]');
      if (setEl) switchTab(setEl, el.getAttribute('data-tab-target'));
      return;
    }
  });

  // Arrow-key navigation on tabsets (WAI-ARIA tabs pattern).
  document.addEventListener('keydown', function (e) {
    if (['ArrowRight', 'ArrowLeft', 'Home', 'End'].indexOf(e.key) === -1) return;
    var tab = e.target.closest('[data-tab-target]');
    var setEl = tab && tab.closest('[data-tabset]');
    if (!setEl) return;
    var tabs = Array.prototype.slice.call(setEl.querySelectorAll('[data-tab-target]'));
    var idx = tabs.indexOf(tab);
    if (idx < 0) return;
    e.preventDefault();
    var next = e.key === 'Home' ? 0
      : e.key === 'End' ? tabs.length - 1
      : e.key === 'ArrowRight' ? (idx + 1) % tabs.length
      : (idx - 1 + tabs.length) % tabs.length;
    switchTab(setEl, tabs[next].getAttribute('data-tab-target'));
    tabs[next].focus();
  });

  // Keyboard activation for row links and expandable rows.
  document.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var el = e.target.closest('[data-href][tabindex], [data-expand][tabindex]');
    if (!el) return;
    e.preventDefault();
    el.click();
  });

  /* ---------- drawer ---------- */
  var lastFocus = null;
  function openDrawer(id) {
    var drawer = document.getElementById(id);
    var bg = document.getElementById(id + '-bg');
    if (!drawer) return;
    lastFocus = document.activeElement;
    drawer.classList.add('on');
    if (bg) bg.classList.add('on');
    var first = drawer.querySelector('input, select, textarea, button');
    if (first) first.focus();
    drawer.addEventListener('keydown', trapFocus);
    document.addEventListener('keydown', escClose);
  }
  function closeDrawer(id) {
    var drawer = document.getElementById(id);
    var bg = document.getElementById(id + '-bg');
    if (!drawer) return;
    drawer.classList.remove('on');
    if (bg) bg.classList.remove('on');
    drawer.removeEventListener('keydown', trapFocus);
    document.removeEventListener('keydown', escClose);
    if (lastFocus) { lastFocus.focus(); lastFocus = null; }
  }
  function escClose(e) {
    if (e.key !== 'Escape') return;
    var open = document.querySelector('.cw-drawer.on');
    if (open) closeDrawer(open.id);
  }
  function trapFocus(e) {
    if (e.key !== 'Tab') return;
    var drawer = e.currentTarget;
    var items = drawer.querySelectorAll('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])');
    if (!items.length) return;
    var first = items[0], last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  }

  /* ---------- menus ---------- */
  function toggleMenu(btn) {
    var menu = document.getElementById(btn.getAttribute('data-menu'));
    if (!menu) return;
    var open = !menu.classList.contains('cw-hidden');
    closeAllMenus(null);
    if (!open) {
      menu.classList.remove('cw-hidden');
      btn.setAttribute('aria-expanded', 'true');
      var first = menu.querySelector('.cw-menu-item');
      if (first) first.focus();
    }
  }
  function closeAllMenus(target) {
    document.querySelectorAll('.cw-menu:not(.cw-hidden)').forEach(function (m) {
      if (target && m.contains(target)) return;
      m.classList.add('cw-hidden');
      var btn = document.querySelector('[data-menu="' + m.id + '"]');
      if (btn) btn.setAttribute('aria-expanded', 'false');
    });
  }
  // WAI-ARIA menu keyboard pattern: arrows/Home/End rove focus, Escape
  // closes and restores focus to the trigger.
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      var open = document.querySelector('.cw-menu:not(.cw-hidden)');
      closeAllMenus(null);
      if (open) {
        var trigger = document.querySelector('[data-menu="' + open.id + '"]');
        if (trigger) trigger.focus();
      }
      return;
    }
    if (['ArrowDown', 'ArrowUp', 'Home', 'End'].indexOf(e.key) === -1) return;
    var menu = e.target.closest('.cw-menu:not(.cw-hidden)');
    if (!menu) return;
    var items = Array.prototype.slice.call(menu.querySelectorAll('.cw-menu-item'));
    if (!items.length) return;
    var idx = items.indexOf(document.activeElement);
    e.preventDefault();
    var next = e.key === 'Home' ? 0
      : e.key === 'End' ? items.length - 1
      : e.key === 'ArrowDown' ? (idx + 1) % items.length
      : (idx - 1 + items.length) % items.length;
    items[next].focus();
  });

  /* ---------- tabsets (drawer intake tabs) ---------- */
  function switchTab(setEl, name) {
    setEl.querySelectorAll('[data-tab-target]').forEach(function (b) {
      var on = b.getAttribute('data-tab-target') === name;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    setEl.querySelectorAll('[data-tab-pane]').forEach(function (p) {
      p.classList.toggle('cw-hidden', p.getAttribute('data-tab-pane') !== name);
    });
    var label = setEl.querySelector('[data-tab-submit]');
    var active = setEl.querySelector('[data-tab-target].on');
    if (label && active && active.getAttribute('data-submit-label')) {
      label.textContent = active.getAttribute('data-submit-label');
    }
  }

  /* ---------- health strip ----------
   * Polls /api/health; pauses when hidden; backs off on failure
   * (30s -> 5m). Reports the MONITORING PIPELINE, not cert health. */
  var strip = document.getElementById('cw-health');
  var stripText = document.getElementById('cw-health-text');
  var stripDot = document.getElementById('cw-health-dot');
  if (strip && stripText) {
    var BASE = 30000, MAX = 300000, fails = 0, timer = null;

    var render = function (data) {
      var tone = data.overall === 'critical' ? 't-crit' : data.overall === 'warning' ? 't-warn' : '';
      strip.className = 'cw-health' + (tone ? ' ' + tone : '');
      if (stripDot) stripDot.className = 'dot';
      var parts = [];
      if (!data.scheduler_running) parts.push('Scheduler is not running');
      if (data.last_scan_status === 'failure' || data.last_scan_status === 'partial') {
        var when = '';
        if (data.last_scan_at) {
          var d = new Date(data.last_scan_at);
          if (!isNaN(d.getTime())) {
            when = ' at ' + d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
          }
        }
        parts.push('Last scan ' + (data.last_scan_status === 'partial' ? 'partially failed' : 'failed') + when);
      }
      if (data.failed_alerts_24h > 0) {
        parts.push(data.failed_alerts_24h + ' failed alert' + (data.failed_alerts_24h > 1 ? 's' : '') + ' in last 24h');
      }
      if (data.overall === 'ok') parts = ['Monitoring pipeline healthy'];
      stripText.textContent = parts.join(' · ') || 'System status unknown';
      strip.classList.remove('cw-hidden');
    };

    var schedule = function (delay) { clearTimeout(timer); timer = setTimeout(poll, delay); };

    var poll = function () {
      if (document.hidden) return; // visibilitychange resumes
      try {
        if (sessionStorage.getItem('cw-health-dismissed') === '1') {
          strip.classList.add('cw-hidden');
          schedule(BASE);
          return;
        }
      } catch (e) { /* ignore */ }
      fetch('/api/health')
        .then(function (r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
        .then(function (data) { fails = 0; render(data); schedule(BASE); })
        .catch(function () {
          fails++;
          strip.className = 'cw-health t-crit';
          stripText.textContent = 'Health check unavailable';
          strip.classList.remove('cw-hidden');
          schedule(Math.min(BASE * Math.pow(2, fails), MAX));
        });
    };

    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
    poll();
  }
})();
