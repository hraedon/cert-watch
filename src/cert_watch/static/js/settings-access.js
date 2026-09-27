/* Keep the Access workflow's in-page tabs aligned with the current hash. */
(function () {
  'use strict';

  var tabs = document.querySelectorAll('[data-access-tabs] a[href^="#"]');
  if (!tabs.length) return;

  function syncAccessTabs() {
    var activeHash = window.location.hash === '#local-users' ? '#local-users' : '#roles';
    Array.prototype.forEach.call(tabs, function (tab) {
      var active = tab.getAttribute('href') === activeHash;
      tab.classList.toggle('on', active);
      if (active) {
        tab.setAttribute('aria-current', 'location');
      } else {
        tab.removeAttribute('aria-current');
      }
    });
  }

  syncAccessTabs();
  window.addEventListener('hashchange', syncAccessTabs);
}());
