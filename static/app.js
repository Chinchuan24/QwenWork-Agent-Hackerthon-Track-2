// Aegis dashboard helper — vendored, no external requests, CSP-safe.
// Polls a run's steps when a page marks itself with data-poll-run.
if (new URLSearchParams(location.search).get('present') === '1') {
  document.body.classList.add('present');
  document.querySelectorAll('pre').forEach(function (pre) {
    if (pre.closest('details')) return;
    var details = document.createElement('details');
    var summary = document.createElement('summary');
    summary.textContent = 'View raw evidence';
    pre.before(details);
    details.append(summary, pre);
  });
  document.querySelectorAll('a[href^="/"]').forEach(function (link) {
    var url = new URL(link.href);
    url.searchParams.set('present', '1');
    link.href = url.pathname + url.search;
  });
}
document.querySelectorAll('table').forEach(function (table) {
  if (table.closest('.table-scroll')) return;
  var wrapper = document.createElement('div');
  wrapper.className = 'table-scroll';
  table.before(wrapper);
  wrapper.append(table);
});
(function () {
  "use strict";
  var el = document.querySelector("[data-poll-run]");
  if (!el) return;
  var runId = el.getAttribute("data-poll-run");
  var timer = setInterval(function () {
    fetch("/api/run/" + encodeURIComponent(runId), { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var target = document.getElementById("poll-steps");
        if (!target || !data.steps) return;
        target.textContent = data.steps
          .map(function (s) { return s.tool + " → " + (s.verdict || s.status); })
          .join("\n");
        if (data.steps.length && data.steps.every(function (s) { return s.status !== "pending"; })) {
          clearInterval(timer);
        }
      })
      .catch(function () { clearInterval(timer); });
  }, 2000);
})();