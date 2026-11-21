// Aegis dashboard helper — vendored, no external requests, CSP-safe.
// Polls a run's steps when a page marks itself with data-poll-run.
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