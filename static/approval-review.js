// External, CSP-safe review visibility tracking; leaves review controls unchanged.
(function () {
  "use strict";

  function activate() {
    var element = document.querySelector("[data-review-view-url]");
    if (!element || typeof IntersectionObserver === "undefined") return;
    var urlValue = element.getAttribute("data-review-view-url");
    var csrf = element.getAttribute("data-csrf");
    if (!urlValue || !csrf) return;
    var url;
    try {
      url = new URL(urlValue, window.location.href);
    } catch (_) {
      return;
    }
    if (url.origin !== window.location.origin || url.username || url.password) return;

    var sent = false;
    var pending = false;
    var intersecting = false;
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.target === element) {
          intersecting = entry.isIntersecting && entry.intersectionRatio > 0;
        }
      });
      attempt();
    });

    async function attempt() {
      if (sent || pending || !intersecting ||
          document.visibilityState !== "visible") return;
      pending = true;
      try {
        var response = await fetch(url.href, {
          method: "POST",
          credentials: "same-origin",
          mode: "same-origin",
          redirect: "error",
          body: new URLSearchParams({ csrf: csrf })
        });
        if (response.ok) {
          sent = true;
          observer.disconnect();
          document.removeEventListener("visibilitychange", attempt);
        }
      } catch (_) {
        // Retry only on a later observer or document visibility event.
      } finally {
        pending = false;
      }
    }

    document.addEventListener("visibilitychange", attempt);
    observer.observe(element);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", activate, { once: true });
  } else {
    activate();
  }
})();
