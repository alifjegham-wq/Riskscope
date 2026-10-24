// Registers the service worker that makes riskscope installable and gives it an offline page.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* Installing is a nice-to-have; the site works the same without it. */
    });
  });
}
