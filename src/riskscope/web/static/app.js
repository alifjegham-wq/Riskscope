// Registers the service worker that makes riskscope installable and gives it an offline page.
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {
      /* Installing is a nice-to-have; the site works the same without it. */
    });
  });
}

// Progressive enhancements. The site works fully without any of this; it just feels nicer with it.
// Everything lives here (not inline) so the strict Content-Security-Policy (script-src 'self') holds.
document.addEventListener("DOMContentLoaded", () => {
  // "Print / save as PDF" button on report pages.
  const printBtn = document.getElementById("print-btn");
  if (printBtn) {
    printBtn.addEventListener("click", () => window.print());
  }

  // "Copy share link" buttons.
  document.querySelectorAll(".copy-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const text = btn.getAttribute("data-copy") || "";
      const original = btn.textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "✓ Copied";
      } catch {
        btn.textContent = "Copy failed — select manually";
      }
      setTimeout(() => { btn.textContent = original; }, 2000);
    });
  });

  // Scanning takes a few seconds: show progress on the button so a tap doesn't feel dead.
  document.querySelectorAll("form[action='/scan'], form[action='/code'], form[action='/bulk']").forEach((form) => {
    form.addEventListener("submit", () => {
      const btn = form.querySelector("button[type=submit], button:not([type])");
      if (btn && !btn.disabled) {
        const busy = btn.getAttribute("data-busy") || "Scanning…";
        // Defer so the form submission captures the button value before it is disabled.
        setTimeout(() => { btn.disabled = true; btn.textContent = busy; }, 0);
      }
    });
  });
});
