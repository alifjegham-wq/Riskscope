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

  // Export bulk / IP-scan results. The rows are rendered server-side into a non-executable JSON
  // <script> tag, so no data is fetched or built from the DOM and the CSP (script-src 'self') holds.
  setupExport();
});

function setupExport() {
  const island = document.getElementById("scan-export");
  const buttons = document.querySelectorAll("[data-export]");
  if (!island || buttons.length === 0) return;
  let rows;
  try {
    rows = JSON.parse(island.textContent || "[]");
  } catch {
    return;
  }
  if (!Array.isArray(rows) || rows.length === 0) return;
  const columns = Object.keys(rows[0]);

  const toCsv = () => {
    const esc = (v) => {
      const s = v === null || v === undefined ? "" : String(v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const lines = [columns.join(",")];
    for (const row of rows) lines.push(columns.map((c) => esc(row[c])).join(","));
    return lines.join("\r\n");
  };

  const download = (text, type, ext, base) => {
    const blob = new Blob([text], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = (base || "riskscope") + "-" + new Date().toISOString().slice(0, 10) + "." + ext;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const base = btn.getAttribute("data-filename") || "riskscope";
      if (btn.getAttribute("data-export") === "json") {
        download(JSON.stringify(rows, null, 2), "application/json", "json", base);
      } else {
        download(toCsv(), "text/csv", "csv", base);
      }
    });
  });
}
