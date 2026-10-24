// riskscope service worker. Scans always need the network (they run on the server), so this only
// caches the app shell (styles, icons, an offline page) and never stores reports or scan results.
const CACHE = "riskscope-shell-v1";
const SHELL = ["/offline", "/static/style.css", "/static/icon.svg", "/static/icon-192.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  if (req.mode === "navigate") {
    // Pages: always fresh from the network; show the offline page when there is none.
    event.respondWith(fetch(req).catch(() => caches.match("/offline")));
  } else if (new URL(req.url).pathname.startsWith("/static/")) {
    event.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
  }
});
