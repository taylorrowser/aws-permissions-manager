// Service worker: notifications, opening the right screen when one is tapped, and an offline page.
// Only static files are cached. Pages, approvals, keys and API responses always come from the
// network, so nothing signed-in is ever stored on the device and nothing is queued offline.
"use strict";
const VERSION = "__VERSION__"; // replaced by the server with a hash of the static files
const CACHE = `apm-static-${VERSION}`;
const PRECACHE = ["/offline.html", "/app.css", `/app.css?v=${VERSION}`, `/app.js?v=${VERSION}`, "/icon-192.png"];
const CACHEABLE = /^\/(app\.css|app\.js|icon-192\.png|icon-512\.png|apple-touch-icon\.png|offline\.html)$/;

self.addEventListener("install", (event) => {
  // cache: "reload" skips the HTTP cache so a new version never precaches stale files.
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(PRECACHE.map((u) => new Request(u, { cache: "reload" }))))
    .then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith("apm-static-") && key !== CACHE) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.mode === "navigate" && req.method === "GET") {
    // Always the network; if it's unreachable, say so. Form posts are never touched here: they go
    // straight to the network, and the page blocks them while offline.
    event.respondWith(fetch(req).catch(async () => {
      const page = await caches.match("/offline.html", { ignoreSearch: true });
      return page
        ? new Response(page.body, { status: 503, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } })
        : Response.error();
    }));
    return;
  }
  if (req.method === "GET" && CACHEABLE.test(url.pathname)) {
    event.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
  }
  // Everything else (/push/*, /api/*, /action, ...) goes straight to the network untouched.
});

function payload(event) {
  const fallback = { title: "AWS Permissions", body: "Something needs your attention.", url: "/" };
  try {
    const data = event.data ? event.data.json() : {};
    return { ...fallback, ...data };
  } catch (_) {
    return fallback;
  }
}

self.addEventListener("push", (event) => {
  const data = payload(event);
  event.waitUntil((async () => {
    await self.registration.showNotification(String(data.title), {
      body: String(data.body), tag: data.tag || undefined, renotify: Boolean(data.tag),
      data: { url: safeUrl(data.url) }, icon: "/icon-192.png", badge: "/icon-192.png",
    });
    if (typeof data.pending === "number" && self.navigator.setAppBadge) {
      await (data.pending ? self.navigator.setAppBadge(data.pending) : self.navigator.clearAppBadge()).catch(() => {});
    }
    for (const client of await self.clients.matchAll({ type: "window" })) client.postMessage({ type: "push" });
  })());
});

// Only ever open pages of this app.
function safeUrl(url) {
  try {
    const u = new URL(url || "/", self.location.origin);
    return u.origin === self.location.origin ? u.pathname + u.search : "/";
  } catch (_) {
    return "/";
  }
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = new URL(safeUrl(event.notification.data?.url), self.location.origin).href;
  event.waitUntil((async () => {
    // Reuse an open window of the app (only windows this worker controls can be navigated).
    for (const w of await self.clients.matchAll({ type: "window" })) {
      try {
        const moved = await w.navigate(url);
        if (moved) { await moved.focus(); return; }
      } catch (_) {}
    }
    await self.clients.openWindow(url);
  })());
});

// The browser rotated or expired the subscription: subscribe again and tell the server, replacing
// the old one. Needs a signed-in session; if there isn't one the page re-registers on next open.
self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil((async () => {
    const old = event.oldSubscription;
    const key = old?.options?.applicationServerKey;
    const sub = event.newSubscription || (key && await self.registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key }));
    if (!sub) return;
    await fetch("/push/subscribe", {
      method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subscription: sub.toJSON(), label: self.navigator.userAgent, replaces: old?.endpoint || "" }),
    }).catch(() => {});
  })());
});
