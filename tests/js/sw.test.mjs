// Service worker behaviour with fake browser APIs. Run: node --test tests/js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const SOURCE = readFileSync(new URL("../../apm/static/sw.js", import.meta.url), "utf8").replace("__VERSION__", "v2");
const ORIGIN = "https://apm.test";

function load({ online = true, windows = [], status = 200 } = {}) {
  const listeners = {}, caches = new Map(), shown = [], opened = [], fetched = [], messages = [], unsubscribed = [];
  let skipped = false, claimed = false, badge = null;
  const cacheApi = {
    async open(name) {
      if (!caches.has(name)) caches.set(name, new Map());
      const c = caches.get(name);
      return { addAll: async (reqs) => reqs.forEach((r) => {
        const u = typeof r === "string" ? r : (() => { const x = new URL(r.url); return x.pathname + x.search; })();
        assert.equal(typeof r === "string" ? "default" : r.cache, "reload");
        c.set(u, new Response(`cached ${u}`));
      }) };
    },
    async keys() { return [...caches.keys()]; },
    async delete(name) { return caches.delete(name); },
    async match(req, opts = {}) {
      const url = new URL(typeof req === "string" ? req : req.url, ORIGIN);
      for (const c of caches.values()) {
        for (const [k, v] of c) {
          const ku = new URL(k, ORIGIN);
          if (ku.pathname === url.pathname && (opts.ignoreSearch || ku.search === url.search)) return v.clone();
        }
      }
      return undefined;
    },
  };
  const self = {
    location: new URL(ORIGIN + "/sw.js"),
    navigator: { userAgent: "test", setAppBadge: async (n) => { badge = n; }, clearAppBadge: async () => { badge = 0; } },
    addEventListener: (type, fn) => { listeners[type] = fn; },
    skipWaiting: async () => { skipped = true; },
    clients: {
      claim: async () => { claimed = true; },
      matchAll: async () => windows,
      openWindow: async (url) => { opened.push(url); },
    },
    registration: {
      showNotification: async (title, options) => { shown.push({ title, ...options }); },
      pushManager: { subscribe: async () => ({ endpoint: "https://push.example/new", unsubscribe: async () => { unsubscribed.push("new"); }, toJSON: () => ({ endpoint: "https://push.example/new", keys: { p256dh: "p", auth: "a" } }) }) },
    },
  };
  for (const w of windows) w.postMessage ??= (m) => messages.push(m);
  const fetchFn = async (req, init) => {
    fetched.push({ url: typeof req === "string" ? req : req.url, init });
    if (!online) throw new TypeError("Failed to fetch");
    return new Response("network", { status });
  };
  // Like a worker, resolve relative URLs against its location.
  class WorkerRequest extends Request { constructor(u, o) { super(new URL(u, ORIGIN), o); } }
  const ctx = vm.createContext({ self, caches: cacheApi, fetch: fetchFn, Response, Request: WorkerRequest, URL, console });
  vm.runInContext(SOURCE, ctx);
  async function fire(type, event) {
    const waits = [];
    let response;
    const e = { ...event, waitUntil: (p) => waits.push(p), respondWith: (p) => { response = p; } };
    listeners[type](e);
    await Promise.all(waits);
    return response && await response;
  }
  return { fire, caches, shown, opened, fetched, messages, unsubscribed, state: () => ({ skipped, claimed, badge }) };
}

const nav = (path, method = "GET") => ({ request: { url: ORIGIN + path, mode: "navigate", method } });
const sub = (path, method = "GET") => ({ request: { url: ORIGIN + path, mode: "cors", method } });
const push = (data) => ({ data: data === undefined ? null : { json: () => (typeof data === "string" ? JSON.parse(data) : data) } });

test("install precaches only static files, then activates immediately", async () => {
  const sw = load();
  await sw.fire("install", {});
  const cached = [...sw.caches.get("apm-static-v2").keys()];
  assert.deepEqual(cached.sort(), ["/app.css", "/app.css?v=v2", "/app.js?v=v2", "/icon-192.png", "/offline.html"].sort());
  assert.equal(sw.state().skipped, true);
});

test("activate deletes old versions' caches only", async () => {
  const sw = load();
  await sw.fire("install", {});
  sw.caches.set("apm-static-v1", new Map());
  sw.caches.set("someone-else", new Map());
  await sw.fire("activate", {});
  assert.deepEqual([...sw.caches.keys()].sort(), ["apm-static-v2", "someone-else"]);
  assert.equal(sw.state().claimed, true);
});

test("pages always come from the network", async () => {
  const sw = load();
  await sw.fire("install", {});
  const resp = await sw.fire("fetch", nav("/requests/3"));
  assert.equal(await resp.text(), "network");
});

test("offline navigation shows the offline page with 503", async () => {
  const sw = load({ online: false });
  await sw.fire("install", {});
  const resp = await sw.fire("fetch", nav("/requests/3"));
  assert.equal(resp.status, 503);
  assert.equal(await resp.text(), "cached /offline.html");
  assert.equal(resp.headers.get("Cache-Control"), "no-store");
});

test("form posts are left to the browser, never replayed by the worker", async () => {
  const sw = load();
  await sw.fire("install", {});
  for (const path of ["/action", "/logout"]) assert.equal(await sw.fire("fetch", nav(path, "POST")), undefined);
});

test("API, push and action requests are never intercepted or cached", async () => {
  const sw = load();
  await sw.fire("install", {});
  for (const event of [sub("/push/subscribe", "POST"), sub("/api/requests"), sub("/push/test", "POST"), sub("/healthz")]) {
    assert.equal(await sw.fire("fetch", event), undefined, event.request.url);
  }
  assert.equal(await sw.fire("fetch", { request: { url: "https://cdn.example/x.js", mode: "cors", method: "GET" } }), undefined);
});

test("static files are served from the cache first", async () => {
  const sw = load({ online: false });
  await sw.fire("install", {});
  assert.equal(await (await sw.fire("fetch", sub("/app.js?v=v2"))).text(), "cached /app.js?v=v2");
});

test("push shows the notification, sets the badge and tells open pages", async () => {
  const w = { url: ORIGIN + "/" };
  const sw = load({ windows: [w] });
  await sw.fire("push", push({ title: "Permission request #4", body: "web: 1 action to review", url: "/requests/4", tag: "req-4", pending: 2 }));
  assert.equal(sw.shown.length, 1);
  assert.equal(sw.shown[0].title, "Permission request #4");
  assert.equal(sw.shown[0].tag, "req-4");
  assert.equal(sw.shown[0].renotify, true);
  assert.equal(sw.shown[0].data.url, "/requests/4");
  assert.equal(sw.state().badge, 2);
  assert.equal(JSON.stringify(sw.messages), JSON.stringify([{ type: "push" }]));
});

test("push with no or broken data still shows a generic notification", async () => {
  for (const event of [push(undefined), { data: { json: () => { throw new SyntaxError("bad"); } } }]) {
    const sw = load();
    await sw.fire("push", event);
    assert.equal(sw.shown[0].title, "AWS Permissions");
    assert.equal(sw.shown[0].data.url, "/");
  }
});

test("notification links can only point into this app", async () => {
  const sw = load();
  await sw.fire("push", push({ title: "x", body: "y", url: "https://evil.example/phish" }));
  assert.equal(sw.shown[0].data.url, "/");
});

test("clicking navigates an open app window to the request and focuses it", async () => {
  const calls = [];
  const w = { url: ORIGIN + "/projects", focus: async () => { calls.push("focus"); return w; }, navigate: async (u) => { calls.push(u); return w; } };
  const sw = load({ windows: [w] });
  await sw.fire("notificationclick", { notification: { close: () => calls.push("close"), data: { url: "/requests/4" } } });
  assert.deepEqual(calls, ["close", ORIGIN + "/requests/4", "focus"]);
  assert.deepEqual(sw.opened, []);
});

test("clicking opens a new window when none is open or navigation fails", async () => {
  const w = { url: ORIGIN + "/", focus: async () => w, navigate: async () => { throw new TypeError("not controlled"); } };
  for (const windows of [[], [w]]) {
    const sw = load({ windows });
    await sw.fire("notificationclick", { notification: { close() {}, data: { url: "/connect/ABCD-EFGH" } } });
    assert.deepEqual(sw.opened, [ORIGIN + "/connect/ABCD-EFGH"]);
  }
});

test("a rotated subscription is re-registered, replacing the old one", async () => {
  const sw = load();
  await sw.fire("pushsubscriptionchange", { oldSubscription: { endpoint: "https://push.example/old", options: { applicationServerKey: new ArrayBuffer(65) } } });
  const call = sw.fetched.find((f) => f.url === "/push/subscribe");
  const body = JSON.parse(call.init.body);
  assert.equal(body.replaces, "https://push.example/old");
  assert.equal(body.auto, true);
  assert.equal(body.subscription.endpoint, "https://push.example/new");
  assert.equal(call.init.credentials, "same-origin");
});

test("a rotated subscription the server didn't accept is dropped, not kept", async () => {
  for (const options of [{ status: 410 }, { status: 401 }, { status: 500 }, { online: false }]) {
    const sw = load(options);
    await sw.fire("pushsubscriptionchange", { oldSubscription: { endpoint: "https://push.example/old", options: { applicationServerKey: new ArrayBuffer(65) } } });
    assert.deepEqual(sw.unsubscribed, ["new"], JSON.stringify(options));
  }
  const ok = load();
  await ok.fire("pushsubscriptionchange", { oldSubscription: { endpoint: "https://push.example/old", options: { applicationServerKey: new ArrayBuffer(65) } } });
  assert.deepEqual(ok.unsubscribed, []);
});
