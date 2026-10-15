// Pure helpers from the page script. Run: node --test tests/js/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const app = require("../../apm/static/app.js");

const base = { ios: false, standalone: false, serviceWorker: true, pushManager: true, notification: true, permission: "default", subscribed: false };

test("push state covers every case the Notifications screen shows", () => {
  const cases = [
    [{ ios: true }, "ios-install"],
    [{ ios: true, pushManager: false }, "ios-install"],
    [{ ios: true, standalone: true }, "off"],
    [{ ios: true, standalone: true, permission: "granted", subscribed: true }, "on"],
    [{ pushManager: false }, "unsupported"],
    [{ serviceWorker: false }, "unsupported"],
    [{ notification: false }, "unsupported"],
    [{ permission: "denied" }, "denied"],
    [{ permission: "granted" }, "off"],
    [{ permission: "granted", subscribed: true }, "on"],
    [{}, "off"],
  ];
  for (const [env, want] of cases) assert.equal(app.pushState({ ...base, ...env }), want, JSON.stringify(env));
});

test("iPadOS, which reports itself as a Mac, counts as iOS", () => {
  assert.equal(app.isIOS({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", maxTouchPoints: 5 }), true);
  assert.equal(app.isIOS({ userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", maxTouchPoints: 0 }), false);
  assert.equal(app.isIOS({ userAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)", maxTouchPoints: 5 }), true);
});

test("blocked-notification help matches the platform", () => {
  assert.match(app.deniedHelp({ ios: true }), /Settings app/);
  assert.match(app.deniedHelp({ userAgent: "Linux; Android 15", standalone: true }), /App info/);
  assert.match(app.deniedHelp({ userAgent: "Linux; Android 15", standalone: false }), /address bar/);
  assert.match(app.deniedHelp({ userAgent: "Macintosh" }), /reload/);
});

test("old #req and #connect links map to the new screens", () => {
  assert.equal(app.legacyTarget("#req-12"), "/requests/12");
  assert.equal(app.legacyTarget("#connect-AB2C-DE3F"), "/connect/AB2C-DE3F");
  assert.equal(app.legacyTarget("#req-x"), null);
  assert.equal(app.legacyTarget("#connect-../../x"), null);
});

test("server key rotation is detected", () => {
  const key = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const bytes = app.keyBytes(key);
  assert.equal(app.sameKey(bytes.buffer, key), true);
  const other = bytes.slice(); other[5] = 9;
  assert.equal(app.sameKey(other.buffer, key), false);
  assert.equal(app.sameKey(null, key), true);
});

test("times read naturally", () => {
  const now = new Date(2026, 9, 11, 15, 0);
  assert.equal(app.relativeTime(new Date(2026, 9, 11, 14, 59, 40), now), "just now");
  assert.equal(app.relativeTime(new Date(2026, 9, 11, 14, 45), now), "15 min ago");
  assert.equal(app.relativeTime(new Date(2026, 9, 11, 17, 5), now), "in 2 h 5 min"); // a grant's end
  assert.equal(app.relativeTime(new Date(2026, 9, 18, 15, 0), now), "in 7 days");
  assert.match(app.relativeTime(new Date(2026, 9, 11, 9, 5), now), /^today /);
  assert.match(app.relativeTime(new Date(2026, 9, 2, 9, 5), now), /Oct 2/);
});

test("a page-driven key rotation the server didn't accept is dropped, not kept", async () => {
  const key = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const fresh = () => {
    const log = [];
    const old = { endpoint: "https://p/old", options: { applicationServerKey: new Uint8Array(65).fill(7).buffer }, unsubscribe: async () => log.push("old") };
    const neu = { endpoint: "https://p/new", unsubscribe: async () => log.push("new") };
    const registration = { pushManager: { getSubscription: async () => old, subscribe: async () => neu } };
    return { log, registration };
  };
  for (const failure of [new Error("offline"), Object.assign(new Error("signed out"), { status: 401 }), Object.assign(new Error("boom"), { status: 500 })]) {
    const { log, registration } = fresh();
    await assert.rejects(app.rotateIfKeyChanged(registration, key, async () => { throw failure; }));
    assert.deepEqual(log, ["old", "new"], failure.message);
  }
  const { log, registration } = fresh();
  const seen = [];
  const sub = await app.rotateIfKeyChanged(registration, key, async (s, old) => seen.push([s.endpoint, old]));
  assert.equal(sub.endpoint, "https://p/new");
  assert.deepEqual(seen, [["https://p/new", "https://p/old"]]);
  assert.deepEqual(log, ["old"]);
});

test("a live refresh waits until the owner isn't mid-task", () => {
  const idle = { visible: true, online: true, busy: false, dialogOpen: false, typing: false, dirty: false, secret: false };
  assert.equal(app.canRefresh(idle), true);
  for (const block of [{ visible: false }, { online: false }, { busy: true }, { dialogOpen: true }, { typing: true }, { dirty: true }, { secret: true }]) {
    assert.equal(app.canRefresh({ ...idle, ...block }), false, JSON.stringify(block));
  }
});

// A pager whose loads resolve when the test says so, recording what reached the screen.
function harness({ idle = () => true } = {}) {
  const loads = [], applied = [];
  const pager = app.createPager({
    load: (url) => new Promise((resolve) => loads.push({ url, resolve: (html = `page ${url}`) => resolve(html) })),
    apply: (page, how) => applied.push([page, how.background]),
    idle,
  });
  return { pager, loads, applied, tick: () => new Promise((r) => setTimeout(r, 0)) };
}

test("opening rows quickly keeps the last one, whatever order the loads finish in", async () => {
  const { pager, loads, applied, tick } = harness();
  const first = pager.open("/requests/1"), second = pager.open("/requests/2");
  loads[1].resolve();
  loads[0].resolve();
  assert.deepEqual(await Promise.all([first, second]), [false, true]);
  await tick();
  assert.deepEqual(applied, [["page /requests/2", false]]);
});

test("a refresh that started before a row opened is dropped; one after it applies", async () => {
  const { pager, loads, applied } = harness();
  const refresh = pager.refresh("/requests/1");
  const open = pager.open("/requests/2");
  loads[1].resolve();
  await open;
  loads[0].resolve();
  assert.equal(await refresh, false);
  const later = pager.refresh("/requests/2");
  loads[2].resolve("fresher /requests/2");
  assert.equal(await later, true);
  assert.deepEqual(applied, [["page /requests/2", false], ["fresher /requests/2", true]]);
});

test("a refresh never lands during or over a decision, and rows don't open mid-submit", async () => {
  const { pager, loads, applied } = harness();
  const refresh = pager.refresh("/requests/1");
  let release;
  const submit = pager.submit(() => new Promise((r) => { release = r; }));
  assert.equal(pager.busy, true);
  assert.equal(await pager.submit(async () => {}), false); // one submit at a time
  assert.equal(await pager.open("/requests/2"), false);
  assert.equal(await pager.refresh("/requests/1"), false);
  loads[0].resolve();
  assert.equal(await refresh, false); // started before the submit
  release();
  assert.equal(await submit, true);
  assert.equal(pager.busy, false);
  assert.deepEqual(applied, []);
});

test("a refresh waits for the owner: dropped if they started typing while it loaded", async () => {
  let idle = true;
  const { pager, loads, applied } = harness({ idle: () => idle });
  const refresh = pager.refresh("/");
  idle = false;
  loads[0].resolve();
  assert.equal(await refresh, false);
  assert.equal(await pager.refresh("/"), false); // and doesn't even start
  assert.deepEqual(applied, []);
});

test("a decision's response moves between inbox screens in place", () => {
  const ok = (url) => ({ ok: true, redirected: true, url: `https://apm.example${url}` });
  assert.equal(app.afterSubmit(ok("/?msg=Approved"), "/requests/7"), "swap");
  assert.equal(app.afterSubmit(ok("/?msg=Connected"), "/connect/AB2C-DE3F"), "swap");
  assert.equal(app.afterSubmit(ok("/projects?msg=Revoked"), "/projects"), "apply");
  assert.equal(app.afterSubmit(ok("/settings?msg=x"), "/requests/7"), "go");
  assert.equal(app.afterSubmit({ ok: false, status: 403, redirected: false, url: "" }, "/requests/7"), "error");
  assert.equal(app.afterSubmit({ ok: true, redirected: false, url: "https://apm.example/action" }, "/settings"), "apply");
});

test("a changed request is refused: Approve keeps the digest the owner saw", () => {
  // The server answers a stale digest by sending the owner back to the same request, error inline.
  const refused = { ok: true, redirected: true, url: "https://apm.example/requests/7?msg=Error%3A+this+request+changed+after+you+opened+it.+Review+it+again." };
  assert.equal(app.afterSubmit(refused, "/requests/7"), "apply"); // the pane redraws with the request as it is now
  // A background refresh that redraws the open request keeps the old digest, so Approve is refused
  // rather than approving what the owner hasn't seen; opening a row or a submit's response uses the new one.
  assert.equal(app.digestToSubmit({ background: true, sameRequest: true, seen: "old", fresh: "new" }), "old");
  assert.equal(app.digestToSubmit({ background: false, sameRequest: true, seen: "old", fresh: "new" }), "new");
  assert.equal(app.digestToSubmit({ background: true, sameRequest: false, seen: "old", fresh: "new" }), "new");
  assert.equal(app.digestToSubmit({ background: true, sameRequest: true, seen: undefined, fresh: "new" }), "new");
});

test("Decided keeps rows already loaded when a refresh or a decision redraws the list", () => {
  // Loaded 20..1 so far; a decision put 21 on top, so the fresh first page is 21..12.
  const fresh = [21, 20, 19, 18, 17, 16, 15, 14, 13, 12];
  const old = Array.from({ length: 20 }, (_, i) => 20 - i);
  assert.deepEqual(app.keepDecided(fresh, old), Array.from({ length: 11 }, (_, i) => 11 - i));
  assert.deepEqual(app.keepDecided(fresh, fresh), []);
  assert.deepEqual(app.keepDecided([], [3, 2]), [3, 2]);
});

test("keyboard: arrows move between rows, a approves, r rejects, never while typing", () => {
  const key = (k, extra = {}) => app.keyCommand({ key: k, ...extra }, false);
  assert.deepEqual(["ArrowDown", "ArrowUp", "a", "r", "x"].map((k) => key(k)), ["next", "prev", "approve", "reject", null]);
  assert.equal(key("a", { metaKey: true }), null);
  assert.equal(app.keyCommand({ key: "a" }, true), null);
  const ids = ["connect-AB2C-DE3F", "req-3", "req-2"];
  assert.equal(app.step(ids, null, "next"), "connect-AB2C-DE3F");
  assert.equal(app.step(ids, "req-3", "next"), "req-2");
  assert.equal(app.step(ids, "req-2", "next"), "req-2");
  assert.equal(app.step(ids, "connect-AB2C-DE3F", "prev"), "connect-AB2C-DE3F");
  assert.equal(app.step([], null, "next"), null);
});

test("a refresh doesn't start while a row is loading, so an older row can't land over it", async () => {
  const { pager, loads, applied } = harness();
  const open = pager.open("/requests/2");
  assert.equal(await pager.refresh("/requests/2"), false);
  loads[0].resolve();
  assert.equal(await open, true);
  const later = pager.refresh("/requests/2"); // once it has landed, refreshes run again
  loads[1].resolve("fresher");
  assert.equal(await later, true);
  assert.deepEqual(applied.map(([page]) => page), ["page /requests/2", "fresher"]);
});

test("a confirm drops a row still loading, so it can't replace the pane behind the dialog", async () => {
  const { pager, loads, applied } = harness();
  const open = pager.open("/requests/2");
  pager.claim(); // the owner pressed Approve on the request on screen
  loads[0].resolve();
  assert.equal(await open, false);
  assert.deepEqual(applied, []);
});

test("Back and Forward keep the pane on the URL: a pending confirm is cancelled, a submit reloads", () => {
  assert.equal(app.onHistory({ dialogOpen: false, busy: false }), "open");
  assert.equal(app.onHistory({ dialogOpen: true, busy: false }), "cancel-then-open");
  assert.equal(app.onHistory({ dialogOpen: false, busy: true }), "reload");
});

test("while a row is loading the pager says so, so a and r can't decide the request still on screen", async () => {
  const { pager, loads } = harness();
  assert.equal(pager.loading, false);
  const open = pager.open("/requests/2");
  assert.equal(pager.loading, true);
  loads[0].resolve();
  await open;
  assert.equal(pager.loading, false);
  const failed = pager.open("/requests/3");
  loads[1].resolve(null); // the load failed: open() is false, so the URL never moves to it
  assert.equal(await failed, false);
  assert.equal(pager.loading, false);
});

test("the card's size check counts each time-limited grant", () => {
  const over = (hours) => app.overLimit(10000, 70, 10240, "apm-grants on role apm-x", hours);
  assert.equal(over(["0", "0", "0", "0"]), "");
  assert.equal(over(["1", "24", "168", "0"]), "");
  assert.equal(over(["1", "24", "168", "3"]),
    "Too big with these time limits: the inline policy apm-grants on role apm-x would be 10,280 characters, " +
    "40 over the 10,240-character limit. Make a grant permanent to approve.");
});
