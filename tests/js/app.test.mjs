// Pure helpers from the page script. Run: node --test tests/js
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
  assert.match(app.relativeTime(new Date(2026, 9, 11, 9, 5), now), /^today /);
  assert.match(app.relativeTime(new Date(2026, 9, 2, 9, 5), now), /Oct 2/);
});
