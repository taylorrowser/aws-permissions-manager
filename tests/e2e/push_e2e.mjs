// Optional end-to-end check in real Chrome: enable notifications, receive real Web Push through
// the browser's push service, then the offline behaviour. Not part of the default test run.
//
//   npm i --prefix /tmp/apm-pw playwright
//   NODE_PATH=/tmp/apm-pw/node_modules node tests/e2e/push_e2e.mjs [--headed]
//
// Needs Google Chrome and internet access (Chrome's push service). Uses scripts/dev_server.py
// (in-memory fakes, throwaway VAPID keys); touches no AWS or WorkOS.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const port = 8790;
const origin = `http://localhost:${port}`;
const python = process.env.PYTHON || path.join(root, ".venv/bin/python");
const log = (...a) => console.log("•", ...a);

const server = spawn(python, ["scripts/dev_server.py", "--port", String(port), "--empty"], { cwd: root, stdio: ["ignore", "pipe", "inherit"], env: { ...process.env, PYTHONUNBUFFERED: "1" } });
await new Promise((resolve) => server.stdout.once("data", resolve));
server.stdout.on("data", (d) => { if (process.env.E2E_VERBOSE) process.stderr.write(d); });
const browser = await chromium.launchPersistentContext("", {
  channel: "chrome", headless: !process.argv.includes("--headed"), viewport: { width: 390, height: 844 },
});
try {
  await browser.grantPermissions(["notifications"], { origin });
  const page = browser.pages()[0] || await browser.newPage();
  page.on("console", (m) => m.type() === "error" && console.log("  console:", m.text()));

  await page.goto(`${origin}/dev/login?next=/devices`);
  await page.getByRole("button", { name: "Turn on notifications" }).click();
  await page.waitForFunction(() => /Test sent|didn't accept|Couldn't|rejected|expired/.test(document.getElementById("push-status").textContent), null, { timeout: 30000 });
  const status = await page.textContent("#push-status");
  log("after enabling:", status);
  assert.match(status, /Test sent/);

  // Headless Chrome may dismiss notifications quickly, so read one in the same poll that finds it.
  // (waitForFunction can't be used: it treats an async predicate's promise as already true.)
  async function notification(tag, timeout = 20000) {
    for (const end = Date.now() + timeout; Date.now() < end; await page.waitForTimeout(100)) {
      const n = await page.evaluate(async (tag) => {
        const [n] = await (await navigator.serviceWorker.ready).getNotifications({ tag });
        return n ? { title: n.title, body: n.body, tag: n.tag, url: n.data?.url } : null;
      }, tag);
      if (n) return n;
    }
    throw new Error(`no notification with tag ${tag} within ${timeout} ms`);
  }
  log("test notification displayed:", JSON.stringify(await notification("test").catch((e) => e.message)));

  await page.reload();
  await page.waitForSelector(".chip.this:not([hidden])");
  log("device row:", (await page.textContent("[data-device]")).replace(/\s+/g, " ").trim());

  // An agent asks for permissions: the notification must not reveal the reason or actions.
  await page.goto(`${origin}/keys`);
  await page.fill("#key-name", "e2e");
  await page.getByRole("button", { name: "Create key" }).click();
  const key = (await page.textContent("#secret")).trim();
  const resp = await fetch(`${origin}/api/requests`, {
    method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ project: "e2e", actions: ["s3:ListAllMyBuckets"], reason: "SECRET-REASON-TEXT" }),
  });
  assert.equal(resp.status, 201);
  const { id } = await resp.json();
  const note = await notification(`req-${id}`);
  log("request notification:", JSON.stringify(note));
  assert.equal(note.url, `/requests/${id}`);
  assert.ok(!JSON.stringify(note).includes("SECRET-REASON") && !JSON.stringify(note).includes("ListAllMyBuckets"));

  // The deep link opens the request screen.
  await page.goto(`${origin}${note.url}`);
  assert.match(await page.textContent("h1"), new RegExp(`Request #${id}`));

  // Offline: approving is blocked in the page, and navigation shows the offline page, not a stale copy.
  await browser.setOffline(true);
  await page.getByRole("button", { name: "Approve" }).click();
  assert.equal(await page.isVisible("#offline"), true);
  assert.equal(new URL(page.url()).pathname, `/requests/${id}`);
  await page.goto(`${origin}/`).catch(() => {});
  log("offline navigation:", await page.textContent("h1"));
  assert.match(await page.textContent("h1"), /offline/);
  await browser.setOffline(false);

  // Turning off removes the device from the server too.
  await page.goto(`${origin}/devices`);
  await page.getByRole("button", { name: "Turn off" }).click();
  await page.waitForFunction(() => /off for this device/.test(document.getElementById("push-status").textContent));
  await page.reload();
  assert.match(await page.textContent("main"), /No devices yet/i);
  log("turned off; device removed from server");
  console.log("PASS");
} catch (err) {
  console.error("FAIL", err.message.split("\n")[0]);
  for (const p of browser.pages()) console.error("  page", p.url(), "status:", await p.textContent("#push-status").catch(() => "-"));
  process.exitCode = 1;
} finally {
  await browser.close();
  server.kill();
}
