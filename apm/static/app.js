// Owner web app behaviour. Pages work without it; this adds confirm prompts, offline and
// double-submit protection, local times, install help and push notification sign-up.
"use strict";

// ---------- pure helpers (also loaded by tests/js) ----------

function isIOS(nav) {
  return /iPhone|iPad|iPod/.test(nav.userAgent) || (/Macintosh/.test(nav.userAgent) && nav.maxTouchPoints > 1);
}

// What this device can do about notifications. env: {ios, standalone, serviceWorker, pushManager,
// notification, permission, subscribed}
function pushState(env) {
  if (env.ios && !env.standalone) return "ios-install"; // iOS only allows push from Home Screen apps
  if (!env.serviceWorker || !env.pushManager || !env.notification) return "unsupported";
  if (env.permission === "denied") return "denied";
  if (env.permission === "granted" && env.subscribed) return "on";
  return "off";
}

function deniedHelp(env) {
  if (env.ios) return "Open the Settings app, tap Notifications, then AWS Permissions, and turn on Allow Notifications. Then reopen this app.";
  if (/Android/.test(env.userAgent)) {
    return env.standalone
      ? "Long-press the AWS Permissions app icon, tap App info, then Notifications, and allow them. Then reopen the app."
      : "Tap the icon left of the address bar, then Permissions or Notifications, and allow them. Then reload this page.";
  }
  return "Click the icon left of the address bar, allow notifications for this site, then reload this page.";
}

function keyBytes(base64url) {
  const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
  const raw = atob((base64url + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

function sameKey(buffer, base64url) {
  if (!buffer) return true; // browser doesn't expose it; assume unchanged
  const a = new Uint8Array(buffer), b = keyBytes(base64url);
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// Old notification and connect links used #req-12 and #connect-ABCD-EFGH on the home page.
function legacyTarget(hash) {
  let m = /^#req-(\d+)$/.exec(hash);
  if (m) return `/requests/${m[1]}`;
  m = /^#connect-([A-Z0-9]{4}-[A-Z0-9]{4})$/.exec(hash);
  return m ? `/connect/${m[1]}` : null;
}

function relativeTime(date, now) {
  const minutes = Math.round((now - date) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const sameDay = date.toDateString() === now.toDateString();
  const clock = date.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (sameDay) return `today ${clock}`;
  return date.toLocaleDateString([], { month: "short", day: "numeric", year: date.getFullYear() === now.getFullYear() ? undefined : "numeric" }) + ` ${clock}`;
}

if (typeof module !== "undefined") {
  module.exports = { isIOS, pushState, deniedHelp, keyBytes, sameKey, legacyTarget, relativeTime };
}

// ---------- page behaviour ----------

if (typeof document !== "undefined") {
  const $ = (id) => document.getElementById(id);
  const page = document.body.dataset.page;
  const signedIn = document.body.dataset.pending !== undefined;

  const target = legacyTarget(location.hash);
  if (target && page === "requests") location.replace(target);

  // Drop ?msg= so a reload doesn't repeat the message.
  if (location.search.includes("msg=")) history.replaceState(null, "", location.pathname + location.hash);

  for (const t of document.querySelectorAll("time[datetime]")) {
    const d = new Date(t.getAttribute("datetime"));
    t.title = d.toLocaleString();
    t.textContent = relativeTime(d, new Date());
  }

  // Forms: confirm, block while offline, and stop double submits.
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!navigator.onLine) {
      event.preventDefault();
      showOffline(true);
      $("offline").focus?.();
      return;
    }
    if (form.dataset.confirm && !confirm(form.dataset.confirm)) {
      event.preventDefault();
      return;
    }
    const button = form.querySelector("button");
    if (button) setTimeout(() => { button.disabled = true; button.dataset.label = button.textContent; button.textContent += "…"; });
  });
  window.addEventListener("pageshow", () => {
    for (const b of document.querySelectorAll("form button:disabled")) {
      b.disabled = false;
      if (b.dataset.label) b.textContent = b.dataset.label;
    }
  });

  function showOffline(offline) {
    const banner = $("offline");
    if (banner) banner.hidden = !offline;
  }
  addEventListener("online", () => showOffline(false));
  addEventListener("offline", () => showOffline(true));
  showOffline(!navigator.onLine);

  // Reopening the app shows fresh requests (but never while a new key is on screen or you're typing).
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") { hiddenAt = Date.now(); return; }
    swReady?.then((r) => r.update()).catch(() => {});
    if (page === "requests" && hiddenAt && Date.now() - hiddenAt > 30000 && navigator.onLine
        && !document.querySelector(".secret") && !document.activeElement?.matches("input,textarea")) {
      location.reload();
    }
  });

  if (signedIn && "setAppBadge" in navigator) {
    const n = Number(document.body.dataset.pending);
    (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
  }

  const copy = $("copy-key");
  copy?.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($(copy.dataset.target).textContent);
      copy.textContent = "Copied";
    } catch (_) {
      copy.textContent = "Select the key and copy it";
    }
  });

  // ----- install -----
  let installPrompt = null;
  addEventListener("beforeinstallprompt", (event) => {
    event.preventDefault();
    installPrompt = event;
    if ($("install-app")) $("install-app").hidden = false;
  });
  addEventListener("appinstalled", () => { if ($("install-app")) $("install-app").hidden = true; });
  $("install-app")?.addEventListener("click", async () => {
    if (!installPrompt) return;
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    $("install-app").hidden = true;
  });

  // ----- service worker and push -----
  const swReady = "serviceWorker" in navigator
    ? navigator.serviceWorker.register("/sw.js", { updateViaCache: "none" }).then(() => navigator.serviceWorker.ready)
    : null;
  swReady?.catch((err) => console.warn("service worker registration failed", err));

  navigator.serviceWorker?.addEventListener("message", (event) => {
    if (event.data?.type === "push" && page === "requests") {
      const flash = document.createElement("p");
      flash.className = "flash";
      flash.setAttribute("role", "status");
      flash.innerHTML = 'Something new arrived. <a href="/">Show it</a>';
      document.querySelector("main h1")?.after(flash);
    }
  });

  const status = $("push-status");
  const vapid = document.body.dataset.vapid || null;
  const env = () => ({
    ios: isIOS(navigator), userAgent: navigator.userAgent,
    standalone: matchMedia("(display-mode: standalone)").matches || navigator.standalone === true,
    serviceWorker: "serviceWorker" in navigator, pushManager: "PushManager" in window,
    notification: "Notification" in window, permission: "Notification" in window ? Notification.permission : "default",
  });

  async function post(path, body) {
    const resp = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || `server returned ${resp.status}`);
    return data;
  }

  async function save(subscription, replaces) {
    const { device } = await post("/push/subscribe", { subscription: subscription.toJSON(), label: navigator.userAgent, replaces });
    for (const li of document.querySelectorAll("[data-device]")) {
      li.querySelector(".chip.this").hidden = li.dataset.device !== device;
    }
    return device;
  }

  // Keeps the server's copy current: re-adds a device the server lost, and moves to a new
  // subscription if the server's push key was rotated.
  async function currentSubscription(registration, key) {
    let sub = await registration.pushManager.getSubscription();
    if (sub && key && !sameKey(sub.options?.applicationServerKey, key)) {
      const old = sub.endpoint;
      await sub.unsubscribe();
      sub = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) });
      await save(sub, old);
    }
    return sub;
  }

  function render(state, message) {
    if (!status) return;
    const show = (id, on) => { if ($(id)) $(id).hidden = !on; };
    show("push-enable", state === "off");
    show("push-test", state === "on");
    show("push-disable", state === "on");
    show("install-ios", state === "ios-install");
    show("push-denied", state === "denied");
    if (state === "denied") $("push-denied-help").textContent = deniedHelp(env());
    status.textContent = message || {
      on: "Notifications are on for this device.",
      off: "Notifications are off for this device.",
      "ios-install": "Add AWS Permissions to your Home Screen to get notifications.",
      denied: "Notifications are blocked for this site on this device.",
      unsupported: "This browser can't show notifications. Try Chrome, Edge, Firefox or Safari, or the Home Screen app on iPhone.",
    }[state];
  }

  // Sends a test to this device and reports what the push service said. Returns the outcome.
  async function testDevice(sub, { justEnabled = false, retrying = false } = {}) {
    render("on", "Sending a test notification…");
    try {
      const { results } = await post("/push/test", { endpoint: sub.endpoint });
      const r = results[0] || { outcome: "failed" };
      if (r.outcome === "delivered") {
        render("on", "Test sent. It should appear within a few seconds. If it doesn't, check Focus or Do Not Disturb and your system notification settings.");
      } else if (r.outcome === "gone") {
        await sub.unsubscribe().catch(() => {});
        if (retrying) return r.outcome; // the caller subscribes again; say nothing yet
        render("off", justEnabled
          ? "The browser's push service rejected this device. Try Turn on notifications again in a minute, or use another browser."
          : "This device's subscription had expired and was removed. Turn notifications on again.");
      } else {
        render("on", `The push service didn't accept the test${r.status ? ` (HTTP ${r.status})` : ""}. Try again in a minute.`);
      }
      return r.outcome;
    } catch (err) {
      render("on", `Couldn't send a test: ${err.message}`);
      return "failed";
    }
  }

  async function setUpPush() {
    const e = env();
    let state = pushState({ ...e, subscribed: false });
    if (state === "ios-install" || state === "unsupported" || !swReady || !signedIn) {
      if ($("push-nudge")) $("push-nudge").hidden = state !== "ios-install";
      return render(state);
    }
    const registration = await swReady;
    let sub = null;
    try {
      sub = e.permission === "granted" ? await currentSubscription(registration, vapid) : null;
      // Re-register now and then (always on this screen) in case the server lost or removed it.
      const last = Number(localStorage.getItem("apm-push-sync") || 0);
      if (sub && (status || Date.now() - last > 3600000)) {
        await save(sub);
        localStorage.setItem("apm-push-sync", String(Date.now()));
      }
    } catch (err) {
      console.warn("couldn't sync push subscription", err);
    }
    state = pushState({ ...e, subscribed: Boolean(sub) });
    if ($("push-nudge")) $("push-nudge").hidden = state !== "off";
    render(state);
    if (!status) return;

    $("push-enable").onclick = async () => {
      $("push-enable").disabled = true;
      try {
        if (Notification.permission !== "granted") {
          const answer = await Notification.requestPermission();
          if (answer !== "granted") {
            return render(answer === "denied" ? "denied" : "off",
              answer === "denied" ? undefined : "Notifications weren't allowed. Tap Turn on notifications to try again.");
          }
        }
        if (!vapid) throw new Error("the server has no push key configured");
        // A brand-new subscription is occasionally rejected as gone by the push service; one
        // fresh subscription usually fixes it.
        for (let attempt = 1; attempt <= 2; attempt++) {
          sub = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(vapid) });
          await save(sub);
          if (await testDevice(sub, { justEnabled: true, retrying: attempt === 1 }) !== "gone") break;
          sub = null;
        }
      } catch (err) {
        render("off", `Couldn't turn on notifications: ${err.message}`);
      } finally {
        $("push-enable").disabled = false;
      }
    };
    $("push-test").onclick = () => sub && testDevice(sub);
    $("push-disable").onclick = async () => {
      try {
        // Server first: if that fails, this device stays subscribed and the screen stays truthful.
        if (sub) await post("/push/unsubscribe", { endpoint: sub.endpoint });
        await sub?.unsubscribe();
        sub = null;
        render("off", "Notifications are off for this device.");
        document.querySelector(".chip.this:not([hidden])")?.closest("li")?.remove();
      } catch (err) {
        render("on", `Couldn't turn off notifications: ${err.message}`);
      }
    };
    // Removing this device from the list also unsubscribes it, or it would re-register next time.
    document.addEventListener("submit", (event) => {
      const li = event.target.closest("[data-device]");
      if (li && sub && !li.querySelector(".chip.this").hidden && !event.defaultPrevented) sub.unsubscribe().catch(() => {});
    });
  }

  setUpPush().catch((err) => render("unsupported", `Couldn't check notifications: ${err.message}`));
}
