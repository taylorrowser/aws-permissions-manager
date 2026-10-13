// Owner web app behaviour. Pages work without it; this adds live refresh (the page polls /poll
// while visible and swaps its data-live regions when something changed), in-page form submits,
// confirm dialogs, offline and double-submit protection, local times, install help and push
// notification sign-up.
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

// If the server's push key changed, replace this device's subscription and register the new one
// as replacing the old. A replacement the server doesn't accept is dropped (never kept), so the
// link to the old endpoint, and any removal of it, can't be lost. Returns the current subscription.
async function rotateIfKeyChanged(registration, key, register) {
  let sub = await registration.pushManager.getSubscription();
  if (sub && key && !sameKey(sub.options?.applicationServerKey, key)) {
    const old = sub.endpoint;
    await sub.unsubscribe();
    sub = await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: keyBytes(key) });
    try {
      await register(sub, old);
    } catch (err) {
      await sub.unsubscribe().catch(() => {});
      throw err;
    }
  }
  return sub;
}

// Whether a background refresh may replace what's on screen right now. Never while the owner is
// mid-task: typing (or with unsaved text in a field), confirming, submitting, looking at a new
// key, or while offline or hidden.
function canRefresh(s) {
  return Boolean(s.visible && s.online && !s.busy && !s.dialogOpen && !s.typing && !s.dirty && !s.secret);
}

if (typeof module !== "undefined") {
  module.exports = { isIOS, pushState, deniedHelp, keyBytes, sameKey, legacyTarget, relativeTime, rotateIfKeyChanged, canRefresh };
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

  // The body is sized to the visual viewport, so the tab bar stays in place when the keyboard opens.
  const vv = window.visualViewport;
  if (vv) {
    const fit = () => { document.documentElement.style.setProperty("--vvh", `${vv.height}px`); scrollTo(0, 0); };
    vv.addEventListener("resize", fit);
    vv.addEventListener("scroll", fit);
  }

  let thisDevice = null; // device id of this browser's push subscription, once known
  function hydrate(root = document) {
    for (const t of root.querySelectorAll("time[datetime]")) {
      const d = new Date(t.getAttribute("datetime"));
      t.title = d.toLocaleString();
      t.textContent = relativeTime(d, new Date());
    }
    for (const li of root.querySelectorAll("[data-device]")) {
      li.querySelector(".chip.this").hidden = li.dataset.device !== thisDevice;
    }
  }
  hydrate();

  function showOffline(offline) {
    const banner = $("offline");
    if (banner) banner.hidden = !offline;
  }
  addEventListener("online", () => { showOffline(false); poll(); });
  addEventListener("offline", () => showOffline(true));
  showOffline(!navigator.onLine);

  function badge() {
    if (!signedIn || !("setAppBadge" in navigator)) return;
    const n = Number(document.body.dataset.pending);
    (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
  }
  badge();

  function flash(text, error = false) {
    const slot = $("flash-slot");
    if (!slot) return;
    slot.innerHTML = "";
    const p = document.createElement("p");
    p.className = error ? "flash error" : "flash";
    p.setAttribute("role", "status");
    p.tabIndex = -1;
    p.textContent = text;
    slot.append(p);
    p.focus({ preventScroll: true });
  }

  // ----- live refresh -----
  // Replace every data-live region with the same region from a freshly rendered page. Elements
  // marked data-keep (the push controls, which hold script state) are carried over by id.
  let busy = false;
  function apply(html) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const regions = doc.querySelectorAll("[data-live]");
    if (!regions.length) { location.reload(); return; } // not a signed-in screen any more
    for (const fresh of regions) {
      const old = document.querySelector(`[data-live="${fresh.dataset.live}"]`);
      if (!old) continue;
      for (const keep of old.querySelectorAll("[data-keep]")) {
        const slot = fresh.querySelector(`#${CSS.escape(keep.id)}`);
        if (slot) slot.replaceWith(keep);
      }
      // Rows the owner opened stay open.
      const open = new Set([...old.querySelectorAll("details[open][id]")].map((d) => d.id));
      for (const d of fresh.querySelectorAll("details[id]")) if (open.has(d.id)) d.open = true;
      old.replaceWith(fresh);
    }
    for (const k of ["pending", "version"]) document.body.dataset[k] = doc.body.dataset[k] ?? "";
    hydrate();
    badge();
    document.querySelector("#flash-slot .flash")?.focus({ preventScroll: true });
  }

  // A background refresh is checked again when its response arrives: the owner may have started
  // typing, opened a confirm or submitted something meanwhile, and a submit's own response
  // (which bumps `generation`) must never be overwritten by an older page.
  let generation = 0;
  async function refresh() {
    if (!signedIn) return;
    const started = generation;
    const resp = await fetch(location.pathname, { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (!resp.ok) return;
    const html = await resp.text();
    if (started === generation && canRefresh(state())) apply(html);
  }

  const state = () => ({
    visible: document.visibilityState === "visible", online: navigator.onLine, busy,
    dialogOpen: Boolean($("confirm")?.open), typing: Boolean(document.activeElement?.matches("input,textarea")),
    dirty: [...document.querySelectorAll("input[type=text],textarea")].some((i) => i.value !== ""),
    secret: Boolean(document.querySelector(".secret")),
  });

  let polling = false;
  async function poll() {
    if (!signedIn || polling || !canRefresh(state())) return;
    polling = true;
    try {
      const resp = await fetch("/poll", { credentials: "same-origin" });
      if (resp.status === 401) { location.reload(); return; } // session ended: show sign-in
      if (!resp.ok) return;
      const { v } = await resp.json();
      if (v !== document.body.dataset.version && canRefresh(state())) await refresh();
    } catch (_) { /* offline or flaky; the next poll tries again */ } finally { polling = false; }
  }
  if (signedIn) setInterval(poll, 10000);
  addEventListener("focus", poll);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    swReady?.then((r) => r.update()).catch(() => {});
    poll();
  });

  // ----- forms: confirm, submit in place, block while offline, stop double submits -----
  const dialog = $("confirm");
  function askConfirm(form) {
    return new Promise((resolve) => {
      if (!dialog?.showModal) return resolve(confirm(form.dataset.confirm));
      $("confirm-text").textContent = form.dataset.confirm;
      $("confirm-ok").textContent = form.querySelector("button")?.textContent.replace(/…$/, "") || "Confirm";
      dialog.returnValue = "";
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "ok"), { once: true });
      dialog.showModal();
    });
  }

  function errorText(html) {
    return new DOMParser().parseFromString(html, "text/html").querySelector(".flash.error")?.textContent || "";
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (form.method.toLowerCase() !== "post" || form.hasAttribute("data-native") || form.closest("dialog")) return;
    event.preventDefault();
    if (busy) return; // one submit at a time, or a later response could replace an earlier one (a new key)
    if (!navigator.onLine) {
      showOffline(true);
      $("offline").focus?.();
      return;
    }
    if (form.dataset.confirm && !(await askConfirm(form))) return;
    if (busy) return; // something else was submitted while the dialog was open
    const button = form.querySelector("button");
    const label = button?.textContent;
    if (button) { button.disabled = true; button.textContent += "…"; }
    busy = true;
    generation++; // any background refresh in flight is now stale
    const removingHere = form.closest("[data-device]")?.dataset.device === thisDevice;
    try {
      const resp = await fetch(form.action, { method: "POST", credentials: "same-origin",
        headers: { Accept: "text/html" }, body: new URLSearchParams(new FormData(form)) });
      const html = await resp.text();
      // Sent somewhere else (a request decided from its own screen goes back to the list): go there.
      // A direct 200 (a new key) and a redirect back here are applied in place.
      if (resp.redirected && new URL(resp.url).pathname !== location.pathname) { location.replace(resp.url); return; }
      if (!resp.ok) { flash(errorText(html) || `That didn't save (HTTP ${resp.status}). Reload and try again.`, true); return; }
      if (removingHere) unsubscribeHere?.(); // the server dropped this device; the browser must too, or it re-registers
      apply(html);
    } catch (_) {
      flash("Couldn't reach the server. Check your connection and try again.", true);
    } finally {
      busy = false;
      if (button && button.isConnected) { button.disabled = false; button.textContent = label; }
    }
  });

  document.addEventListener("click", async (event) => {
    const copy = event.target.closest("#copy-key");
    if (!copy) return;
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

  // A notification arrived: something changed, so refresh whatever screen is open.
  navigator.serviceWorker?.addEventListener("message", (event) => {
    if (event.data?.type === "push" && signedIn && canRefresh(state())) refresh().catch(() => {});
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
    if (!resp.ok) throw Object.assign(new Error(data.error || `server returned ${resp.status}`), { status: resp.status });
    return data;
  }

  // auto: a background re-sync rather than the owner tapping Turn on. The server refuses those
  // (410) for a device the owner removed, so a removal sticks.
  async function save(subscription, replaces, auto = false) {
    const { device } = await post("/push/subscribe", { subscription: subscription.toJSON(), label: navigator.userAgent, replaces, auto });
    thisDevice = device;
    hydrate();
    return device;
  }

  // Keeps the server's copy current: moves to a new subscription if the server's push key was
  // rotated (see rotateIfKeyChanged).
  const currentSubscription = (registration, key) =>
    rotateIfKeyChanged(registration, key, (sub, old) => save(sub, old, true));

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

  let unsubscribeHere = null; // set once this device's subscription is known
  async function setUpPush() {
    const e = env();
    let state = pushState({ ...e, subscribed: false });
    if (state === "ios-install" || state === "unsupported" || !swReady || !signedIn) {
      if ($("push-nudge")) $("push-nudge").hidden = state !== "ios-install";
      return render(state);
    }
    const registration = await swReady;
    let sub = null, removedHere = false;
    try {
      sub = e.permission === "granted" ? await currentSubscription(registration, vapid) : null;
      // Re-register now and then (always on this screen) in case the server lost or removed it.
      const last = Number(localStorage.getItem("apm-push-sync") || 0);
      if (sub && (status || Date.now() - last > 3600000)) {
        await save(sub, undefined, true);
        localStorage.setItem("apm-push-sync", String(Date.now()));
      }
    } catch (err) {
      if (err.status === 410) {
        await (await registration.pushManager.getSubscription())?.unsubscribe().catch(() => {});
        sub = null;
        removedHere = true;
      } else {
        console.warn("couldn't sync push subscription", err);
      }
    }
    unsubscribeHere = () => {
      sub?.unsubscribe().catch(() => {});
      sub = null;
      thisDevice = null;
      render("off", "This device was removed from notifications. Turn them on again to get alerts here.");
    };
    state = pushState({ ...e, subscribed: Boolean(sub) });
    if ($("push-nudge")) $("push-nudge").hidden = state !== "off";
    render(state, removedHere ? "This device was removed from notifications. Turn them on again to get alerts here." : undefined);
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
        refresh().catch(() => {}); // the device list now includes this device
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
        thisDevice = null;
        render("off", "Notifications are off for this device.");
        refresh().catch(() => {});
      } catch (err) {
        render("on", `Couldn't turn off notifications: ${err.message}`);
      }
    };
  }

  setUpPush().catch((err) => render("unsupported", `Couldn't check notifications: ${err.message}`));
}
