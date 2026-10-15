// Owner web app behaviour. Pages work without it; this adds live refresh (the page polls /poll
// while visible and swaps its data-live regions when something changed), the Requests reading pane
// (rows open in place on wide screens), keyboard shortcuts, in-page form submits, toasts, confirm
// dialogs, offline and double-submit protection, local times, install help and push notification
// sign-up.
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
  if (minutes < 0) { // a grant's end: a countdown
    const left = -minutes, hours = Math.floor(left / 60);
    if (hours >= 48) return `in ${Math.round(hours / 24)} days`;
    return hours ? `in ${hours} h${left % 60 ? ` ${left % 60} min` : ""}` : `in ${left} min`;
  }
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

// Orders everything that replaces the screen, so a slow, older response never lands on top of a
// newer one. Opening a row and submitting a form each claim the screen: a row load that another
// open or a submit overtook is dropped. A background refresh applies only if nothing claimed the
// screen while it loaded and the owner is idle, and none starts while a row is loading. One submit
// at a time, and no row opens during one. claim() drops whatever is loading (before a confirm).
// load(url) resolves to a page (or null); apply(page, {url, background}) puts it on screen.
function createPager({ load, apply, idle }) {
  let latest = 0, busy = false, opening = 0;
  return {
    get busy() { return busy; },
    get loading() { return opening !== 0; }, // a row is on its way into the pane
    claim() { latest++; },
    async open(url) {
      if (busy) return false;
      const mine = ++latest;
      opening = mine;
      try {
        const page = await load(url);
        if (mine !== latest || !page) return false;
        apply(page, { url, background: false });
        return true;
      } finally { if (opening === mine) opening = 0; }
    },
    async refresh(url) {
      if (busy || opening || !idle()) return false;
      const at = latest;
      const page = await load(url);
      if (at !== latest || busy || !page || !idle()) return false;
      apply(page, { url, background: true });
      return true;
    },
    async submit(send) {
      if (busy) return false;
      busy = true;
      latest++;
      try { await send(); return true; } finally { busy = false; }
    },
  };
}

// Screens that are the Requests inbox: the list, a request, a connect request.
function isInboxPath(path) {
  return /^\/(requests\/\d{1,12}|connect\/[A-Z0-9]{4}-[A-Z0-9]{4})?$/.test(path);
}

// What to do with a form's response. here: the current path. "error": show it inline; "go": load
// another screen; "swap": another inbox URL, put in place; "apply": same screen, put in place. A
// refused approval ("Review it again") comes back to the same request, so the pane shows the
// request as it is now with the error next to Approve.
function afterSubmit({ ok, redirected, url }, here) {
  if (!ok) return "error";
  const path = redirected ? new URL(url, "http://x").pathname : here;
  if (path === here) return "apply";
  return isInboxPath(path) && isInboxPath(here) ? "swap" : "go";
}

// The digest an open request's Approve submits. A background refresh may redraw the pane with a
// changed request; Approve keeps the digest of what the owner was looking at, so the server
// refuses it ("Review it again") instead of approving changes nobody saw.
function digestToSubmit({ background, sameRequest, seen, fresh }) {
  return background && sameRequest && seen ? seen : fresh;
}

// Back or Forward while the Requests screen is open. The pane must follow the URL, so a pending
// confirm (for the request being left) is cancelled first; mid-submit the page simply reloads.
function onHistory({ dialogOpen, busy }) {
  if (busy) return "reload";
  return dialogOpen ? "cancel-then-open" : "open";
}

// Decided rows to carry over when a refresh redraws the list: rows loaded past the fresh first
// page stay (ids are newest first); rows the fresh page has are taken from it.
function keepDecided(freshIds, oldIds) {
  const fresh = new Set(freshIds), floor = Math.min(...freshIds);
  return oldIds.filter((id) => !fresh.has(id) && (!freshIds.length || id < floor));
}

// Requests keyboard: ↑/↓ (and k/j) move between rows, a approves, r rejects. Not while typing,
// not with modifiers.
function keyCommand(e, typing) {
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return null;
  return { ArrowDown: "next", j: "next", ArrowUp: "prev", k: "prev", a: "approve", r: "reject" }[e.key] || null;
}

// The size check on the card (pages.request_pane): the grants policy with every grant permanent is
// `size` characters, and each time-limited grant adds `perLimit`. Returns the warning to show, or "".
function overLimit(size, perLimit, limit, policyName, hours) {
  const total = size + perLimit * hours.filter((h) => h !== "0").length;
  if (total <= limit) return "";
  const n = (x) => x.toLocaleString("en-US");
  return `Too big with these time limits: the inline policy ${policyName} would be ${n(total)} characters, ` +
    `${n(total - limit)} over the ${n(limit)}-character limit. Make a grant permanent to approve.`;
}

// The row to move to from `current` (an id, or null for none) in `ids`.
function step(ids, current, dir) {
  if (!ids.length) return null;
  const i = ids.indexOf(current);
  if (i < 0) return dir === "next" ? ids[0] : ids[ids.length - 1];
  return ids[Math.min(ids.length - 1, Math.max(0, i + (dir === "next" ? 1 : -1)))];
}

if (typeof module !== "undefined") {
  module.exports = { isIOS, pushState, deniedHelp, keyBytes, sameKey, legacyTarget, relativeTime, rotateIfKeyChanged,
    canRefresh, createPager, isInboxPath, afterSubmit, onHistory, digestToSubmit, keepDecided, keyCommand, step,
    overLimit };
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
      const now = new Date();
      t.textContent = ("ends" in t.dataset ? (d > now ? "Ends " : "Ended ") : "") + relativeTime(d, now);
    }
    for (const li of root.querySelectorAll("[data-device]")) {
      li.querySelector(".badge.this").hidden = li.dataset.device !== thisDevice;
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

  // Errors stay inline, where they happened; anything else is a toast.
  function flash(text) {
    const slot = $("flash-slot");
    if (!slot) return;
    slot.innerHTML = "";
    const p = document.createElement("p");
    p.className = "flash error";
    p.setAttribute("role", "alert");
    p.tabIndex = -1;
    p.textContent = text;
    slot.append(p);
    p.focus({ preventScroll: true });
  }

  function toast(text) {
    const old = $("toast");
    if (!old || !text) return;
    const fresh = old.cloneNode(); // a new element restarts the fade
    fresh.textContent = text;
    old.replaceWith(fresh);
  }

  const wide = () => matchMedia("(min-width: 900px)").matches;
  const pane = () => document.querySelector("[data-live=pane]");

  function markSelected() {
    const id = pane()?.dataset.id || "";
    for (const a of document.querySelectorAll("a.item")) {
      if (id && a.id === id) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
    }
  }

  // ----- live refresh -----
  // Replace every data-live region with the same region from a freshly rendered page. Elements
  // marked data-keep (the push controls, which hold script state) are carried over by id, open
  // details stay open, Decided rows loaded so far stay, and the reading pane keeps its scroll
  // position and, on a background refresh, the digest the owner saw.
  function apply(html, { background = false } = {}) {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const regions = doc.querySelectorAll("[data-live]");
    if (!regions.length) { location.reload(); return; } // not a signed-in screen any more
    const focused = document.activeElement?.id;
    const oldDecided = [...document.querySelectorAll("#decided-list > li:not(.more)")];
    const oldMore = document.querySelector("#decided-list > .more");
    const oldPane = pane();
    const paneScroll = oldPane?.querySelector(".pane-body")?.scrollTop || 0;
    for (const fresh of regions) {
      const old = document.querySelector(`[data-live="${fresh.dataset.live}"]`);
      if (!old) continue;
      for (const keep of old.querySelectorAll("[data-keep]")) {
        const slot = fresh.querySelector(`#${CSS.escape(keep.id)}`);
        if (slot) slot.replaceWith(keep);
      }
      for (const pick of old.querySelectorAll("select[id]")) { // durations picked but not submitted yet
        const slot = fresh.querySelector(`select#${CSS.escape(pick.id)}`);
        if (slot) slot.value = pick.value;
      }
      const open = new Set([...old.querySelectorAll("details[open][id]")].map((d) => d.id));
      for (const d of fresh.querySelectorAll("details[id]")) if (open.has(d.id)) d.open = true;
      if (fresh.dataset.live === "pane") {
        const sameRequest = Boolean(fresh.dataset.id) && fresh.dataset.id === old.dataset.id;
        const seen = old.querySelector("input[name=digest]")?.value;
        for (const input of fresh.querySelectorAll("input[name=digest]")) {
          input.value = digestToSubmit({ background, sameRequest, seen, fresh: input.value });
        }
      }
      old.replaceWith(fresh);
    }
    document.querySelectorAll("form[data-size]").forEach(checkSize); // picks restored above
    const list = $("decided-list");
    if (list && oldDecided.length) {
      const id = (li) => Number(li.querySelector("a")?.id.slice(4));
      const keep = new Set(keepDecided([...list.querySelectorAll(":scope > li:not(.more)")].map(id), oldDecided.map(id)));
      const carried = oldDecided.filter((li) => keep.has(id(li)));
      const freshMore = list.querySelector(":scope > .more");
      for (const li of carried) freshMore ? freshMore.before(li) : list.append(li);
      if (carried.length) { // the old list already reached further; its sentinel (or its end) wins
        freshMore?.remove();
        if (oldMore) list.append(oldMore);
        // Shown at once, then reloaded: rows below the first page may have changed (a revoke, or
        // an older request decided since).
        reloadDecided(Math.min(...carried.map(id)));
      }
    }
    const main = doc.querySelector("main");
    if (main?.dataset.view) document.querySelector("main").dataset.view = main.dataset.view;
    document.title = doc.title;
    for (const k of ["pending", "version"]) document.body.dataset[k] = doc.body.dataset[k] ?? "";
    toast(doc.getElementById("toast")?.textContent.trim());
    const freshPane = pane();
    if (freshPane && oldPane && freshPane.dataset.id === oldPane.dataset.id) {
      const body = freshPane.querySelector(".pane-body");
      if (body) body.scrollTop = paneScroll;
    }
    markSelected();
    hydrate();
    badge();
    watchOlder();
    const error = document.querySelector("#flash-slot .flash");
    if (error) error.focus({ preventScroll: true });
    else if (focused && $(focused)) $(focused).focus({ preventScroll: true });
  }

  // Replace the Decided rows below the first page, from `oldest` up to (not including) the fresh
  // first page's last row, with what the server says now. A later redraw supersedes this one.
  let decidedReload = 0;
  async function reloadDecided(oldest) {
    const mine = ++decidedReload;
    try {
      const list = $("decided-list");
      const firstPage = [...list.querySelectorAll(":scope > li:not(.more)")].slice(0, 10);
      const before = Number(firstPage[firstPage.length - 1]?.querySelector("a")?.id.slice(4));
      if (!before) return;
      const resp = await fetch(`/decided?before=${before}&since=${oldest}`, { credentials: "same-origin" });
      if (!resp.ok || mine !== decidedReload) return;
      const { html } = await resp.json();
      const current = $("decided-list");
      if (mine !== decidedReload || !current) return;
      const t = document.createElement("template");
      t.innerHTML = html;
      const keep = [...current.querySelectorAll(":scope > li:not(.more)")].slice(0, 10);
      current.replaceChildren(...keep, ...t.content.children);
      hydrate(current);
      markSelected();
      watchOlder();
    } catch (_) { /* rows stay as they were; the next refresh tries again */ }
  }

  async function load(url) {
    const resp = await fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } });
    if (resp.status === 401) { location.reload(); return null; }
    return resp.ok ? resp.text() : null;
  }

  const changed = (el) => el.type === "hidden" || el.type === "submit" ? false
    : el.matches("select") ? [...el.options].some((o) => o.selected !== o.defaultSelected)
      : el.type === "checkbox" || el.type === "radio" ? el.checked !== el.defaultChecked : el.value !== el.defaultValue;
  const typingNow = () => Boolean(document.activeElement?.matches("input:not([type=hidden]),textarea,select,[contenteditable]"));
  const state = () => ({
    visible: document.visibilityState === "visible", online: navigator.onLine, busy: pager.busy,
    dialogOpen: Boolean($("confirm")?.open), typing: typingNow(),
    dirty: [...document.querySelectorAll("input,textarea,select")].some(changed), // any unsaved choice or text
    secret: Boolean(document.querySelector(".secret")),
  });
  const pager = createPager({ load, apply: (html, how) => apply(html, how), idle: () => canRefresh(state()) });
  const refresh = () => (signedIn ? pager.refresh(location.pathname) : Promise.resolve(false));

  let polling = false;
  async function poll() {
    if (!signedIn || polling || !canRefresh(state())) return;
    polling = true;
    try {
      const resp = await fetch("/poll", { credentials: "same-origin" });
      if (resp.status === 401) { location.reload(); return; } // session ended: show sign-in
      if (!resp.ok) return;
      const { v } = await resp.json();
      if (v !== document.body.dataset.version) await refresh();
    } catch (_) { /* offline or flaky; the next poll tries again */ } finally { polling = false; }
  }
  if (signedIn) setInterval(poll, 10000);
  if (signedIn) setInterval(() => hydrate(), 30000); // countdowns and "5 min ago" keep moving while idle
  addEventListener("focus", poll);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState !== "visible") return;
    swReady?.then((r) => r.update()).catch(() => {});
    poll();
  });

  // ----- Requests: the reading pane, Decided paging and the keyboard -----
  // On wide screens a row opens in the pane without a page load; the URL still follows it. On
  // phones a request is its own page, so links work as links.
  // The URL moves once the row has loaded, so a failed load leaves URL and pane together and the
  // row can be opened again.
  async function openPane(path) {
    if (path === location.pathname || pager.busy || $("confirm")?.open) return;
    try {
      if (await pager.open(path)) history.pushState(null, "", path);
    } catch (_) { flash("Couldn't reach the server. Check your connection and try again."); }
  }
  document.addEventListener("click", (event) => {
    const a = event.target.closest("a.item");
    if (!a || !wide() || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    openPane(a.getAttribute("href"));
  });
  addEventListener("popstate", () => {
    if (page !== "requests" || !isInboxPath(location.pathname)) return;
    const how = onHistory({ dialogOpen: Boolean($("confirm")?.open), busy: pager.busy });
    if (how === "reload") { location.reload(); return; }
    if (how === "cancel-then-open") $("confirm").close(); // the confirm was for the request being left
    pager.open(location.pathname).catch(() => location.reload());
  });

  // Decided loads 10 rows at a time as its end scrolls into view (or Older is tapped).
  let loadingOlder = false, olderFailed = false;
  async function loadOlder() {
    const more = document.querySelector("#decided-list > .more");
    if (!more || loadingOlder || !$("decided")?.open) return;
    loadingOlder = true;
    try {
      const resp = await fetch(`/decided?before=${encodeURIComponent(more.dataset.before)}`, { credentials: "same-origin" });
      if (!resp.ok) { olderFailed = true; return; }
      const { html } = await resp.json();
      const list = $("decided-list"), sentinel = list?.querySelector(":scope > .more");
      if (!sentinel || sentinel.dataset.before !== more.dataset.before) return; // a refresh moved on meanwhile
      const t = document.createElement("template");
      t.innerHTML = html;
      const have = new Set([...list.querySelectorAll("a.item")].map((a) => a.id));
      for (const li of [...t.content.children]) {
        if (!li.classList.contains("more") && !have.has(li.querySelector("a")?.id)) sentinel.before(li);
      }
      const next = t.content.querySelector(".more");
      if (next) sentinel.replaceWith(next); else sentinel.remove();
      hydrate(list);
      markSelected();
      olderFailed = false;
    } catch (_) {
      olderFailed = true; // Older stays as a button; scrolling doesn't retry in a loop
    } finally {
      loadingOlder = false;
      watchOlder();
    }
  }
  const olderObserver = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => { if (entries.some((x) => x.isIntersecting)) loadOlder(); }) : null;
  function watchOlder() {
    if (!olderObserver) return;
    olderObserver.disconnect();
    const more = document.querySelector("#decided-list > .more");
    if (more && !olderFailed) olderObserver.observe(more);
  }
  watchOlder();
  document.addEventListener("click", (event) => {
    if (!event.target.closest("#decided-list > .more button")) return;
    olderFailed = false;
    loadOlder();
  });
  document.addEventListener("toggle", (event) => { if (event.target.id === "decided") watchOlder(); }, true);

  document.addEventListener("keydown", (event) => {
    if (page !== "requests") return;
    const command = keyCommand(event, typingNow() || Boolean($("confirm")?.open));
    if (!command) return;
    if (command === "approve" || command === "reject") {
      const button = document.querySelector(`.pane-actions button.${command}`);
      // Not while another row is loading: the pane on screen isn't the one selected.
      if (!button || button.disabled || pager.busy || pager.loading) return;
      event.preventDefault();
      button.click(); // the form's own submit: confirm, one at a time, digest
      return;
    }
    const rows = [...document.querySelectorAll("a.item")].filter((a) => a.offsetParent !== null);
    const current = document.activeElement?.matches("a.item") ? document.activeElement.id : pane()?.dataset.id || null;
    const next = $(step(rows.map((a) => a.id), current, command) || "");
    if (!next) return;
    event.preventDefault();
    next.focus();
    next.scrollIntoView({ block: "nearest" });
    if (wide()) openPane(next.getAttribute("href"));
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
    // Read attributes, not the method and action properties: a field named "action" (Remove on Projects) shadows them.
    if ((form.getAttribute("method") || "").toLowerCase() !== "post" || form.hasAttribute("data-native") || form.closest("dialog")) return;
    event.preventDefault();
    if (pager.busy) return; // one submit at a time, or a later response could replace an earlier one (a new key)
    if (!navigator.onLine) {
      showOffline(true);
      $("offline").focus?.();
      return;
    }
    if (form.dataset.confirm) {
      pager.claim(); // a row still loading must not replace the pane behind the dialog
      if (!(await askConfirm(form))) return;
    }
    const button = form.querySelector("button:not([type=button])"); // not e.g. Copy note
    const label = button?.textContent;
    const removingHere = form.closest("[data-device]")?.dataset.device === thisDevice;
    await pager.submit(async () => { // false if something else was submitted while the dialog was open
      if (button) { button.disabled = true; button.textContent += "…"; }
      try {
        const resp = await fetch(form.getAttribute("action"), { method: "POST", credentials: "same-origin",
          headers: { Accept: "text/html" }, body: new URLSearchParams(new FormData(form)) });
        const html = await resp.text();
        const next = afterSubmit(resp, location.pathname);
        if (next === "go") { location.replace(resp.url); return; }
        if (next === "error") { flash(errorText(html) || `That didn't save (HTTP ${resp.status}). Reload and try again.`); return; }
        if (removingHere) unsubscribeHere?.(); // the server dropped this device; the browser must too, or it re-registers
        if (next === "swap") history.replaceState(null, "", new URL(resp.url).pathname);
        apply(html);
      } catch (_) {
        flash("Couldn't reach the server. Check your connection and try again.");
      } finally {
        if (button && button.isConnected) { button.disabled = false; button.textContent = label; checkSize(button.form); }
      }
    });
  });

  // Only offer Approve while the chosen durations fit (see overLimit). Runs when a picker changes,
  // and after a refresh or a submit, which can restore picks or re-enable the button.
  function checkSize(form) {
    if (!form || !form.dataset.size) return;
    const d = form.dataset;
    const hours = [...form.elements].filter((el) => el.tagName === "SELECT").map((el) => el.value);
    const warning = overLimit(Number(d.size), Number(d.perLimit), Number(d.limit), d.policy, hours);
    // getAttribute: form.id would be the form's hidden "id" input.
    const slot = $(form.getAttribute("id").replace("approve-", "size-")), button = form.querySelector("button.approve");
    if (slot) { slot.textContent = warning; slot.hidden = !warning; }
    if (button) button.disabled = Boolean(warning);
  }
  document.addEventListener("change", (event) => checkSize(event.target.form));

  document.addEventListener("click", async (event) => {
    const copy = event.target.closest("#copy-key, button.copy");
    if (!copy) return;
    const target = $(copy.dataset.target);
    try {
      await navigator.clipboard.writeText(target.value ?? target.textContent);
      copy.textContent = "Copied";
    } catch (_) {
      copy.textContent = copy.id === "copy-key" ? "Select the key and copy it" : "Select the note and copy it";
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
    if (event.data?.type === "push") refresh().catch(() => {});
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
