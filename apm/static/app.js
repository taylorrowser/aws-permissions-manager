// Dashboard behaviour: confirm prompts, push notification sign-up, refresh when reopened.
document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !confirm(message)) event.preventDefault();
});

const loadedAt = Date.now();
document.addEventListener("visibilitychange", () => {
  // Reopening the app from the home screen or a notification shows fresh requests.
  if (document.visibilityState === "visible" && Date.now() - loadedAt > 30000 && !document.querySelector(".secret")) {
    location.reload();
  }
});

function keyBytes(base64url) {
  const pad = "=".repeat((4 - (base64url.length % 4)) % 4);
  const raw = atob((base64url + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}

async function setUpPush() {
  const status = document.getElementById("push-status");
  const button = document.getElementById("enable-push");
  if (!status) return;
  if (!("serviceWorker" in navigator)) {
    status.textContent = "This browser doesn't support notifications.";
    return;
  }
  const registration = await navigator.serviceWorker.register("/sw.js");
  const standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
  if (!("PushManager" in window)) {
    status.textContent = ios && !standalone
      ? "On iPhone: tap Share, then Add to Home Screen. Open AWS Permissions from your home screen and enable notifications there."
      : "This browser doesn't support push notifications.";
    return;
  }
  const existing = await registration.pushManager.getSubscription();
  if (existing && Notification.permission === "granted") {
    status.textContent = "Notifications are on for this device.";
    // Re-register in case the server lost it (for example after the device was removed).
    fetch("/push/subscribe", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subscription: existing.toJSON(), label: navigator.userAgent }) });
    return;
  }
  if (Notification.permission === "denied") {
    status.textContent = "Notifications are blocked for this site. Allow them in your browser or iOS settings.";
    return;
  }
  status.textContent = "Notifications are off for this device.";
  button.hidden = false;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      if ((await Notification.requestPermission()) !== "granted") {
        status.textContent = "Notification permission was not granted.";
        return;
      }
      const subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true, applicationServerKey: keyBytes(status.dataset.vapid),
      });
      const resp = await fetch("/push/subscribe", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subscription: subscription.toJSON(), label: navigator.userAgent }) });
      if (!resp.ok) throw new Error(`server returned ${resp.status}`);
      location.reload();
    } catch (err) {
      status.textContent = `Couldn't enable notifications: ${err.message}`;
    } finally {
      button.disabled = false;
    }
  });
}

setUpPush();
