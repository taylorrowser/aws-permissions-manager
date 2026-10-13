"""The hosted service: one Lambda behind API Gateway at https://$DOMAIN.

- Owner dashboard (installable web app): WorkOS AuthKit sign-in, approve/reject/revoke, API keys,
  push notification devices.
- Agent API (Bearer API key): list projects and grants, request permissions, check requests,
  get short-lived credentials for a project role.
"""
import base64
import fnmatch
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import traceback
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlencode

from . import pages, policy
from .broker import Broker, BrokerError
from .store import CONNECT_SECONDS, PENDING_LIMIT, Conflict, Store, subscription_id

STATIC = Path(__file__).parent / "static"
STATIC_FILES = {
    "/sw.js": ("sw.js", "text/javascript"),
    "/app.js": ("app.js", "text/javascript"),
    "/app.css": ("app.css", "text/css"),
    "/offline.html": ("offline.html", "text/html; charset=utf-8"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
}
# Changes whenever any static file changes. Pages load /app.js?v=VERSION, so those URLs can be
# cached forever, and the service worker uses it to name (and replace) its cache.
ASSET_VERSION = hashlib.sha256(b"".join((STATIC / n).read_bytes() for n, _ in STATIC_FILES.values())).hexdigest()[:12]
# Checked by the browser on every start, so app updates arrive the next time the app opens.
REVALIDATE = {"/sw.js", "/manifest.webmanifest", "/offline.html"}
# Owner screens. Signed-out visits show the sign-in page and come back here after signing in.
SCREENS = re.compile(r"/(projects|devices|keys|requests/[0-9]{1,12}|connect/[A-Z0-9]{4}-[A-Z0-9]{4})?")
SESSION_COOKIE = "__Host-apm_session"
OAUTH_COOKIE = "__Host-apm_oauth"
SESSION_SECONDS = 30 * 24 * 3600
WORKOS_API = "https://api.workos.com/user_management"
CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")


class Settings:
    def __init__(self, domain, workos_client_id, owner_emails, vapid_public, session_secret,
                 vapid_private="", workos_api_key="", stage="prod"):
        self.domain, self.origin = domain, f"https://{domain}"
        self.stage = stage or "prod"
        self.workos_client_id, self.workos_api_key = workos_client_id, workos_api_key
        self.owner_emails = {e.strip().lower() for e in owner_emails.split(",") if e.strip()}
        self.vapid_public, self.vapid_private = vapid_public, vapid_private
        self.session_secret = session_secret.encode()

    @classmethod
    def from_env(cls):
        import boto3
        ssm = boto3.client("ssm")

        def param(name, default=None):
            try:
                return ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound:
                if default is None:
                    raise
                return default

        prefix = os.environ.get("PARAM_PREFIX", "/apm")
        return cls(os.environ["DOMAIN"], os.environ["WORKOS_CLIENT_ID"], os.environ["OWNER_EMAILS"],
                   os.environ["VAPID_PUBLIC_KEY"], param(f"{prefix}/session-secret"),
                   param(f"{prefix}/vapid-private-key", ""), param(f"{prefix}/workos-api-key", ""),
                   os.environ.get("APM_STAGE", "prod"))


class Response:
    def __init__(self, status=200, body="", content_type="text/html; charset=utf-8", headers=None, cookies=()):
        self.status, self.body, self.content_type = status, body, content_type
        self.headers, self.cookies = dict(headers or {}), list(cookies)

    def lambda_result(self):
        binary = isinstance(self.body, bytes)
        headers = {"Content-Type": self.content_type, "Cache-Control": "no-store",
                   "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                   "Referrer-Policy": "same-origin", "Strict-Transport-Security": "max-age=63072000",
                   **self.headers}
        return {"statusCode": self.status, "headers": headers, "cookies": self.cookies,
                "isBase64Encoded": binary,
                "body": base64.b64encode(self.body).decode() if binary else self.body}


def json_response(data, status=200):
    return Response(status, json.dumps(data), "application/json")


def redirect(location, cookies=()):
    return Response(303, "", headers={"Location": location}, cookies=cookies)


class Request:
    def __init__(self, method, path, query=None, headers=None, cookies=None, body=b""):
        self.method, self.path = method.upper(), path
        self.query = query or {}
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.cookies = cookies or {}
        self.body = body

    @classmethod
    def from_lambda(cls, event):
        body = event.get("body") or ""
        body = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode()
        jar = SimpleCookie()
        for c in event.get("cookies") or []:
            try:
                jar.load(c)
            except Exception:
                pass
        return cls(event["requestContext"]["http"]["method"], event.get("rawPath", "/"),
                   event.get("queryStringParameters") or {}, event.get("headers") or {},
                   {k: m.value for k, m in jar.items()}, body)

    def form(self):
        return {k: v[0] for k, v in parse_qs(self.body.decode(), keep_blank_values=True).items()}

    def json(self):
        try:
            data = json.loads(self.body or b"{}")
        except ValueError:
            raise ApiError(400, "body must be JSON")
        if not isinstance(data, dict):
            raise ApiError(400, "body must be a JSON object")
        return data


class ApiError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


# ---------- signed cookies ----------

def sign(settings, data):
    raw = base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()
    mac = hmac.new(settings.session_secret, raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{mac}"


def unsign(settings, value):
    try:
        raw, mac = (value or "").rsplit(".", 1)
    except ValueError:
        return None
    if not hmac.compare_digest(mac, hmac.new(settings.session_secret, raw.encode(), hashlib.sha256).hexdigest()):
        return None
    data = json.loads(base64.urlsafe_b64decode(raw))
    return data if data.get("x", 0) > time.time() else None


def cookie(name, value, max_age):
    return f"{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={max_age}"


# ---------- the app ----------

class App:
    def __init__(self, settings, store, broker, http=None):
        self.s, self.store, self.broker = settings, store, broker
        self.http = http or _http_json

    def __call__(self, req):
        try:
            return self.route(req)
        except ApiError as e:
            return json_response({"error": str(e)}, e.status)
        except Exception:
            traceback.print_exc()
            if req.path.startswith("/api/"):
                return json_response({"error": "internal error"}, 500)
            return Response(500, pages.error_page(self, "Something went wrong, and nothing may have been saved. "
                                                        "Reload to check, or see the Lambda logs.", "/"))

    def route(self, req):
        p, m = req.path, req.method
        if p in STATIC_FILES and m == "GET":
            return self.static(req)
        if p == "/healthz":
            return json_response({"ok": True})
        if p.startswith("/api/"):
            return self.api(req)
        if p == "/login" and m == "GET":
            return self.login(req.query.get("next", "/"))
        if p == "/auth/callback" and m == "GET":
            return self.callback(req)

        owner = self.owner(req)
        if p == "/poll" and m == "GET":
            # Polled by open pages (session-authenticated) to learn when something changed.
            if not owner:
                raise ApiError(401, "signed out")
            pending = len(self.store.list(status="pending")) + len(self.store.connects())
            return json_response({"v": state_version(self.store), "pending": pending})
        if m == "GET" and SCREENS.fullmatch(p):
            if not owner:
                return Response(200, pages.login_page(self, req.query.get("error", ""), p))
            return self.screen(req, owner)
        if m == "POST":
            json_call = p.startswith("/push/")
            if req.headers.get("origin") != self.s.origin:
                return Response(403, pages.error_page(self, "Forbidden: that form came from another site."))
            if p == "/logout":  # works even when the session already expired
                return redirect("/", [cookie(SESSION_COOKIE, "", 0)])
            if not owner:
                if json_call:
                    raise ApiError(401, "signed out; reload the page and sign in again")
                return Response(403, pages.error_page(self, "You've been signed out, so nothing was changed. "
                                                            "Sign in and try again.", "/"))
            if p == "/action":
                return self.action(req.form(), owner)
            if json_call:
                return self.push_api(p, req.json())
        return Response(404, pages.error_page(self, "Not found."))

    def static(self, req):
        name, ctype = STATIC_FILES[req.path]
        data = (STATIC / name).read_bytes()
        if req.path == "/sw.js":
            data = data.replace(b"__VERSION__", ASSET_VERSION.encode())
        if req.path in REVALIDATE:
            cache = "no-cache"
        elif req.query.get("v") == ASSET_VERSION:
            cache = "public, max-age=31536000, immutable"
        else:
            cache = "public, max-age=300"
        return Response(200, data if ctype == "image/png" else data.decode(), ctype, headers={"Cache-Control": cache})

    def screen(self, req, owner):
        p, msg = req.path, req.query.get("msg", "")
        if p.startswith("/requests/"):
            r = self.store.get(int(p.rsplit("/", 1)[1]))
            if not r:
                return Response(404, pages.error_page(self, f"There is no request #{p.rsplit('/', 1)[1]}.", "/"))
            return Response(200, pages.request_page(self, owner, r, msg))
        if p.startswith("/connect/"):
            return Response(200, pages.connect_page(self, owner, p.rsplit("/", 1)[1], msg))
        view = {"/": pages.requests_page, "/projects": pages.projects_page,
                "/devices": pages.devices_page, "/keys": pages.keys_page}[p]
        return Response(200, view(self, owner, msg))

    # ----- owner auth (WorkOS AuthKit, PKCE) -----

    def owner(self, req):
        data = unsign(self.s, req.cookies.get(SESSION_COOKIE))
        return data["e"] if data and data.get("e") in self.s.owner_emails else None

    def login(self, next_path="/"):
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        url = f"{WORKOS_API}/authorize?" + urlencode({
            "client_id": self.s.workos_client_id, "redirect_uri": f"{self.s.origin}/auth/callback",
            "response_type": "code", "provider": "authkit", "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256"})
        oauth = sign(self.s, {"s": state, "v": verifier, "n": _safe_next(next_path), "x": int(time.time()) + 600})
        return redirect(url, [cookie(OAUTH_COOKIE, oauth, 600)])

    def callback(self, req):
        clear = cookie(OAUTH_COOKIE, "", 0)
        oauth = unsign(self.s, req.cookies.get(OAUTH_COOKIE))
        code, state = req.query.get("code"), req.query.get("state", "")
        if not oauth or not code or not hmac.compare_digest(state, oauth["s"]):
            return redirect("/?error=" + _q("Sign-in expired. Try again."), [clear])
        body = {"client_id": self.s.workos_client_id, "grant_type": "authorization_code",
                "code": code, "code_verifier": oauth["v"]}
        if self.s.workos_api_key:
            body["client_secret"] = self.s.workos_api_key
        try:
            user = self.http(f"{WORKOS_API}/authenticate", body)["user"]
        except Exception as e:
            print(f"WorkOS authenticate failed: {e}")
            return redirect("/?error=" + _q("Sign-in failed."), [clear])
        email = str(user.get("email", "")).lower()
        if not user.get("email_verified") or email not in self.s.owner_emails:
            print(f"Rejected sign-in for {email!r}")
            return redirect("/?error=" + _q("That account is not allowed to use this dashboard."), [clear])
        session = sign(self.s, {"e": email, "x": int(time.time()) + SESSION_SECONDS})
        return redirect(_safe_next(oauth.get("n", "/")), [clear, cookie(SESSION_COOKIE, session, SESSION_SECONDS)])

    # ----- owner actions -----

    def action(self, form, owner):
        op, back = form.get("op"), _safe_next(form.get("back", "/"))
        try:
            if op in ("approve_connect", "reject_connect"):
                c = self.store.decide_connect(form.get("code", ""), op == "approve_connect")
                verb = "Connected" if op == "approve_connect" else "Rejected"
                return redirect("/?msg=" + _q(f"{verb} agent {c['name']!r}."))
            if op == "create_key":
                name = re.sub(r"[^A-Za-z0-9 ._@-]", "", form.get("name", "")).strip()[:40] or "agent"
                secret = self.store.create_key(name)
                return Response(200, pages.keys_page(self, owner, f"Created API key {name!r}.", new_key=secret))
            msg = self.decide(form)
            # A decided request has nothing left to do on its own page; go back to the list.
            if op in ("approve", "reject") and back.startswith("/requests/"):
                back = "/"
            return redirect(back + "?msg=" + _q(msg))
        except (BrokerError, Conflict, ValueError) as e:
            return redirect(back + "?msg=" + _q(f"Error: {e}"))

    def decide(self, form):
        """Grant changes run entirely under the project's lease. The decision is recorded in
        DynamoDB first (conditional, strongly consistent), then the role's policy is rewritten
        from the project's approved requests, so IAM never holds a grant for a request that
        isn't approved and a stale IAM read can't bring a revoked grant back."""
        op = form.get("op")
        if op in ("approve", "reject"):
            seen = self.store.get(int(form["id"]))
            if not seen:
                return "That request is no longer pending."
            project = seen["project"]
            with self.store.lease(project):
                r = self.store.get(seen["id"], consistent=True)
                if not r or r["status"] != "pending":
                    return "That request is no longer pending."
                if r["digest"] != form.get("digest"):
                    return "That request changed after the page loaded. Review it again."
                if op == "reject":
                    self.store.set_status(r["id"], "rejected", form.get("note", "")[:500], expect="pending")
                    return f"Rejected request #{r['id']}."
                self.store.set_status(r["id"], "approved", expect="pending")
                try:
                    self.broker.sync(project, self.store.approved(project))
                except BrokerError:
                    # Refused before writing anything (e.g. the size limit): safe to undo.
                    self.store.set_status(r["id"], "pending", expect="approved")
                    raise
                except Exception as e:
                    # The write may or may not have reached IAM (e.g. a timeout after IAM applied
                    # it). Keep the approval recorded; Projects shows the mismatch and re-applies.
                    print(f"IAM sync for {project} failed after approving #{r['id']}: {e!r}")
                    return (f"Approved request #{r['id']}, but updating IAM failed ({type(e).__name__}). "
                            f"Open Projects and tap Re-apply decisions for {project}.")
                return f"Approved request #{r['id']} for {project}."
        if op == "revoke":
            project, sid = form["project"], form["sid"]
            with self.store.lease(project):
                if sid.startswith("Req") and sid[3:].isdigit():
                    r = self.store.get(int(sid[3:]), consistent=True)
                    if r and r["project"] == project and r["status"] == "approved":
                        self.store.set_status(r["id"], "revoked", expect="approved")
                # Rewriting from the approved requests drops this grant (and anything else not approved).
                try:
                    self.broker.sync(project, self.store.approved(project))
                except Exception as e:
                    print(f"IAM sync for {project} failed while revoking {sid}: {e!r}")
                    return (f"Error: recorded the revoke of {sid}, but updating IAM failed ({type(e).__name__}). "
                            f"It may still be active: open Projects and tap Re-apply decisions for {project}.")
            return f"Revoked {sid} from {project}."
        if op == "sync_project":
            project = form["project"]
            with self.store.lease(project):
                self.broker.sync(project, self.store.approved(project))
            return f"Re-applied your decisions to {project}."
        if op == "remove_project":
            project = form["project"]
            with self.store.lease(project):
                for r in self.store.approved(project):
                    self.store.set_status(r["id"], "revoked", "project removed", expect="approved")
                self.broker.remove_project(project)
            return f"Removed project {project} and its role."
        if op == "delete_key":
            self.store.delete_key(form.get("pk", ""))
            return "Deleted the API key. Agents using it can no longer connect."
        if op == "delete_device":
            self.store.remove_device(form.get("pk", ""))
            return "Removed the device from notifications."
        return "Unknown action."

    # ----- notifications -----

    def notify_safely(self, message, **kw):
        """For the agent API: the request is already saved, so a push problem must not fail the call."""
        try:
            return self.notify(message, **kw)
        except Exception as e:
            print(json.dumps({"event": "push_failed", "error": str(e)[:300]}))
            return {}

    def notify(self, message, only=None, ttl=86400):
        """Push to all devices (or the device ids in `only`). Payloads land on lock screens, so
        callers keep them to a title and a short line with no policy details or reasons. Returns
        {device id: (outcome, status)}; devices the push service says are gone are removed."""
        if not self.s.vapid_private:
            print(json.dumps({"event": "push_skipped", "reason": "no VAPID private key"}))
            return {}
        from . import push
        subs = [s for s in self.store.subscriptions() if only is None or s["pk"] in only]
        message = {**message, "pending": len(self.store.list(status="pending")) + len(self.store.connects())}
        results = push.deliver(subs, message, self.s.vapid_private, self.s.origin, ttl=ttl)
        for pk, (outcome, status) in results.items():
            print(json.dumps({"event": "push", "tag": message.get("tag", ""), "device": pk[4:16],
                              "outcome": outcome, "status": status}))
            try:
                if outcome == "gone":
                    self.store.delete_subscription(pk)
                else:
                    self.store.record_delivery(pk, outcome == "delivered", status)
            except Exception as e:  # the request is already saved; don't fail the agent's call
                print(json.dumps({"event": "push_bookkeeping_error", "device": pk[4:16], "error": str(e)[:200]}))
        return results

    def push_api(self, path, body):
        """JSON calls from the dashboard's script: register, unregister and test this device."""
        sub = body.get("subscription") or {}
        if path == "/push/subscribe":
            if not str(sub.get("endpoint", "")).startswith("https://") or not isinstance(sub.get("keys"), dict) \
                    or not sub["keys"].get("p256dh") or not sub["keys"].get("auth"):
                raise ApiError(400, "invalid subscription")
            device, replaces = subscription_id(sub["endpoint"]), str(body.get("replaces", ""))
            removed = [d for d in (device, subscription_id(replaces) if replaces else None)
                       if d and self.store.device_removed(d)]
            if body.get("auto") and removed:
                # Background re-syncs must not undo a removal; only tapping Turn on does. Mark the
                # new endpoint too, so a rotated subscription can't sneak back in later.
                self.store.remove_device(device)
                raise ApiError(410, "this device was removed from notifications")
            for d in removed:
                self.store.clear_removed(d)
            if replaces and replaces != sub["endpoint"]:
                self.store.delete_subscription(subscription_id(replaces))
            device = self.store.add_subscription(sub, str(body.get("label", "device")))
            return json_response({"ok": True, "device": device})
        if path == "/push/unsubscribe":
            self.store.delete_subscription(subscription_id(str(body.get("endpoint", ""))))
            return json_response({"ok": True})
        if path == "/push/test":
            only = None
            if body.get("endpoint"):
                only = {subscription_id(str(body["endpoint"]))}
                if not any(s["pk"] in only for s in self.store.subscriptions()):
                    raise ApiError(404, "this device isn't registered; turn notifications on again")
            if not self.s.vapid_private:
                raise ApiError(503, "push isn't configured on the server (no VAPID private key)")
            results = self.notify({"title": "AWS Permissions", "body": "Test notification: this device will be "
                                   "notified of new requests.", "url": "/devices", "tag": "test"}, only=only, ttl=300)
            return json_response({"results": [{"device": pk, "outcome": o, "status": st}
                                              for pk, (o, st) in results.items()]})
        raise ApiError(404, "unknown endpoint")

    # ----- agent API -----

    def api(self, req):
        if req.path.startswith("/api/connect") and req.method == "POST":
            return self.connect_api(req)
        auth = req.headers.get("authorization", "")
        key = self.store.find_key(auth[7:].strip()) if auth.lower().startswith("bearer ") else None
        if not key:
            raise ApiError(401, "missing or invalid API key; connect with the `connect` MCP tool or `apm login`")
        p, m = req.path, req.method
        if p == "/api/whoami" and m == "GET":
            return json_response({"key": key["name"], "account": self.broker.account, "region": self.broker.region})
        if p == "/api/projects" and m == "GET":
            return json_response({"projects": self.projects(req.query.get("search", ""))})
        if p == "/api/requests" and m == "POST":
            return json_response(self.create_request(req.json(), key), 201)
        if p == "/api/requests" and m == "GET":
            rows = self.store.list(status=req.query.get("status"), project=req.query.get("project"))[:50]
            return json_response({"requests": [_public(r) for r in rows]})
        if re.fullmatch(r"/api/requests/\d+", p) and m == "GET":
            r = self.store.get(int(p.rsplit("/", 1)[1]))
            if not r:
                raise ApiError(404, "no such request")
            return json_response(_public(r))
        if p == "/api/credentials" and m == "POST":
            project = str(req.json().get("project", ""))
            if not policy.PROJECT_RE.match(project):
                raise ApiError(400, "invalid project name")
            session = "apm-" + re.sub(r"[^\w+=,.@-]", "-", key["name"])
            try:
                return json_response(self.broker.credentials(project, session))
            except BrokerError as e:
                raise ApiError(404, str(e))
            except Exception as e:
                if getattr(e, "response", {}).get("Error", {}).get("Code") != "AccessDenied":
                    raise
                # IAM takes a few seconds to make a newly created role assumable.
                raise ApiError(503, "the project role was just created; retry in about 10 seconds")
        raise ApiError(404, "unknown endpoint")

    def connect_api(self, req):
        """No API key needed: an agent registers the hash of a key it generated, then polls until the
        owner approves it on the dashboard. The key itself never leaves the agent's machine."""
        body = req.json()
        if req.path == "/api/connect":
            key_hash, prefix = str(body.get("key_hash", "")), str(body.get("prefix", ""))
            if not re.fullmatch(r"[0-9a-f]{64}", key_hash) or not re.fullmatch(r"apm_[A-Za-z0-9_-]{6}", prefix):
                raise ApiError(400, "key_hash must be a SHA-256 hex digest and prefix the key's first 10 characters")
            name = re.sub(r"[^A-Za-z0-9 ._@-]", "", str(body.get("name", ""))).strip()[:40] or "agent"
            info = f"{req.headers.get('x-forwarded-for', '').split(',')[0].strip()} {req.headers.get('user-agent', '')}"
            try:
                code = self.store.add_connect(name, key_hash, prefix, info.strip())
            except Conflict as e:
                raise ApiError(429, str(e))
            self.notify_safely({"title": "An agent wants to connect", "body": f"{name} is waiting for you to approve it.",
                         "url": f"/connect/{code}", "tag": f"connect-{code}"}, ttl=CONNECT_SECONDS)
            return json_response({"code": code, "url": f"{self.s.origin}/connect/{code}"}, 201)
        if req.path == "/api/connect/status":
            key = str(body.get("key", ""))
            if not key.startswith("apm_"):
                raise ApiError(400, "key is required")
            return json_response({"status": self.store.connect_status(key)})
        raise ApiError(404, "unknown endpoint")

    def create_request(self, body, key):
        try:
            project, actions, resources, reason = policy.validate_request(
                str(body.get("project", "")), _strs(body.get("actions")), _strs(body.get("resources")),
                str(body.get("reason", "")))
        except ValueError as e:
            raise ApiError(400, str(e))
        if len(reason) > 1000:
            raise ApiError(400, "reason is too long (max 1000 characters)")
        if self.store.pending_count(key["name"]) >= PENDING_LIMIT:
            raise ApiError(429, f"this API key already has {PENDING_LIMIT} pending requests; wait for the owner")
        rid = self.store.add(project, actions, resources, reason, key["name"])
        n = len(actions)
        self.notify_safely({"title": f"Permission request #{rid}",
                     "body": f"{project}: {n} action{'s' if n != 1 else ''} to review",
                     "url": f"/requests/{rid}", "tag": f"req-{rid}"})
        return _public(self.store.get(rid))

    def projects(self, search=""):
        terms = [t.lower() for t in search.split() if t]
        out = []
        for project in self.store.projects():
            grants = self.broker.grants(project)
            if not grants or not grants["Statement"]:
                continue
            statements = []
            for s in grants["Statement"]:
                sid = s.get("Sid", "")
                req = self.store.get(int(sid[3:])) if sid.startswith("Req") and sid[3:].isdigit() else None
                statements.append({"grant": sid, "actions": _list(s.get("Action", [])),
                                   "resources": _list(s.get("Resource", [])),
                                   "reason": req["reason"] if req else ""})
            item = {"project": project, "grants": statements}
            if all(_matches(t, item) for t in terms):
                out.append(item)
        return out


def _matches(term, item):
    if term in item["project"]:
        return True
    for g in item["grants"]:
        for a in g["actions"]:
            if term in a.lower() or fnmatch.fnmatchcase(term, a.lower()):
                return True
        if any(term in r.lower() for r in g["resources"]) or term in g["reason"].lower():
            return True
    return False


def state_version(store):
    """Fingerprint of everything the screens show, so an open page can tell when to refresh.
    Key usage times are left out: an agent polling its request would refresh the page every
    few seconds for nothing."""
    state = [[(r["id"], r["status"], r["digest"], r.get("decided_at")) for r in store.list()],
             [(c["code"], c["status"]) for c in store.connects()],
             [k["pk"] for k in store.keys()],
             [(s["pk"], s.get("last_ok_at"), s.get("last_error_at"), s.get("failures")) for s in store.subscriptions()]]
    return hashlib.sha256(json.dumps(state, default=str).encode()).hexdigest()[:16]


def _public(r):
    keep = ("id", "project", "actions", "resources", "reason", "status", "note", "requester", "created_at", "decided_at")
    return {k: r.get(k) for k in keep}


def _strs(v):
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return v
    raise ApiError(400, "actions and resources must be strings or lists of strings")


def _list(v):
    return v if isinstance(v, list) else [v]


def _q(s):
    return urlencode({"x": s})[2:]


def _safe_next(path):
    """Only ever redirect to one of our own screens, never to another site."""
    path = str(path or "/")
    return path if SCREENS.fullmatch(path) else "/"


def _http_json(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read()[:300].decode(errors='replace')}")


# ---------- Lambda entry point ----------

_app = None


def handler(event, context):
    global _app
    if _app is None:
        import boto3
        account = context.invoked_function_arn.split(":")[4]
        region = os.environ.get("AWS_REGION", "us-east-1")
        table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        store = Store(table)
        _app = App(Settings.from_env(), store, Broker(account, region))
    return _app(Request.from_lambda(event)).lambda_result()
