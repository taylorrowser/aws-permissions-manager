"""The installable web app: screens, deep links through sign-in, caching rules, push sign-up and
notification delivery. Service worker and page-script tests are in tests/js (run with node)."""
import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlparse

from apm import push, web
from test_apm import ORIGIN, OWNER, make_app, session_cookie

ROOT = Path(__file__).resolve().parent.parent
SUB = {"endpoint": "https://push.example/device-1", "keys": {"p256dh": "p", "auth": "a"}}


class Base(unittest.TestCase):
    def setUp(self):
        self.app, self.iam, self.sts = make_app()
        self.app.s.vapid_private = "unused: push.send is mocked"
        self.key = self.app.store.create_key("laptop")

    def get(self, path, owner=True, query=None):
        return self.app(web.Request("GET", path, query or {}, cookies=session_cookie(self.app) if owner else {}))

    def post_json(self, path, body, origin=ORIGIN, owner=True):
        resp = self.app(web.Request("POST", path, headers={"Origin": origin}, body=json.dumps(body).encode(),
                                    cookies=session_cookie(self.app) if owner else {}))
        return resp.status, json.loads(resp.body) if resp.content_type == "application/json" else resp.body

    def action(self, form):
        body = "&".join(f"{k}={v}" for k, v in form.items()).encode()
        return self.app(web.Request("POST", "/action", headers={"Origin": ORIGIN}, cookies=session_cookie(self.app), body=body))

    def agent_request(self, actions=("s3:GetObject",), reason="ship the site", project="web"):
        req = web.Request("POST", "/api/requests", headers={"Authorization": f"Bearer {self.key}"},
                          body=json.dumps({"project": project, "actions": list(actions), "reason": reason}).encode())
        resp = self.app(req)
        self.assertEqual(resp.status, 201, resp.body)
        return json.loads(resp.body)["id"]


class ScreenTests(Base):
    def test_every_screen_renders_for_the_owner(self):
        rid = self.agent_request()
        for path, heading in [("/", "Requests (1)"), ("/projects", "Projects"), ("/devices", "Notifications"),
                              ("/keys", "Agent API keys"), (f"/requests/{rid}", f"Request #{rid}"),
                              ("/connect/ABCD-EFGH", "Connect an agent")]:
            with self.subTest(path=path):
                resp = self.get(path)
                self.assertEqual(resp.status, 200)
                self.assertIn(f">{heading}</h1>", resp.body)
                self.assertIn('aria-current="page"', resp.body)

    def test_signed_out_screens_show_sign_in_that_returns_there(self):
        for path in ["/", "/projects", "/devices", "/keys", "/requests/7", "/connect/ABCD-EFGH"]:
            with self.subTest(path=path):
                body = self.get(path, owner=False).body
                self.assertIn("Sign in", body)
                self.assertNotIn("Requests (", body)
                if path != "/":
                    self.assertIn(f'href="/login?next={path.replace("/", "%2F")}"', body)

    def test_sign_in_returns_to_the_deep_link(self):
        self.app.http = lambda url, body: {"user": {"email": OWNER, "email_verified": True}}
        resp = self.app(web.Request("GET", "/login", {"next": "/requests/12"}))
        q = {k: v[0] for k, v in parse_qs(urlparse(resp.headers["Location"]).query).items()}
        oauth = resp.cookies[0].split(";")[0].split("=", 1)[1]
        cb = self.app(web.Request("GET", "/auth/callback", {"code": "c", "state": q["state"]}, cookies={web.OAUTH_COOKIE: oauth}))
        self.assertEqual(cb.headers["Location"], "/requests/12")

    def test_sign_in_never_redirects_off_site(self):
        self.app.http = lambda url, body: {"user": {"email": OWNER, "email_verified": True}}
        for evil in ["//evil.test/x", "https://evil.test", "/\\evil.test", "/requests/1@evil.test", "javascript:alert(1)",
                     "/requests/../../x"]:
            with self.subTest(next=evil):
                resp = self.app(web.Request("GET", "/login", {"next": evil}))
                q = {k: v[0] for k, v in parse_qs(urlparse(resp.headers["Location"]).query).items()}
                oauth = resp.cookies[0].split(";")[0].split("=", 1)[1]
                cb = self.app(web.Request("GET", "/auth/callback", {"code": "c", "state": q["state"]},
                                          cookies={web.OAUTH_COOKIE: oauth}))
                self.assertEqual(cb.headers["Location"], "/")

    def test_action_redirects_stay_on_site(self):
        rid = self.agent_request()
        r = self.app.store.get(rid)
        resp = self.action({"op": "reject", "id": rid, "digest": r["digest"], "back": "https://evil.test"})
        self.assertTrue(resp.headers["Location"].startswith("/?msg="))
        resp = self.action({"op": "delete_device", "pk": "sub#x", "back": "/devices"})
        self.assertTrue(resp.headers["Location"].startswith("/devices?msg="))

    def test_deciding_from_the_request_screen_returns_to_the_list(self):
        rid = self.agent_request()
        r = self.app.store.get(rid)
        resp = self.action({"op": "approve", "id": rid, "digest": r["digest"], "back": f"/requests/{rid}"})
        self.assertTrue(resp.headers["Location"].startswith("/?msg=Approved"))
        page = self.get(f"/requests/{rid}").body
        self.assertIn("This request was", page)
        self.assertIn("Approved", page)
        self.assertNotIn(">Approve</button>", page)

    def test_missing_request_and_expired_connect(self):
        self.assertEqual(self.get("/requests/999").status, 404)
        self.assertEqual(self.get("/requests/" + "9" * 40).status, 404)  # too long for DynamoDB
        self.assertEqual(self.get("/requests/\u0661\u0662").status, 404)  # non-ASCII digits
        self.assertIn("no longer waiting", self.get("/connect/ABCD-EFGH").body)
        self.assertEqual(self.get("/connect/not-a-code").status, 404)

    def test_request_card_explains_scope(self):
        rid = self.agent_request(actions=["dynamodb:*", "s3:Get*"])
        body = self.get(f"/requests/{rid}").body
        self.assertIn("every DynamoDB action", body)
        self.assertIn("matches several S3 actions", body)
        self.assertIn("all resources in the account", body)
        self.assertIn("Approving creates the project", body)
        self.assertIn('data-confirm="Approve broad access', body)

    def test_reason_and_names_are_escaped(self):
        rid = self.agent_request(reason="<script>alert(1)</script>")
        body = self.get(f"/requests/{rid}").body
        self.assertNotIn("<script>alert", body)
        self.assertIn("&lt;script&gt;", body)

    def test_sign_out_works_with_an_expired_session(self):
        resp = self.app(web.Request("POST", "/logout", headers={"Origin": ORIGIN}))
        self.assertEqual(resp.status, 303)
        self.assertTrue(resp.cookies[0].startswith(web.SESSION_COOKIE + "=;"))
        self.assertEqual(self.app(web.Request("POST", "/logout", headers={"Origin": "https://evil.test"})).status, 403)

    def test_every_screen_carries_the_push_key(self):
        for path in ["/", "/projects", "/keys"]:
            self.assertIn('data-vapid="VAPIDPUB"', self.get(path).body)

    def test_stage_badge_only_outside_prod(self):
        self.assertNotIn("class=stage", self.get("/").body)
        self.app.s.stage = "pr-12"
        body = self.get("/").body
        self.assertIn("class=stage", body)
        self.assertIn("<title>[pr-12] Requests", body)

    def test_app_shell_keeps_the_tab_bar_out_of_the_scroll_and_marks_live_regions(self):
        body = self.get("/devices").body
        self.assertLess(body.index("<main"), body.index("<nav class=tabs"))  # tabs after main: bottom bar in flow
        for region in ("title", "flash", "page", "nav"):
            self.assertIn(f"data-live={region}", body)
        self.assertIn("id=this-device data-keep", body)  # script-driven card survives live refreshes
        self.assertIn("<dialog id=confirm", body)
        css = (ROOT / "apm" / "static" / "app.css").read_text()
        for bad in ("position:fixed", "position:sticky", "100vh", "100dvh"):
            self.assertNotIn(bad, css)  # these move with the page on iOS; the body never scrolls instead

    def test_empty_states(self):
        self.assertIn("Nothing to review", self.get("/").body)
        self.assertIn("No projects yet", self.get("/projects").body)
        self.assertIn("No devices get notifications yet", self.get("/devices").body)


class PollTests(Base):
    def test_poll_reports_a_version_that_changes_with_the_data(self):
        resp = self.get("/poll")
        self.assertEqual((resp.status, resp.content_type), (200, "application/json"))
        self.assertEqual(resp.lambda_result()["headers"]["Cache-Control"], "no-store")
        first = json.loads(resp.body)
        self.assertEqual(first["pending"], 0)
        self.assertIn(f'data-version="{first["v"]}"', self.get("/").body)  # pages carry the same fingerprint
        rid = self.agent_request()
        after_request = json.loads(self.get("/poll").body)
        self.assertNotEqual(after_request["v"], first["v"])
        self.assertEqual(after_request["pending"], 1)
        self.assertEqual(json.loads(self.get("/poll").body)["v"], after_request["v"])  # stable while nothing changes
        self.action({"op": "approve", "id": rid, "digest": self.app.store.get(rid)["digest"], "back": "/"})
        after_decision = json.loads(self.get("/poll").body)
        self.assertNotEqual(after_decision["v"], after_request["v"])
        self.assertEqual(after_decision["pending"], 0)

    def test_poll_sees_connects_keys_and_devices(self):
        v = lambda: json.loads(self.get("/poll").body)["v"]  # noqa: E731
        before = v()
        self.app.store.add_connect("ci", "ab" * 32, "apm_abcdef")
        after_connect = v()
        self.assertNotEqual(after_connect, before)
        self.app.store.create_key("phone")
        after_key = v()
        self.assertNotEqual(after_key, after_connect)
        self.post_json("/push/subscribe", {"subscription": SUB})
        self.assertNotEqual(v(), after_key)

    def test_key_usage_does_not_change_the_version(self):
        before = json.loads(self.get("/poll").body)["v"]
        self.app(web.Request("GET", "/api/whoami", headers={"Authorization": f"Bearer {self.key}"}))
        self.assertEqual(json.loads(self.get("/poll").body)["v"], before)

    def test_page_fingerprint_is_read_before_its_content(self):
        # A request that lands while a page renders must show up on the next poll, so the page's
        # fingerprint must predate its content (otherwise the request stays hidden until the next change).
        original, added = self.app.store.list, []

        def list_and_add_once(*a, **kw):
            rows = original(*a, **kw)
            if not added:
                added.append(self.agent_request())
            return rows
        with mock.patch.object(self.app.store, "list", side_effect=list_and_add_once):
            body = self.get("/").body
        version = re.search(r'data-version="([^"]+)"', body).group(1)
        self.assertNotEqual(version, json.loads(self.get("/poll").body)["v"])

    def test_poll_needs_a_session(self):
        resp = self.get("/poll", owner=False)
        self.assertEqual((resp.status, resp.content_type), (401, "application/json"))


class CachingTests(Base):
    def test_signed_in_pages_and_api_are_never_cached(self):
        for resp in [self.get("/"), self.get("/devices"), self.get("/", owner=False),
                     self.app(web.Request("GET", "/api/whoami", headers={"Authorization": f"Bearer {self.key}"}))]:
            self.assertEqual(resp.lambda_result()["headers"]["Cache-Control"], "no-store")

    def test_static_cache_rules(self):
        def cache(path, query=None):
            return self.app(web.Request("GET", path, query or {})).lambda_result()["headers"]["Cache-Control"]
        self.assertEqual(cache("/sw.js"), "no-cache")
        self.assertEqual(cache("/manifest.webmanifest"), "no-cache")
        self.assertEqual(cache("/app.js", {"v": web.ASSET_VERSION}), "public, max-age=31536000, immutable")
        self.assertEqual(cache("/app.css", {"v": "old"}), "public, max-age=300")

    def test_pages_load_versioned_assets_and_worker_knows_the_version(self):
        self.assertIn(f"/app.js?v={web.ASSET_VERSION}", self.get("/").body)
        sw = self.app(web.Request("GET", "/sw.js")).body
        self.assertIn(f'const VERSION = "{web.ASSET_VERSION}"', sw)
        self.assertNotIn("__VERSION__", sw)

    def test_manifest_is_installable(self):
        m = json.loads(self.app(web.Request("GET", "/manifest.webmanifest")).body)
        self.assertEqual((m["id"], m["start_url"], m["scope"], m["display"]), ("/", "/", "/", "standalone"))
        sizes = {(i["sizes"], i["purpose"]) for i in m["icons"]}
        self.assertTrue({("192x192", "any"), ("512x512", "any"), ("512x512", "maskable")} <= sizes)
        for icon in m["icons"] + [i for s in m["shortcuts"] for i in s["icons"]]:
            resp = self.app(web.Request("GET", icon["src"]))
            self.assertEqual(resp.status, 200, icon["src"])
            w, h = int.from_bytes(resp.body[16:20], "big"), int.from_bytes(resp.body[20:24], "big")
            self.assertEqual(f"{w}x{h}", icon["sizes"], icon["src"])

    def test_offline_page_is_static(self):
        body = self.app(web.Request("GET", "/offline.html")).body
        self.assertIn("won't be sent later", body)
        self.assertNotIn(OWNER, body)


class PushApiTests(Base):
    def test_subscribe_validates_and_returns_device_id(self):
        for bad in [{}, {"endpoint": "http://x", "keys": {"p256dh": "p", "auth": "a"}},
                    {"endpoint": "https://x"}, {"endpoint": "https://x", "keys": {"p256dh": "p"}}]:
            self.assertEqual(self.post_json("/push/subscribe", {"subscription": bad})[0], 400, bad)
        status, data = self.post_json("/push/subscribe", {"subscription": SUB, "label": "iPhone Safari"})
        self.assertEqual(status, 200)
        self.assertEqual([s["pk"] for s in self.app.store.subscriptions()], [data["device"]])

    def test_resubscribing_keeps_history_and_replaces_rotated_endpoint(self):
        _, first = self.post_json("/push/subscribe", {"subscription": SUB})
        self.app.store.record_delivery(first["device"], True, 201)
        created = self.app.store.subscriptions()[0]["created_at"]
        self.post_json("/push/subscribe", {"subscription": SUB})
        again = self.app.store.subscriptions()
        self.assertEqual((len(again), again[0]["created_at"], again[0]["last_status"]), (1, created, 201))
        new = {**SUB, "endpoint": "https://push.example/device-1-rotated"}
        self.post_json("/push/subscribe", {"subscription": new, "replaces": SUB["endpoint"]})
        self.assertEqual([s["sub"]["endpoint"] for s in self.app.store.subscriptions()], [new["endpoint"]])

    def test_removed_device_cannot_silently_resubscribe(self):
        _, data = self.post_json("/push/subscribe", {"subscription": SUB})
        self.action({"op": "delete_device", "pk": data["device"], "back": "/devices"})
        self.assertEqual(self.app.store.subscriptions(), [])
        # The phone's browser still holds its subscription; background syncs are refused...
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB, "auto": True})[0], 410)
        rotated = {**SUB, "endpoint": "https://push.example/rotated"}
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": rotated, "replaces": SUB["endpoint"],
                                                            "auto": True})[0], 410)
        self.assertEqual(self.app.store.subscriptions(), [])
        # The rotated endpoint is marked too, so the next page sync can't register it either.
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": rotated, "auto": True})[0], 410)
        self.assertEqual(self.app.store.subscriptions(), [])
        # ...until the owner taps Turn on there, which clears the removal.
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB})[0], 200)
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB, "auto": True})[0], 200)

    def test_lost_device_still_resyncs_automatically(self):
        # Not removed by the owner (e.g. the push service said gone, or the table lost it).
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB, "auto": True})[0], 200)

    def test_unsubscribe(self):
        self.post_json("/push/subscribe", {"subscription": SUB})
        self.assertEqual(self.post_json("/push/unsubscribe", {"endpoint": SUB["endpoint"]})[0], 200)
        self.assertEqual(self.app.store.subscriptions(), [])

    def test_push_calls_need_owner_and_same_origin(self):
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB}, owner=False)[0], 401)
        self.assertEqual(self.post_json("/push/subscribe", {"subscription": SUB}, origin="https://evil.test")[0], 403)
        self.assertEqual(self.post_json("/push/test", {}, origin="https://evil.test")[0], 403)
        self.assertEqual(self.app.store.subscriptions(), [])

    def test_test_push_reports_per_device_outcome(self):
        self.post_json("/push/subscribe", {"subscription": SUB})
        with mock.patch("apm.push.send", return_value=201) as send:
            status, data = self.post_json("/push/test", {"endpoint": SUB["endpoint"]})
        self.assertEqual(status, 200)
        self.assertEqual([r["outcome"] for r in data["results"]], ["delivered"])
        self.assertEqual(send.call_args.kwargs["ttl"], 300)
        self.assertEqual(self.post_json("/push/test", {"endpoint": "https://push.example/unknown"})[0], 404)
        self.app.s.vapid_private = ""
        self.assertEqual(self.post_json("/push/test", {})[0], 503)


class DeliveryTests(Base):
    def setUp(self):
        super().setUp()
        self.post_json("/push/subscribe", {"subscription": SUB, "label": "iPhone"})
        self.device = self.app.store.subscriptions()[0]["pk"]
        sleep = mock.patch("apm.push.time.sleep")
        sleep.start()
        self.addCleanup(sleep.stop)

    def test_lock_screen_payload_has_no_reason_or_actions(self):
        with mock.patch("apm.push.send", return_value=201) as send:
            rid = self.agent_request(actions=["secretsmanager:GetSecretValue"], reason="read the prod DB password")
        message = send.call_args.args[1]
        self.assertEqual(message, {"title": f"Permission request #{rid}", "body": "web: 1 action to review",
                                   "url": f"/requests/{rid}", "tag": f"req-{rid}", "pending": 1})
        self.assertNotIn("password", json.dumps(message))
        self.assertNotIn("GetSecretValue", json.dumps(message))

    def test_connect_payload_omits_the_code_and_expires_with_it(self):
        import hashlib
        with mock.patch("apm.push.send", return_value=201) as send:
            resp = self.app(web.Request("POST", "/api/connect", body=json.dumps({
                "name": "ci", "key_hash": hashlib.sha256(b"k").hexdigest(), "prefix": "apm_abcdef"}).encode()))
        code = json.loads(resp.body)["code"]
        message = send.call_args.args[1]
        self.assertNotIn(code, message["title"] + message["body"])
        self.assertEqual(message["url"], f"/connect/{code}")
        self.assertEqual(send.call_args.kwargs["ttl"], 900)

    def test_gone_devices_are_removed(self):
        for status in (404, 410):
            with self.subTest(status=status):
                self.post_json("/push/subscribe", {"subscription": SUB})
                with mock.patch("apm.push.send", return_value=status):
                    self.agent_request()
                self.assertEqual(self.app.store.subscriptions(), [])

    def test_transient_failure_retried_once(self):
        with mock.patch("apm.push.send", side_effect=[503, 201]) as send:
            self.agent_request()
        self.assertEqual(send.call_count, 2)
        self.assertEqual(self.app.store.subscriptions()[0]["last_status"], 201)
        with mock.patch("apm.push.send", side_effect=[OSError("timed out"), 201]) as send:
            self.agent_request()
        self.assertEqual(send.call_count, 2)

    def test_permanent_failure_recorded_and_shown_not_retried(self):
        with mock.patch("apm.push.send", return_value=403) as send:
            self.agent_request()
            self.agent_request()
        self.assertEqual(send.call_count, 2)
        sub = self.app.store.subscriptions()[0]
        self.assertEqual((sub["last_status"], sub["failures"]), (403, 2))
        self.assertIn("Last notification failed (HTTP 403)", self.get("/devices").body)
        with mock.patch("apm.push.send", return_value=201):
            self.agent_request()
        sub = self.app.store.subscriptions()[0]
        self.assertEqual(sub["failures"], 0)
        self.assertIn("Last notified", self.get("/devices").body)

    def test_one_bad_device_does_not_block_others(self):
        other = {**SUB, "endpoint": "https://push.example/device-2"}
        self.post_json("/push/subscribe", {"subscription": other})
        with mock.patch("apm.push.send", side_effect=lambda sub, *a, **k: 410 if sub["endpoint"] == SUB["endpoint"] else 201):
            self.agent_request()
        self.assertEqual([s["sub"]["endpoint"] for s in self.app.store.subscriptions()], [other["endpoint"]])

    def test_record_delivery_ignores_removed_device(self):
        self.app.store.delete_subscription(self.device)
        self.app.store.record_delivery(self.device, False, 500)
        self.assertNotIn(self.device, self.app.store.t.items)

    def test_storage_errors_while_notifying_do_not_fail_the_agent(self):
        with mock.patch("apm.push.send", return_value=201), \
                mock.patch.object(self.app.store, "record_delivery", side_effect=RuntimeError("throttled")):
            rid = self.agent_request()
        self.assertEqual(self.app.store.get(rid)["status"], "pending")
        with mock.patch("apm.push.deliver", side_effect=RuntimeError("boom")):
            self.agent_request()

    def test_badge_count_includes_connect_requests(self):
        self.app.store.add_connect("ci", "ab" * 32, "apm_abcdef")
        with mock.patch("apm.push.send", return_value=201) as send:
            self.agent_request()
        self.assertEqual(send.call_args.args[1]["pending"], 2)

    def test_no_vapid_key_skips_quietly(self):
        self.app.s.vapid_private = ""
        with mock.patch("apm.push.send") as send:
            self.agent_request()
        send.assert_not_called()


class DeadlineTests(unittest.TestCase):
    def test_slow_push_service_cannot_hold_the_request(self):
        import threading
        import time
        release = threading.Event()
        subs = [{"pk": "sub#fast", "sub": SUB}, {"pk": "sub#slow", "sub": {**SUB, "endpoint": "https://slow"}}]

        def fake_send(sub, *a, **k):
            if sub["endpoint"] == "https://slow":
                release.wait(5)
            return 201
        start = time.monotonic()
        with mock.patch("apm.push.send", side_effect=fake_send):
            out = push.deliver(subs, {"title": "t"}, "pem", ORIGIN, budget=0.3)
        release.set()
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(out, {"sub#fast": ("delivered", 201), "sub#slow": ("failed", None)})

    def test_sends_queued_past_the_budget_are_failed_not_raised(self):
        import threading
        release = threading.Event()
        subs = [{"pk": f"sub#{i}", "sub": {**SUB, "endpoint": f"https://p/{i}"}} for i in range(20)]

        def blocked(sub, *a, **k):
            release.wait(5)
            return 201
        with mock.patch("apm.push.send", side_effect=blocked):
            out = push.deliver(subs, {}, "pem", ORIGIN, budget=0.3)
        release.set()
        self.assertEqual(len(out), 20)
        self.assertTrue(all(v == ("failed", None) for v in out.values()))

    def test_no_retry_once_the_budget_is_nearly_spent(self):
        with mock.patch("apm.push.send", return_value=503) as send:
            out = push.deliver([{"pk": "sub#a", "sub": SUB}], {}, "pem", ORIGIN, budget=1)
        self.assertEqual((out["sub#a"], send.call_count), (("failed", 503), 1))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class ServiceWorkerTests(unittest.TestCase):
    def test_node_suite(self):
        # Explicit files: older Node (e.g. 20 on GitHub runners) doesn't accept a directory here.
        files = sorted(str(p) for p in (ROOT / "tests" / "js").glob("*.test.mjs"))
        out = subprocess.run(["node", "--test", *files], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout[-3000:] + out.stderr[-2000:])


if __name__ == "__main__":
    unittest.main()
