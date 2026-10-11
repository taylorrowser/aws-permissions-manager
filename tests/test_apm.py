import base64
import datetime
import fnmatch
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from apm import policy, push, web
from apm.broker import Broker
from apm.store import Store

ACCOUNT = "111122223333"
ROOT = Path(__file__).resolve().parent.parent
CLIENT = ROOT / "plugins" / "aws-permissions" / "scripts" / "apm.py"
ORIGIN = "https://apm.test"
OWNER = "owner@example.com"


class Missing(Exception):
    response = {"Error": {"Code": "NoSuchEntity"}}


class FakeIAM:
    def __init__(self):
        self.roles, self.policies = {}, {}

    def get_role(self, RoleName):
        if RoleName not in self.roles:
            raise Missing()
        return {"Role": self.roles[RoleName]}

    def create_role(self, **kw):
        self.roles[kw["RoleName"]] = kw

    def get_role_policy(self, RoleName, PolicyName):
        if (RoleName, PolicyName) not in self.policies:
            raise Missing()
        return {"PolicyDocument": self.policies[RoleName, PolicyName]}

    def put_role_policy(self, RoleName, PolicyName, PolicyDocument):
        self.policies[RoleName, PolicyName] = json.loads(PolicyDocument)

    def delete_role_policy(self, RoleName, PolicyName):
        if self.policies.pop((RoleName, PolicyName), None) is None:
            raise Missing()

    def list_role_policies(self, RoleName):
        if RoleName not in self.roles:
            raise Missing()
        return {"PolicyNames": [p for r, p in self.policies if r == RoleName]}

    def delete_role(self, RoleName):
        del self.roles[RoleName]


class FakeSTS:
    def __init__(self):
        self.calls = []

    def assume_role(self, **kw):
        self.calls.append(kw)
        return {"Credentials": {"AccessKeyId": "ASIAFAKE", "SecretAccessKey": "fake-secret", "SessionToken": "fake-token",
                                "Expiration": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)}}


class ConditionFailed(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"}}


class FakeTable:
    """The subset of the DynamoDB Table API that Store uses."""

    def __init__(self):
        self.items = {}

    def put_item(self, Item, ConditionExpression=None, ExpressionAttributeValues=None):
        if ConditionExpression == "attribute_not_exists(pk) OR expires_at < :now":
            held = self.items.get(Item["pk"])
            if held and held["expires_at"] >= ExpressionAttributeValues[":now"]:
                raise ConditionFailed()
        elif ConditionExpression:
            raise NotImplementedError(ConditionExpression)
        self.items[Item["pk"]] = json.loads(json.dumps(Item))

    def get_item(self, Key, ConsistentRead=False):
        item = self.items.get(Key["pk"])
        return {"Item": json.loads(json.dumps(item))} if item else {}

    def delete_item(self, Key, ConditionExpression=None, ExpressionAttributeNames=None, ExpressionAttributeValues=None):
        if ConditionExpression:
            field = (ExpressionAttributeNames or {}).get("#t", "token")
            if self.items.get(Key["pk"], {}).get(field) != ExpressionAttributeValues[":t"]:
                raise ConditionFailed()
        self.items.pop(Key["pk"], None)

    def scan(self, FilterExpression, ExpressionAttributeValues, **kw):
        kind = ExpressionAttributeValues[":k"]
        return {"Items": [json.loads(json.dumps(i)) for i in self.items.values() if i.get("kind") == kind]}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ExpressionAttributeNames=None,
                    ConditionExpression=None, ReturnValues=None):
        names = ExpressionAttributeNames or {}
        if ConditionExpression == "attribute_exists(pk)":
            if Key["pk"] not in self.items:
                raise ConditionFailed()
        elif ConditionExpression:
            field, value = ConditionExpression.split(" = ")
            if self.items.get(Key["pk"], {}).get(names.get(field, field)) != ExpressionAttributeValues[value]:
                raise ConditionFailed()
        item = self.items.setdefault(Key["pk"], {"pk": Key["pk"]})
        for verb, rest in re.findall(r"(SET|ADD) (.*?)(?= SET | ADD |$)", UpdateExpression):
            for part in rest.split(","):
                if verb == "ADD":
                    field, value = part.split()
                    item[field] = item.get(field, 0) + ExpressionAttributeValues[value]
                else:
                    field, value = [x.strip() for x in part.split("=")]
                    item[names.get(field, field)] = ExpressionAttributeValues[value]
        return {"Attributes": dict(item)}


def make_app(http=None):
    settings = web.Settings("apm.test", "client_test", OWNER, "VAPIDPUB", "session-secret-for-tests")
    iam, sts = FakeIAM(), FakeSTS()
    store = Store(FakeTable())
    app = web.App(settings, store, Broker(ACCOUNT, "us-east-1", iam=iam, sts=sts), http=http)
    return app, iam, sts


def session_cookie(app, email=OWNER):
    return {web.SESSION_COOKIE: web.sign(app.s, {"e": email, "x": 4102444800})}


class PolicyTests(unittest.TestCase):
    def test_validate_cleans_and_defaults(self):
        project, actions, resources, reason = policy.validate_request(
            "myapp", ["s3:PutObject", "s3:GetObject", "s3:GetObject"], [], " upload builds ")
        self.assertEqual(actions, ["s3:GetObject", "s3:PutObject"])
        self.assertEqual(resources, ["*"])
        self.assertEqual(reason, "upload builds")

    def test_blocked_actions_rejected(self):
        for action in ["iam:CreateUser", "iam:*", "sts:AssumeRole", "sts:*", "organizations:ListAccounts",
                       "iam:AttachRolePolicy", "billing:ViewBilling"]:
            with self.subTest(action=action), self.assertRaises(ValueError):
                policy.validate_request("myapp", [action], [], "x")

    def test_allowed_actions(self):
        for action in ["s3:*", "ec2:StartInstances", "iam:PassRole", "iam:GetRole", "sts:GetCallerIdentity", "lambda:*"]:
            with self.subTest(action=action):
                policy.validate_request("myapp", [action], [], "x")

    def test_bad_inputs(self):
        for args in [("My_App", ["s3:GetObject"], [], "x"), ("myapp", ["*"], [], "x"),
                     ("myapp", ["s3:GetObject"], ["bucket"], "x"), ("myapp", ["s3:GetObject"], [], "  ")]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                policy.validate_request(*args)

    def test_broker_can_only_create_roles_with_boundary(self):
        stmt = policy.broker_policy(ACCOUNT)["Statement"][0]
        self.assertEqual(stmt["Condition"]["StringEquals"]["iam:PermissionsBoundary"], policy.boundary_arn(ACCOUNT))
        self.assertEqual(stmt["Resource"], f"arn:aws:iam::{ACCOUNT}:role/agents/*")

    def test_only_broker_can_assume_agent_roles(self):
        principal = policy.agent_role_trust(ACCOUNT)["Statement"][0]["Principal"]
        self.assertEqual(principal, {"AWS": f"arn:aws:iam::{ACCOUNT}:role/apm/apm-broker"})

    def test_template_renders(self):
        from apm import deploy
        t = deploy.template(ACCOUNT, "us-east-1", "apm.test", "Z1", OWNER, "client_x", "PUB", "b", "k.zip")
        role = t["Resources"]["BrokerRole"]["Properties"]
        self.assertEqual(role["Path"], "/apm/")
        sids = [s.get("Sid") for s in role["Policies"][0]["PolicyDocument"]["Statement"]]
        self.assertIn("VendAgentCredentials", sids)
        self.assertEqual(t["Resources"]["Boundary"]["Properties"]["PolicyDocument"], policy.boundary(ACCOUNT))


class ProtectApmTests(unittest.TestCase):
    """Approved grants are capped by the boundary; none may reach apm's own secrets or code."""

    def denied(self, arn):
        stmt = next(s for s in policy.boundary(ACCOUNT)["Statement"] if s["Sid"] == "DenyApmInfrastructure")
        return stmt["Action"] == "*" and any(fnmatch.fnmatchcase(arn, p) for p in stmt["Resource"])

    def test_apm_infrastructure_is_denied_to_agents(self):
        for arn in [f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm/session-secret",
                    f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm/vapid-private-key",
                    f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm-dev/session-secret",
                    f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:apm",
                    f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:apm:live",
                    f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/apm",
                    f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/apm/abc",
                    f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/aws/lambda/apm:log-stream:x",
                    f"arn:aws:s3:::apm-artifacts-{ACCOUNT}-us-east-1",
                    f"arn:aws:s3:::apm-artifacts-{ACCOUNT}-us-east-1/lambda/x.zip",
                    "arn:aws:apigateway:us-east-1::/domainnames/apm.taylorrowser.com"]:
            with self.subTest(arn=arn):
                self.assertTrue(self.denied(arn))

    def test_ordinary_project_resources_stay_allowed(self):
        for arn in [f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/myapp/db-url",
                    f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:myapp-api",
                    f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders",
                    "arn:aws:s3:::example-site/index.html"]:
            with self.subTest(arn=arn):
                self.assertFalse(self.denied(arn))

    def test_tagged_resources_and_dns_denied_but_agent_roles_still_passable(self):
        sids = {s["Sid"]: s for s in policy.boundary(ACCOUNT)["Statement"]}
        tagged = sids["DenyApmTaggedResources"]
        self.assertEqual((tagged["NotAction"], tagged["Condition"]),
                         ("iam:*", {"StringEquals": {"aws:ResourceTag/managed-by": "apm"}}))
        self.assertIn("route53:ChangeResourceRecordSets", sids["DenyApmDnsRecords"]["Action"])
        self.assertIn("AllowPassAgentRoles", sids)

    def test_recursive_ssm_read_of_the_root_is_denied(self):
        stmt = next(s for s in policy.boundary(ACCOUNT)["Statement"] if s["Sid"] == "DenyRecursiveReadOfRoot")
        self.assertEqual(stmt["Action"], "ssm:GetParametersByPath")
        for path_arn in [f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/", f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter"]:
            self.assertTrue(any(fnmatch.fnmatchcase(path_arn, p) for p in stmt["Resource"]))
        # /apm itself is covered by DenyApmInfrastructure; other paths stay readable.
        self.assertTrue(self.denied(f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm"))
        self.assertFalse(any(fnmatch.fnmatchcase(f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/myapp", p)
                             for p in stmt["Resource"]))

    def test_boundary_fits_a_managed_policy(self):
        self.assertLess(len(json.dumps(policy.boundary(ACCOUNT), separators=(",", ":"))), 6144)


class LeaseTests(unittest.TestCase):
    def test_one_holder_at_a_time_and_lapsed_leases_are_taken_over(self):
        from apm import store as store_mod
        s = Store(FakeTable())
        with s.lease("myapp"):
            with self.assertRaises(store_mod.Conflict):
                with s.lease("myapp", wait=0.3, poll=0.05):
                    pass
            with s.lease("other", wait=0):  # other projects aren't blocked
                pass
        with s.lease("myapp", wait=0):  # released
            pass
        s.t.items["lease#myapp"] = {"pk": "lease#myapp", "kind": "lease", "token": "dead", "expires_at": 1}
        with s.lease("myapp", wait=0):  # a crashed holder's lease lapses
            self.assertNotEqual(s.t.items["lease#myapp"]["token"], "dead")
        self.assertNotIn("lease#myapp", s.t.items)

    def test_every_grant_change_runs_under_the_project_lease(self):
        app, iam, _ = make_app()
        key = app.store.create_key("k")
        held, real = [], app.store.lease

        def lease(project, **kw):
            held.append(project)
            return real(project, **kw)
        app.store.lease = lease
        rid = app.store.add("myapp", ["s3:GetObject"], ["*"], "x", "k")
        app.decide({"op": "approve", "id": str(rid), "digest": app.store.get(rid)["digest"]})
        app.decide({"op": "revoke", "project": "myapp", "sid": f"Req{rid}"})
        app.decide({"op": "remove_project", "project": "myapp"})
        self.assertEqual(held, ["myapp"] * 3)
        self.assertNotIn("lease#myapp", app.store.t.items)


class GrantConsistencyTests(unittest.TestCase):
    """The role's policy is always rebuilt from approved requests, never from an IAM read."""

    def setUp(self):
        self.app, self.iam, _ = make_app()

    def add(self, project="myapp", actions=("s3:GetObject",), resources=("*",)):
        rid = self.app.store.add(project, list(actions), list(resources), "x", "k")
        return self.app.store.get(rid)

    def approve(self, r):
        return self.app.decide({"op": "approve", "id": str(r["id"]), "digest": r["digest"]})

    def sids(self):
        doc = self.iam.policies.get(("apm-myapp", "apm-grants"))
        return [s["Sid"] for s in doc["Statement"]] if doc else []

    def test_stale_iam_read_cannot_bring_back_a_revoked_grant(self):
        r1, r2 = self.add(), self.add()
        self.approve(r1)
        stale = self.iam.policies["apm-myapp", "apm-grants"]
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        self.iam.get_role_policy = lambda RoleName, PolicyName: {"PolicyDocument": stale}  # IAM still shows Req1
        self.approve(r2)
        self.assertEqual(self.sids(), ["Req2"])

    def test_a_late_approval_sees_the_request_was_already_decided(self):
        r = self.add()
        self.approve(r)
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        real_get = self.app.store.get
        self.app.store.get = lambda rid, consistent=False: (
            real_get(rid, True) if consistent else {**real_get(rid), "status": "pending"})
        self.assertEqual(self.approve(r), "That request is no longer pending.")
        self.assertEqual(self.sids(), [])

    def test_failed_iam_write_is_reported_and_reapply_completes_it(self):
        r = self.add()
        self.iam.put_role_policy = mock.Mock(side_effect=RuntimeError("throttled"))
        self.assertIn("updating IAM failed", self.approve(r))
        self.assertEqual(self.sids(), [])
        self.assertFalse(self.app.broker.in_sync("myapp", self.app.store.approved("myapp")))
        del self.iam.put_role_policy
        self.app.decide({"op": "sync_project", "project": "myapp"})
        self.assertEqual(self.sids(), ["Req1"])

    def test_failed_status_write_after_iam_cannot_hide_a_grant(self):
        r = self.add()
        real = self.app.store.set_status
        calls = []

        def flaky(rid, status, note="", expect=None):
            calls.append(status)
            if status == "approved":
                raise RuntimeError("dynamodb down")
            return real(rid, status, note, expect)
        self.app.store.set_status = flaky
        with self.assertRaises(RuntimeError):
            self.approve(r)
        self.assertEqual(self.sids(), [])  # status is written before IAM, so IAM was never touched

    def test_revoke_drops_grants_that_are_no_longer_approved(self):
        r1, r2 = self.add(), self.add()
        self.approve(r1)
        self.approve(r2)
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        self.assertEqual(self.sids(), ["Req2"])
        self.assertEqual(self.app.store.get(1)["status"], "revoked")
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req2"})
        self.assertNotIn(("apm-myapp", "apm-grants"), self.iam.policies)

    def test_uncertain_iam_write_keeps_the_approval_and_offers_reapply(self):
        r = self.add()
        real_put = self.iam.put_role_policy

        def applied_then_timed_out(**kw):
            real_put(**kw)
            raise TimeoutError("read timed out")
        self.iam.put_role_policy = applied_then_timed_out
        msg = self.approve(r)
        self.assertIn("updating IAM failed", msg)
        self.assertEqual(self.app.store.get(r["id"])["status"], "approved")  # can't be rejected into a hidden grant
        self.assertEqual(self.app.decide({"op": "reject", "id": str(r["id"]), "digest": r["digest"]}),
                         "That request is no longer pending.")
        self.iam.put_role_policy = real_put
        self.assertTrue(self.app.broker.in_sync("myapp", self.app.store.approved("myapp")))

    def test_drift_is_shown_and_reapply_fixes_it(self):
        r1, r2 = self.add(), self.add()
        self.approve(r1)
        self.approve(r2)
        self.iam.put_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        msg = self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        self.assertTrue(msg.startswith("Error: recorded the revoke"))
        self.assertEqual(self.sids(), ["Req1", "Req2"])  # IAM still grants it...
        page = self.app(web.Request("GET", "/projects", cookies=session_cookie(self.app))).body
        self.assertIn("match your decisions", page)  # ...and the dashboard says so
        del self.iam.put_role_policy
        self.app.decide({"op": "sync_project", "project": "myapp"})
        self.assertEqual(self.sids(), ["Req2"])
        page = self.app(web.Request("GET", "/projects", cookies=session_cookie(self.app))).body
        self.assertNotIn("match your decisions", page)

    def test_remove_project_continues_past_a_stale_listing(self):
        r = self.add()
        self.approve(r)
        real = self.iam.list_role_policies
        self.iam.list_role_policies = lambda RoleName, **kw: {"PolicyNames": ["already-gone"] + real(RoleName)["PolicyNames"]}
        self.app.decide({"op": "remove_project", "project": "myapp"})
        self.assertNotIn("apm-myapp", self.iam.roles)
        self.assertEqual(self.iam.policies, {})

    def test_too_large_approval_is_refused_and_stays_pending(self):
        from apm.broker import BrokerError
        big = ["arn:aws:s3:::bucket-" + "x" * 60 + f"-{i}/*" for i in range(60)]
        self.approve(self.add(resources=big))
        r = self.add(actions=["s3:PutObject"], resources=big)
        msg = self.app.action({"op": "approve", "id": str(r["id"]), "digest": r["digest"]}, "owner")
        self.assertIn("inline+policy+limit", msg.headers["Location"])
        self.assertEqual(self.app.store.get(r["id"])["status"], "pending")
        self.assertEqual(self.sids(), ["Req1"])

    def test_remove_project_deletes_every_page_of_policies(self):
        self.iam.roles["apm-myapp"] = {}
        for i in range(5):
            self.iam.policies["apm-myapp", f"extra-{i}"] = {}
        real = self.iam.list_role_policies

        def paged(RoleName, Marker=None):
            names = real(RoleName)["PolicyNames"]
            start = int(Marker or 0)
            page = names[start:start + 2]
            more = start + 2 < len(names)
            return {"PolicyNames": page, "IsTruncated": more, **({"Marker": str(start + 2)} if more else {})}
        self.iam.list_role_policies = paged
        self.app.broker.remove_project("myapp")
        self.assertEqual(self.iam.policies, {})
        self.assertNotIn("apm-myapp", self.iam.roles)


class PushTests(unittest.TestCase):
    def test_payload_decrypts_like_a_browser(self):
        ua_key = ec.generate_private_key(ec.SECP256R1())
        ua_public = ua_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        auth = os.urandom(16)
        body = push.encrypt(b'{"hi":1}', push.b64url(ua_public), push.b64url(auth))
        # RFC 8291 receiver side
        salt, rs, idlen = body[:16], int.from_bytes(body[16:20], "big"), body[20]
        as_public, ciphertext = body[21:21 + idlen], body[21 + idlen:]
        self.assertEqual(rs, 4096)
        shared = ua_key.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))

        def hkdf(s, ikm, info, n):
            return HKDF(algorithm=hashes.SHA256(), length=n, salt=s, info=info).derive(ikm)
        ikm = hkdf(auth, shared, b"WebPush: info\x00" + ua_public + as_public, 32)
        plain = AESGCM(hkdf(salt, ikm, b"Content-Encoding: aes128gcm\x00", 16)).decrypt(
            hkdf(salt, ikm, b"Content-Encoding: nonce\x00", 12), ciphertext, None)
        self.assertEqual(plain, b'{"hi":1}\x02')

    def test_vapid_signature_verifies(self):
        pem, public = push.generate_vapid_keys()
        header = push.vapid_header("https://web.push.apple.com/abc", pem, ORIGIN)
        jwt = header.split("t=")[1].split(",")[0]
        self.assertTrue(header.endswith("k=" + public))
        h, c, sig = jwt.split(".")
        self.assertEqual(json.loads(push.unb64url(c))["aud"], "https://web.push.apple.com")
        raw = push.unb64url(sig)
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), push.unb64url(public))
        key.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                   f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))


class WebTests(unittest.TestCase):
    def setUp(self):
        self.app, self.iam, self.sts = make_app()
        self.key = self.app.store.create_key("laptop")

    def api(self, method, path, body=None, key="default"):
        headers = {"Authorization": f"Bearer {self.key if key == 'default' else key}"} if key else {}
        req = web.Request(method, path.split("?")[0], {k: v[0] for k, v in parse_qs(urlparse(path).query).items()},
                          headers, body=json.dumps(body).encode() if body is not None else b"")
        resp = self.app(req)
        return resp.status, json.loads(resp.body)

    def owner_post(self, form, origin=ORIGIN, cookies=None):
        body = "&".join(f"{k}={v}" for k, v in form.items()).encode()
        return self.app(web.Request("POST", "/action", headers={"Origin": origin},
                                    cookies=session_cookie(self.app) if cookies is None else cookies, body=body))

    def request(self, actions=("s3:GetObject",), resources=("*",), project="myapp"):
        status, r = self.api("POST", "/api/requests", {"project": project, "actions": list(actions),
                                                       "resources": list(resources), "reason": "because"})
        self.assertEqual(status, 201, r)
        return self.app.store.get(r["id"])

    def approve(self, r):
        resp = self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]})
        self.assertEqual(resp.status, 303)
        return resp

    def test_api_requires_valid_key(self):
        self.assertEqual(self.api("GET", "/api/projects", key=None)[0], 401)
        self.assertEqual(self.api("GET", "/api/projects", key="apm_wrong")[0], 401)
        self.assertEqual(self.api("GET", "/api/whoami")[1]["key"], "laptop")

    def test_request_validation(self):
        status, r = self.api("POST", "/api/requests", {"project": "myapp", "actions": ["iam:CreateUser"], "reason": "x"})
        self.assertEqual(status, 400)
        self.assertIn("never grantable", r["error"])

    def test_dashboard_needs_owner_session(self):
        self.assertIn("Sign in", self.app(web.Request("GET", "/")).body)
        self.assertIn("Sign in", self.app(web.Request("GET", "/", cookies=session_cookie(self.app, "x@evil.com"))).body)
        forged = {web.SESSION_COOKIE: session_cookie(self.app)[web.SESSION_COOKIE][:-2] + "00"}
        self.assertIn("Sign in", self.app(web.Request("GET", "/", cookies=forged)).body)
        self.request()
        page = self.app(web.Request("GET", "/", cookies=session_cookie(self.app))).body
        self.assertIn("<h1>Requests (1)</h1>", page)

    def test_owner_posts_need_origin_and_session(self):
        r = self.request()
        self.assertEqual(self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]}, origin="https://evil.test").status, 403)
        self.assertEqual(self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]}, cookies={}).status, 403)
        self.assertEqual(self.iam.roles, {})

    def test_approve_creates_bounded_role_trusting_broker(self):
        r = self.request()
        self.approve(r)
        role = self.iam.roles["apm-myapp"]
        self.assertEqual(role["PermissionsBoundary"], policy.boundary_arn(ACCOUNT))
        self.assertEqual(role["Path"], "/agents/")
        self.assertEqual(json.loads(role["AssumeRolePolicyDocument"]), policy.agent_role_trust(ACCOUNT))
        self.assertEqual(self.app.store.get(r["id"])["status"], "approved")

    def test_grants_accumulate_revoke_and_remove(self):
        a, b = self.request(), self.request(["ec2:StartInstances"], ["arn:aws:ec2:us-east-1:1:instance/i-1"])
        self.approve(a), self.approve(b)
        self.assertEqual([s["Sid"] for s in self.app.broker.grants("myapp")["Statement"]], [f"Req{a['id']}", f"Req{b['id']}"])
        self.owner_post({"op": "revoke", "project": "myapp", "sid": f"Req{a['id']}"})
        self.assertEqual(self.app.store.get(a["id"])["status"], "revoked")
        self.owner_post({"op": "remove_project", "project": "myapp"})
        self.assertEqual(self.iam.roles, {})
        self.assertEqual(self.app.store.get(b["id"])["status"], "revoked")

    def test_stale_digest_and_reject(self):
        r = self.request()
        resp = self.owner_post({"op": "approve", "id": r["id"], "digest": "0" * 64})
        self.assertIn("changed", resp.headers["Location"])
        self.owner_post({"op": "reject", "id": r["id"], "digest": r["digest"]})
        self.assertEqual(self.app.store.get(r["id"])["status"], "rejected")
        self.assertEqual(self.iam.roles, {})

    def test_projects_search_and_credentials(self):
        self.assertEqual(self.api("POST", "/api/credentials", {"project": "myapp"})[0], 404)
        self.approve(self.request(["s3:Get*"], ["arn:aws:s3:::builds/*"]))
        self.assertEqual(len(self.api("GET", "/api/projects?search=s3:GetObject")[1]["projects"]), 1)
        self.assertEqual(len(self.api("GET", "/api/projects?search=builds")[1]["projects"]), 1)
        self.assertEqual(self.api("GET", "/api/projects?search=lambda")[1]["projects"], [])
        status, creds = self.api("POST", "/api/credentials", {"project": "myapp"})
        self.assertEqual(status, 200)
        self.assertEqual(creds["Version"], 1)
        self.assertEqual(self.sts.calls[0]["RoleArn"], policy.role_arn(ACCOUNT, "myapp"))
        self.assertEqual(self.sts.calls[0]["RoleSessionName"], "apm-laptop")

    def test_api_keys_created_shown_once_and_deleted(self):
        resp = self.owner_post({"op": "create_key", "name": "codex"})
        self.assertIn("won't be shown again", resp.body)
        secret = resp.body.split("<p class=secret id=secret>")[1].split("</p>")[0]
        self.assertEqual(self.api("GET", "/api/whoami", key=secret)[1]["key"], "codex")
        pk = next(k["pk"] for k in self.app.store.keys() if k["name"] == "codex")
        self.owner_post({"op": "delete_key", "pk": pk})
        self.assertEqual(self.api("GET", "/api/whoami", key=secret)[0], 401)

    def test_connect_flow_registers_only_a_hash(self):
        import hashlib
        secret = "apm_" + "x" * 43
        body = {"name": "me@mac", "key_hash": hashlib.sha256(secret.encode()).hexdigest(), "prefix": secret[:10]}
        self.assertEqual(self.api("POST", "/api/connect", {**body, "key_hash": "nope"}, key=None)[0], 400)
        status, r = self.api("POST", "/api/connect", body, key=None)
        self.assertEqual(status, 201, r)
        self.assertEqual(r["url"], f"{ORIGIN}/connect/{r['code']}")
        self.assertEqual(self.api("POST", "/api/connect", body, key=None)[0], 429)  # same key twice
        self.assertNotIn(secret, json.dumps(self.app.store.t.items))
        poll = lambda: self.api("POST", "/api/connect/status", {"key": secret}, key=None)[1]["status"]
        self.assertEqual(poll(), "pending")
        self.assertEqual(self.api("GET", "/api/whoami", key=secret)[0], 401)
        page = self.app(web.Request("GET", "/", cookies=session_cookie(self.app))).body
        self.assertIn(r["code"], page)
        # Only the signed-in owner, from the dashboard's origin, can approve.
        self.assertEqual(self.owner_post({"op": "approve_connect", "code": r["code"]}, origin="https://evil.test").status, 403)
        self.assertEqual(self.owner_post({"op": "approve_connect", "code": r["code"]}).status, 303)
        self.assertEqual(poll(), "approved")
        self.assertEqual(self.api("GET", "/api/whoami", key=secret)[1]["key"], "me@mac")
        resp = self.owner_post({"op": "reject_connect", "code": r["code"]})
        self.assertIn("no+longer+pending", resp.headers["Location"])
        self.assertEqual(self.api("POST", "/api/connect/status", {"key": "apm_other"}, key=None)[1]["status"], "expired")

    def test_connect_reject_and_limit(self):
        import hashlib
        codes = []
        for i in range(5):
            h = hashlib.sha256(str(i).encode()).hexdigest()
            status, r = self.api("POST", "/api/connect", {"name": "a", "key_hash": h, "prefix": "apm_abcdef"}, key=None)
            self.assertEqual(status, 201)
            codes.append(r["code"])
        h = hashlib.sha256(b"6").hexdigest()
        self.assertEqual(self.api("POST", "/api/connect", {"name": "a", "key_hash": h, "prefix": "apm_abcdef"}, key=None)[0], 429)
        self.owner_post({"op": "reject_connect", "code": codes[0]})
        self.assertEqual(len(self.app.store.connects()), 4)
        self.assertEqual(len(self.app.store.keys()), 1)

    def test_workos_login_flow(self):
        seen = {}

        def fake_workos(url, body):
            seen.update(body)
            return {"user": {"email": seen.get("_email", OWNER), "email_verified": True}}
        self.app.http = fake_workos
        resp = self.app(web.Request("GET", "/login"))
        location = urlparse(resp.headers["Location"])
        q = {k: v[0] for k, v in parse_qs(location.query).items()}
        self.assertEqual(q["redirect_uri"], f"{ORIGIN}/auth/callback")
        self.assertEqual(q["code_challenge_method"], "S256")
        oauth = resp.cookies[0].split(";")[0].split("=", 1)[1]
        cb = self.app(web.Request("GET", "/auth/callback", {"code": "c1", "state": q["state"]},
                                  cookies={web.OAUTH_COOKIE: oauth}))
        self.assertTrue(any(c.startswith(web.SESSION_COOKIE + "=") and "Max-Age=2592000" in c for c in cb.cookies))
        self.assertEqual(seen["code_verifier"] and seen["code"], "c1")
        bad = self.app(web.Request("GET", "/auth/callback", {"code": "c1", "state": "wrong"}, cookies={web.OAUTH_COOKIE: oauth}))
        self.assertIn("expired", bad.headers["Location"])
        seen["_email"] = "intruder@example.com"
        other = self.app(web.Request("GET", "/auth/callback", {"code": "c2", "state": q["state"]}, cookies={web.OAUTH_COOKIE: oauth}))
        self.assertIn("not+allowed", other.headers["Location"])

    def test_lambda_event_roundtrip(self):
        event = {"rawPath": "/api/whoami", "requestContext": {"http": {"method": "GET"}},
                 "headers": {"authorization": f"Bearer {self.key}"}, "cookies": ["a=b"]}
        out = self.app(web.Request.from_lambda(event)).lambda_result()
        self.assertEqual(out["statusCode"], 200)
        icon = self.app(web.Request.from_lambda({"rawPath": "/icon-192.png", "requestContext": {"http": {"method": "GET"}}})).lambda_result()
        self.assertTrue(icon["isBase64Encoded"])
        self.assertEqual(base64.b64decode(icon["body"])[:4], b"\x89PNG")


def serve_locally(app):
    """Run the App behind a plain HTTP server, like API Gateway would."""
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _do(self):
            u = urlparse(self.path)
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            resp = app(web.Request(self.command, u.path, {k: v[0] for k, v in parse_qs(u.query).items()},
                                   dict(self.headers), body=body))
            data = resp.body if isinstance(resp.body, bytes) else resp.body.encode()
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        do_GET = do_POST = _do

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class ClientTests(unittest.TestCase):
    """The plugin's stdlib client, run with the system Python like Claude Code/Codex would."""

    def setUp(self):
        self.app, self.iam, _ = make_app()
        self.server = serve_locally(self.app)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.tmp = Path(tempfile.mkdtemp())
        self.env = {**os.environ, "APM_URL": f"http://127.0.0.1:{self.server.server_port}",
                    "APM_API_KEY": self.app.store.create_key("mcp-test"), "APM_HOME": str(self.tmp / "apm"),
                    "AWS_CONFIG_FILE": str(self.tmp / "aws-config")}
        self.python = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable

    def approve_all(self):
        for r in self.app.store.list(status="pending"):
            self.app.decide({"op": "approve", "id": str(r["id"]), "digest": r["digest"]})

    def test_mcp_session(self):
        proc = subprocess.Popen([self.python, str(CLIENT), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=self.env, text=True)
        def stop():
            proc.stdin.close()
            proc.wait(5)
            proc.stdout.close()
        self.addCleanup(stop)

        def rpc(i, method, params=None):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        init = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}})
        self.assertEqual(init["result"]["protocolVersion"], "2025-06-18")
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        names = [t["name"] for t in rpc(2, "tools/list")["result"]["tools"]]
        self.assertEqual(names, ["connect", "list_projects", "get_aws_credentials", "request_permissions", "check_request", "list_requests"])

        def tool(i, name, **args):
            return rpc(i, "tools/call", {"name": name, "arguments": args})["result"]

        self.assertIn("No projects yet", tool(3, "list_projects")["content"][0]["text"])
        self.assertTrue(tool(4, "get_aws_credentials", project="myapp")["isError"])
        bad = tool(5, "request_permissions", project="myapp", actions=["iam:CreateUser"], reason="x")
        self.assertTrue(bad["isError"])
        sent = tool(6, "request_permissions", project="myapp", actions=["s3:ListAllMyBuckets"], reason="list buckets")
        self.assertIn("Request #1", sent["content"][0]["text"])
        self.assertEqual(json.loads(tool(7, "check_request", request_id=1)["content"][0]["text"])["status"], "pending")
        self.approve_all()
        self.assertEqual(json.loads(tool(8, "check_request", request_id=1, wait_seconds=5)["content"][0]["text"])["status"], "approved")
        self.assertIn("s3:ListAllMyBuckets", tool(9, "list_projects", search="s3")["content"][0]["text"])
        out = tool(10, "get_aws_credentials", project="myapp")["content"][0]["text"]
        self.assertIn("apm-myapp", out)
        self.assertNotIn("fake-secret", out)
        config = (self.tmp / "aws-config").read_text()
        self.assertIn("[profile apm-myapp]", config)
        self.assertIn("credentials myapp", config)
        self.assertEqual(rpc(11, "nope")["error"]["code"], -32601)

        # The AWS CLI would run this credential_process command from the profile.
        stable = self.tmp / "apm" / "bin" / "apm.py"
        creds = json.loads(subprocess.run([self.python, str(stable), "credentials", "myapp"], env=self.env,
                                          capture_output=True, text=True, check=True).stdout)
        self.assertEqual(creds["Version"], 1)
        self.assertEqual(oct((self.tmp / "apm" / "cache" / "myapp.json").stat().st_mode & 0o777), "0o600")

    def test_connect_from_mcp_without_a_key(self):
        env = {**self.env, "APM_NO_BROWSER": "1"}
        del env["APM_API_KEY"]
        proc = subprocess.Popen([self.python, str(CLIENT), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=env, text=True)
        def stop():
            proc.stdin.close()
            proc.wait(5)
            proc.stdout.close()
        self.addCleanup(stop)

        def tool(i, name, **args):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                                         "params": {"name": name, "arguments": args}}) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())["result"]

        self.assertIn("connect", tool(1, "list_projects")["content"][0]["text"])
        first = tool(2, "connect")["content"][0]["text"]
        code = self.app.store.connects()[0]["code"]
        self.assertIn(code, first)
        self.assertIn(code, tool(3, "connect")["content"][0]["text"])  # reuses the pending request
        self.assertEqual(len(self.app.store.connects()), 1)
        self.app.store.decide_connect(code, True)
        self.assertIn("Connected", tool(4, "connect", wait_seconds=5)["content"][0]["text"])
        self.assertIn("No projects yet", tool(5, "list_projects")["content"][0]["text"])
        self.assertIn("Connected", tool(6, "connect")["content"][0]["text"])
        key_file = self.tmp / "apm" / "api-key"
        self.assertEqual(oct(key_file.stat().st_mode & 0o777), "0o600")
        self.assertFalse((self.tmp / "apm" / "pending-key").exists())

    def test_mcp_server_survives_unexpected_errors(self):
        (self.tmp / "aws-config").mkdir()  # unreadable as a file: an OSError inside the tool
        proc = subprocess.Popen([self.python, str(CLIENT), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=self.env, text=True)
        def stop():
            proc.stdin.close()
            proc.wait(5)
            proc.stdout.close()
        self.addCleanup(stop)

        def rpc(i, method, params=None):
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        def tool(i, name, **args):
            return rpc(i, "tools/call", {"name": name, "arguments": args})["result"]

        tool(1, "request_permissions", project="myapp", actions=["s3:ListAllMyBuckets"], reason="list buckets")
        self.approve_all()
        broken = tool(2, "get_aws_credentials", project="myapp")
        self.assertTrue(broken["isError"])
        self.assertIn("IsADirectoryError", broken["content"][0]["text"])
        unknown = tool(3, "no_such_tool")
        self.assertTrue(unknown["isError"])
        self.assertIn("unknown tool", unknown["content"][0]["text"])
        # Still serving after both.
        self.assertIn("myapp", tool(4, "list_projects")["content"][0]["text"])
        self.assertIsNone(proc.poll())

    def test_profile_update_keeps_the_rest_of_aws_config(self):
        config = self.tmp / "aws-config"
        original = ("# keep this comment\n[default]\nregion = eu-west-1\n\n"
                    "[profile apm-web]\ncredential_process = stale command\noutput = json\n\n"
                    "[profile other]\nregion = ap-south-1\n")
        config.write_text(original)
        config.chmod(0o600)
        run = lambda *a: subprocess.run([self.python, str(CLIENT), *a], env=self.env, capture_output=True, text=True)
        run("request", "--project", "web", "-a", "s3:GetObject", "--reason", "read")
        self.approve_all()
        for _ in range(2):  # a second `use` leaves the file unchanged
            r = run("use", "web")
            self.assertEqual(r.returncode, 0, r.stderr)
        text = config.read_text()
        self.assertTrue(text.startswith("# keep this comment\n[default]\nregion = eu-west-1\n"))
        self.assertIn("[profile other]\nregion = ap-south-1\n", text)
        self.assertIn("output = json", text)
        self.assertNotIn("stale command", text)
        self.assertEqual(text.count("[profile apm-web]"), 1)
        self.assertEqual(text.count("credential_process"), 1)
        self.assertIn("credentials web", text)
        self.assertEqual(oct(config.stat().st_mode & 0o777), "0o600")
        self.assertEqual((self.tmp / "aws-config.apm-backup").read_text(), original)

    def test_cli(self):
        run = lambda *a: subprocess.run([self.python, str(CLIENT), *a], env=self.env, capture_output=True, text=True)
        r = run("request", "--project", "web", "-a", "s3:GetObject", "--reason", "read")
        self.assertIn("Request #1", r.stdout)
        self.assertIn("pending", run("status").stdout)
        self.approve_all()
        self.assertEqual(run("wait", "1", "--timeout", "5").returncode, 0)
        self.assertIn("web", run("projects").stdout)
        self.assertEqual(run("projects", "--search", "nothing").stdout.strip(), "No matching projects.")


if __name__ == "__main__":
    unittest.main()
