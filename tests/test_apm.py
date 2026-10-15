import base64
import datetime
import fnmatch
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

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


class FakeCloudFormation:
    """Live stacks per region, listed two per page. Regions in `failing` raise on every listing."""

    def __init__(self):
        self.stacks, self.failing, self.calls = {}, set(), []

    def add(self, region, name, role_arn=""):
        stack_id = f"arn:aws:cloudformation:{region}:{ACCOUNT}:stack/{name}/{len(self.calls):08d}-0000-0000-0000-000000000000"
        self.stacks.setdefault(region, []).append({"StackName": name, "StackId": stack_id,
                                                   **({"RoleARN": role_arn} if role_arn else {})})

    def client(self, region):
        fake = self

        class Client:
            def describe_stacks(self, NextToken=None):
                fake.calls.append(region)
                if region in fake.failing:
                    raise RuntimeError("throttled")
                start = int(NextToken or 0)
                stacks = fake.stacks.get(region, [])
                more = start + 2 < len(stacks)
                return {"Stacks": stacks[start:start + 2], **({"NextToken": str(start + 2)} if more else {})}
        return Client()


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
                    item[names.get(field, field)] = json.loads(json.dumps(ExpressionAttributeValues[value]))
        return {"Attributes": dict(item)}


def make_app(http=None, cfn=None):
    settings = web.Settings("apm.test", "client_test", OWNER, "VAPIDPUB", "session-secret-for-tests")
    iam, sts, cfn = FakeIAM(), FakeSTS(), cfn or FakeCloudFormation()
    store = Store(FakeTable())
    app = web.App(settings, store, Broker(ACCOUNT, "us-east-1", iam=iam, sts=sts, cloudformation=cfn.client), http=http)
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
        self.assertEqual(t["Resources"]["Boundary"]["Properties"]["PolicyDocument"],
                         policy.doc(*policy.boundary(ACCOUNT)["Statement"], policy.api_deny()))


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
        from apm import deploy
        deployed = deploy.boundary_document(ACCOUNT, policy.Names("prod"))
        self.assertLess(len(json.dumps(deployed, separators=(",", ":"))), 6144)

    def test_domain_registration_is_never_grantable(self):
        for action in ["route53domains:UpdateDomainNameservers", "route53domains:TransferDomain",
                       "route53domains:RegisterDomain", "route53domains:*", "route53domains:Get*"]:
            with self.subTest(action=action):
                self.assertTrue(policy.is_blocked(action))
                with self.assertRaises(ValueError):
                    policy.validate_request("myapp", [action], ["*"], "x")
        allow = next(s for s in policy.boundary(ACCOUNT)["Statement"] if s["Sid"] == "AllowNonAdminServices")
        self.assertIn("route53domains:*", allow["NotAction"])
        # Ordinary DNS work in other names stays grantable.
        self.assertFalse(policy.is_blocked("route53:ChangeResourceRecordSets"))

    def test_audit_trail_tampering_is_denied_but_reading_is_not(self):
        stmt = next(s for s in policy.boundary(ACCOUNT)["Statement"] if s["Sid"] == "DenyAuditTampering")
        self.assertEqual((stmt["Effect"], stmt["Resource"]), ("Deny", "*"))
        for action in ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
                       "cloudtrail:PutEventSelectors"]:
            self.assertIn(action, stmt["Action"])
        for action in ["cloudtrail:LookupEvents", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]:
            self.assertFalse(any(fnmatch.fnmatchcase(action, a) for a in stmt["Action"]))

    def test_the_stacks_own_api_is_denied(self):
        from apm import deploy
        t = deploy.template(ACCOUNT, "us-east-1", "apm.test", "Z1", OWNER, "client_x", "PUB", "b", "k.zip")
        stmts = t["Resources"]["Boundary"]["Properties"]["PolicyDocument"]["Statement"]
        api = next(s for s in stmts if s["Sid"] == "DenyApmApi")
        self.assertEqual((api["Effect"], api["Action"]), ("Deny", "apigateway:*"))
        self.assertEqual(api["Resource"], [{"Fn::Sub": "arn:aws:apigateway:*::/apis/${Api}"},
                                           {"Fn::Sub": "arn:aws:apigateway:*::/apis/${Api}/*"}])
        self.assertIn("Api", t["Resources"])  # the reference resolves to this stack's HTTP API


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

        def flaky(rid, status, note="", expect=None, **kw):
            calls.append(status)
            if status == "approved":
                raise RuntimeError("dynamodb down")
            return real(rid, status, note, expect, **kw)
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
        self.assertIn("inline+policy+apm-grants+on+role+apm-myapp+would+be+10%2C720+characters%2C+480+over", msg.headers["Location"])
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


class AuditTests(unittest.TestCase):
    """Every IAM rewrite records exactly one event, whether it applied, was refused or failed."""

    def setUp(self):
        self.app, self.iam, _ = make_app()

    def add(self, resources=("*",)):
        rid = self.app.store.add("myapp", ["s3:GetObject"], list(resources), "x", "laptop")
        return self.app.store.get(rid)

    def approve(self, r):
        return self.app.decide({"op": "approve", "id": str(r["id"]), "digest": r["digest"]}, "owner@example.com")

    def events(self):
        return self.app.store.events()

    def test_each_op_writes_one_applied_event(self):
        r1, r2 = self.add(), self.add()
        self.approve(r1)
        self.approve(r2)
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        self.app.decide({"op": "sync_project", "project": "myapp"})
        self.app.decide({"op": "remove_project", "project": "myapp"})
        ev = self.events()
        self.assertEqual([(e["op"], e["outcome"]) for e in ev],
                         [("approve", "applied"), ("approve", "applied"), ("revoke", "applied"),
                          ("sync_project", "applied"), ("remove_project", "applied")])
        first = ev[0]
        self.assertEqual((first["project"], first["account"], first["actor"], first["request_ids"], first["agent_keys"]),
                         ("myapp", ACCOUNT, "owner@example.com", [1], ["laptop"]))
        self.assertEqual(first["role_arn"], policy.role_arn(ACCOUNT, "myapp"))
        self.assertEqual(first["grants"], ["Req1"])
        self.assertEqual(ev[1]["grants"], ["Req1", "Req2"])
        self.assertEqual(ev[1]["request_ids"], [1, 2])  # Req1 was live in IAM
        self.assertEqual(first["policy_sha256"], hashlib.sha256(policy.dumps(policy.grants_document([r1])).encode()).hexdigest())
        self.assertEqual(ev[2]["grants"], ["Req2"])
        self.assertEqual((ev[4]["grants"], ev[4]["policy_sha256"], ev[4]["request_ids"]), ([], "", [2]))
        self.app.decide({"op": "revoke", "project": "other", "sid": "Req2"})  # another project's request
        self.assertEqual(self.events()[-1]["request_ids"], [])

    def test_refused_and_failed_writes_are_recorded(self):
        big = ["arn:aws:s3:::bucket-" + "x" * 60 + f"-{i}/*" for i in range(60)]
        self.approve(self.add(big))
        from apm.broker import BrokerError
        with self.assertRaises(BrokerError):
            self.approve(self.add(big))
        self.iam.put_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        self.assertIn("updating IAM failed", self.approve(self.add()))
        ev = self.events()
        self.assertEqual([e["outcome"] for e in ev], ["applied", "refused", "failed"])
        self.assertIn("480 over the 10,240-character limit", ev[1]["error"])
        self.assertEqual(ev[2]["error"], "TimeoutError: read timed out")

    def test_a_grant_cleared_by_a_later_sync_traces_back_to_its_request(self):
        self.approve(self.add())
        self.iam.put_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        self.iam.delete_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        del self.iam.put_role_policy, self.iam.delete_role_policy
        self.app.decide({"op": "sync_project", "project": "myapp"})
        reapply = self.events()[-1]
        self.assertEqual((reapply["op"], reapply["request_ids"], reapply["grants"]), ("sync_project", [1], []))
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertIn("History", page)
        for label in ("Approved", "Revoke failed", "Grant removed (re-apply)"):
            self.assertIn(label, page)

    def test_history_shows_only_changes_for_the_request_or_that_removed_its_grant(self):
        self.approve(self.add())
        self.approve(self.add())
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1"})
        self.assertEqual(self.events()[-1]["targets"], [1])
        page = self.app(web.Request("GET", "/requests/2", cookies=session_cookie(self.app))).body
        history = page[page.index("<section class=history>"):]
        history = history[:history.index("</section>")]
        self.assertIn("Approved", history)
        self.assertNotIn("Revoked", history)  # request 2 kept its grant

    def test_a_grant_restored_by_another_approval_shows_in_its_history(self):
        real_put = self.iam.put_role_policy
        self.iam.put_role_policy = mock.Mock(side_effect=RuntimeError("throttled"))
        self.approve(self.add())  # recorded as approved, but IAM never got it
        self.iam.put_role_policy = real_put
        self.approve(self.add())
        last = self.events()[-1]
        self.assertEqual((last["targets"], last["request_ids"], last["agent_keys"]), ([2], [1, 2], ["laptop"]))
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertIn("Grant added (approval)", page)

    def test_a_failed_live_read_refuses_the_change_before_writing(self):
        self.approve(self.add())
        self.iam.get_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        msg = self.app.action({"op": "sync_project", "project": "myapp", "back": "/projects"}, "owner")
        self.assertIn("nothing+was+changed", msg.headers["Location"])
        del self.iam.get_role_policy
        self.assertEqual([s["Sid"] for s in self.app.broker.grants("myapp")["Statement"]], ["Req1"])
        last = self.events()[-1]
        self.assertEqual((last["op"], last["outcome"]), ("sync_project", "refused"))

    def test_cloudwatch_first_and_a_failed_table_write_does_not_fail_the_change(self):
        real_put = self.app.store.t.put_item

        def put(Item, **kw):
            if Item.get("kind") == "event":
                raise RuntimeError("dynamodb down")
            return real_put(Item, **kw)
        self.app.store.t.put_item = put
        with mock.patch("builtins.print") as out:
            self.assertEqual(self.approve(self.add()), "Approved request #1 for myapp.")
        lines = [json.loads(c.args[0]) for c in out.call_args_list]
        self.assertEqual([l["event"] for l in lines], ["iam_change", "audit_store_failed"])
        self.assertEqual(lines[0]["outcome"], "applied")
        self.assertEqual(self.app.broker.grants("myapp")["Statement"][0]["Sid"], "Req1")


class TimeLimitTests(unittest.TestCase):
    """Time-limited grants: IAM ends them by a condition; the sweep tidies them away."""

    def setUp(self):
        self.app, self.iam, _ = make_app()
        self.key = self.app.store.create_key("laptop")

    def ask(self, **extra):
        body = {"project": "myapp", "actions": ["s3:GetObject"], "reason": "x", **extra}
        resp = self.app(web.Request("POST", "/api/requests", headers={"Authorization": f"Bearer {self.key}"},
                                    body=json.dumps(body).encode()))
        return resp.status, json.loads(resp.body)

    def approve(self, rid, hours):
        r = self.app.store.get(rid)
        return self.app.decide({"op": "approve", "id": str(rid), "digest": r["digest"], "hours-1": str(hours)}, "owner")

    def statements(self):
        doc = self.iam.policies.get(("apm-myapp", "apm-grants"))
        return {s["Sid"]: s for s in doc["Statement"]} if doc else {}

    def test_the_owner_picks_the_duration_and_the_condition_is_written(self):
        self.assertEqual(self.ask(suggested_hours=2)[0], 400)
        status, r = self.ask(suggested_hours=3)
        self.assertEqual((status, r["suggested_hours"]), (201, 3))
        page = self.app(web.Request("GET", f"/requests/{r['id']}", cookies=session_cookie(self.app))).body
        self.assertIn(f'<select name="hours-1" form="approve-{r["id"]}"', page)
        self.assertIn('<option value="3" selected>3 hours (suggested)</option>', page)
        self.assertEqual(self.approve(r["id"], 24), "Approved request #1 for myapp for 1 day.")
        end = self.app.store.get(r["id"])["expires_at"]
        self.assertAlmostEqual(end, time.time() + 24 * 3600, delta=5)
        self.assertEqual(self.statements()["Req1"]["Condition"], {"DateLessThan": {"aws:CurrentTime": policy.iso(end)}})
        self.approve(self.ask()[1]["id"], 0)  # permanent: no condition
        self.assertNotIn("Condition", self.statements()["Req2"])
        self.assertTrue(self.app.broker.in_sync("myapp", self.app.store.approved("myapp")))

    def test_the_sweep_removes_expired_grants_then_records_them_and_is_idempotent(self):
        self.approve(self.ask()[1]["id"], 1)
        self.approve(self.ask()[1]["id"], 0)
        later = time.time() + 2 * 3600
        self.assertEqual(self.app.sweep(later), {"expired": {"myapp": [1]}})
        self.assertEqual(list(self.statements()), ["Req2"])
        self.assertEqual(self.app.store.get(1)["status"], "expired")
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["outcome"], ev["actor"], ev["request_ids"], ev["grants"]),
                         ("expire", "applied", "APM (time limit)", [1, 2], ["Req2"]))  # every live grant, as for any write
        self.assertEqual(ev["targets"], [1])
        before = (len(self.app.store.events()), repr(sorted(self.iam.policies.items())))
        self.assertEqual(self.app.sweep(later), {"expired": {}})
        self.assertEqual((len(self.app.store.events()), repr(sorted(self.iam.policies.items()))), before)
        page = self.app(web.Request("GET", "/", cookies=session_cookie(self.app))).body
        self.assertIn(f'Expired <time datetime="{policy.iso(self.app.store.get(1)["expires_at"])}"', page)

    def test_iam_failing_during_the_sweep_changes_nothing_and_the_next_sweep_retries(self):
        self.approve(self.ask()[1]["id"], 1)
        written = repr(self.iam.policies)
        self.iam.delete_role_policy = mock.Mock(side_effect=RuntimeError("throttled"))
        later = time.time() + 2 * 3600
        with mock.patch("builtins.print"):
            self.assertEqual(self.app.sweep(later), {"expired": {}})
        self.assertEqual(self.app.store.get(1)["status"], "approved")
        self.assertEqual(repr(self.iam.policies), written)
        self.assertEqual([(e["op"], e["outcome"]) for e in self.app.store.events()][-1], ("expire", "failed"))
        del self.iam.delete_role_policy
        self.assertEqual(self.app.sweep(later), {"expired": {"myapp": [1]}})
        self.assertEqual((self.statements(), self.app.store.get(1)["status"]), ({}, "expired"))

    def test_extend_and_a_failed_extend_is_reported(self):
        self.approve(self.ask()[1]["id"], 1)
        page = self.app(web.Request("GET", "/projects", cookies=session_cookie(self.app))).body
        self.assertIn("Revoke early", page)
        self.assertIn("<time data-ends datetime=", page)  # the page script keeps the countdown moving
        self.assertIn('name="op" value="extend"', page)
        self.assertEqual(self.app.decide({"op": "extend", "project": "myapp", "sid": "Req1", "hours": "0"}, "owner"),
                         "Extended Req1 on myapp permanently.")
        self.assertNotIn("Condition", self.statements()["Req1"])
        self.assertEqual(self.app.store.get(1)["expires_at"], 0)
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["outcome"], ev.get("detail")), ("extend", "applied", "permanently"))
        self.iam.put_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        msg = self.app.decide({"op": "extend", "project": "myapp", "sid": "Req1", "hours": "3"}, "owner")
        self.assertTrue(msg.startswith("Error: couldn't extend Req1"), msg)
        self.assertEqual(self.app.store.events()[-1]["outcome"], "failed")
        del self.iam.put_role_policy
        page = self.app(web.Request("GET", "/projects", cookies=session_cookie(self.app))).body
        self.assertIn("match your decisions", page)  # IAM still has no end; Re-apply fixes it

    def test_the_schedule_invokes_the_sweep(self):
        with mock.patch.object(web, "_app", self.app), mock.patch.object(self.app, "sweep", return_value={"expired": {}}) as sweep:
            self.assertEqual(web.handler({"apm_sweep": True}, None), {"expired": {}})
        sweep.assert_called_once_with()


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
        self.assertIn('data-pending="1"', page)

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


class RefusalTests(unittest.TestCase):
    """Grants that would run as another role, or can't be checked as written, are refused when
    requested, again (fresh) at approval, and before every credential hand-out."""
    STACK = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/web-*/*"

    def setUp(self):
        self.cfn = FakeCloudFormation()
        self.app, self.iam, _ = make_app(cfn=self.cfn)
        self.key = self.app.store.create_key("laptop")

    api, owner_post = WebTests.api, WebTests.owner_post

    def ask(self, actions, resources):
        return self.api("POST", "/api/requests", {"project": "myapp", "actions": actions, "resources": resources,
                                                  "reason": "deploy"})

    def refused(self, actions, resources):
        return policy.refusals(actions, resources, ACCOUNT, lambda region: self.app.broker.stacks(region))

    def test_static_refusals(self):
        fn = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:"
        for actions, resources in [
                (["lambda:UpdateFunctionCode"], ["*"]), (["lambda:*"], ["*"]), (["ecs:RunTask"], ["*"]),
                (["lambda:UpdateFunctionConfiguration"], [fn + "*"]), (["ssm:Send*"], ["*"]),
                (["lambda:UpdateFunctionCode"], [f"arn:aws:lambda:us-east-1:{ACCOUNT}:function*"]),
                (["lambda:UpdateFunctionCode"], [fn + "?*"]),
                (["cloudformation:UpdateStack"], ["*"]), (["cloudformation:*"], ["*"]),
                (["cloudformation:ExecuteStackRefactor"], ["*"]),
                (["cloudformation:CreateChangeSet"], [f"arn:aws:cloudformation:*:{ACCOUNT}:stack/web/*"]),
                (["cloudformation:DeleteStack"], [f"arn:aws:cloudformation:us-*:{ACCOUNT}:stack/web/*"]),
                (["s3:GetObject"], ["arn:aws:s3:::home/${aws:username}/*"]),
                (["cloudformation:DescribeStacks"], ["arn:aws:cloudformation"])]:
            with self.subTest(actions=actions, resources=resources):
                self.assertTrue(self.refused(actions, resources))
        for actions, resources in [
                (["lambda:UpdateFunctionCode"], [fn + "api"]), (["lambda:UpdateFunctionCode"], [fn + "api-*"]),
                (["lambda:GetFunction"], ["*"]), (["cloudformation:DescribeStacks"], ["*"]),
                (["s3:PutBucketPolicy"], ["*"]), (["s3:GetObject"], ["arn:aws:s3:::bucket/*"])]:
            with self.subTest(actions=actions, resources=resources):
                self.assertEqual(self.refused(actions, resources), [])

    def test_resource_policy_actions_are_labelled_not_refused(self):
        status, r = self.ask(["s3:PutBucketPolicy"], ["arn:aws:s3:::site"])
        self.assertEqual(status, 201, r)
        page = self.app(web.Request("GET", f"/requests/{r['id']}", cookies=session_cookie(self.app))).body
        self.assertIn("Can grant anyone anything on this resource", page)

    def test_refused_at_request(self):
        status, r = self.ask(["lambda:UpdateFunctionCode"], ["*"])
        self.assertEqual(status, 400)
        self.assertIn("lambda:UpdateFunctionCode on every resource", r["error"])
        for i in range(3):
            self.cfn.add("us-east-1", f"other-{i}")
        self.cfn.add("us-east-1", "web-prod", f"arn:aws:iam::{ACCOUNT}:role/cdk-exec")  # on the second page
        status, r = self.ask(["cloudformation:UpdateStack"], [self.STACK])
        self.assertEqual(status, 400)
        self.assertIn("stored role of stack web-prod", r["error"])
        for odd in ("*/web-prod/*", "stack*/web-prod/*"):  # wildcard resource types still match stack/web-prod/<id>
            status, r = self.ask(["cloudformation:UpdateStack"], [f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:{odd}"])
            self.assertEqual(status, 400)
            self.assertIn("stored role of stack web-prod", r["error"])
        self.assertEqual(self.ask(["cloudformation:UpdateStack"],
                                  [f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/other-*/*"])[0], 201)
        self.assertEqual(len(self.app.store.list()), 1)

    def test_a_failed_stack_listing_fails_closed(self):
        self.cfn.failing.add("us-east-1")
        status, r = self.ask(["cloudformation:UpdateStack"], [self.STACK])
        self.assertEqual(status, 400)
        self.assertIn("couldn't list CloudFormation stacks in us-east-1", r["error"])

    def test_refused_at_approval_with_a_fresh_listing(self):
        status, body = self.ask(["cloudformation:UpdateStack"], [self.STACK])
        self.assertEqual(status, 201, body)
        self.cfn.add("us-east-1", "web-prod", f"arn:aws:iam::{ACCOUNT}:role/cdk-exec")  # gained a role since
        r = self.app.store.get(body["id"])
        resp = self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]})
        self.assertIn("refused", resp.headers["Location"])
        self.assertEqual(self.app.store.get(r["id"])["status"], "pending")
        self.assertNotIn(("apm-myapp", "apm-grants"), self.iam.policies)
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["outcome"], ev["request_ids"]), ("approve", "refused", [r["id"]]))
        self.assertIn("stored role of stack web-prod", ev["error"])

    def test_flagged_grants_get_no_credentials(self):
        status, body = self.ask(["cloudformation:UpdateStack"], [self.STACK])
        r = self.app.store.get(body["id"])
        self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]})
        self.assertEqual(self.api("POST", "/api/credentials", {"project": "myapp"})[0], 200)
        calls = len(self.cfn.calls)
        self.cfn.add("us-east-1", "web-prod", f"arn:aws:iam::{ACCOUNT}:role/cdk-exec")
        status, err = self.api("POST", "/api/credentials", {"project": "myapp"})
        self.assertEqual(status, 403)
        self.assertIn(f"Req{r['id']}", err["error"])
        self.assertGreater(len(self.cfn.calls), calls)  # listed again, not cached
        self.iam.policies.pop(("apm-myapp", "apm-grants"))  # e.g. the approval's IAM write failed
        page = self.app(web.Request("GET", "/projects", cookies=session_cookie(self.app))).body
        self.assertIn("Credentials blocked", page)
        self.assertIn(f'name="sid" value="Req{r["id"]}"', page)  # still listed, so it can be revoked
        self.cfn.stacks.clear()
        self.cfn.failing.add("us-east-1")  # a failed listing blocks credentials too
        self.assertEqual(self.api("POST", "/api/credentials", {"project": "myapp"})[0], 403)

    def test_a_statement_iam_still_holds_is_flagged(self):
        # e.g. a revoke whose IAM write failed: the request is revoked but IAM still grants it.
        status, body = self.ask(["s3:GetObject"], ["*"])
        r = self.app.store.get(body["id"])
        self.owner_post({"op": "approve", "id": r["id"], "digest": r["digest"]})
        self.iam.policies["apm-myapp", "apm-grants"]["Statement"].append(
            {"Sid": "Req99", "Effect": "Allow", "Action": "ecs:RunTask", "Resource": "*"})
        status, err = self.api("POST", "/api/credentials", {"project": "myapp"})
        self.assertEqual(status, 403)
        self.assertIn("Req99", err["error"])
        self.assertNotIn(f"Req{r['id']}", err["error"])

    def test_broker_may_list_stacks(self):
        allows = [s for s in policy.broker_policy(ACCOUNT)["Statement"] if s["Effect"] == "Allow"]
        self.assertIn({"Sid": "CheckStackRoles", "Effect": "Allow", "Resource": "*",
                       "Action": ["cloudformation:DescribeStacks", "cloudformation:ListStacks"]}, allows)


class MultiGrantTests(unittest.TestCase):
    """Several grants in one request: each its own statement, duration, revoke and extend; the
    request ends with its last grant. The flat form keeps working as before."""
    BUCKET = ["arn:aws:s3:::exports", "arn:aws:s3:::exports/*"]
    TABLE = [f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders"]

    def setUp(self):
        self.cfn = FakeCloudFormation()
        self.app, self.iam, _ = make_app(cfn=self.cfn)
        self.key = self.app.store.create_key("laptop")

    api, owner_post = WebTests.api, WebTests.owner_post

    def ask(self, grants=None, **body):
        if grants is not None:
            body["grants"] = grants
        return self.api("POST", "/api/requests", {"project": "myapp", "reason": "backfill", **body})

    def two(self):
        status, r = self.ask([{"actions": ["s3:GetObject", "s3:ListBucket"], "resources": self.BUCKET,
                               "suggested_hours": 3},
                              {"actions": ["dynamodb:PutItem"], "resources": self.TABLE}])
        self.assertEqual(status, 201, r)
        return r

    def approve(self, rid, **hours):
        r = self.app.store.get(rid)
        return self.app.decide({"op": "approve", "id": str(rid), "digest": r["digest"], **hours}, "owner")

    def statements(self):
        doc = self.iam.policies.get(("apm-myapp", "apm-grants"))
        return {s["Sid"]: s for s in doc["Statement"]} if doc else {}

    def test_the_flat_form_is_unchanged_and_one_grant_keeps_its_sid(self):
        status, r = self.ask(actions=["s3:GetObject"], resources=self.BUCKET, suggested_hours=3)
        self.assertEqual(status, 201, r)
        self.assertNotIn("grants", r)
        self.assertEqual((r["actions"], r["resources"], r["suggested_hours"]), (["s3:GetObject"], self.BUCKET, 3))
        status, one = self.ask([{"actions": ["s3:GetObject"], "resources": self.BUCKET}])  # grants with one entry
        self.assertEqual((status, "grants" in one, one["actions"]), (201, False, ["s3:GetObject"]))
        self.approve(r["id"], **{"hours-1": "1"})
        self.approve(one["id"])
        self.assertEqual(list(self.statements()), ["Req1", "Req2"])

    def test_bad_grants_are_refused(self):
        g = {"actions": ["s3:GetObject"], "resources": ["*"]}
        for body, error in [({"grants": [g], "actions": ["s3:GetObject"]}, "not both"),
                            ({"grants": [g], "suggested_hours": 3}, "not both"),
                            ({"grants": []}, "1-9"), ({"grants": [g] * 10}, "1-9"), ({"grants": ["s3:GetObject"]}, "1-9"),
                            ({"grants": [g, {"actions": ["iam:CreateUser"]}]}, "grant 2: iam:CreateUser"),
                            ({"grants": [g, {**g, "suggested_hours": 2}]}, "grant 2: suggested_hours"),
                            ({"grants": [g, {"actions": ["ecs:RunTask"], "resources": ["*"]}]}, "refused: grant 2: ecs:RunTask")]:
            with self.subTest(body=body):
                status, r = self.ask(**body)
                self.assertEqual(status, 400)
                self.assertIn(error, r["error"])
        self.assertEqual(self.app.store.list(), [])

    def test_each_grant_is_approved_with_its_own_duration(self):
        r = self.two()
        self.assertEqual((r["actions"], r["resources"]),  # the union, for listing
                         (["dynamodb:PutItem", "s3:GetObject", "s3:ListBucket"], sorted(self.BUCKET + self.TABLE)))
        self.assertEqual([(g["sid"], g["suggested_hours"], g["ended"]) for g in r["grants"]],
                         [("Req1g1", 3, ""), ("Req1g2", None, "")])
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertIn('<option value="3" selected>3 hours (suggested)</option>', page)
        self.assertIn('<select name="hours-2" form="approve-1"', page)
        self.assertEqual([m for m in re.findall(r'risk-(\w+)', page)], ["write", "read", "write"])  # row, grant 1, grant 2
        self.assertEqual(self.approve(1, **{"hours-1": "1", "hours-2": "0"}),
                         "Approved request #1 for myapp: grant 1 for 1 hour, grant 2 permanently.")
        st = self.statements()
        self.assertEqual(list(st), ["Req1g1", "Req1g2"])
        self.assertEqual(st["Req1g1"]["Resource"], self.BUCKET)
        self.assertIn("Condition", st["Req1g1"])
        self.assertNotIn("Condition", st["Req1g2"])
        self.assertTrue(self.app.broker.in_sync("myapp", self.app.store.approved("myapp")))
        self.assertEqual(self.api("GET", "/api/projects")[1]["projects"][0]["grants"][1]["reason"], "backfill")

    def test_each_grant_is_revoked_on_its_own_and_the_request_ends_with_its_last(self):
        self.two()
        self.approve(1)
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertEqual(page.count('name="op" value="revoke"'), 2)  # on the card, per grant
        self.assertEqual(page.count('name="op" value="extend"'), 2)
        self.assertEqual(self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1g1"}, "owner"),
                         "Revoked Req1g1 from myapp.")
        r = self.app.store.get(1)
        self.assertEqual((r["status"], [g["ended"] for g in r["grants"]]), ("approved", ["revoked", ""]))
        self.assertEqual(list(self.statements()), ["Req1g2"])
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["request_ids"], ev["detail"], ev["grants"]), ("revoke", [1], "grant 1 of #1", ["Req1g2"]))
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertEqual(page.count('name="op" value="revoke"'), 1)
        self.assertNotIn("Req1g1", page)  # Details shows only what IAM holds
        self.assertIn("Revoked: grant 1 of #1", page)
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1g2"}, "owner")
        self.assertEqual((self.app.store.get(1)["status"], self.statements()), ("revoked", {}))

    def test_the_sweep_and_extend_work_per_grant(self):
        self.two()
        self.approve(1, **{"hours-1": "1", "hours-2": "3"})
        self.assertEqual(self.app.decide({"op": "extend", "project": "myapp", "sid": "Req1g2", "hours": "24"}, "owner"),
                         "Extended Req1g2 on myapp for 1 day.")
        self.assertRegex(self.app.store.events()[-1]["detail"], r"^grant 2 of #1 until \d{4}-")
        later = time.time() + 2 * 3600
        self.assertEqual(self.app.sweep(later), {"expired": {"myapp": [1]}})
        r = self.app.store.get(1)
        self.assertEqual((r["status"], [g["ended"] for g in r["grants"]]), ("approved", ["expired", ""]))
        self.assertEqual(list(self.statements()), ["Req1g2"])
        self.assertEqual(self.app.store.events()[-1]["detail"], "grant 1 of #1")
        self.assertEqual(self.app.sweep(later), {"expired": {}})  # idempotent
        self.assertEqual(self.app.sweep(time.time() + 25 * 3600), {"expired": {"myapp": [1]}})
        self.assertEqual((self.app.store.get(1)["status"], self.statements()), ("expired", {}))
        with self.assertRaises(Exception):
            self.app.decide({"op": "extend", "project": "myapp", "sid": "Req1g2", "hours": "0"}, "owner")

    def test_refusals_apply_per_grant_at_approval_and_credential_time(self):
        stack = f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/web-*/*"
        status, r = self.ask([{"actions": ["s3:GetObject"], "resources": self.BUCKET},
                              {"actions": ["cloudformation:UpdateStack"], "resources": [stack]}])
        self.assertEqual(status, 201, r)
        self.cfn.add("us-east-1", "web-prod", f"arn:aws:iam::{ACCOUNT}:role/cdk-exec")
        from apm.broker import BrokerError
        with self.assertRaisesRegex(BrokerError, "grant 2: cloudformation:UpdateStack"):
            self.approve(1, **{"hours-1": "1"})
        r = self.app.store.get(1)
        self.assertEqual((r["status"], [g["expires_at"] for g in r["grants"]]), ("pending", [0, 0]))
        self.cfn.stacks.clear()
        self.approve(1)
        self.cfn.add("us-east-1", "web-prod", f"arn:aws:iam::{ACCOUNT}:role/cdk-exec")
        status, err = self.api("POST", "/api/credentials", {"project": "myapp"})
        self.assertEqual(status, 403)
        self.assertIn("Req1g2", err["error"])
        self.assertNotIn("Req1g1", err["error"])
        self.app.decide({"op": "revoke", "project": "myapp", "sid": "Req1g2"}, "owner")
        self.assertEqual(self.api("POST", "/api/credentials", {"project": "myapp"})[0], 200)


class SizeAndReplacesTests(unittest.TestCase):
    """Every write is size-checked first, and so is the card; a request can supersede grants."""
    BIG = ["arn:aws:s3:::bucket-" + "x" * 60 + f"-{i}/*" for i in range(60)]  # about half the limit

    def setUp(self):
        self.app, self.iam, _ = make_app()
        self.key = self.app.store.create_key("laptop")

    api, owner_post, ask, approve, statements = (WebTests.api, WebTests.owner_post, MultiGrantTests.ask,
                                                 MultiGrantTests.approve, MultiGrantTests.statements)

    def big(self, action="s3:GetObject", **body):
        status, r = self.ask(actions=[action], resources=self.BIG, **body)
        self.assertEqual(status, 201, r)
        return r

    def card(self, rid):
        return self.app(web.Request("GET", f"/requests/{rid}", cookies=session_cookie(self.app))).body

    def test_replaces_is_validated_at_request_time(self):
        self.approve(self.big()["id"])
        self.big("s3:PutObject")  # #2, pending
        status, other = self.api("POST", "/api/requests", {"project": "other", "actions": ["s3:GetObject"], "reason": "x"})
        self.approve(other["id"])  # #3
        for replaces, error in [(["Req9"], "Req9 isn't a grant myapp holds now"), (["Req2"], "Req2 isn't"),
                                (["Req3"], "Req3 isn't"), (["Req1g1"], "Req1g1 isn't"), (["s3:GetObject"], "Req52g3"),
                                ([1], "Req52g3"), (["Req1"] * 21, "up to 20")]:
            with self.subTest(replaces=replaces):
                status, r = self.ask(actions=["s3:GetObject"], replaces=replaces)
                self.assertEqual(status, 400)
                self.assertIn(error, r["error"])
        status, r = self.ask(actions=["s3:GetObject"], replaces=["Req1", "Req1"])
        self.assertEqual((status, r["replaces"]), (201, ["Req1"]))

    def test_the_card_names_the_policy_and_offers_reject_with_a_note(self):
        self.approve(self.big()["id"])
        r = self.big("s3:PutObject")
        page = self.card(r["id"])
        self.assertIn("Too big to approve.", page)
        self.assertIn("inline policy apm-grants on role apm-myapp would be 10,720 characters, 480 over", page)
        self.assertNotIn(f'id="approve-{r["id"]}"', page)
        self.assertIn("Reject and tell the agent", page)
        note = re.search(r"<textarea[^>]*>([^<]*)</textarea>", page).group(1)
        self.assertIn("--replaces", note)
        self.owner_post({"op": "reject", "id": str(r["id"]), "digest": self.app.store.get(r["id"])["digest"],
                         "note": "edited: use --replaces Req1"})
        self.assertEqual(self.api("GET", f"/api/requests/{r['id']}")[1]["note"], "edited: use --replaces Req1")
        # The same request superseding the first grant fits: the card lists it and offers Approve.
        r = self.big("s3:PutObject", replaces=["Req1"])
        page = self.card(r["id"])
        self.assertNotIn("Too big", page)
        self.assertIn(f'id="approve-{r["id"]}"', page)
        self.assertIn("<code>Req1</code>", page)
        self.assertIn("Approving revokes these first", page)

    def test_the_card_checks_the_chosen_time_limits(self):
        self.approve(self.big()["id"])
        r = self.big("s3:PutObject", suggested_hours=1)
        smallest = policy.size(self.app.approval(self.app.store.get(r["id"]), {1: 0}, self.app.store.approved("myapp"))[2])
        with mock.patch.object(policy, "MAX_INLINE_POLICY_CHARS", smallest + 10):  # fits only if permanent
            page = self.card(r["id"])
            self.assertNotIn("Too big to approve", page)  # making it permanent fits, so no reject-only card
            self.assertIn(f'data-size="{smallest}" data-per-limit="{policy.CONDITION_CHARS}"', page)
            self.assertIn('<button class="approve" disabled>', page)
            self.assertIn("Too big with these time limits: the inline policy apm-grants on role apm-myapp", page)
            self.assertIn("62+over", self.app.action({"op": "approve", "id": str(r["id"]), "digest": self.app.store.get(r["id"])["digest"],
                                                      "hours-1": "1"}, "owner").headers["Location"])
            self.assertIn("Approved", self.approve(r["id"], **{"hours-1": "0"}))

    def test_approving_revokes_the_replaced_grants_then_approves(self):
        self.approve(self.big()["id"])
        status, two = self.ask(grants=[{"actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:1:q"]},
                                       {"actions": ["sns:Publish"], "resources": ["arn:aws:sns:us-east-1:1:t"]}])
        self.approve(two["id"])
        r = self.big("s3:PutObject", replaces=["Req1", "Req2g2"])
        self.assertEqual(self.approve(r["id"]), f"Approved request #{r['id']} for myapp. It replaced Req1, Req2g2.")
        self.assertEqual(sorted(self.statements()), ["Req2g1", f"Req{r['id']}"])
        old = self.app.store.get(1)
        self.assertEqual((old["status"], old["note"]), ("revoked", f"replaced by #{r['id']}"))
        self.assertEqual([g["ended"] for g in self.app.store.get(2)["grants"]], ["", "revoked"])
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["outcome"], ev["request_ids"], ev["detail"]),
                         ("approve", "applied", [1, 2, r["id"]], "replaces Req1, Req2g2"))

    def test_a_failed_save_puts_the_replaced_grants_back(self):
        self.approve(self.big()["id"])
        r = self.big("s3:PutObject", replaces=["Req1"])
        real = self.app.store.set_status

        def flaky(rid, status, *a, **kw):
            if rid == r["id"] and status == "approved":
                raise RuntimeError("dynamodb down")
            return real(rid, status, *a, **kw)
        self.app.store.set_status = flaky
        with self.assertRaises(RuntimeError):
            self.approve(r["id"])
        del self.app.store.set_status
        self.assertEqual([self.app.store.get(i)["status"] for i in (1, r["id"])], ["approved", "pending"])
        self.assertEqual(list(self.statements()), ["Req1"])
        self.assertIn("Approved", self.approve(r["id"]))  # and it can simply be approved again

    def test_the_size_check_runs_before_anything_changes(self):
        self.approve(self.big()["id"])
        status, small = self.ask(actions=["sqs:SendMessage"], resources=["arn:aws:sqs:us-east-1:1:q"])
        self.approve(small["id"])
        r = self.big("s3:PutObject", replaces=["Req2"])  # replacing the small grant isn't enough
        from apm.broker import BrokerError
        with self.assertRaisesRegex(BrokerError, "apm-grants on role apm-myapp .* over the 10,240-character limit"):
            self.approve(r["id"])
        self.assertEqual([self.app.store.get(i)["status"] for i in (1, 2, r["id"])], ["approved", "approved", "pending"])
        self.assertEqual(self.app.store.events()[-1]["outcome"], "refused")

    def test_a_refused_approval_that_replaced_grants_goes_back_to_pending(self):
        self.approve(self.big()["id"])
        r = self.big("s3:PutObject", replaces=["Req1"])
        class LimitExceeded(Exception):  # what boto3 raises when IAM rejects the document
            response = {"Error": {"Code": "LimitExceeded"}}
        self.iam.put_role_policy = mock.Mock(side_effect=LimitExceeded("Maximum policy size exceeded"))
        resp = self.owner_post({"op": "approve", "id": str(r["id"]), "digest": self.app.store.get(r["id"])["digest"]})
        msg = parse_qs(urlparse(resp.headers["Location"]).query)["msg"][0]
        self.assertIn("IAM refused the policy for apm-myapp (LimitExceeded): Maximum policy size exceeded. It's pending "
                      "again, but the grants it replaces (Req1) were already revoked and IAM may still hold them: open "
                      "Projects and tap Re-apply decisions for myapp.", msg)
        self.assertEqual(self.app.store.get(r["id"])["status"], "pending")
        self.assertEqual(self.app.store.get(1)["status"], "revoked")
        self.assertEqual(list(self.statements()), ["Req1"])  # IAM still holds it until Re-apply
        self.assertEqual(self.app.store.events()[-1]["outcome"], "refused")
        del self.iam.put_role_policy
        self.app.decide({"op": "sync_project", "project": "myapp"})
        self.assertEqual(self.statements(), {})


class RemoveTests(unittest.TestCase):
    """Access only shrinks without approval: an agent's remove and the owner's narrow. Each records
    one event and the agent's remove always pushes the owner, failures included."""
    BUCKET = ["arn:aws:s3:::exports", "arn:aws:s3:::exports/*"]
    TABLE = [f"arn:aws:dynamodb:us-east-1:{ACCOUNT}:table/orders"]

    def setUp(self):
        self.app, self.iam, _ = make_app()
        self.key = self.app.store.create_key("laptop")
        self.pushes = []
        self.app.notify = lambda message, **kw: self.pushes.append(message) or {}

    api = WebTests.api

    def grant(self, **body):
        status, r = self.api("POST", "/api/requests", {"project": "myapp", "reason": "backfill", **body})
        self.assertEqual(status, 201, r)
        r = self.app.store.get(r["id"])
        self.app.decide({"op": "approve", "id": str(r["id"]), "digest": r["digest"]}, "owner")
        self.pushes.clear()
        return r["id"]

    def remove(self, grant, **body):
        return self.api("POST", "/api/remove", {"project": "myapp", "grant": grant, "reason": "export done", **body})

    def statements(self):
        doc = self.iam.policies.get(("apm-myapp", "apm-grants"))
        return {s["Sid"]: (s["Action"], s["Resource"]) for s in doc["Statement"]} if doc else {}

    def test_partial_removal_applies_at_once_and_names_the_key_and_reason(self):
        self.grant(actions=["s3:GetObject", "s3:PutObject"], resources=self.BUCKET)
        status, out = self.remove("Req1", actions=["s3:PutObject"], resources=["arn:aws:s3:::exports"])
        self.assertEqual(status, 200, out)
        self.assertEqual((out["ended"], out["message"]),
                         (False, "Removed s3:PutObject, arn:aws:s3:::exports from Req1 on myapp."))
        self.assertEqual(self.statements(), {"Req1": (["s3:GetObject"], ["arn:aws:s3:::exports/*"])})
        self.assertEqual(self.app.store.get(1)["status"], "approved")
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["outcome"], ev["actor"], ev["agent_keys"]), ("remove", "applied", "laptop", ["laptop"]))
        self.assertIn("Reason: export done", ev["detail"])
        self.assertEqual([p["title"] for p in self.pushes], ["laptop narrowed Req1"])
        self.assertNotIn("s3:", json.dumps(self.pushes))  # nothing sensitive on a lock screen
        page = self.app(web.Request("GET", "/requests/1", cookies=session_cookie(self.app))).body
        self.assertIn("Removed by the agent: removed s3:PutObject, arn:aws:s3:::exports from Req1. Reason: export done", page)
        # Names must match exactly, and nothing changes when they don't.
        status, out = self.remove("Req1", actions=["s3:getobject"])
        self.assertEqual(status, 400)
        self.assertIn("Use the exact names", out["error"])
        self.assertEqual(self.statements()["Req1"][0], ["s3:GetObject"])
        self.assertEqual(self.pushes[-1]["title"], "laptop couldn't remove Req1")
        # Dropping the last action ends the grant.
        status, out = self.remove("Req1", actions=["s3:GetObject"])
        self.assertEqual((status, out["ended"], self.app.store.get(1)["status"], self.statements()), (200, True, "revoked", {}))

    def test_removing_a_whole_grant_and_asking_which_grant(self):
        self.grant(grants=[{"actions": ["s3:GetObject"], "resources": self.BUCKET},
                           {"actions": ["dynamodb:PutItem", "dynamodb:GetItem"], "resources": self.TABLE}])
        status, out = self.remove("Req1", actions=["dynamodb:PutItem"])
        self.assertEqual(status, 400)
        self.assertIn("Req1 is a request with several grants; name the one to remove from: Req1g1, Req1g2", out["error"])
        self.assertEqual(self.remove("Req1g2", actions=["dynamodb:PutItem"])[0], 200)
        r = self.app.store.get(1)
        self.assertEqual((r["grants"][1]["actions"], r["actions"]), (["dynamodb:GetItem"], ["dynamodb:GetItem", "s3:GetObject"]))
        status, out = self.remove("Req1g1")
        self.assertEqual((status, out["message"]), (200, "Removed Req1g1 from myapp."))
        self.assertEqual(list(self.statements()), ["Req1g2"])
        self.assertEqual([g["ended"] for g in self.app.store.get(1)["grants"]], ["revoked", ""])
        self.assertIn("name the one", self.remove("Req1", actions=["dynamodb:GetItem"])[1]["error"])  # even with one left
        self.assertEqual(self.remove("Req1")[0], 200)  # the base Sid with nothing named: all that's left
        self.assertEqual((self.app.store.get(1)["status"], self.statements()), ("revoked", {}))
        self.assertEqual(self.remove("Req1")[0], 409)  # no longer held
        self.assertEqual(self.remove("nope")[0], 400)  # malformed: still pushed, without echoing it
        bad = self.app(web.Request("POST", "/api/remove", headers={"Authorization": f"Bearer {self.key}"}, body=b"{"))
        self.assertEqual(bad.status, 400)
        self.assertEqual(len(self.pushes), 8)
        self.assertEqual(self.pushes[-1]["title"], "laptop couldn't remove access")

    def test_a_failed_iam_write_reports_what_was_applied_and_still_pushes(self):
        self.grant(actions=["s3:GetObject", "s3:PutObject"], resources=self.BUCKET)
        self.iam.put_role_policy = mock.Mock(side_effect=TimeoutError("read timed out"))
        status, out = self.remove("Req1", actions=["s3:PutObject"])
        self.assertEqual(status, 502)
        self.assertIn("recorded the removal (Removed s3:PutObject from Req1 on myapp), but updating IAM failed", out["error"])
        self.assertEqual(self.app.store.get(1)["actions"], ["s3:GetObject"])
        self.assertEqual(self.app.store.events()[-1]["outcome"], "failed")
        self.assertEqual(self.pushes[-1]["body"], "myapp: but updating IAM failed. Open Projects and re-apply.")
        self.assertFalse(self.app.broker.in_sync("myapp", self.app.store.approved("myapp")))  # Re-apply is offered
        del self.iam.put_role_policy
        self.app.decide({"op": "sync_project", "project": "myapp"})
        self.assertEqual(self.statements(), {"Req1": (["s3:GetObject"], self.BUCKET)})

    def test_the_owner_narrows_one_action_or_resource_on_projects(self):
        self.grant(actions=["s3:GetObject", "s3:PutObject"], resources=self.BUCKET)
        cookies = session_cookie(self.app)
        page = self.app(web.Request("GET", "/projects", cookies=cookies)).body
        self.assertEqual(page.count('name="op" value="narrow"'), 4)

        def narrow(**field):
            body = urlencode({"op": "narrow", "project": "myapp", "sid": "Req1", "back": "/projects", **field}).encode()
            resp = self.app(web.Request("POST", "/action", headers={"Origin": ORIGIN}, cookies=cookies, body=body))
            return parse_qs(urlparse(resp.headers["Location"]).query)["msg"][0]
        self.assertEqual(narrow(resource="arn:aws:s3:::exports"), "Removed arn:aws:s3:::exports from Req1 on myapp.")
        self.assertEqual(self.statements(), {"Req1": (["s3:GetObject", "s3:PutObject"], ["arn:aws:s3:::exports/*"])})
        ev = self.app.store.events()[-1]
        self.assertEqual((ev["op"], ev["actor"], ev["detail"]), ("narrow", OWNER, "removed arn:aws:s3:::exports"))
        page = self.app(web.Request("GET", "/requests/1", cookies=cookies)).body
        self.assertIn("Narrowed: removed arn:aws:s3:::exports", page)
        self.assertIn("Error:", narrow(action="s3:DeleteObject"))
        self.assertEqual(narrow(resource="arn:aws:s3:::exports/*"),
                         "Removed arn:aws:s3:::exports/* from Req1 on myapp, which ended it.")
        self.assertEqual((self.app.store.get(1)["status"], self.statements()), ("revoked", {}))
        self.assertEqual(self.pushes, [])  # the owner did it


    def test_remove_on_a_projects_row_narrows_every_grant_on_it_and_the_row_stays_open(self):
        self.grant(actions=["s3:GetObject", "s3:PutObject"], resources=self.BUCKET)
        self.grant(actions=["s3:GetObject"], resources=self.BUCKET)  # same resources and time limit: one row
        cookies = session_cookie(self.app)
        page = self.app(web.Request("GET", "/projects", cookies=cookies)).body
        row = re.findall(r'class=grant-row id="(row-myapp-[0-9a-f]+)"', page)
        self.assertEqual(len(row), 1)
        self.assertIn('name="sid" value="Req1 Req2"><input type="hidden" name="action" value="s3:GetObject"', page)
        body = urlencode({"op": "narrow", "project": "myapp", "sid": "Req1 Req2", "action": "s3:GetObject",
                          "back": "/projects"}).encode()
        resp = self.app(web.Request("POST", "/action", headers={"Origin": ORIGIN}, cookies=cookies, body=body))
        self.assertEqual(parse_qs(urlparse(resp.headers["Location"]).query)["msg"][0],
                         "Removed s3:GetObject from Req1 on myapp. Removed s3:GetObject from Req2 on myapp, which ended it.")
        self.assertEqual(self.statements(), {"Req1": (["s3:PutObject"], self.BUCKET)})
        page = self.app(web.Request("GET", "/projects", cookies=cookies)).body
        self.assertEqual(re.findall(r'class=grant-row id="(row-myapp-[0-9a-f]+)"', page), row)  # same id: still open

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
        self.assertEqual(names, ["connect", "list_projects", "get_aws_credentials", "request_permissions", "remove_permissions", "check_request", "list_requests"])

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
        sent = tool(12, "request_permissions", project="myapp", reason="sync", grants=[
            {"actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::b/*"], "duration": "3h"},
            {"actions": ["sqs:SendMessage"], "resources": ["arn:aws:sqs:us-east-1:1:q"]}])
        self.assertIn("Request #2", sent["content"][0]["text"])
        checked = json.loads(tool(13, "check_request", request_id=2)["content"][0]["text"])
        self.assertEqual([g["grant"] for g in checked["grants"]], ["Req2g1", "Req2g2"])
        self.assertEqual(self.app.store.get(2)["grants"][0]["suggested_hours"], 3)
        mixed = tool(14, "request_permissions", project="myapp", reason="sync", resources=["arn:aws:s3:::b/*"],
                     grants=[{"actions": ["s3:GetObject"]}])
        self.assertTrue(mixed["isError"])  # resources outside grants would be dropped, widening the request to *

        # The AWS CLI would run this credential_process command from the profile.
        stable = self.tmp / "apm" / "bin" / "apm.py"
        creds = json.loads(subprocess.run([self.python, str(stable), "credentials", "myapp"], env=self.env,
                                          capture_output=True, text=True, check=True).stdout)
        self.assertEqual(creds["Version"], 1)
        self.assertEqual(oct((self.tmp / "apm" / "cache" / "myapp.json").stat().st_mode & 0o777), "0o600")
        removed = tool(14, "remove_permissions", project="myapp", grant="Req1", reason="listing done")
        self.assertEqual(removed["content"][0]["text"], "Removed Req1 from myapp.")

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
        contents = []
        for _ in range(2):  # a second `use` leaves the file unchanged
            r = run("use", "web")
            self.assertEqual(r.returncode, 0, r.stderr)
            contents.append(config.read_text())
        self.assertEqual(contents[0], contents[1])
        text = contents[1]
        self.assertTrue(text.startswith("# keep this comment\n[default]\nregion = eu-west-1\n"))
        self.assertIn("[profile other]\nregion = ap-south-1\n", text)
        self.assertIn("output = json", text)
        self.assertNotIn("stale command", text)
        self.assertEqual(text.count("[profile apm-web]"), 1)
        self.assertEqual(text.count("credential_process"), 1)
        self.assertIn("credentials web", text)
        self.assertEqual(oct(config.stat().st_mode & 0o777), "0o600")
        self.assertEqual((self.tmp / "aws-config.apm-backup").read_text(), original)

    def test_profile_update_writes_through_a_symlinked_config(self):
        real = self.tmp / "shared-config"
        real.write_text("[default]\nregion = eu-west-1\n")
        real.chmod(0o640)
        (self.tmp / "aws-config").symlink_to(real)
        run = lambda *a: subprocess.run([self.python, str(CLIENT), *a], env=self.env, capture_output=True, text=True)
        run("request", "--project", "web", "-a", "s3:GetObject", "--reason", "read")
        self.approve_all()
        r = run("use", "web")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((self.tmp / "aws-config").is_symlink())
        self.assertIn("[profile apm-web]", real.read_text())
        self.assertEqual(oct(real.stat().st_mode & 0o777), "0o640")

    def test_mcp_rejects_malformed_requests_and_hides_keys(self):
        env = {**self.env, "APM_API_KEY": "apm_SYNTHETICSECRET\nx"}  # breaks the HTTP header
        proc = subprocess.Popen([self.python, str(CLIENT), "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                env=env, text=True)
        def stop():
            proc.stdin.close()
            proc.wait(5)
            proc.stdout.close()
        self.addCleanup(stop)

        def send(raw):
            proc.stdin.write(raw + "\n")
            proc.stdin.flush()
            return json.loads(proc.stdout.readline())

        self.assertEqual(send("null")["error"]["code"], -32600)
        self.assertEqual(send("[1]")["error"]["code"], -32600)
        self.assertEqual(send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "nope"}))["error"]["code"], -32601)
        out = send(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": "list_projects", "arguments": {}}}))["result"]
        self.assertTrue(out["isError"])
        self.assertNotIn("SYNTHETICSECRET", out["content"][0]["text"])
        self.assertEqual(send(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"}))["result"], {})


    def test_cli(self):
        run = lambda *a: subprocess.run([self.python, str(CLIENT), *a], env=self.env, capture_output=True, text=True)
        r = run("request", "--project", "web", "-a", "s3:GetObject", "--reason", "read", "--for", "3h")
        self.assertIn("Request #1", r.stdout)
        self.assertEqual(self.app.store.get(1)["suggested_hours"], 3)
        self.assertIn("pending", run("status").stdout)
        self.approve_all()
        self.assertEqual(run("wait", "1", "--timeout", "5").returncode, 0)
        self.assertIn("web", run("projects").stdout)
        self.assertEqual(run("projects", "--search", "nothing").stdout.strip(), "No matching projects.")
        r = run("request", "--project", "web", "--grant", "s3:GetObject,s3:ListBucket=arn:aws:s3:::b,arn:aws:s3:::b/*",
                "--grant", "sqs:SendMessage=arn:aws:sqs:us-east-1:1:q", "--reason", "sync", "--for", "1h")
        self.assertIn("Request #2", r.stdout, r.stderr)
        self.assertEqual([(g["actions"], g["resources"], g["suggested_hours"]) for g in self.app.store.get(2)["grants"]],
                         [(["s3:GetObject", "s3:ListBucket"], ["arn:aws:s3:::b", "arn:aws:s3:::b/*"], 1),
                          (["sqs:SendMessage"], ["arn:aws:sqs:us-east-1:1:q"], 1)])
        self.assertIn("Req2g2: sqs:SendMessage on arn:aws:sqs:us-east-1:1:q", run("status", "2").stdout)
        run("request", "--project", "web", "-a", "s3:PutObject", "--replaces", "Req1", "--reason", "swap")
        self.assertEqual(self.app.store.get(3)["replaces"], ["Req1"])
        self.assertIn("not both", run("request", "--project", "web", "--grant", "s3:GetObject", "-a", "s3:GetObject",
                                      "--reason", "x").stderr)
        self.assertIn("not both", run("request", "--project", "web", "--grant", "s3:GetObject", "-r", "arn:aws:s3:::b",
                                      "--reason", "x").stderr)
        self.approve_all()
        r = run("remove", "--project", "web", "--grant", "Req2g1", "-a", "s3:ListBucket", "--reason", "done")
        self.assertEqual(r.stdout.strip(), "Removed s3:ListBucket from Req2g1 on web.", r.stderr)
        self.assertIn("exact names", run("remove", "--project", "web", "--grant", "Req2g1", "-a", "s3:listbucket",
                                         "--reason", "done").stderr)


class AwsConfigEditTests(unittest.TestCase):
    """upsert_profile must leave a file the AWS CLI (botocore's RawConfigParser) still reads."""
    SECTION = "profile apm-a"
    VALUES = {"credential_process": '"python3" "/x/apm.py" credentials a', "region": "us-east-1"}

    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("apm_client", CLIENT)
        cls.client = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.client)

    def parse(self, text):
        import configparser
        ini = configparser.RawConfigParser()
        ini.read_string(text)
        return ini

    def test_edge_cases_parse_and_are_idempotent(self):
        cases = {
            "empty": "",
            "no trailing newline": "[default]\nregion = eu-west-1",
            "crlf": "[default]\r\nregion = eu-west-1\r\n",
            "colon delimiter and comment after header": "[profile apm-a] # mine\nregion: eu-west-1\ncredential_process : old\n",
            "indented keys": "[profile apm-a]\n  region = eu\n  output = json\n",
            "nested values": "[profile apm-a]\ns3 =\n    region = nested\ncredential_process = old\n    more\n[default]\nregion=x\n",
            "commented-out header": "# [profile apm-a]\n[default]\nregion=x\n",
            "upper-case keys": "[profile apm-a]\nREGION = eu\n",
        }
        for name, text in cases.items():
            with self.subTest(name):
                out = self.client.upsert_profile(text, self.SECTION, self.VALUES)
                ini = self.parse(out)
                for k, v in self.VALUES.items():
                    self.assertEqual(ini.get(self.SECTION, k), v)
                self.assertEqual(self.client.upsert_profile(out, self.SECTION, self.VALUES), out)
                self.assertEqual(sum(l.startswith("[profile apm-a]") for l in out.splitlines()), 1)
                if "\r\n" in text:
                    self.assertNotIn("\n", out.replace("\r\n", ""))
        nested = self.parse(self.client.upsert_profile(cases["nested values"], self.SECTION, self.VALUES))
        self.assertIn("region = nested", nested.get(self.SECTION, "s3"))

    def test_unparsable_file_is_refused_without_echoing_it(self):
        # Broken elsewhere in the file (a duplicate option in another profile): don't touch it.
        bad = "[default]\nregion = 1\nregion = 2\naws_secret_access_key = SECRETVALUE\n"
        out = self.client.upsert_profile(bad, self.SECTION, self.VALUES)
        with self.assertRaises(self.client.ApmError) as e:
            self.client._check_config(out, self.SECTION, self.VALUES)
        self.assertNotIn("SECRETVALUE", str(e.exception))
        self.assertIn("left unchanged", str(e.exception))

    def test_use_reports_a_broken_config_even_when_the_profile_is_already_right(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config"
            good = self.client.upsert_profile("", self.SECTION, self.VALUES)
            config.write_text(good + "[default]\nregion = 1\nregion = 2\n")
            before = config.read_text()
            with mock.patch.object(self.client, "AWS_CONFIG", config), \
                 mock.patch.object(self.client, "fetch_credentials"), \
                 mock.patch.object(self.client, "_stable_copy", return_value="/x/apm.py"), \
                 mock.patch.object(self.client, "call", return_value={"region": "us-east-1"}), \
                 mock.patch.object(self.client.sys, "executable", "python3"):
                with self.assertRaises(self.client.ApmError):
                    self.client.use("a")
            self.assertEqual(config.read_text(), before)


if __name__ == "__main__":
    unittest.main()
