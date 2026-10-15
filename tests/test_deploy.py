"""Stage naming, template rendering and artifact checks. No AWS calls and no network."""
import copy
import fnmatch
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path

from apm import cli, deploy, policy

ROOT = Path(__file__).resolve().parent.parent
ACCOUNT = "654654478411"
# The exact arguments used to capture tests/fixtures/prod_template_before_stages.json from the
# single-stage deploy.py (commit bf98c18 on baseline/hosted-apm) before stages were added.
PROD_ARGS = (ACCOUNT, "us-east-1", "apm.taylorrowser.com", "Z0EXAMPLE", "owner@example.com", "client_EXAMPLE",
             "VAPIDPUB", "apm-artifacts-654654478411-us-east-1", "lambda/0123456789abcdef.zip")
# The only boundary statements prod gained since the fixture was captured (baseline commits 290bf35
# and 759d908), in boundary order.
PROD_BOUNDARY_DENIES = [
    {"Sid": "DenyApmInfrastructure", "Effect": "Deny", "Action": "*", "Resource": [
        f"arn:aws:ssm:*:{ACCOUNT}:parameter/apm*",
        f"arn:aws:lambda:*:{ACCOUNT}:function:apm*",
        f"arn:aws:dynamodb:*:{ACCOUNT}:table/apm*",
        f"arn:aws:cloudformation:*:{ACCOUNT}:stack/apm*",
        f"arn:aws:logs:*:{ACCOUNT}:log-group:/aws/lambda/apm*",
        "arn:aws:s3:::apm-*",
        "arn:aws:apigateway:*::/domainnames/*apm*"]},
    {"Sid": "DenyApmTaggedResources", "Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
     "Condition": {"StringEquals": {"aws:ResourceTag/managed-by": "apm"}}},
    {"Sid": "DenyRecursiveReadOfRoot", "Effect": "Deny", "Action": "ssm:GetParametersByPath",
     "Resource": [f"arn:aws:ssm:*:{ACCOUNT}:parameter/", f"arn:aws:ssm:*:{ACCOUNT}:parameter"]},
    {"Sid": "DenyApmDnsRecords", "Effect": "Deny", "Action": "route53:ChangeResourceRecordSets", "Resource": "*",
     "Condition": {"ForAnyValue:StringLike": {
         "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["apm.*", "*.apm.*"]}}},
]
# V1 hardening: domain registration never grantable, audit-trail tampering and the stack's own API denied.
PROD_V1_BOUNDARY_DENIES = [
    {"Sid": "DenyAuditTampering", "Effect": "Deny", "Resource": "*", "Action": [
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors", "cloudtrail:DeleteEventDataStore", "cloudtrail:UpdateEventDataStore",
        "cloudtrail:StopEventDataStoreIngestion"]},
    {"Sid": "DenyApmApi", "Effect": "Deny", "Action": "apigateway:*", "Resource": [
        {"Fn::Sub": "arn:aws:apigateway:*::/apis/${Api}"}, {"Fn::Sub": "arn:aws:apigateway:*::/apis/${Api}/*"}]},
]
NONPROD = ["dev", "pr-1", "pr-12", "pr-123"]
# Prod project names chosen to collide with naive nonprod naming.
TRICKY_PROJECTS = ["myapp", "dev", "dev-broker", "broker", "pr-1", "pr-12-app", "agents", "dev-agent-boundary"]


def iam_match(pattern, arn):
    # IAM resource wildcards: * matches any run of characters (including /), ? one character.
    return fnmatch.fnmatchcase(arn, pattern)


SWEEP = {
    "Sweep": {"Type": "AWS::Events::Rule", "Properties": {
        "Name": "apm-sweep", "Description": "apm: remove expired grants every 15 minutes",
        "ScheduleExpression": "rate(15 minutes)", "State": "ENABLED",
        "Targets": [{"Id": "sweep", "Arn": {"Fn::GetAtt": ["Function", "Arn"]}, "Input": '{"apm_sweep": true}'}]}},
    "SweepPermission": {"Type": "AWS::Lambda::Permission", "Properties": {
        "FunctionName": {"Ref": "Function"}, "Action": "lambda:InvokeFunction",
        "Principal": "events.amazonaws.com", "SourceArn": {"Fn::GetAtt": ["Sweep", "Arn"]}}},
}


def resources(stmt):
    r = stmt["Resource"]
    return [r] if isinstance(r, str) else r


class ProdCompatibility(unittest.TestCase):
    def test_prod_template_matches_pre_stage_template(self):
        before = json.loads((ROOT / "tests/fixtures/prod_template_before_stages.json").read_text())
        expected = copy.deepcopy(before)
        # Intended change 1: the Lambda learns its stage (the PWA badge and policy.py read it).
        expected["Resources"]["Function"]["Properties"]["Environment"]["Variables"]["APM_STAGE"] = "prod"
        # Intended change 2: the baseline security fixes (290bf35, 759d908) appended four Deny statements
        # to the agent boundary. Spelled out literally so any other boundary drift fails this test.
        expected["Resources"]["Boundary"]["Properties"]["PolicyDocument"]["Statement"] += PROD_BOUNDARY_DENIES
        # Intended change 3 (V1 hardening): route53domains:* joins the never-grantable actions, and two
        # more Deny statements follow.
        statements = expected["Resources"]["Boundary"]["Properties"]["PolicyDocument"]["Statement"]
        allow = next(st for st in statements if st["Sid"] == "AllowNonAdminServices")
        allow["NotAction"] = allow["NotAction"][:11] + ["route53domains:*"] + allow["NotAction"][11:]
        statements += PROD_V1_BOUNDARY_DENIES
        # Intended change 4: the broker may list stacks (read-only), to refuse stack writes that would run
        # as a stack's stored role.
        broker = expected["Resources"]["BrokerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        broker.insert(4, {"Sid": "CheckStackRoles", "Effect": "Allow", "Resource": "*",
                          "Action": ["cloudformation:DescribeStacks", "cloudformation:ListStacks"]})
        # Intended change 5: the expiry sweep, a 15-minute schedule that invokes the Lambda.
        expected["Resources"].update(SWEEP)
        # Intended change 6: the AI reviewer may manage its one key parameter and invoke its own function.
        broker.extend([
            {"Sid": "ReviewerKey", "Effect": "Allow",
             "Action": ["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"],
             "Resource": f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm/llm-key"},
            {"Sid": "QueueReview", "Effect": "Allow", "Action": "lambda:InvokeFunction",
             "Resource": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:apm"}])
        # Intended change 7 (usage audit): the broker may read Access Advisor reports on agent roles.
        at = next(i for i, st in enumerate(broker) if st["Sid"] == "VendAgentCredentials") + 1
        broker[at:at] = [
            {"Sid": "AuditAgentRoleUsage", "Effect": "Allow", "Action": "iam:GenerateServiceLastAccessedDetails",
             "Resource": f"arn:aws:iam::{ACCOUNT}:role/agents/*"},
            {"Sid": "ReadUsageReports", "Effect": "Allow", "Action": "iam:GetServiceLastAccessedDetails", "Resource": "*"}]
        self.assertEqual(json.loads(json.dumps(deploy.template(*PROD_ARGS))), expected)
        self.assertEqual(json.loads(json.dumps(deploy.template(*PROD_ARGS, stage="prod"))), expected)

    def test_prod_resource_names_byte_identical(self):
        before = json.loads((ROOT / "tests/fixtures/prod_template_before_stages.json").read_text())
        after = json.loads(json.dumps(deploy.template(*PROD_ARGS)))
        for added in SWEEP:  # new since, so not in the old template
            del after["Resources"][added]
        self.assertEqual(sorted(after["Resources"]), sorted(before["Resources"]))

        def names(t):
            out = {}
            for logical, r in t["Resources"].items():
                for k, v in r.get("Properties", {}).items():
                    if k.endswith("Name") or k in ("Path", "DomainName", "Bucket"):
                        out[(logical, k)] = json.dumps(v, sort_keys=True)
            return out
        self.assertEqual(names(after), names(before))
        self.assertTrue(names(before))

    def test_prod_names_unchanged(self):
        n = policy.Names("prod")
        self.assertEqual(
            (n.stack, n.table, n.function, n.param_prefix, n.role_path, n.role_prefix, n.boundary_name,
             n.broker_role, n.broker_role_path, n.artifact_bucket(ACCOUNT, "us-east-1")),
            ("apm", "apm", "apm", "/apm", "/agents/", "apm-", "apm-agent-boundary", "apm-broker", "/apm/",
             "apm-artifacts-654654478411-us-east-1"))
        self.assertEqual((deploy.STACK, deploy.TABLE, deploy.FUNCTION, deploy.PARAM_PREFIX), ("apm", "apm", "apm", "/apm"))

    def test_runtime_defaults_to_prod_and_follows_apm_stage(self):
        code = ("import json; from apm import policy as p; print(json.dumps([p.ROLE_PATH, p.ROLE_PREFIX, "
                "p.BOUNDARY_NAME, p.BROKER_ROLE, p.BROKER_ROLE_PATH, p.role_arn('1', 'x')]))")
        env = {k: v for k, v in os.environ.items() if k != "APM_STAGE"}

        def run(extra):
            out = subprocess.run([sys.executable, "-c", code], env={**env, **extra}, cwd=ROOT,
                                 capture_output=True, text=True, check=True).stdout
            return json.loads(out)

        self.assertEqual(run({}), ["/agents/", "apm-", "apm-agent-boundary", "apm-broker", "/apm/",
                                   "arn:aws:iam::1:role/agents/apm-x"])
        self.assertEqual(run({"APM_STAGE": "prod"}), run({}))
        self.assertEqual(run({"APM_STAGE": "pr-7"}), ["/agents-pr-7/", "apm-pr-7_", "apm-pr-7_agent-boundary",
                                                      "apm-pr-7__broker", "/apm-pr-7/",
                                                      "arn:aws:iam::1:role/agents-pr-7/apm-pr-7_x"])


class StageIsolation(unittest.TestCase):
    def test_invalid_stages_rejected(self):
        for bad in ["", "Prod", "staging", "pr-", "pr-0", "pr-01", "pr-x", "dev/../prod", "pr-12345678"]:
            with self.assertRaises(ValueError, msg=bad):
                policy.Names(bad)

    def test_names_fit_iam_limits(self):
        n = policy.Names("pr-9999999")
        self.assertLessEqual(len(policy.role_name("a" + "b" * 40, n)), 64)
        self.assertLessEqual(len(n.broker_role), 64)
        self.assertLessEqual(len(n.boundary_name), 128)

    def test_nonprod_broker_cannot_touch_prod_or_other_stages(self):
        prod = policy.Names("prod")
        all_stages = [prod] + [policy.Names(s) for s in NONPROD]
        for n in all_stages:
            others = [o for o in all_stages if o != n]
            pol = policy.broker_policy(ACCOUNT, n)
            for stmt in pol["Statement"]:
                if stmt["Effect"] != "Allow" or not any(x.startswith(("iam:", "sts:")) for x in _actions(stmt, "Action")):
                    continue  # only IAM and STS actions can touch a role
                for pattern in resources(stmt):
                    for o in others:
                        if n.is_prod and stmt["Sid"] == "LookUpAgentRoles":
                            continue  # prod's pre-existing read-only lookup pattern role/apm-*; see docs
                        if stmt["Sid"] == "ReadUsageReports":
                            continue  # reads finished Access Advisor jobs; AWS allows no resource but *
                        for project in TRICKY_PROJECTS:
                            for arn in (policy.role_arn(ACCOUNT, project, o),
                                        f"arn:aws:iam::{ACCOUNT}:role/{policy.role_name(project, o)}"):
                                self.assertFalse(iam_match(pattern, arn), (n.stage, stmt["Sid"], pattern, arn))
                        self.assertFalse(iam_match(pattern, policy.broker_role_arn(ACCOUNT, o)))

    def test_prod_writes_never_match_nonprod_roles(self):
        prod_writes = [s for s in policy.broker_policy(ACCOUNT, policy.Names("prod"))["Statement"]
                       if s["Sid"] in ("CreateAgentRolesWithBoundary", "EditAgentRoles", "VendAgentCredentials")]
        for stage in NONPROD:
            arn = policy.role_arn(ACCOUNT, "myapp", policy.Names(stage))
            for s in prod_writes:
                for pattern in resources(s):
                    self.assertFalse(iam_match(pattern, arn), (s["Sid"], arn))

    def test_nonprod_iam_names_cannot_equal_any_prod_role(self):
        for stage in NONPROD:
            n = policy.Names(stage)
            for name in (n.broker_role, policy.role_name("myapp", n)):
                # Prod roles are apm-<project> with project matching PROJECT_RE; nonprod names never are.
                self.assertFalse(name.startswith("apm-") and policy.PROJECT_RE.match(name[4:]), name)
            # ...and a nonprod project can never be named like the nonprod broker.
            self.assertFalse(policy.PROJECT_RE.match(n.broker_role[len(n.role_prefix):]))

    def test_nonprod_template_names(self):
        for stage in NONPROD:
            n = policy.Names(stage)
            t = deploy.template(ACCOUNT, "us-east-1", f"{stage}.preview.apm.example.com", "Z1", "o@example.com",
                                "client_s", "PUB", "b", "k.zip", stage=stage)
            r = t["Resources"]
            self.assertEqual(r["Table"]["Properties"]["TableName"], f"apm-{stage}")
            self.assertEqual(r["Function"]["Properties"]["FunctionName"], f"apm-{stage}")
            env = r["Function"]["Properties"]["Environment"]["Variables"]
            self.assertEqual((env["APM_STAGE"], env["PARAM_PREFIX"], env["TABLE_NAME"]),
                             (stage, f"/apm-{stage}", f"apm-{stage}"))
            self.assertEqual(r["Logs"]["Properties"]["LogGroupName"], f"/aws/lambda/apm-{stage}")
            self.assertEqual(r["Boundary"]["Properties"]["ManagedPolicyName"], n.boundary_name)
            self.assertEqual(r["BrokerRole"]["Properties"]["RoleName"], n.broker_role)
            self.assertEqual(r["Api"]["Properties"]["Name"], f"apm-{stage}")
            secrets_stmt = [s for s in r["BrokerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
                            if s["Sid"] == "Secrets"][0]
            self.assertTrue(secrets_stmt["Resource"].endswith(f":parameter/apm-{stage}/*"))
            self.assertFalse(iam_match(secrets_stmt["Resource"],
                                       f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/apm/session-secret"))
            self.assertIn(f"stage {stage}", t["Description"])

    def test_reviewer_writes_only_its_own_stage_key_and_invokes_only_itself(self):
        stages = ["prod"] + NONPROD
        for stage in stages:
            t = deploy.template(*PROD_ARGS, stage=stage)
            stmts = {s["Sid"]: s for s in t["Resources"]["BrokerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]}
            key, invoke = stmts["ReviewerKey"]["Resource"], stmts["QueueReview"]["Resource"]
            for other in stages:
                o = policy.Names(other)
                own = other == stage
                self.assertEqual(iam_match(key, f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{o.param_prefix}/llm-key"), own)
                self.assertEqual(iam_match(invoke, f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:{o.function}"), own)
                self.assertFalse(iam_match(key, f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter{o.param_prefix}/session-secret"))

    def test_retention_policies(self):
        def table(stage):
            return deploy.template(*PROD_ARGS, stage=stage)["Resources"]["Table"]
        for stage, policy_ in (("prod", "Retain"), ("dev", "Retain"), ("pr-5", "Delete")):
            self.assertEqual(table(stage)["DeletionPolicy"], policy_, stage)
            self.assertEqual(table(stage)["UpdateReplacePolicy"], policy_, stage)

    def test_existing_certificate(self):
        arn = "arn:aws:acm:us-east-1:1:certificate/abc"
        r = deploy.template(*PROD_ARGS, stage="pr-3", certificate_arn=arn)["Resources"]
        self.assertNotIn("Certificate", r)
        self.assertEqual(r["DomainName"]["Properties"]["DomainNameConfigurations"][0]["CertificateArn"], arn)

    def test_destroy_refuses_long_lived_stages(self):
        for stage in ("prod", "dev"):
            with self.assertRaises(SystemExit):
                deploy.destroy(stage)


def _actions(stmt, key):
    a = stmt.get(key, [])
    return [a] if isinstance(a, str) else a


def boundary_decision(boundary, action, arn):
    """Minimal IAM evaluation of a boundary for one unconditioned request: "deny", "allow" or "implicit"."""
    def matches(stmt):
        if "Action" in stmt and not any(iam_match(p.lower(), action.lower()) for p in _actions(stmt, "Action")):
            return False
        if "NotAction" in stmt and any(iam_match(p.lower(), action.lower()) for p in _actions(stmt, "NotAction")):
            return False
        return any(iam_match(p, arn) for p in resources(stmt))
    stmts = [s for s in boundary["Statement"] if "Condition" not in s]  # conditions only narrow a Deny
    if any(s["Effect"] == "Deny" and matches(s) for s in stmts):
        return "deny"
    return "allow" if any(s["Effect"] == "Allow" and matches(s) for s in stmts) else "implicit"


class PreviewCannotReachReleaseArtifacts(unittest.TestCase):
    """Review finding 1: PR code controls a preview Lambda, whose broker creates (and assumes) agent
    roles. Those roles must never reach dev or prod bundles, manifests or release records."""
    REGIONS = ("us-east-1", "eu-west-2")
    WRITES = ("s3:PutObject", "s3:DeleteObject", "s3:PutObjectAcl", "s3:RestoreObject", "s3:PutBucketPolicy",
              "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration", "s3:DeleteBucket", "s3:GetObject", "s3:*")

    def artifact_arns(self, stage, account=ACCOUNT):
        out = []
        for region in self.REGIONS:
            bucket = policy.Names(stage).artifact_bucket(account, region)
            out += [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/lambda/0123456789abcdef.zip",
                    f"arn:aws:s3:::{bucket}/manifests/{'a' * 64}.json"]
            if stage in ("dev", "prod"):
                out += [f"arn:aws:s3:::{bucket}/releases/{stage}/{stage}-20261011T120000Z-aaaaaaaaaaaa.json",
                        f"arn:aws:s3:::{bucket}/releases/{stage}/current.json"]
        return out

    def test_every_artifact_bucket_is_an_apm_resource(self):
        s3_patterns = [p for p in policy.apm_resources(ACCOUNT) if p.startswith("arn:aws:s3:::")]
        for stage in ["prod"] + NONPROD:
            for arn in self.artifact_arns(stage):
                self.assertTrue(any(iam_match(p, arn) for p in s3_patterns), arn)

    def test_preview_agent_boundary_denies_dev_and_prod_artifacts(self):
        for stage in ("pr-1", "pr-12", "pr-9999999"):
            b = policy.boundary(ACCOUNT, policy.Names(stage))
            # Sanity: without the deny the broad allow would cover these writes.
            self.assertEqual(boundary_decision(b, "s3:PutObject", "arn:aws:s3:::someone-elses-bucket/x"), "allow")
            for target in ("dev", "prod", "pr-1", stage):
                # The prod bucket lives in the prod account, the others in nonprod; deny either way.
                for account in (ACCOUNT, "999988887777"):
                    for arn in self.artifact_arns(target, account):
                        for action in self.WRITES:
                            self.assertEqual(boundary_decision(b, action, arn), "deny", (stage, target, action, arn))

    def test_every_stage_boundary_has_the_apm_denies(self):
        for stage in ["prod"] + NONPROD:
            sids = {s["Sid"]: s for s in policy.boundary(ACCOUNT, policy.Names(stage))["Statement"]}
            for sid in ("DenyApmInfrastructure", "DenyApmTaggedResources", "DenyRecursiveReadOfRoot", "DenyApmDnsRecords",
                        "DenyAuditTampering"):
                self.assertEqual(sids[sid]["Effect"], "Deny", (stage, sid))
            self.assertEqual(sids["DenyApmInfrastructure"]["Resource"], policy.apm_resources(ACCOUNT))
            self.assertEqual(sids["DenyApmInfrastructure"]["Action"], "*")

    def test_every_stage_boundary_denies_recursive_read_of_root(self):
        # The SSM root is shared by every stage in an account, so the same root deny applies to all of them.
        b_prod = policy.boundary(ACCOUNT, policy.Names("prod"))
        for stage in ["prod"] + NONPROD:
            b = policy.boundary(ACCOUNT, policy.Names(stage))
            root = next(s for s in b["Statement"] if s["Sid"] == "DenyRecursiveReadOfRoot")
            self.assertEqual(root, next(s for s in b_prod["Statement"] if s["Sid"] == "DenyRecursiveReadOfRoot"))
            for arn in (f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/", f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter"):
                self.assertEqual(boundary_decision(b, "ssm:GetParametersByPath", arn), "deny", (stage, arn))
            # Other paths stay usable; /apm* paths were already denied for every stage.
            self.assertEqual(boundary_decision(b, "ssm:GetParametersByPath",
                                               f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/myapp"), "allow")
            for prefix in ("apm", "apm-dev", "apm-pr-1"):
                self.assertEqual(boundary_decision(b, "ssm:GetParametersByPath",
                                                   f"arn:aws:ssm:us-east-1:{ACCOUNT}:parameter/{prefix}"), "deny")

    def test_broker_can_sync_grants_and_remove_projects_on_its_own_stage_roles(self):
        # Broker.sync reads, rewrites or deletes the role's single grants policy and creates (and tags)
        # the role on first grant; remove_project pages through ListRolePolicies, deletes each inline
        # policy and then the role. All of it only on the broker's own stage's agent roles.
        needed = ["iam:ListRolePolicies", "iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
                  "iam:GetRole", "iam:CreateRole", "iam:DeleteRole", "iam:TagRole"]
        for stage in ["prod"] + NONPROD:
            n = policy.Names(stage)
            allows = [s for s in policy.broker_policy(ACCOUNT, n)["Statement"] if s["Effect"] == "Allow"]
            arn = policy.role_arn(ACCOUNT, "myapp", n)
            for action in needed:
                self.assertTrue(any(any(iam_match(a.lower(), action.lower()) for a in _actions(s, "Action"))
                                    and any(iam_match(r, arn) for r in resources(s)) for s in allows),
                                (stage, action, arn))

    def test_preview_broker_creates_roles_only_in_its_stage_with_its_boundary(self):
        for stage in ("pr-1", "pr-12"):
            n = policy.Names(stage)
            t = deploy.template(ACCOUNT, "us-east-1", f"{stage}.preview.apm.example.com", "Z1", "o@example.com",
                                "client_s", "PUB", "b", "k.zip", stage=stage)
            role_policy = t["Resources"]["BrokerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
            allows = [s for s in role_policy["Statement"] if s["Effect"] == "Allow"]
            create = [s for s in allows if "iam:CreateRole" in _actions(s, "Action")]
            self.assertEqual(len(create), 1)
            self.assertEqual(create[0]["Resource"], f"arn:aws:iam::{ACCOUNT}:role/agents-{stage}/*")
            self.assertEqual(create[0]["Condition"],
                             {"StringEquals": {"iam:PermissionsBoundary": f"arn:aws:iam::{ACCOUNT}:policy/apm-{stage}_agent-boundary"}})
            # ...and that boundary is this stack's own policy, which carries the apm denies.
            boundary = t["Resources"]["Boundary"]["Properties"]
            self.assertEqual(boundary["ManagedPolicyName"], n.boundary_name)
            self.assertIn("DenyApmInfrastructure", {s["Sid"] for s in boundary["PolicyDocument"]["Statement"]})
            # The broker can never change a boundary, attach managed policies or write S3 itself.
            never = ("iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
                     "iam:PutRolePermissionsBoundary", "iam:DeleteRolePermissionsBoundary", "iam:AttachRolePolicy",
                     "iam:UpdateAssumeRolePolicy", "iam:PassRole", "s3:PutObject")
            for s in allows:
                for action in _actions(s, "Action"):
                    for bad in never:
                        self.assertFalse(iam_match(action.lower(), bad.lower()), (stage, s["Sid"], action))
            # Other stages' boundaries (prod, dev) don't satisfy the condition.
            for other in ("prod", "dev", "pr-2"):
                self.assertNotEqual(policy.boundary_arn(ACCOUNT, policy.Names(other)),
                                    create[0]["Condition"]["StringEquals"]["iam:PermissionsBoundary"])


class Artifacts(unittest.TestCase):
    def make(self, tmp, body=b"code"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("apm/web.py", body)
        code = buf.getvalue()
        digest = hashlib.sha256(code).hexdigest()
        (Path(tmp) / deploy.ZIP_NAME).write_bytes(code)
        (Path(tmp) / deploy.MANIFEST_NAME).write_text(json.dumps({
            "schema": 1, "git_sha": "a" * 40, "sha256": digest, "s3_key": deploy.s3_key(digest)}))
        return digest

    def test_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = self.make(tmp)
            self.assertEqual(deploy.verify_artifact(tmp, digest, "a" * 40)["sha256"], digest)
            with self.assertRaises(SystemExit):
                deploy.verify_artifact(tmp, "0" * 64)
            with self.assertRaises(SystemExit):
                deploy.verify_artifact(tmp, expected_git_sha="b" * 40)
            (Path(tmp) / deploy.ZIP_NAME).write_bytes(b"tampered")
            with self.assertRaises(SystemExit):
                deploy.verify_artifact(tmp)

    def test_s3_key_matches_original_scheme(self):
        self.assertEqual(deploy.s3_key("0123456789abcdef" + "f" * 48), "lambda/0123456789abcdef.zip")

    def test_lock_is_pinned_with_hashes(self):
        deps = dict(deploy.lock_dependencies())
        self.assertIn("cryptography", deps)
        text = deploy.LOCK_FILE.read_text()
        for name in deps:
            block = text.split(f"{name}==", 1)[1].split("\n", 2)
            self.assertIn("--hash=sha256:", "\n".join(block[:2]), name)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(cli.main(list(args)), 0)
        return json.loads(out.getvalue())

    def test_names_and_template(self):
        self.assertEqual(self.run_cli("names")["stack"], "apm")
        self.assertEqual(self.run_cli("names", "--stage", "pr-42")["stack"], "apm-pr-42")
        t = self.run_cli("template", "--stage", "dev", "--domain", "dev.apm.example.com")
        self.assertEqual(t["Resources"]["Function"]["Properties"]["FunctionName"], "apm-dev")


if __name__ == "__main__":
    unittest.main()
