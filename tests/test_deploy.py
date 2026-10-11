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
# The only boundary statements prod gained since the fixture was captured (baseline commit 290bf35).
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
    {"Sid": "DenyApmDnsRecords", "Effect": "Deny", "Action": "route53:ChangeResourceRecordSets", "Resource": "*",
     "Condition": {"ForAnyValue:StringLike": {
         "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["apm.*", "*.apm.*"]}}},
]
NONPROD = ["dev", "pr-1", "pr-12", "pr-123"]
# Prod project names chosen to collide with naive nonprod naming.
TRICKY_PROJECTS = ["myapp", "dev", "dev-broker", "broker", "pr-1", "pr-12-app", "agents", "dev-agent-boundary"]


def iam_match(pattern, arn):
    # IAM resource wildcards: * matches any run of characters (including /), ? one character.
    return fnmatch.fnmatchcase(arn, pattern)


def resources(stmt):
    r = stmt["Resource"]
    return [r] if isinstance(r, str) else r


class ProdCompatibility(unittest.TestCase):
    def test_prod_template_matches_pre_stage_template(self):
        before = json.loads((ROOT / "tests/fixtures/prod_template_before_stages.json").read_text())
        expected = copy.deepcopy(before)
        # Intended change 1: the Lambda learns its stage (the PWA badge and policy.py read it).
        expected["Resources"]["Function"]["Properties"]["Environment"]["Variables"]["APM_STAGE"] = "prod"
        # Intended change 2: the baseline security fix (290bf35) appended three Deny statements to the
        # agent boundary. Spelled out literally so any other boundary drift fails this test.
        expected["Resources"]["Boundary"]["Properties"]["PolicyDocument"]["Statement"] += PROD_BOUNDARY_DENIES
        self.assertEqual(json.loads(json.dumps(deploy.template(*PROD_ARGS))), expected)
        self.assertEqual(json.loads(json.dumps(deploy.template(*PROD_ARGS, stage="prod"))), expected)

    def test_prod_resource_names_byte_identical(self):
        before = json.loads((ROOT / "tests/fixtures/prod_template_before_stages.json").read_text())
        after = json.loads(json.dumps(deploy.template(*PROD_ARGS)))
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
                if stmt["Effect"] != "Allow":
                    continue
                for pattern in resources(stmt):
                    for o in others:
                        if n.is_prod and stmt["Sid"] == "LookUpAgentRoles":
                            continue  # prod's pre-existing read-only lookup pattern role/apm-*; see docs
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
