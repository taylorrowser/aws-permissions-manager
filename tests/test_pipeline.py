"""Deployment-policy guards: cleanup allowlist, release records, promotion/rollback rules, preview
planning and sweeping, credential isolation in the bootstrap template, and workflow hygiene.
No AWS calls and no network: S3 and the GitHub API are fakes."""
import datetime as dt
import fnmatch
import hashlib
import io
import json
import re
import tempfile
import unittest
import zipfile
from pathlib import Path

from botocore.exceptions import ClientError

from apm import deploy, policy, preview, release

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ACCOUNT, REGION = "111122223333", "us-east-1"
REPO = "taylorrowser/aws-permissions-manager"
SHA_A, SHA_B = "a" * 40, "b" * 40
T0 = dt.datetime(2026, 10, 11, 12, 0, 0, tzinfo=dt.timezone.utc)

try:
    import yaml
    from cfnlint.decode import cfn_yaml
except ImportError:  # cfn-lint (and its PyYAML) are installed in CI and by the README's test setup
    yaml = cfn_yaml = None


def _client_error(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "op")


class FakeS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, Bucket, Key, Body, IfNoneMatch=None, **_):
        if IfNoneMatch == "*" and (Bucket, Key) in self.objects:
            raise _client_error("PreconditionFailed")
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode()

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise _client_error("NoSuchKey")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}


def make_artifact(tmp, git_sha=SHA_A, body=b"code"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("apm/web.py", body)
    code = buf.getvalue()
    digest = hashlib.sha256(code).hexdigest()
    manifest = {"schema": 1, "git_sha": git_sha, "sha256": digest, "size": len(code), "s3_key": deploy.s3_key(digest)}
    Path(tmp).mkdir(parents=True, exist_ok=True)
    (Path(tmp) / deploy.ZIP_NAME).write_bytes(code)
    (Path(tmp) / deploy.MANIFEST_NAME).write_text(json.dumps(manifest))
    return manifest, code


def store_artifact(s3, bucket, manifest, code):
    s3.put_object(Bucket=bucket, Key=manifest["s3_key"], Body=code)
    s3.put_object(Bucket=bucket, Key=f"manifests/{manifest['sha256']}.json", Body=json.dumps(manifest).encode())


def record(stage, manifest, bucket, health="passed", kind=None, source=None, when=T0, ci_run_id=11):
    kind = kind or ("deploy" if stage == "dev" else "promotion")
    return release.make_record(stage, kind, manifest, ci_run_id=ci_run_id, ci_run_url="https://ci", deploy_run_id=22,
                               deploy_run_url="https://run", health=health, health_url="https://x/healthz",
                               account=ACCOUNT, region=REGION, domain="x", bucket=bucket,
                               source_release_id=source, when=when)


# ---------- cleanup allowlist ----------

class CleanupAllowlist(unittest.TestCase):
    MALFORMED = ["dev", "prod", "", " ", "pr-", "pr", "PR-1", "Pr-1", "pr-1 ", " pr-1", "pr-1\n", "pr-1\x00",
                 "pr-01", "pr-0", "pr-1a", "pr--1", "pr-1-dev", "pr-1/../prod", "../prod", "pr-*", "pr-?",
                 "pr-12345678", "apm-pr-1", "pr-١", "pr-１", "dev\n", "prod ", "*", "apm", "apm-dev",
                 None, 1, ["pr-1"], {"stage": "pr-1"}, b"pr-1"]

    def test_accepts_previews_only(self):
        for ok in ("pr-1", "pr-12", "pr-9999999"):
            self.assertEqual(policy.cleanup_stage(ok), ok)

    def test_rejects_dev_prod_and_malformed(self):
        for bad in self.MALFORMED:
            with self.assertRaises(ValueError, msg=repr(bad)):
                policy.cleanup_stage(bad)

    def test_stack_names(self):
        self.assertEqual(policy.stage_from_stack("apm-pr-7"), "pr-7")
        for bad in ("apm", "apm-dev", "apm-prod", "apm-pr-07", "apm-pr-7-x", "xapm-pr-7", "apm-pr-7 ", None, "pr-7"):
            with self.assertRaises(ValueError, msg=repr(bad)):
                policy.stage_from_stack(bad)

    def test_destroy_refuses_before_touching_aws(self):
        # boto3 is never reached: these fail on the allowlist (no credentials exist in tests).
        for bad in self.MALFORMED:
            with self.assertRaises(SystemExit, msg=repr(bad)):
                deploy.destroy(bad)


# ---------- release records, promotion and rollback ----------

class ReleaseRecords(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.s3 = FakeS3()
        self.dev_bucket = policy.Names("dev").artifact_bucket(ACCOUNT, REGION)
        self.prod_bucket = policy.Names("prod").artifact_bucket(ACCOUNT, REGION)
        self.manifest, self.code = make_artifact(Path(self.tmp.name) / "a")
        store_artifact(self.s3, self.dev_bucket, self.manifest, self.code)

    def out(self, name="out"):
        return Path(self.tmp.name) / name

    def test_record_contents(self):
        r = record("dev", self.manifest, self.dev_bucket)
        self.assertRegex(r["release_id"], r"^dev-20261011T120000Z-aaaaaaaaaaaa$")
        self.assertEqual(r["git_sha"], SHA_A)
        self.assertEqual(r["artifact"]["sha256"], self.manifest["sha256"])
        self.assertEqual((r["ci_run"]["id"], r["deploy_run"]["id"]), ("11", "22"))
        self.assertEqual(r["health"]["result"], "passed")
        self.assertEqual(r["created_at"], "2026-10-11T12:00:00Z")

    def test_records_are_write_once(self):
        r = record("dev", self.manifest, self.dev_bucket)
        release.put_record(self.s3, self.dev_bucket, r)
        with self.assertRaises(ClientError):
            release.put_record(self.s3, self.dev_bucket, r)
        self.assertEqual(release.current(self.s3, self.dev_bucket, "dev")["release_id"], r["release_id"])

    def test_release_id_validation(self):
        for bad in ("", "dev", "dev-20261011T120000Z-AAAAAAAAAAAA", "dev-20261011T120000Z-aaaa",
                    "prod-20261011T120000Z-aaaaaaaaaaaa\n", "../dev-20261011T120000Z-aaaaaaaaaaaa", None,
                    "pr-1-20261011T120000Z-aaaaaaaaaaaa"):
            with self.assertRaises(release.ReleaseError, msg=repr(bad)):
                release.validate_release_id(bad)
        with self.assertRaises(release.ReleaseError):
            release.validate_release_id("prod-20261011T120000Z-aaaaaaaaaaaa", "dev")

    def test_promote_current_dev_release(self):
        r = record("dev", self.manifest, self.dev_bucket)
        release.put_record(self.s3, self.dev_bucket, r)
        got, notes = release.resolve(self.s3, "promote", r["release_id"], self.out(), dev_bucket=self.dev_bucket,
                                     expected_sha256=self.manifest["sha256"])
        self.assertEqual((got["release_id"], notes), (r["release_id"], []))
        self.assertEqual((self.out() / deploy.ZIP_NAME).read_bytes(), self.code)
        deploy.verify_artifact(self.out(), self.manifest["sha256"], SHA_A)

    def test_promote_rejects_failed_health(self):
        r = record("dev", self.manifest, self.dev_bucket, health="failed")
        release.put_record(self.s3, self.dev_bucket, r)
        with self.assertRaisesRegex(release.ReleaseError, "failed its dev health check"):
            release.resolve(self.s3, "promote", r["release_id"], self.out(), dev_bucket=self.dev_bucket,
                            allow_superseded=True)

    def test_promote_stale_needs_explicit_selection(self):
        old = record("dev", self.manifest, self.dev_bucket)
        release.put_record(self.s3, self.dev_bucket, old)
        m2, code2 = make_artifact(Path(self.tmp.name) / "b", git_sha=SHA_B, body=b"newer")
        store_artifact(self.s3, self.dev_bucket, m2, code2)
        release.put_record(self.s3, self.dev_bucket, record("dev", m2, self.dev_bucket, when=T0 + dt.timedelta(hours=1)))
        with self.assertRaisesRegex(release.ReleaseError, "dev has moved on"):
            release.resolve(self.s3, "promote", old["release_id"], self.out(), dev_bucket=self.dev_bucket)
        got, notes = release.resolve(self.s3, "promote", old["release_id"], self.out(), dev_bucket=self.dev_bucket,
                                     allow_superseded=True)
        self.assertEqual(got["git_sha"], SHA_A)  # exactly the selected release, never the newer sha
        self.assertTrue(notes)

    def test_promote_rejects_digest_mismatch_and_tampering(self):
        r = record("dev", self.manifest, self.dev_bucket)
        release.put_record(self.s3, self.dev_bucket, r)
        with self.assertRaisesRegex(release.ReleaseError, "not "):
            release.resolve(self.s3, "promote", r["release_id"], self.out(), dev_bucket=self.dev_bucket,
                            expected_sha256="0" * 64)
        self.s3.objects[(self.dev_bucket, self.manifest["s3_key"])] = b"tampered"
        with self.assertRaisesRegex(release.ReleaseError, "sha256"):
            release.resolve(self.s3, "promote", r["release_id"], self.out(), dev_bucket=self.dev_bucket)

    def test_promote_rejects_unknown_wrong_stage_and_foreign_bucket(self):
        with self.assertRaisesRegex(release.ReleaseError, "no release record"):
            release.resolve(self.s3, "promote", "dev-20261011T120000Z-cccccccccccc", self.out(),
                            dev_bucket=self.dev_bucket)
        with self.assertRaises(release.ReleaseError):
            release.resolve(self.s3, "promote", "prod-20261011T120000Z-aaaaaaaaaaaa", self.out(),
                            dev_bucket=self.dev_bucket)
        r = record("dev", self.manifest, "some-other-bucket")
        release.put_record(self.s3, self.dev_bucket, r)
        with self.assertRaisesRegex(release.ReleaseError, "expected"):
            release.resolve(self.s3, "promote", r["release_id"], self.out(), dev_bucket=self.dev_bucket)

    def test_rollback_to_previous_successful_prod_release(self):
        store_artifact(self.s3, self.prod_bucket, self.manifest, self.code)
        dev_rec = record("dev", self.manifest, self.dev_bucket)
        good = record("prod", self.manifest, self.prod_bucket, source=dev_rec["release_id"])
        release.put_record(self.s3, self.prod_bucket, good)
        m2, code2 = make_artifact(Path(self.tmp.name) / "b", git_sha=SHA_B, body=b"broken")
        store_artifact(self.s3, self.prod_bucket, m2, code2)
        bad = record("prod", m2, self.prod_bucket, health="failed", source="dev-20261011T130000Z-bbbbbbbbbbbb",
                     when=T0 + dt.timedelta(hours=1))
        release.put_record(self.s3, self.prod_bucket, bad)
        got, _ = release.resolve(self.s3, "rollback", good["release_id"], self.out(), prod_bucket=self.prod_bucket)
        self.assertEqual(got["artifact"]["sha256"], self.manifest["sha256"])
        with self.assertRaisesRegex(release.ReleaseError, "failed its prod health check"):
            release.resolve(self.s3, "rollback", bad["release_id"], self.out(), prod_bucket=self.prod_bucket)
        with self.assertRaises(release.ReleaseError):  # a dev release is not a rollback target
            release.resolve(self.s3, "rollback", dev_rec["release_id"], self.out(), prod_bucket=self.prod_bucket)

    def test_rollback_window_note(self):
        good = record("prod", self.manifest, self.prod_bucket, source="dev-20261011T120000Z-aaaaaaaaaaaa")
        notes = release.check_rollback(good, None, when=T0 + dt.timedelta(days=release.ROLLBACK_WINDOW_DAYS + 1))
        self.assertTrue(any("rollback window" in n for n in notes))

    def test_prod_records_need_a_source(self):
        with self.assertRaises(release.ReleaseError):
            record("prod", self.manifest, self.prod_bucket, source=None)


# ---------- preview planning ----------

def pr_payload(number=5, sha=SHA_A, state="open", labels=("preview",), head_repo=REPO):
    return {"number": number, "state": state, "labels": [{"name": n} for n in labels],
            "head": {"sha": sha, "repo": {"full_name": head_repo} if head_repo else None},
            "base": {"repo": {"full_name": REPO}}}


def fake_api(pr=None, runs=()):
    def api(path):
        if path.startswith(f"repos/{REPO}/pulls/"):
            return pr
        if "/actions/workflows/ci.yml/runs" in path:
            return {"workflow_runs": list(runs)}
        raise AssertionError(path)
    return api


def ci_run(sha=SHA_A, run_id=99, conclusion="success", repo=REPO):
    return {"id": run_id, "head_sha": sha, "conclusion": conclusion, "path": ".github/workflows/ci.yml",
            "head_repository": {"full_name": repo}}


class PreviewPlan(unittest.TestCase):
    def wr_event(self, **kw):
        run = {"id": 99, "conclusion": "success", "event": "pull_request", "path": ".github/workflows/ci.yml",
               "head_sha": SHA_A, "head_repository": {"full_name": REPO},
               "pull_requests": [{"number": 5, "head": {"sha": SHA_A}}]}
        run.update(kw)
        return {"workflow_run": run}

    def test_ci_success_on_labeled_pr_deploys_head(self):
        p = preview.plan("workflow_run", self.wr_event(), REPO, fake_api(pr_payload()))
        self.assertEqual((p["action"], p["pr"], p["stage"], p["head_sha"], p["ci_run_id"]),
                         ("deploy", "5", "pr-5", SHA_A, "99"))

    def test_no_deploy_without_label_failure_fork_or_stale_head(self):
        api = fake_api(pr_payload(labels=()))
        self.assertEqual(preview.plan("workflow_run", self.wr_event(), REPO, api)["action"], "none")
        self.assertEqual(preview.plan("workflow_run", self.wr_event(conclusion="failure"), REPO,
                                      fake_api(pr_payload()))["action"], "none")
        fork = self.wr_event(head_repository={"full_name": "evil/fork"})
        self.assertEqual(preview.plan("workflow_run", fork, REPO, fake_api(pr_payload()))["action"], "none")
        self.assertEqual(preview.plan("workflow_run", self.wr_event(), REPO,
                                      fake_api(pr_payload(head_repo="evil/fork")))["action"], "none")
        moved = fake_api(pr_payload(sha=SHA_B))
        self.assertEqual(preview.plan("workflow_run", self.wr_event(), REPO, moved)["action"], "none")
        push = self.wr_event(event="push")
        self.assertEqual(preview.plan("workflow_run", push, REPO, fake_api(pr_payload()))["action"], "none")

    def test_label_uses_latest_successful_ci_for_head(self):
        ev = {"action": "labeled", "label": {"name": "preview"}, "pull_request": pr_payload()}
        p = preview.plan("pull_request_target", ev, REPO, fake_api(pr_payload(), [ci_run(run_id=3), ci_run(run_id=7)]))
        self.assertEqual((p["action"], p["ci_run_id"]), ("deploy", "7"))
        # CI not finished (or failed) for the head yet: wait for workflow_run.
        p = preview.plan("pull_request_target", ev, REPO, fake_api(pr_payload(), [ci_run(sha=SHA_B)]))
        self.assertEqual(p["action"], "none")
        other = {"action": "labeled", "label": {"name": "bug"}, "pull_request": pr_payload()}
        self.assertEqual(preview.plan("pull_request_target", other, REPO, fake_api(pr_payload()))["action"], "none")

    def test_opt_out_and_close_remove(self):
        un = {"action": "unlabeled", "label": {"name": "preview"}, "pull_request": pr_payload(labels=())}
        self.assertEqual(preview.plan("pull_request_target", un, REPO, fake_api())["action"], "remove")
        closed = {"action": "closed", "pull_request": pr_payload(state="closed")}
        p = preview.plan("pull_request_target", closed, REPO, fake_api())
        self.assertEqual((p["action"], p["stage"]), ("remove", "pr-5"))
        closed_unlabeled = {"action": "closed", "pull_request": pr_payload(state="closed", labels=())}
        self.assertEqual(preview.plan("pull_request_target", closed_unlabeled, REPO, fake_api())["action"], "none")

    def test_dispatch(self):
        p = preview.plan("workflow_dispatch", {}, REPO, fake_api(pr_payload(labels=()), [ci_run()]), "5", "deploy")
        self.assertEqual(p["action"], "deploy")
        self.assertEqual(preview.plan("workflow_dispatch", {}, REPO, fake_api(), "5", "remove")["stage"], "pr-5")
        for bad in ("0", "05", "-1", "5; rm -rf /", "dev", "prod", "", "1" * 9, "5\n"):
            with self.assertRaises(preview.PlanError, msg=repr(bad)):
                preview.plan("workflow_dispatch", {}, REPO, fake_api(), bad, "remove")


# ---------- sweeper ----------

def stack(name, stage_tag=None, expires=None, status="UPDATE_COMPLETE"):
    tags = [{"Key": "managed-by", "Value": "apm"}]
    if stage_tag is not None:
        tags.append({"Key": deploy.STAGE_TAG, "Value": stage_tag})
    if expires is not None:
        tags.append({"Key": deploy.EXPIRES_TAG, "Value": expires})
    return {"StackName": name, "StackStatus": status, "Tags": tags}


class Sweeper(unittest.TestCase):
    FUTURE, PAST = "2026-10-20T00:00:00Z", "2026-10-01T00:00:00Z"

    def decide(self, stacks, info=None):
        info = info or {}
        return dict(preview.sweep_decisions(stacks, lambda n: info.get(n, ("open", True)), T0))

    def test_never_dev_or_prod_even_with_hostile_tags(self):
        stacks = [stack("apm", "pr-1", self.PAST), stack("apm-dev", "pr-1", self.PAST),
                  stack("apm-pr-1", "prod", self.PAST), stack("apm-pr-2", "dev", self.PAST),
                  stack("apm-pr-3", "pr-4", self.PAST), stack("apm-pr-5", None, self.PAST),
                  stack("apm-pr-6", "pr-6\n", self.PAST), stack("other", "pr-7", self.PAST),
                  stack("apm-pr-08", "pr-08", self.PAST)]
        self.assertEqual(self.decide(stacks, {n: ("closed", False) for n in range(10)}), {})

    def test_expiry_close_and_opt_out(self):
        stacks = [stack("apm-pr-1", "pr-1", self.FUTURE), stack("apm-pr-2", "pr-2", self.PAST),
                  stack("apm-pr-3", "pr-3", self.FUTURE), stack("apm-pr-4", "pr-4", self.FUTURE),
                  stack("apm-pr-5", "pr-5", "not-a-date"), stack("apm-pr-6", "pr-6", self.PAST, "UPDATE_IN_PROGRESS")]
        got = self.decide(stacks, {3: ("closed", True), 4: ("open", False)})
        self.assertEqual(sorted(got), ["pr-2", "pr-3", "pr-4", "pr-5"])
        self.assertIn("expired", got["pr-2"])

    def test_preview_stacks_get_expiry_tags(self):
        tags = {t["Key"]: t["Value"] for t in deploy.stack_tags("pr-3", now=T0, ttl_days=7)}
        self.assertEqual(tags[deploy.EXPIRES_TAG], "2026-10-18T12:00:00Z")
        self.assertEqual(tags[deploy.STAGE_TAG], "pr-3")
        self.assertNotIn(deploy.EXPIRES_TAG, {t["Key"] for t in deploy.stack_tags("dev")})
        self.assertEqual(deploy.stack_tags("prod"), [{"Key": "managed-by", "Value": "apm"}])


# ---------- per-environment secrets, buckets and artifact upload ----------

class FakeSSM:
    class exceptions:
        class ParameterNotFound(Exception):
            pass

    def __init__(self, params=None):
        self.params = dict(params or {})

    def get_parameter(self, Name, WithDecryption=False):
        if Name not in self.params:
            raise self.exceptions.ParameterNotFound(Name)
        return {"Parameter": {"Value": self.params[Name]}}

    def put_parameter(self, Name, Value, Type, Overwrite=False):
        self.params[Name] = Value


class EnvironmentIsolation(unittest.TestCase):
    def test_secrets_are_per_stage(self):
        ssm = FakeSSM({"/apm/session-secret": "PROD", "/apm/workos-api-key": "PRODKEY",
                       "/apm-nonprod/workos-api-key": "STAGINGKEY"})
        deploy._ensure_secrets(ssm, "/apm-pr-4", "/apm-nonprod", log=lambda *_: None)
        new = {k: v for k, v in ssm.params.items() if k.startswith("/apm-pr-4/")}
        self.assertEqual(set(new), {"/apm-pr-4/session-secret", "/apm-pr-4/vapid-private-key",
                                    "/apm-pr-4/vapid-public-key", "/apm-pr-4/workos-api-key"})
        self.assertEqual(new["/apm-pr-4/workos-api-key"], "STAGINGKEY")
        self.assertNotIn("PROD", new.values())

    def test_never_copy_prod_secrets(self):
        for prefix, source in (("/apm-pr-4", "/apm"), ("/apm-dev", "/apm"), ("/apm", "/apm-nonprod"),
                               ("/apm-pr-4", "/apm-dev"), ("/apm-pr-4", "/apm-nonprod/../apm"), ("/apm-pr-4", "")):
            with self.assertRaises(SystemExit, msg=(prefix, source)):
                deploy.check_workos_copy(prefix, source)
        deploy.check_workos_copy("/apm-dev", "/apm-nonprod")

    def test_buckets_are_per_environment(self):
        names = {s: policy.Names(s).artifact_bucket(ACCOUNT, REGION) for s in ("prod", "dev", "pr-1", "pr-2")}
        self.assertEqual(names["prod"], f"apm-artifacts-{ACCOUNT}-{REGION}")
        self.assertEqual(names["dev"], f"apm-dev-artifacts-{ACCOUNT}-{REGION}")
        self.assertEqual(names["pr-1"], names["pr-2"])
        self.assertEqual(len({names["prod"], names["dev"], names["pr-1"]}), 3)
        self.assertLessEqual(len(policy.Names("pr-1").artifact_bucket(ACCOUNT, "ap-southeast-2")), 63)

    def test_existing_bundle_is_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest, code = make_artifact(tmp)
            s3 = FakeS3()
            deploy._upload_code(s3, "b", manifest, code, log=lambda *_: None)
            deploy._upload_code(s3, "b", manifest, code, log=lambda *_: None)  # same bytes: fine
            s3.objects[("b", manifest["s3_key"])] = b"planted by someone else"
            with self.assertRaises(SystemExit):
                deploy._upload_code(s3, "b", manifest, code, log=lambda *_: None)


# ---------- credential isolation in the bootstrap template ----------

def _sub(value):
    if isinstance(value, dict) and "Fn::Sub" in value:
        value = value["Fn::Sub"]
    if not isinstance(value, str):
        return None
    return (value.replace("${AWS::Partition}", "aws").replace("${AWS::AccountId}", ACCOUNT)
            .replace("${AWS::Region}", REGION))


def stage_arns(stage):
    """Representative ARNs of everything one stage owns."""
    n = policy.Names(stage)
    bucket = n.artifact_bucket(ACCOUNT, REGION)
    return [
        f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{n.stack}/0f0e0d0c-1111",
        policy.broker_role_arn(ACCOUNT, n), policy.role_arn(ACCOUNT, "myapp", n),
        policy.boundary_arn(ACCOUNT, n),
        f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{n.function}",
        f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{n.table}",
        f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter{n.param_prefix}/session-secret",
        f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/aws/lambda/{n.function}:*",
        f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/releases/{stage}/current.json",
    ]


@unittest.skipIf(cfn_yaml is None, "needs cfn-lint (pip install cfn-lint)")
class BootstrapIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t = cfn_yaml.load(str(ROOT / "infra" / "github-oidc-bootstrap.yaml"))
        cls.roles = {r["Properties"]["RoleName"]: r["Properties"] for r in t["Resources"].values()
                     if r["Type"] == "AWS::IAM::Role"}

    def statements(self, role, effect):
        for pol in self.roles[role]["Policies"]:
            for st in pol["PolicyDocument"]["Statement"]:
                if st["Effect"] == effect:
                    res = st["Resource"] if isinstance(st["Resource"], list) else [st["Resource"]]
                    yield st, [r for r in map(_sub, res) if r]

    def allowed(self, role, arn):
        return [(st["Sid"], p) for st, pats in self.statements(role, "Allow") for p in pats
                if p != "*" and fnmatch.fnmatchcase(arn, p)]

    def denied(self, role, arn):
        return any(fnmatch.fnmatchcase(arn, p) for _, pats in self.statements(role, "Deny") for p in pats)

    def test_preview_role_cannot_touch_dev_or_prod(self):
        for stage in ("dev", "prod"):
            for arn in stage_arns(stage):
                self.assertEqual(self.allowed("apm-github-preview", arn), [], arn)
                self.assertTrue(self.denied("apm-github-preview", arn), arn)
        for arn in stage_arns("pr-12"):  # sanity: it can manage previews
            self.assertFalse(self.denied("apm-github-preview", arn), arn)

    def test_dev_role_cannot_touch_prod_or_previews_buckets(self):
        for arn in stage_arns("prod"):
            self.assertEqual(self.allowed("apm-github-dev", arn), [], arn)
            self.assertTrue(self.denied("apm-github-dev", arn), arn)
        for arn in stage_arns("dev"):
            self.assertFalse(self.denied("apm-github-dev", arn), arn)

    def test_release_reader_is_read_only_on_dev_releases(self):
        for st, pats in self.statements("apm-github-release-reader", "Allow"):
            self.assertEqual(st["Action"], "s3:GetObject")
            for p in pats:
                self.assertTrue(p.startswith(f"arn:aws:s3:::apm-dev-artifacts-{ACCOUNT}-{REGION}/"), p)

    def test_trust_is_exact(self):
        expected = {"apm-github-dev": "DevSubject", "apm-github-preview": "PreviewSubject",
                    "apm-github-release-reader": "ProdSubject", "apm-github-prod": "ProdSubject"}
        for role, param in expected.items():
            (st,) = self.roles[role]["AssumeRolePolicyDocument"]["Statement"]
            cond = st["Condition"]
            variants = cond["Fn::If"][1:] if "Fn::If" in cond else [cond]
            for c in variants:
                self.assertEqual(list(c), ["StringEquals"], role)  # no StringLike wildcards
                self.assertEqual(c["StringEquals"]["token.actions.githubusercontent.com:sub"], {"Ref": param})
                self.assertEqual(c["StringEquals"]["token.actions.githubusercontent.com:aud"], "sts.amazonaws.com")


# ---------- workflow hygiene ----------

@unittest.skipIf(yaml is None, "needs PyYAML (installed with cfn-lint)")
class Workflows(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wf = {p.name: yaml.safe_load(p.read_text()) for p in sorted(WORKFLOWS.glob("*.yml"))}

    def on(self, name):
        w = self.wf[name]
        return w.get("on", w.get(True))

    def steps(self):
        for name, w in self.wf.items():
            for job_id, job in w["jobs"].items():
                for step in job.get("steps", []):
                    yield name, job_id, step

    def test_pr_checks_have_no_cloud_access(self):
        ci = self.wf["ci.yml"]
        self.assertEqual(ci["permissions"], {"contents": "read"})
        for job in ci["jobs"].values():
            self.assertNotIn("id-token", job.get("permissions", {}))
            self.assertNotIn("environment", job)
        self.assertNotIn("configure-aws-credentials", (WORKFLOWS / "ci.yml").read_text())

    def test_no_expressions_in_shell(self):
        # Every value reaches a script through env:, never interpolated into the script text.
        for name, job_id, step in self.steps():
            self.assertNotIn("${{", step.get("run", ""), f"{name}:{job_id}:{step.get('name')}")

    def test_runners_are_portable(self):
        for name, w in self.wf.items():
            for job_id, job in w["jobs"].items():
                if "uses" in job:
                    continue
                self.assertEqual(job["runs-on"], "${{ vars.APM_RUNNER || 'ubuntu-24.04' }}", f"{name}:{job_id}")

    def test_pull_request_target_never_checks_out_pr_code(self):
        for name in self.wf:
            on = self.on(name)
            if isinstance(on, dict) and "pull_request_target" in on:
                for wf_name, job_id, step in self.steps():
                    if wf_name == name and "actions/checkout" in step.get("uses", ""):
                        self.assertNotIn("ref", step.get("with", {}), f"{name}:{job_id}")
        self.assertNotIn("pull_request_target", self.on("ci.yml"))

    def test_deploys_are_serialized_and_never_cancelled(self):
        groups = {"deploy-dev.yml": self.wf["deploy-dev.yml"]["concurrency"],
                  "promote-prod.yml": self.wf["promote-prod.yml"]["concurrency"],
                  "rollback-prod.yml": self.wf["rollback-prod.yml"]["concurrency"],
                  "preview deploy": self.wf["preview.yml"]["jobs"]["deploy"]["concurrency"],
                  "preview remove": self.wf["preview.yml"]["jobs"]["remove"]["concurrency"]}
        for name, c in groups.items():
            self.assertIs(c["cancel-in-progress"], False, name)
        self.assertEqual(groups["promote-prod.yml"]["group"], groups["rollback-prod.yml"]["group"])
        self.assertEqual(groups["preview deploy"]["group"], groups["preview remove"]["group"])

    def test_only_the_reusable_prod_workflow_uses_the_prod_role(self):
        users = [p.name for p in WORKFLOWS.glob("*.yml") if "APM_PROD_ROLE_ARN" in p.read_text()]
        self.assertEqual(users, ["prod-release.yml"])
        for name in ("promote-prod.yml", "rollback-prod.yml"):
            (job,) = self.wf[name]["jobs"].values()
            self.assertEqual(job["uses"], "./.github/workflows/prod-release.yml")
            self.assertEqual(job["if"], "github.ref == 'refs/heads/main'")
        for job_id in ("resolve", "claims"):
            self.assertIn("github.ref == 'refs/heads/main'", self.wf["prod-release.yml"]["jobs"][job_id]["if"])

    def test_cloud_workflows_are_disabled_until_bootstrap(self):
        gates = {"deploy-dev.yml": "APM_DEV_ENABLED", "preview.yml": "APM_PREVIEW_ENABLED",
                 "prod-release.yml": "APM_PROD_DEPLOY_ENABLED"}
        for name, var in gates.items():
            for job_id, job in self.wf[name]["jobs"].items():
                perms = job.get("permissions", {})
                if perms.get("id-token") != "write" or job_id == "claims":
                    continue
                gated = var in str(job.get("if", "")) or any(
                    var in str(self.wf[name]["jobs"][n].get("if", "")) for n in ([job["needs"]] if isinstance(
                        job.get("needs"), str) else job.get("needs", [])))
                self.assertTrue(gated, f"{name}:{job_id}")


    def test_git_network_commands_never_rely_on_persisted_credentials(self):
        problems = [p for name, w in self.wf.items() for job_id, job in w["jobs"].items()
                    for p in git_auth_problems(job, f"{name}:{job_id}")]
        self.assertEqual(problems, [])

    def test_git_auth_checker_catches_the_unauthenticated_fetch(self):
        checkout = {"uses": "actions/checkout@x", "with": {"persist-credentials": False}}
        full = {"uses": "actions/checkout@x", "with": {"fetch-depth": 0, "persist-credentials": False}}
        bad_fetch = {"run": "git fetch --no-tags origin main\ngit merge-base --is-ancestor \"$SHA\" origin/main"}
        self.assertTrue(git_auth_problems({"steps": [checkout, bad_fetch]}, "j"))
        self.assertTrue(git_auth_problems({"steps": [full, bad_fetch]}, "j"))  # the fetch itself still fails
        self.assertTrue(git_auth_problems({"steps": [checkout, {"run": "git ls-remote origin"}]}, "j"))
        self.assertTrue(git_auth_problems({"steps": [checkout, {"run": "git -C x push origin HEAD"}]}, "j"))
        # origin/<branch> without a fetch needs the full-history checkout to exist at all.
        self.assertTrue(git_auth_problems({"steps": [checkout, {"run": "git merge-base --is-ancestor a origin/main"}]}, "j"))
        self.assertEqual(git_auth_problems({"steps": [full, {"run": "git merge-base --is-ancestor a origin/main"}]}, "j"), [])
        authed = {"run": 'git -c http.extraheader="AUTHORIZATION: basic $B" fetch origin main', "env": {"GITHUB_TOKEN": "t"}}
        self.assertEqual(git_auth_problems({"steps": [checkout, authed]}, "j"), [])
        # With persisted credentials (the checkout default) a fetch is fine.
        self.assertEqual(git_auth_problems({"steps": [{"uses": "actions/checkout@x"}, bad_fetch]}, "j"), [])


GIT_NETWORK = re.compile(r"\bgit\b(?:\s+-[cC]\s+(?:\"[^\"]*\"|'[^']*'|\S+)|\s+--?[\w-]+(?:=\S+)?)*\s+"
                         r"(fetch|pull|push|ls-remote|clone|remote\s+update)\b")


def git_auth_problems(job, where):
    """Network git commands in a job whose checkout dropped its credentials must authenticate
    explicitly (http.extraheader), and origin/<branch> refs need a full-history checkout."""
    problems, no_creds, full_history = [], False, False
    for step in job.get("steps", []):
        if "actions/checkout" in step.get("uses", ""):
            w = step.get("with", {}) or {}
            no_creds = no_creds or w.get("persist-credentials") is False
            full_history = full_history or str(w.get("fetch-depth")) == "0"
            continue
        lines = step.get("run", "").splitlines()
        fetches = any(GIT_NETWORK.search(line) for line in lines)
        for line in lines:
            label = f"{where}:{step.get('name')}: {line.strip()}"
            if no_creds and GIT_NETWORK.search(line) and "http.extraheader" not in line.lower():
                problems.append(f"unauthenticated git network command after persist-credentials: false: {label}")
            if re.search(r"\borigin/[\w.-]+", line) and not (full_history or fetches):
                problems.append(f"origin/<branch> used without a fetch-depth: 0 checkout: {label}")
    return problems



# ---------- review finding 4: GitHub API failures must not delete previews ----------

class SweeperFailsSafe(unittest.TestCase):
    FUTURE, FAR_FUTURE, PAST = "2026-10-20T00:00:00Z", "2099-01-01T00:00:00Z", "2026-10-01T00:00:00Z"

    def test_unknown_state_never_deletes_an_unexpired_preview(self):
        logs = []
        stacks = [stack("apm-pr-1", "pr-1", self.FAR_FUTURE), stack("apm-pr-2", "pr-2", self.FUTURE),
                  stack("apm-pr-3", "pr-3", "not-a-date"), stack("apm-pr-4", "pr-4")]
        got = preview.sweep_decisions(stacks, lambda n: ("unknown", None), T0, log=logs.append)
        self.assertEqual(got, [])
        self.assertEqual(len(logs), 4)
        self.assertIn("unknown", logs[0])

    def test_expiry_alone_suffices_even_when_github_is_down(self):
        def broken(n):
            raise AssertionError("an expired preview needs no GitHub answer")
        got = dict(preview.sweep_decisions([stack("apm-pr-1", "pr-1", self.PAST)], broken, T0))
        self.assertEqual(list(got), ["pr-1"])
        self.assertIn("expired", got["pr-1"])

    def test_only_confirmed_states_delete(self):
        stacks = [stack(f"apm-pr-{i}", f"pr-{i}", self.FAR_FUTURE) for i in range(1, 7)]
        info = {1: ("closed", False), 2: ("open", False), 3: ("open", True), 4: ("", None),
                5: ("merged?", True), 6: ("open", None)}
        got = dict(preview.sweep_decisions(stacks, lambda n: info[n], T0))
        self.assertEqual(sorted(got), ["pr-1", "pr-2"])

    def sweep_with(self, api, expires):
        from unittest import mock
        stacks = [stack("apm-pr-7", "pr-7", expires)]
        session = mock.MagicMock()
        session.client.return_value.get_caller_identity.return_value = {"Account": ACCOUNT}
        session.client.return_value.get_paginator.return_value.paginate.return_value = [{"Stacks": stacks}]
        destroyed, logs = [], []
        with mock.patch("boto3.Session", return_value=session), \
                mock.patch.object(deploy, "destroy", side_effect=lambda stage, **kw: destroyed.append(stage)):
            preview.sweep(REPO, api=api, unlabel=lambda *a: None, expected_account=ACCOUNT, log=logs.append)
        return destroyed, logs

    def test_sweep_api_error_far_future_expiry_is_kept(self):
        def api(path):
            raise RuntimeError("HTTP 403: API rate limit exceeded")
        destroyed, logs = self.sweep_with(api, self.FAR_FUTURE)
        self.assertEqual(destroyed, [])
        self.assertTrue(any("rate limit" in m for m in logs), logs)
        self.assertTrue(any("skipping pr-7" in m for m in logs), logs)

    def test_sweep_api_error_expired_is_deleted(self):
        def api(path):
            raise RuntimeError("HTTP 502")
        destroyed, _ = self.sweep_with(api, self.PAST)
        self.assertEqual(destroyed, ["pr-7"])

    def test_sweep_malformed_api_answer_is_unknown(self):
        destroyed, _ = self.sweep_with(lambda path: {"message": "Server Error"}, self.FAR_FUTURE)
        self.assertEqual(destroyed, [])
        destroyed, _ = self.sweep_with(lambda path: {"state": "closed", "labels": []}, self.FAR_FUTURE)
        self.assertEqual(destroyed, ["pr-7"])

    def test_plan_never_removes_on_unexpected_state(self):
        pr = {"number": 7, "state": None, "labels": [{"name": "preview"}],
              "head": {"sha": SHA_A, "repo": {"full_name": REPO}}, "base": {"repo": {"full_name": REPO}}}
        with self.assertRaises(preview.PlanError):
            preview.plan("workflow_dispatch", {}, REPO, fake_api(pr), dispatch_pr="7", dispatch_action="deploy")


# ---------- review finding 1: promotion re-checks provenance with GitHub ----------

def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)
    return buf.getvalue()


class FakeGitHub:
    """Workflow runs, their artifacts and artifact downloads, as the REST API returns them."""

    def __init__(self):
        self.runs, self.artifacts, self.blobs, self.fail = {}, {}, {}, set()
        self.next_id = 500

    def add_run(self, run_id, **kw):
        run = {"id": run_id, "status": "completed", "conclusion": "success", "head_branch": "main",
               "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO}}
        run.update(kw)
        self.runs[run_id] = run
        return run

    def add_artifact(self, run_id, name, files, expired=False):
        self.next_id += 1
        self.artifacts.setdefault(run_id, []).append(
            {"id": self.next_id, "name": name, "expired": expired, "workflow_run": {"id": run_id}})
        self.blobs[self.next_id] = _zip(files)

    def api(self, path):
        if path in self.fail:
            raise RuntimeError("HTTP 503")
        m = re.fullmatch(rf"repos/{re.escape(REPO)}/actions/runs/(\d+)", path)
        if m:
            if int(m.group(1)) not in self.runs:
                raise RuntimeError("HTTP 404")
            return self.runs[int(m.group(1))]
        m = re.fullmatch(rf"repos/{re.escape(REPO)}/actions/runs/(\d+)/artifacts\?name=([^&]+)&per_page=100", path)
        if m:
            arts = [a for a in self.artifacts.get(int(m.group(1)), []) if a["name"] == m.group(2)]
            return {"total_count": len(arts), "artifacts": arts}
        raise AssertionError(path)

    def download(self, path):
        m = re.fullmatch(rf"repos/{re.escape(REPO)}/actions/artifacts/(\d+)/zip", path)
        return self.blobs[int(m.group(1))]


class Provenance(unittest.TestCase):
    CI_ID, DEPLOY_ID = 11, 22

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.manifest, self.code = make_artifact(Path(tmp.name) / "a")
        self.bucket = policy.Names("dev").artifact_bucket(ACCOUNT, REGION)
        self.rec = record("dev", self.manifest, self.bucket, ci_run_id=self.CI_ID)
        self.gh = FakeGitHub()
        self.gh.add_run(self.CI_ID, path=".github/workflows/ci.yml", event="push", head_sha=SHA_A)
        self.gh.add_artifact(self.CI_ID, f"lambda-{SHA_A}",
                             {"lambda.zip": self.code, "manifest.json": json.dumps(self.manifest)})
        # workflow_run runs report main's head at trigger time, which may be a later commit.
        self.gh.add_run(self.DEPLOY_ID, path=".github/workflows/deploy-dev.yml", event="workflow_run", head_sha=SHA_B)
        self.gh.add_artifact(self.DEPLOY_ID, f"dev-release-{self.rec['release_id']}",
                             {"release.json": json.dumps(self.rec)})

    def verify(self, rec=None, mode="promote"):
        return release.verify_provenance(rec or self.rec, REPO, self.gh.api, self.gh.download, mode)

    def assertRejected(self, pattern, rec=None, mode="promote"):
        with self.assertRaisesRegex(release.ReleaseError, pattern):
            self.verify(rec, mode)

    def test_genuine_release_passes(self):
        notes = self.verify()
        self.assertEqual(len(notes), 3)

    def test_ci_run_wrong_workflow(self):
        self.gh.runs[self.CI_ID]["path"] = ".github/workflows/preview.yml"
        self.assertRejected("ran '.github/workflows/preview.yml'")

    def test_ci_run_from_pull_request_event(self):
        self.gh.runs[self.CI_ID]["event"] = "pull_request"
        self.assertRejected("triggered by 'pull_request'")

    def test_ci_run_on_another_branch(self):
        self.gh.runs[self.CI_ID]["head_branch"] = "feature/x"
        self.assertRejected("branch 'feature/x'")

    def test_ci_run_for_another_sha(self):
        self.gh.runs[self.CI_ID]["head_sha"] = SHA_B
        self.assertRejected(f"built '{SHA_B}', not {SHA_A}")

    def test_ci_run_from_another_repo(self):
        self.gh.runs[self.CI_ID]["repository"] = {"full_name": "attacker/aws-permissions-manager"}
        self.assertRejected("belongs to 'attacker/aws-permissions-manager'")
        self.gh.runs[self.CI_ID]["repository"] = {"full_name": REPO}
        self.gh.runs[self.CI_ID]["head_repository"] = {"full_name": "attacker/aws-permissions-manager"}
        self.assertRejected("head repository")

    def test_ci_run_not_successful_or_not_finished(self):
        self.gh.runs[self.CI_ID]["conclusion"] = "failure"
        self.assertRejected("completed/failure")
        self.gh.runs[self.CI_ID].update(status="in_progress", conclusion=None)
        self.assertRejected("in_progress")

    def test_api_returns_a_different_run(self):
        self.gh.runs[self.CI_ID]["id"] = 12
        self.assertRejected("returned run 12")

    def test_forged_bundle_claiming_a_real_main_sha(self):
        # The attack from the review: a preview wrote a bundle + record that claims an existing,
        # genuinely CI-built main commit and its real CI run. The digests can't both match.
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        forged_manifest, _ = make_artifact(Path(tmp.name) / "f", body=b"backdoor")
        forged = record("dev", forged_manifest, self.bucket, ci_run_id=self.CI_ID)
        self.assertRejected("CI run 11 built sha256 .*, but the release record and S3 bundle are", forged)

    def test_ci_artifact_digest_mismatch(self):
        self.gh.artifacts[self.CI_ID] = []
        self.gh.add_artifact(self.CI_ID, f"lambda-{SHA_A}", {"lambda.zip": b"other bytes",
                                                             "manifest.json": json.dumps(self.manifest)})
        self.assertRejected("built sha256")

    def test_ci_artifact_manifest_mismatch(self):
        self.gh.artifacts[self.CI_ID] = []
        self.gh.add_artifact(self.CI_ID, f"lambda-{SHA_A}",
                             {"lambda.zip": self.code, "manifest.json": json.dumps({**self.manifest, "git_sha": SHA_B})})
        self.assertRejected("manifest does not describe")

    def test_expired_ci_artifact_fails_closed_with_instructions(self):
        self.gh.artifacts[self.CI_ID][0]["expired"] = True
        self.assertRejected("has expired.*Rebuild and redeploy dev")

    def test_missing_ci_artifact(self):
        self.gh.artifacts[self.CI_ID] = []
        self.assertRejected(f"has no artifact lambda-{SHA_A}")

    def test_github_api_error_fails_closed(self):
        self.gh.fail.add(f"repos/{REPO}/actions/runs/{self.CI_ID}")
        self.assertRejected("could not read CI run 11")
        self.gh.fail = {f"repos/{REPO}/actions/runs/{self.DEPLOY_ID}"}
        self.assertRejected("could not read dev deploy run 22")

    def test_dev_deploy_run_must_be_deploy_dev_on_main(self):
        for change, pattern in (({"path": ".github/workflows/preview.yml"}, "ran"),
                                ({"event": "workflow_dispatch"}, "triggered by"),
                                ({"head_branch": "pr-branch"}, "branch"),
                                ({"conclusion": "failure"}, "failure"),
                                ({"repository": {"full_name": "attacker/x"}}, "belongs to")):
            with self.subTest(change=change):
                original = dict(self.gh.runs[self.DEPLOY_ID])
                self.gh.runs[self.DEPLOY_ID].update(change)
                self.assertRejected(f"dev deploy run 22 does not prove this release: .*{pattern}")
                self.gh.runs[self.DEPLOY_ID] = original

    def test_record_points_at_the_ci_run_as_its_deploy_run(self):
        rec = dict(self.rec, deploy_run={"id": str(self.CI_ID), "url": "x"})
        self.assertRejected("dev deploy run 11 does not prove", rec)

    def test_dev_deploy_run_recorded_a_different_release(self):
        self.gh.artifacts[self.DEPLOY_ID] = []
        other = json.loads(json.dumps(self.rec))
        other["artifact"]["sha256"] = "f" * 64
        self.gh.add_artifact(self.DEPLOY_ID, f"dev-release-{self.rec['release_id']}",
                             {"release.json": json.dumps(other)})
        self.assertRejected("dev deploy run 22 recorded")
        self.gh.artifacts[self.DEPLOY_ID] = []
        self.assertRejected("has no artifact dev-release-")

    def test_wrong_stage_record(self):
        prod = record("prod", self.manifest, "b", source=self.rec["release_id"], ci_run_id=self.CI_ID)
        self.assertRejected("not a dev release", prod)

    def test_rollback_checks_ci_run_and_prod_release_run(self):
        prod = record("prod", self.manifest, "b", source=self.rec["release_id"], ci_run_id=self.CI_ID)
        self.gh.artifacts[self.CI_ID][0]["expired"] = True  # normal by rollback time; not required
        self.gh.add_run(22, path=".github/workflows/promote-prod.yml", event="workflow_dispatch", head_sha=SHA_B)
        self.assertEqual(len(self.verify(prod, "rollback")), 2)
        self.gh.runs[22]["path"] = ".github/workflows/deploy-dev.yml"
        self.assertRejected("prod release run 22 does not prove", prod, "rollback")
        self.gh.runs[22]["path"] = ".github/workflows/promote-prod.yml"
        self.gh.runs[self.CI_ID]["event"] = "pull_request"
        self.assertRejected("CI run 11", prod, "rollback")

    def test_cli_requires_a_token_and_fails_closed(self):
        import os
        from contextlib import redirect_stderr
        from unittest import mock
        from apm import cli
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(self.rec, f)
        self.addCleanup(os.unlink, f.name)
        env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        err = io.StringIO()
        with mock.patch.dict(os.environ, env, clear=True), redirect_stderr(err):
            self.assertEqual(cli.main(["release", "provenance", "--mode", "promote", "--record", f.name,
                                       "--repo", REPO]), 1)
        self.assertIn("GH_TOKEN", err.getvalue())
        with mock.patch.dict(os.environ, {"GH_TOKEN": "t"}), redirect_stderr(io.StringIO()), \
                mock.patch.object(release, "github_client", return_value=(self.gh.api, self.gh.download)):
            self.assertEqual(cli.main(["release", "provenance", "--mode", "promote", "--record", f.name,
                                       "--repo", REPO]), 0)
            self.gh.runs[self.CI_ID]["event"] = "pull_request"
            self.assertEqual(cli.main(["release", "provenance", "--mode", "promote", "--record", f.name,
                                       "--repo", REPO]), 1)

    def test_invalid_repo(self):
        with self.assertRaises(release.ReleaseError):
            release.verify_provenance(self.rec, "../x", self.gh.api, self.gh.download)

    def test_prod_release_workflow_checks_provenance_before_deploying(self):
        if yaml is None:
            self.skipTest("PyYAML not installed")
        wf = yaml.safe_load((WORKFLOWS / "prod-release.yml").read_text())
        resolve = wf["jobs"]["resolve"]
        self.assertEqual(resolve["permissions"].get("actions"), "read")
        names = [s.get("name") for s in resolve["steps"]]
        i = names.index("Verify provenance with the GitHub API")
        self.assertLess(names.index("Resolve and verify the recorded artifact"), i)
        self.assertIn("apm-admin release provenance", resolve["steps"][i]["run"])
        self.assertTrue(any("upload-artifact" in str(s.get("uses")) for s in resolve["steps"][i + 1:]))
        self.assertEqual(wf["jobs"]["deploy"]["needs"], "resolve")
        for caller in ("promote-prod.yml", "rollback-prod.yml"):
            (job,) = yaml.safe_load((WORKFLOWS / caller).read_text())["jobs"].values()
            self.assertEqual(job["permissions"].get("actions"), "read", caller)
        dev = yaml.safe_load((WORKFLOWS / "deploy-dev.yml").read_text())["jobs"]["deploy"]["steps"]
        upload = [s for s in dev if "upload-artifact" in str(s.get("uses"))]
        self.assertEqual(len(upload), 1)
        self.assertEqual(upload[0]["with"]["name"], "dev-release-${{ steps.record.outputs.release_id }}")

if __name__ == "__main__":
    unittest.main()
