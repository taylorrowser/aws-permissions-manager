"""Release records: the durable evidence that an artifact was deployed and health checked.

A release record is written once per dev or prod deploy, to the stage's artifact bucket:

    releases/<stage>/<release_id>.json   immutable (S3 conditional write; never overwritten)
    releases/<stage>/current.json        pointer to the newest deploy attempt of that stage

The artifact itself is content-addressed in the same bucket (lambda/<sha256[:16]>.zip, plus
manifests/<sha256>.json), and every read re-checks the full sha256, so a record can always be
resolved back to the exact bytes it describes. Nothing here expires: retention is indefinite,
which is longer than the rollback window (ROLLBACK_WINDOW_DAYS). See docs/deployment.md.

Promotion takes a dev release ID and rollback a prod release ID. Both are validated here, in
plain Python, so the rules are unit tested and the workflows only pass validated references.
"""
import datetime as dt
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path

from . import deploy, policy

RECORD_SCHEMA = 1
RELEASE_STAGES = ("dev", "prod")
RELEASE_ID_RE = re.compile(r"(dev|prod)-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{12})", re.ASCII)
SHA_RE = re.compile(r"[0-9a-f]{40}", re.ASCII)
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
RUN_ID_RE = re.compile(r"[1-9][0-9]{0,19}", re.ASCII)
KINDS = {"dev": ("deploy",), "prod": ("promotion", "rollback")}
HEALTH = ("passed", "failed")
# Rollback is supported to any prod release in this window. Records and bundles are kept
# indefinitely (no lifecycle expiry), so retention always exceeds the window.
ROLLBACK_WINDOW_DAYS = 90


class ReleaseError(ValueError):
    """A release reference or record that must not be deployed."""


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _ts(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_release_id(release_id, stage=None):
    if not isinstance(release_id, str) or not RELEASE_ID_RE.fullmatch(release_id):
        raise ReleaseError(f"invalid release id {release_id!r}; expected e.g. dev-20261011T120000Z-0123456789ab")
    if stage and not release_id.startswith(stage + "-"):
        raise ReleaseError(f"{release_id} is not a {stage} release")
    return release_id


def new_release_id(stage, git_sha, when=None):
    if stage not in RELEASE_STAGES:
        raise ReleaseError(f"releases are recorded for dev and prod only, not {stage!r}")
    return f"{stage}-{(when or _now()).strftime('%Y%m%dT%H%M%SZ')}-{git_sha[:12]}"


def record_key(stage, release_id):
    return f"releases/{stage}/{validate_release_id(release_id, stage)}.json"


def current_key(stage):
    if stage not in RELEASE_STAGES:
        raise ReleaseError(f"no release pointer for stage {stage!r}")
    return f"releases/{stage}/current.json"


def make_record(stage, kind, manifest, *, ci_run_id, ci_run_url, deploy_run_id, deploy_run_url, health,
                health_url, account, region, domain, bucket, source_release_id=None, previous_release_id=None,
                when=None):
    when = when or _now()
    record = {
        "schema": RECORD_SCHEMA,
        "release_id": new_release_id(stage, manifest["git_sha"], when),
        "stage": stage,
        "kind": kind,
        "git_sha": manifest["git_sha"],
        "artifact": {"sha256": manifest["sha256"], "size": manifest.get("size"), "bucket": bucket,
                     "s3_key": manifest["s3_key"], "manifest_key": f"manifests/{manifest['sha256']}.json"},
        "ci_run": {"id": str(ci_run_id), "url": ci_run_url},
        "deploy_run": {"id": str(deploy_run_id), "url": deploy_run_url},
        "health": {"result": health, "url": health_url, "checked_at": _ts(when)},
        "target": {"account": str(account), "region": region, "domain": domain},
        "source_release_id": source_release_id,
        "previous_release_id": previous_release_id,
        "created_at": _ts(when),
    }
    validate_record(record)
    return record


def validate_record(record, stage=None, release_id=None):
    """Raise ReleaseError unless record is a well-formed release record (of stage / release_id)."""
    if not isinstance(record, dict) or record.get("schema") != RECORD_SCHEMA:
        raise ReleaseError("not a release record (unknown schema)")
    rid = validate_release_id(record.get("release_id"), stage or record.get("stage"))
    if release_id is not None and rid != release_id:
        raise ReleaseError(f"record is {rid}, not the requested {release_id}")
    if record.get("stage") not in RELEASE_STAGES or (stage and record["stage"] != stage):
        raise ReleaseError(f"record stage {record.get('stage')!r} is not {stage or 'dev/prod'}")
    if record.get("kind") not in KINDS[record["stage"]]:
        raise ReleaseError(f"record kind {record.get('kind')!r} is not valid for {record['stage']}")
    if not SHA_RE.fullmatch(str(record.get("git_sha"))) or not rid.endswith(record["git_sha"][:12]):
        raise ReleaseError("record git_sha is malformed or does not match its release id")
    art = record.get("artifact") or {}
    if not SHA256_RE.fullmatch(str(art.get("sha256"))) or art.get("s3_key") != deploy.s3_key(art["sha256"]):
        raise ReleaseError("record artifact digest or key is malformed")
    for run in ("ci_run", "deploy_run"):
        if not RUN_ID_RE.fullmatch(str((record.get(run) or {}).get("id"))):
            raise ReleaseError(f"record {run} id is missing")
    if (record.get("health") or {}).get("result") not in HEALTH:
        raise ReleaseError("record health result is missing")
    if record["kind"] in ("promotion", "rollback"):
        validate_release_id(record.get("source_release_id"), "dev" if record["kind"] == "promotion" else "prod")
    return record


# ---------- S3 storage (client injected, so tests use a fake) ----------

def _get_json(s3, bucket, key):
    """The object as JSON, or None if it doesn't exist (or the role may not see it)."""
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception as e:  # botocore ClientError: NoSuchKey / AccessDenied (no ListBucket)
        code = getattr(e, "response", {}).get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404", "AccessDenied", "403"):
            return None
        raise
    return json.loads(body)


def put_record(s3, bucket, record):
    """Write the immutable record, then move the stage's current pointer to it."""
    validate_record(record)
    body = json.dumps(record, indent=2, sort_keys=True).encode()
    # IfNoneMatch: S3 refuses to overwrite an existing release record.
    s3.put_object(Bucket=bucket, Key=record_key(record["stage"], record["release_id"]), Body=body,
                  ContentType="application/json", IfNoneMatch="*")
    pointer = {k: record[k] for k in ("release_id", "git_sha", "kind", "created_at")}
    pointer["sha256"] = record["artifact"]["sha256"]
    pointer["health"] = record["health"]["result"]
    s3.put_object(Bucket=bucket, Key=current_key(record["stage"]), Body=json.dumps(pointer, indent=2).encode(),
                  ContentType="application/json")
    return record["release_id"]


def get_record(s3, bucket, stage, release_id):
    record = _get_json(s3, bucket, record_key(stage, release_id))
    if record is None:
        raise ReleaseError(f"no release record {release_id} in s3://{bucket}")
    return validate_record(record, stage, release_id)


def current(s3, bucket, stage):
    """The stage's newest deploy attempt pointer, or None."""
    return _get_json(s3, bucket, current_key(stage))


def fetch_artifact(s3, record, out_dir):
    """Download the recorded bundle and manifest to out_dir and check them against the record."""
    art = record["artifact"]
    code = s3.get_object(Bucket=art["bucket"], Key=art["s3_key"])["Body"].read()
    digest = hashlib.sha256(code).hexdigest()
    if digest != art["sha256"]:
        raise ReleaseError(f"s3://{art['bucket']}/{art['s3_key']} has sha256 {digest}, record says {art['sha256']}")
    manifest = _get_json(s3, art["bucket"], art["manifest_key"])
    if manifest is None:
        raise ReleaseError(f"manifest {art['manifest_key']} is missing")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / deploy.ZIP_NAME).write_bytes(code)
    (out / deploy.MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "release.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    try:
        deploy.verify_artifact(out, art["sha256"], record["git_sha"])
    except SystemExit as e:
        raise ReleaseError(str(e)) from None
    return out


# ---------- the promotion and rollback rules ----------

def check_promotion(record, dev_current, allow_superseded=False):
    """A dev release may go to prod if its health check passed and it is still what dev runs,
    or, when dev has moved on, only if the maintainer explicitly selected this older release."""
    validate_record(record, "dev")
    if record["health"]["result"] != "passed":
        raise ReleaseError(f"{record['release_id']} failed its dev health check; it can't be promoted")
    notes = []
    if not dev_current or dev_current.get("release_id") != record["release_id"]:
        now = (dev_current or {}).get("release_id", "unknown")
        if not allow_superseded:
            raise ReleaseError(
                f"dev has moved on: it now runs {now}, not {record['release_id']}. Promote {now} instead "
                f"(if it passed), or re-run with allow_superseded to deploy this older tested release on purpose.")
        notes.append(f"explicitly promoting {record['release_id']} although dev now runs {now}")
    return notes


def check_rollback(record, prod_current, when=None):
    """Rollback targets a previous prod release whose prod health check passed."""
    validate_record(record, "prod")
    if record["health"]["result"] != "passed":
        raise ReleaseError(f"{record['release_id']} failed its prod health check; pick a release that passed")
    notes = []
    if prod_current and prod_current.get("sha256") == record["artifact"]["sha256"] \
            and prod_current.get("health") == "passed":
        notes.append(f"prod already runs artifact {record['artifact']['sha256'][:16]}; redeploying it")
    created = dt.datetime.strptime(record["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    age = ((when or _now()) - created).days
    if age > ROLLBACK_WINDOW_DAYS:
        notes.append(f"{record['release_id']} is {age} days old, outside the {ROLLBACK_WINDOW_DAYS}-day rollback "
                     "window: check data/schema compatibility notes before relying on it")
    return notes


def resolve(s3, mode, release_id, out_dir, *, dev_bucket=None, prod_bucket=None, allow_superseded=False,
            expected_sha256=None):
    """Resolve a promotion (dev release id) or rollback (prod release id) to verified files in out_dir.
    Returns (record, notes)."""
    if expected_sha256 and not SHA256_RE.fullmatch(expected_sha256):
        raise ReleaseError("expected sha256 must be 64 lowercase hex characters")
    if mode == "promote":
        record = get_record(s3, dev_bucket, "dev", validate_release_id(release_id, "dev"))
        notes = check_promotion(record, current(s3, dev_bucket, "dev"), allow_superseded)
    elif mode == "rollback":
        record = get_record(s3, prod_bucket, "prod", validate_release_id(release_id, "prod"))
        notes = check_rollback(record, current(s3, prod_bucket, "prod"))
    else:
        raise ReleaseError(f"unknown mode {mode!r}")
    expected_bucket = dev_bucket if mode == "promote" else prod_bucket
    if record["artifact"]["bucket"] != expected_bucket:
        raise ReleaseError(f"{release_id} points at bucket {record['artifact']['bucket']}, expected {expected_bucket}")
    if expected_sha256 and expected_sha256 != record["artifact"]["sha256"]:
        raise ReleaseError(f"{release_id} has artifact {record['artifact']['sha256']}, not {expected_sha256}")
    fetch_artifact(s3, record, out_dir)
    return record, notes


def bucket_for(stage, account, region):
    return policy.Names(stage).artifact_bucket(account, region)


# ---------- provenance: re-check a record against GitHub, never S3 alone ----------
#
# Release records live in S3 buckets that code running in the nonprod account can reach in more
# ways than the deploy roles alone (a preview Lambda runs PR code there). So before a promotion
# deploys anything, the record's claims are checked independently through the GitHub API:
#   - its CI run is a completed, successful run of ci.yml, on a push to main, in this repository,
#     for exactly the record's commit;
#   - that run's uploaded build artifact (lambda-<sha>) has the same sha256 as the S3 bundle;
#   - its dev deploy run is a successful deploy-dev.yml run in this repository, on main, whose
#     uploaded release record (dev-release-<release_id>) names the same commit, digest and CI run.
# Workflow runs, their artifacts and artifact names can only be created by GitHub Actions in this
# repository, and push/workflow_run runs on main execute main's reviewed workflow files.

CI_WORKFLOW = ".github/workflows/ci.yml"
DEV_DEPLOY_WORKFLOW = ".github/workflows/deploy-dev.yml"
PROD_WORKFLOWS = (".github/workflows/promote-prod.yml", ".github/workflows/rollback-prod.yml")
RELEASE_BRANCH = "main"
GITHUB_API = "https://api.github.com"
EXPIRED_HELP = ("GitHub has expired that run's build artifact, so the S3 bundle can no longer be checked against "
                "what CI built. Rebuild and redeploy dev: re-run the CI workflow on main for this commit (or push "
                "a new commit), let \"Deploy dev\" record a fresh dev release, and promote that release instead.")


def ci_artifact_name(git_sha):
    return f"lambda-{git_sha}"


def dev_release_artifact_name(release_id):
    return f"dev-release-{validate_release_id(release_id, 'dev')}"


def github_client(token, base=GITHUB_API):
    """(api, download) callables for the GitHub REST API. api(path) -> JSON, download(path) -> bytes.
    The token is never forwarded on redirects (artifact downloads redirect to blob storage)."""
    import urllib.request

    def _get(path, accept):
        req = urllib.request.Request(f"{base}/{path}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_unredirected_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read()

    return (lambda path: json.loads(_get(path, "application/vnd.github+json")),
            lambda path: _get(path, "application/vnd.github+json"))


def _api(api, path, what):
    try:
        return api(path)
    except Exception as e:  # network, 404, rate limit: never treated as success
        raise ReleaseError(f"could not read {what} from the GitHub API ({path}): {e}") from None


def check_run(run, repo, run_id, *, what, paths, events, head_sha=None):
    """Raise ReleaseError unless `run` (a GitHub workflow run object) is the completed, successful
    run `run_id` of one of `paths`, triggered by one of `events` on main in `repo`."""
    problems = []
    if str(run.get("id")) != str(run_id):
        problems.append(f"the API returned run {run.get('id')}")
    if (run.get("repository") or {}).get("full_name") != repo:
        problems.append(f"it belongs to {(run.get('repository') or {}).get('full_name')!r}, not {repo}")
    if (run.get("head_repository") or {}).get("full_name") != repo:
        problems.append(f"its head repository is {(run.get('head_repository') or {}).get('full_name')!r}")
    if run.get("path") not in paths:
        problems.append(f"it ran {run.get('path')!r}, not {' or '.join(paths)}")
    if run.get("event") not in events:
        problems.append(f"it was triggered by {run.get('event')!r}, not {' or '.join(events)}")
    if run.get("head_branch") != RELEASE_BRANCH:
        problems.append(f"it ran on branch {run.get('head_branch')!r}, not {RELEASE_BRANCH}")
    if head_sha is not None and run.get("head_sha") != head_sha:
        problems.append(f"it built {run.get('head_sha')!r}, not {head_sha}")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        problems.append(f"it is {run.get('status')}/{run.get('conclusion')}, not completed/success")
    if problems:
        raise ReleaseError(f"{what} run {run_id} does not prove this release: " + "; ".join(problems))
    return run


def _get_run(api, repo, run_id, what):
    if not RUN_ID_RE.fullmatch(str(run_id)):
        raise ReleaseError(f"{what} run id {run_id!r} is malformed")
    return _api(api, f"repos/{repo}/actions/runs/{run_id}", f"{what} run {run_id}")


def _run_artifact(api, download, repo, run_id, name, what, expired_help):
    """Download the one unexpired artifact `name` uploaded by run `run_id`; return {filename: bytes}."""
    listing = _api(api, f"repos/{repo}/actions/runs/{run_id}/artifacts?name={name}&per_page=100",
                   f"the artifacts of {what} run {run_id}")
    found = [a for a in listing.get("artifacts") or [] if a.get("name") == name
             and str((a.get("workflow_run") or {}).get("id", run_id)) == str(run_id)]
    if not found:
        raise ReleaseError(f"{what} run {run_id} has no artifact {name}")
    live = [a for a in found if not a.get("expired")]
    if not live:
        raise ReleaseError(f"{what} run {run_id}: artifact {name} has expired. {expired_help}")
    if len(live) != 1:
        raise ReleaseError(f"{what} run {run_id} has {len(live)} artifacts named {name}; refusing to guess")
    art = live[0]
    try:
        archive = download(f"repos/{repo}/actions/artifacts/{art['id']}/zip")
    except Exception as e:
        raise ReleaseError(f"could not download artifact {name} of {what} run {run_id}: {e}") from None
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            return {i.filename: z.read(i) for i in z.infolist() if not i.is_dir()}
    except zipfile.BadZipFile:
        raise ReleaseError(f"artifact {name} of {what} run {run_id} is not a zip archive") from None


def verify_provenance(record, repo, api, download, mode="promote"):
    """Check a dev (promote) or prod (rollback) record against GitHub. Returns notes; raises ReleaseError."""
    if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ReleaseError(f"invalid repository {repo!r}")
    stage = {"promote": "dev", "rollback": "prod"}.get(mode)
    if stage is None:
        raise ReleaseError(f"unknown mode {mode!r}")
    validate_record(record, stage)
    git_sha, digest = record["git_sha"], record["artifact"]["sha256"]
    ci_id, deploy_id = record["ci_run"]["id"], record["deploy_run"]["id"]

    check_run(_get_run(api, repo, ci_id, "CI"), repo, ci_id, what="CI", paths=(CI_WORKFLOW,), events=("push",),
              head_sha=git_sha)
    notes = [f"CI run {ci_id}: successful ci.yml push run on {RELEASE_BRANCH} for {git_sha}"]

    if mode == "rollback":
        # Prod records are written only by the prod role into the prod account's bucket. The CI build
        # artifact has usually expired by rollback time, so its digest isn't required here; the run
        # metadata and the prod release run are.
        check_run(_get_run(api, repo, deploy_id, "prod release"), repo, deploy_id, what="prod release",
                  paths=PROD_WORKFLOWS, events=("workflow_dispatch",))
        notes.append(f"prod release run {deploy_id}: successful promote/rollback run on {RELEASE_BRANCH}")
        return notes

    files = _run_artifact(api, download, repo, ci_id, ci_artifact_name(git_sha), "CI", EXPIRED_HELP)
    code = files.get(deploy.ZIP_NAME)
    if code is None:
        raise ReleaseError(f"CI artifact {ci_artifact_name(git_sha)} has no {deploy.ZIP_NAME}")
    built = hashlib.sha256(code).hexdigest()
    if built != digest:
        raise ReleaseError(f"CI run {ci_id} built sha256 {built}, but the release record and S3 bundle are {digest}")
    try:
        ci_manifest = json.loads(files.get(deploy.MANIFEST_NAME) or b"null")
    except ValueError:
        ci_manifest = None
    if not isinstance(ci_manifest, dict) or ci_manifest.get("sha256") != digest or ci_manifest.get("git_sha") != git_sha:
        raise ReleaseError(f"CI artifact manifest does not describe {git_sha} / {digest}")
    notes.append(f"CI artifact {ci_artifact_name(git_sha)} matches sha256 {digest}")

    check_run(_get_run(api, repo, deploy_id, "dev deploy"), repo, deploy_id, what="dev deploy",
              paths=(DEV_DEPLOY_WORKFLOW,), events=("workflow_run",))
    name = dev_release_artifact_name(record["release_id"])
    files = _run_artifact(api, download, repo, deploy_id, name, "dev deploy", EXPIRED_HELP)
    try:
        uploaded = json.loads(files.get("release.json") or b"null")
    except ValueError:
        uploaded = None
    want = (record["release_id"], git_sha, digest, str(ci_id))
    got = None
    if isinstance(uploaded, dict):
        got = (uploaded.get("release_id"), uploaded.get("git_sha"), (uploaded.get("artifact") or {}).get("sha256"),
               str((uploaded.get("ci_run") or {}).get("id")))
    if got != want:
        raise ReleaseError(f"dev deploy run {deploy_id} recorded {got}, but the S3 record says {want}")
    notes.append(f"dev deploy run {deploy_id} recorded this exact release")
    return notes
