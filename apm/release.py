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
import json
import re
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
