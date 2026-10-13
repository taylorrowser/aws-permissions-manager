"""apm-admin: owner and CI commands. Agents use the `apm` client in the plugin instead."""
import argparse
import json
import os
import sys

from . import deploy as d
from . import policy


def _deploy_target_args(s):
    s.add_argument("--domain", help="e.g. apm.example.com (needs a Route 53 hosted zone for the parent)")
    s.add_argument("--owner-email", help="WorkOS account email(s) allowed to approve, comma-separated")
    s.add_argument("--workos-client-id", help="WorkOS AuthKit client ID (client_...)")
    s.add_argument("--profile", help="AWS profile (default: your default credentials)")
    s.add_argument("--region", help="AWS region (default us-east-1)")


def _github_output(**values):
    """Append key=value lines to $GITHUB_OUTPUT (when running in Actions). Values are validated
    upstream and never contain newlines."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as f:
            for k, v in values.items():
                if "\n" in str(v):
                    raise SystemExit(f"refusing to write a multi-line output {k}")
                f.write(f"{k}={v}\n")


def _s3(profile, region):
    import boto3
    return boto3.Session(profile_name=profile, region_name=region).client("s3")


def _release(a):
    from . import release as r
    try:
        if a.release_cmd == "record":
            manifest = d.verify_artifact(a.artifact, a.sha256, a.git_sha)
            bucket = r.bucket_for(a.stage, a.account, a.region)
            s3 = _s3(a.profile, a.region)
            prev = r.current(s3, bucket, a.stage) if a.stage == "prod" else None
            record = r.make_record(
                a.stage, a.kind, manifest, ci_run_id=a.ci_run_id, ci_run_url=a.ci_run_url,
                deploy_run_id=a.deploy_run_id, deploy_run_url=a.deploy_run_url, health=a.health,
                health_url=a.health_url, account=a.account, region=a.region, domain=a.domain, bucket=bucket,
                source_release_id=a.source_release_id or None,
                previous_release_id=(prev or {}).get("release_id"))
            r.put_record(s3, bucket, record)
            print(json.dumps(record, indent=2, sort_keys=True))
            if a.record_out:  # deploy-dev uploads this as run evidence that promotion re-checks
                os.makedirs(os.path.dirname(os.path.abspath(a.record_out)), exist_ok=True)
                with open(a.record_out, "w") as f:
                    f.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
            _github_output(release_id=record["release_id"])
            return 0
        if a.release_cmd == "current":
            pointer = r.current(_s3(a.profile, a.region), r.bucket_for(a.stage, a.account, a.region), a.stage)
            print(json.dumps(pointer or {}, indent=2))
            _github_output(release_id=(pointer or {}).get("release_id", ""),
                           git_sha=(pointer or {}).get("git_sha", ""))
            return 0
        if a.release_cmd == "provenance":
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            if not token:
                raise r.ReleaseError("GH_TOKEN (or GITHUB_TOKEN) is required to check provenance")
            with open(a.record) as f:
                record = json.load(f)
            api, download = r.github_client(token)
            for note in r.verify_provenance(record, a.repo, api, download, a.mode):
                print(f"verified: {note}")
            print(f"OK provenance of {record['release_id']}")
            return 0
        # resolve
        dev_bucket = r.bucket_for("dev", a.account, a.region) if a.mode == "promote" else None
        prod_bucket = r.bucket_for("prod", a.account, a.region) if a.mode == "rollback" else None
        record, notes = r.resolve(_s3(a.profile, a.region), a.mode, a.release_id, a.out, dev_bucket=dev_bucket,
                                  prod_bucket=prod_bucket, allow_superseded=a.allow_superseded,
                                  expected_sha256=a.sha256 or None)
    except (r.ReleaseError, OSError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"note: {note}")
    print(f"OK {record['release_id']}: git {record['git_sha']} sha256 {record['artifact']['sha256']}")
    _github_output(release_id=record["release_id"], git_sha=record["git_sha"], sha256=record["artifact"]["sha256"],
                   ci_run_id=record["ci_run"]["id"], ci_run_url=record["ci_run"]["url"] or "")
    return 0


def _preview(a):
    from . import preview as pv
    if a.preview_cmd == "plan":
        with open(os.environ["GITHUB_EVENT_PATH"]) as f:
            event = json.load(f)
        try:
            result = pv.plan(os.environ["GITHUB_EVENT_NAME"], event, os.environ["GITHUB_REPOSITORY"], pv.gh_api,
                             dispatch_pr=a.pr, dispatch_action=a.action)
        except (pv.PlanError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2))
        _github_output(**{k: v for k, v in result.items() if k != "reason"})
        return 0
    decisions, failed = pv.sweep(a.repo, region=a.region, profile=a.profile, expected_account=a.account,
                                 dry_run=a.dry_run)
    print(f"{len(decisions)} preview(s) {'to delete' if a.dry_run else 'deleted'}, {len(failed)} failed")
    return 1 if failed else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="apm-admin", description="Build and deploy the hosted AWS Permissions Manager.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("deploy", help="build and deploy (or update) the hosted service with your admin login")
    _deploy_target_args(s)
    s.add_argument("--stage", default=policy.PROD, help="prod (default), dev or pr-<number>")

    s = sub.add_parser("build", help="build the Lambda artifact (lambda.zip + manifest.json); no AWS calls")
    s.add_argument("--out", required=True, help="output directory")
    s.add_argument("--git-sha", help="commit the artifact is built from (default: git rev-parse HEAD)")

    s = sub.add_parser("verify", help="check an artifact's digest against its manifest; no AWS calls")
    s.add_argument("--artifact", required=True, help="directory with lambda.zip and manifest.json")
    s.add_argument("--sha256", help="expected artifact sha256")
    s.add_argument("--git-sha", help="expected source commit")

    s = sub.add_parser("deploy-artifact", help="deploy an existing artifact to a stage (CI)")
    _deploy_target_args(s)
    s.add_argument("--stage", required=True, help="prod, dev or pr-<number>")
    s.add_argument("--artifact", required=True, help="directory with lambda.zip and manifest.json")
    s.add_argument("--sha256", help="refuse unless the artifact has this sha256")
    s.add_argument("--git-sha", help="refuse unless the artifact was built from this commit")
    s.add_argument("--account", help="refuse unless the credentials are for this AWS account")
    s.add_argument("--zone-id", help="Route 53 hosted zone ID (default: look it up from the domain)")
    s.add_argument("--certificate-arn", help="existing ACM certificate (e.g. a wildcard) instead of a new one")
    s.add_argument("--copy-workos-key-from", help="nonprod SSM prefix holding a shared workos-api-key, e.g. /apm-nonprod")
    s.add_argument("--preview-ttl-days", type=int, default=d.PREVIEW_TTL_DAYS,
                   help="previews: days until the sweeper may delete the stage (refreshed on each deploy)")

    s = sub.add_parser("destroy", help="delete a preview stage (pr-<number> only)")
    s.add_argument("--stage", required=True)
    s.add_argument("--profile")
    s.add_argument("--region", default="us-east-1")
    s.add_argument("--account", help="refuse unless the credentials are for this AWS account")
    s.add_argument("--yes", action="store_true", help="required: confirm deletion")

    s = sub.add_parser("release", help="dev/prod release records in S3 (CI)")
    rs = s.add_subparsers(dest="release_cmd", required=True)
    x = rs.add_parser("record", help="record a deploy and its health check result (write-once)")
    x.add_argument("--stage", required=True, choices=["dev", "prod"])
    x.add_argument("--kind", required=True, choices=["deploy", "promotion", "rollback"])
    x.add_argument("--artifact", required=True)
    x.add_argument("--sha256")
    x.add_argument("--git-sha", required=True)
    x.add_argument("--health", required=True, choices=["passed", "failed"])
    x.add_argument("--health-url", required=True)
    for f in ("--ci-run-id", "--ci-run-url", "--deploy-run-id", "--deploy-run-url", "--account", "--domain"):
        x.add_argument(f, required=True)
    x.add_argument("--source-release-id", help="promotion: the dev release; rollback: the prod release")
    x.add_argument("--record-out", help="also write the record JSON to this file")
    x = rs.add_parser("current", help="print a stage's newest release pointer")
    x.add_argument("--stage", required=True, choices=["dev", "prod"])
    x.add_argument("--account", required=True)
    x = rs.add_parser("resolve", help="validate a release id and download its verified artifact")
    x.add_argument("--mode", required=True, choices=["promote", "rollback"])
    x.add_argument("--release-id", required=True)
    x.add_argument("--account", required=True, help="account holding the release records")
    x.add_argument("--out", required=True)
    x.add_argument("--sha256", help="refuse unless the recorded artifact has this sha256")
    x.add_argument("--allow-superseded", action="store_true",
                   help="promote: explicitly accept a tested dev release that dev has since moved past")
    x = rs.add_parser("provenance", help="check a resolved record against GitHub: CI run, CI artifact digest, "
                      "dev deploy run (GH_TOKEN; no AWS calls)")
    x.add_argument("--mode", required=True, choices=["promote", "rollback"])
    x.add_argument("--record", required=True, help="release.json written by `release resolve`")
    x.add_argument("--repo", required=True, help="owner/repo")
    for x in rs.choices.values():
        x.add_argument("--region", default="us-east-1")
        x.add_argument("--profile")

    s = sub.add_parser("preview", help="preview lifecycle (CI)")
    ps = s.add_subparsers(dest="preview_cmd", required=True)
    x = ps.add_parser("plan", help="decide deploy/remove/none from the GitHub event; no AWS calls")
    x.add_argument("--pr", help="workflow_dispatch: PR number")
    x.add_argument("--action", help="workflow_dispatch: deploy or remove")
    x = ps.add_parser("sweep", help="delete closed, unlabeled and expired previews")
    x.add_argument("--repo", required=True)
    x.add_argument("--account", required=True)
    x.add_argument("--region", default="us-east-1")
    x.add_argument("--profile")
    x.add_argument("--dry-run", action="store_true")

    s = sub.add_parser("smoke", help="check /healthz and the web app manifest of a deployed URL")
    s.add_argument("--url", required=True)
    s.add_argument("--attempts", type=int, default=30)

    s = sub.add_parser("names", help="print the AWS names for a stage as JSON")
    s.add_argument("--stage", default=policy.PROD)

    s = sub.add_parser("template", help="print the CloudFormation template with placeholder values")
    s.add_argument("--stage", default=policy.PROD)
    s.add_argument("--domain", default="apm.example.com")
    s.add_argument("--certificate-arn")
    a = p.parse_args(argv)

    if a.cmd == "template":
        print(json.dumps(d.template("111122223333", "us-east-1", a.domain, "Z123", "owner@example.com",
                                    "client_123", "VAPID", "bucket", "key.zip", stage=a.stage,
                                    certificate_arn=a.certificate_arn), indent=2))
        return 0
    if a.cmd == "names":
        n = policy.Names(a.stage)
        print(json.dumps({k: getattr(n, k) for k in (
            "stage", "stack", "table", "function", "param_prefix", "role_path", "role_prefix",
            "boundary_name", "broker_role", "broker_role_path", "is_preview")}, indent=2))
        return 0
    if a.cmd == "build":
        d.build_artifact(a.out, git_sha=a.git_sha)
        return 0
    if a.cmd == "verify":
        m = d.verify_artifact(a.artifact, a.sha256, a.git_sha)
        print(f"OK {m['sha256']} git {m['git_sha']}")
        return 0
    if a.cmd == "release":
        return _release(a)
    if a.cmd == "preview":
        return _preview(a)
    if a.cmd == "smoke":
        d.smoke(a.url, attempts=a.attempts)
        return 0
    if a.cmd == "destroy":
        if not a.yes:
            print("error: destroy needs --yes", file=sys.stderr)
            return 2
        d.destroy(a.stage, profile=a.profile, region=a.region, expected_account=a.account)
        return 0
    if a.cmd == "deploy-artifact":
        missing = [f for f, v in (("--domain", a.domain), ("--owner-email", a.owner_email),
                                  ("--workos-client-id", a.workos_client_id)) if not v]
        if missing:
            print(f"error: missing {', '.join(missing)}", file=sys.stderr)
            return 2
        d.deploy_artifact(a.artifact, a.domain, a.owner_email, a.workos_client_id, stage=a.stage,
                          profile=a.profile, region=a.region or "us-east-1", zone_id=a.zone_id,
                          certificate_arn=a.certificate_arn, expected_sha256=a.sha256, expected_git_sha=a.git_sha,
                          expected_account=a.account, copy_workos_key_from=a.copy_workos_key_from,
                          preview_ttl_days=a.preview_ttl_days)
        return 0

    # deploy: the owner path. Saved settings in ~/.apm/deploy.json are for prod only.
    stage = policy.Names(a.stage).stage
    saved = d.load_settings() if stage == policy.PROD else {}
    settings = {"domain": a.domain or saved.get("domain"), "owner_emails": a.owner_email or saved.get("owner_emails"),
                "workos_client_id": a.workos_client_id or saved.get("workos_client_id"),
                "profile": a.profile or saved.get("profile"), "region": a.region or saved.get("region") or "us-east-1"}
    missing = [k for k in ("domain", "owner_emails", "workos_client_id") if not settings[k]]
    if missing:
        print(f"error: missing {', '.join('--' + m.replace('_emails', '_email').replace('_', '-') for m in missing)}"
              " (saved to ~/.apm/deploy.json after the first prod deploy)", file=sys.stderr)
        return 2
    if stage == policy.PROD:
        d.save_settings(settings)
    d.deploy(**settings, stage=stage)
    return 0


if __name__ == "__main__":
    sys.exit(main())
