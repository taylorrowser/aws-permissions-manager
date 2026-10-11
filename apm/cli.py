"""apm-admin: owner and CI commands. Agents use the `apm` client in the plugin instead."""
import argparse
import json
import sys

from . import deploy as d
from . import policy


def _deploy_target_args(s):
    s.add_argument("--domain", help="e.g. apm.example.com (needs a Route 53 hosted zone for the parent)")
    s.add_argument("--owner-email", help="WorkOS account email(s) allowed to approve, comma-separated")
    s.add_argument("--workos-client-id", help="WorkOS AuthKit client ID (client_...)")
    s.add_argument("--profile", help="AWS profile (default: your default credentials)")
    s.add_argument("--region", help="AWS region (default us-east-1)")


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

    s = sub.add_parser("destroy", help="delete a preview stage (pr-<number> only)")
    s.add_argument("--stage", required=True)
    s.add_argument("--profile")
    s.add_argument("--region", default="us-east-1")
    s.add_argument("--account", help="refuse unless the credentials are for this AWS account")
    s.add_argument("--yes", action="store_true", help="required: confirm deletion")

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
                          expected_account=a.account, copy_workos_key_from=a.copy_workos_key_from)
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
