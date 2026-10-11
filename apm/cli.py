"""apm-admin: owner commands. Agents use the `apm` client in the plugin instead."""
import argparse
import sys

from . import deploy as d


def main(argv=None):
    p = argparse.ArgumentParser(prog="apm-admin", description="Deploy the hosted AWS Permissions Manager.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("deploy", help="build and deploy (or update) the hosted service with your admin login")
    s.add_argument("--domain", help="e.g. apm.example.com (needs a Route 53 hosted zone for the parent)")
    s.add_argument("--owner-email", help="WorkOS account email(s) allowed to approve, comma-separated")
    s.add_argument("--workos-client-id", help="WorkOS AuthKit client ID (client_...)")
    s.add_argument("--profile", help="admin AWS profile (default: your default credentials)")
    s.add_argument("--region", help="AWS region (default us-east-1)")
    sub.add_parser("template", help="print the CloudFormation template with placeholder values")
    a = p.parse_args(argv)

    if a.cmd == "template":
        import json
        print(json.dumps(d.template("111122223333", "us-east-1", "apm.example.com", "Z123", "owner@example.com",
                                    "client_123", "VAPID", "bucket", "key.zip"), indent=2))
        return 0

    saved = d.load_settings()
    settings = {"domain": a.domain or saved.get("domain"), "owner_emails": a.owner_email or saved.get("owner_emails"),
                "workos_client_id": a.workos_client_id or saved.get("workos_client_id"),
                "profile": a.profile or saved.get("profile"), "region": a.region or saved.get("region") or "us-east-1"}
    missing = [k for k in ("domain", "owner_emails", "workos_client_id") if not settings[k]]
    if missing:
        print(f"error: missing {', '.join('--' + m.replace('_emails', '_email').replace('_', '-') for m in missing)}"
              " (saved to ~/.apm/deploy.json after the first deploy)", file=sys.stderr)
        return 2
    d.save_settings(settings)
    d.deploy(**settings)
    return 0


if __name__ == "__main__":
    sys.exit(main())
