---
name: aws-access
description: How to access AWS. Use whenever a task needs the AWS CLI, an AWS SDK, Terraform/CDK against AWS, or hits an AWS AccessDenied error.
---

# AWS access

You never get admin AWS credentials. AWS access is organised into **projects**, each with permissions the owner has approved. Use the `aws-permissions` MCP tools; if they aren't available, use the `apm` command, which offers the same operations.

1. **Pick a project.**
   - If the user or the repo's CLAUDE.md/AGENTS.md names one, use it.
   - Otherwise call `list_projects` (or `apm projects --search s3:GetObject`) to find one that already allows what you need.
2. **Get access.** Call `get_aws_credentials` with the project (or `apm use <project>`). This sets up the AWS profile `apm-<project>`. Then run AWS commands with `--profile apm-<project>` or `AWS_PROFILE=apm-<project>`.
   - Never use other AWS profiles or the default credentials.
   - Never try to print, export or copy credentials. The profile refreshes them automatically.
3. **When a call fails with AccessDenied**, call `request_permissions` (or `apm request ... --wait`).
   - Ask for exactly the denied action(s) on the specific resource ARN(s) from the error message.
   - Give a one-sentence reason the owner will understand.
   - Prefer narrow requests. Wildcards like `s3:*` or `Resource: *` are harder for the owner to approve.
   - Then wait with `check_request` (`wait_seconds: 120`, repeat while pending), and retry once it is approved.
   - If it's rejected, read the note and stop or adjust. Don't re-request the same thing.
4. **Some actions can never be granted:** IAM changes, `sts:AssumeRole`, Organizations, account, SSO/identity, billing and domain registration (`route53domains`). Stopping or changing CloudTrail logging, and anything belonging to AWS Permissions itself, is denied even if approved. Don't request them. Tell the user if a task needs them.

If the tools say this machine isn't connected, call `connect`. It opens the owner's dashboard in the browser. Tell the user the code it returns so they can check it matches, then call `connect` with `wait_seconds: 120` until it reports connected. This only happens once per machine. Without the MCP tools, run `apm login`.
