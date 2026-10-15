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
   - Group what one task needs into **one request, with one grant per resource set** (`grants`, or `apm request --grant 's3:GetObject=arn:aws:s3:::my-bucket/*' --grant 'dynamodb:PutItem=arn:aws:dynamodb:...:table/orders'`). Don't send the union of all actions on the union of all resources, and don't send several requests for one task. The owner approves, times and revokes each grant on its own.
   - Suggest how long you need it (`duration`, or `--for 3h`): 1h, 3h, 1d, 1w or permanent. Pick the shortest that covers the task; the owner decides, and a time-limited grant ends by itself.
   - If the new grants supersede ones the project already has (a broader or corrected version), name the old ones in `replaces` (`--replaces Req22 --replaces Req52g3`, as `list_projects` shows them). Approving revokes them, which keeps the role's policy under IAM's size limit. A request that's too big is rejected with a note saying how far over it is.
   - Then wait with `check_request` (`wait_seconds: 120`, repeat while pending), and retry once it is approved.
   - If it's rejected, read the note and stop or adjust. Don't re-request the same thing.
4. **Give back what you no longer need.** `remove_permissions` (or `apm remove --project P --grant Req22 [-a ACTION] [-r ARN] --reason WHY`) drops actions or resources from one grant, or the whole grant if you name neither. It takes effect at once without approval, and the owner is told.
   - Name the grant and every action or ARN exactly as `list_projects` shows them. For a request with several grants, name the one (`Req52g3`), not `Req52`, when dropping parts of it.
   - A grant left with no actions or no resources ends.
   - If it reports that IAM failed, part of it is already recorded: tell the user, and the owner re-applies decisions in Projects.
5. **Some actions can never be granted:** IAM changes, `sts:AssumeRole`, Organizations, account, SSO/identity, billing and domain registration (`route53domains`). Stopping or changing CloudTrail logging, and anything belonging to AWS Permissions itself, is denied even if approved. Don't request them. Tell the user if a task needs them.

If the tools say this machine isn't connected, call `connect`. It opens the owner's dashboard in the browser. Tell the user the code it returns so they can check it matches, then call `connect` with `wait_seconds: 120` until it reports connected. This only happens once per machine. Without the MCP tools, run `apm login`.

## Cleaning up a project

When the user asks you to tidy a project's access, or a task that needed temporary access is done:

1. See what the project holds with `list_projects`, then call `project_usage` (or `apm usage <project>`) to see when each grant was last used. If it says AWS is still preparing the report, call it again in a minute.
2. Decide per grant from its reason, the task and its usage: is anything still going to need it? A grant marked `unused` hasn't been used for 30 days. Usage shows up to about 4 hours late, and `per_action: false` means AWS only reported the service's last use, so a recent use there may have come from another grant.
3. Remove only what you're sure of, with `remove_permissions` and a reason, and tell the user what you removed.
4. Ask the user first before removing grants used by a pipeline or for production.
5. If the whole project is unused, don't empty it grant by grant: recommend that the owner deletes the project in the dashboard.

## Leave AWS Permissions itself alone

Don't change AWS Permissions' own parameters, functions, tables, stacks, buckets, API, DNS records or roles, or its code and rules, even when a grant would allow it, unless the user explicitly asked for that exact change.
