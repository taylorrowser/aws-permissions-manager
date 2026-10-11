# Operating apm

What to do when something goes wrong in prod: a bad deploy, damaged data, or a leaked key, session or device. Every AWS command here uses your own admin login (`aws login`), not an agent's `apm-*` profile, because agent roles are denied all of apm's infrastructure on purpose.

Prod values used below:

```sh
ACCOUNT=654654478411
REGION=us-east-1
BUCKET=apm-artifacts-$ACCOUNT-$REGION
```

## Deploy prod (owner path)

Deploy only merged `main`, from a clean checkout, never from a working copy with local changes:

```sh
git worktree add /tmp/apm-release origin/main && cd /tmp/apm-release
python3 -m venv .venv && .venv/bin/pip install -e .
SHA=$(git rev-parse HEAD)
aws s3 cp s3://$BUCKET/deployments/prod/current.json - | python3 -m json.tool   # note sha256 + git_sha: your rollback target
.venv/bin/apm-admin build --out /tmp/apm-artifact --git-sha "$SHA"              # prints the sha256
.venv/bin/apm-admin deploy-artifact --stage prod --artifact /tmp/apm-artifact --sha256 <sha256> \
  --git-sha "$SHA" --account $ACCOUNT --domain apm.taylorrowser.com \
  --owner-email taylorrowser@outlook.com --workos-client-id client_01M4F8908R45SEPPWV0KN3Q7NW
.venv/bin/apm-admin smoke --url https://apm.taylorrowser.com
```

`deploy-artifact` refuses to run if the digest, commit or account doesn't match. It records the deploy at `deployments/prod/<git_sha>.json` and overwrites `deployments/prod/current.json`, so note the previous `current.json` **before** deploying.

A boundary change (`apm/policy.py`) takes effect only through a deploy. After one, check it with the IAM policy simulator against an agent role, e.g. `aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::$ACCOUNT:role/agents/apm-<project> --action-names route53domains:UpdateDomainNameservers`. It should come back `explicitDeny` or `implicitDeny`, never `allowed`.

## Roll back prod

Every prod bundle stays in the artifact bucket; nothing expires there. To go back to the previous release, redeploy its exact bytes:

```sh
aws s3 ls s3://$BUCKET/deployments/prod/                                  # one record per deployed commit
aws s3 cp s3://$BUCKET/deployments/prod/<git_sha>.json - | python3 -m json.tool   # sha256, s3_key, deployed_at
mkdir -p /tmp/apm-rollback
aws s3 cp s3://$BUCKET/<s3_key> /tmp/apm-rollback/lambda.zip
aws s3 cp s3://$BUCKET/manifests/<sha256>.json /tmp/apm-rollback/manifest.json
apm-admin deploy-artifact --stage prod --artifact /tmp/apm-rollback --sha256 <sha256> --git-sha <git_sha> \
  --account $ACCOUNT --domain apm.taylorrowser.com \
  --owner-email taylorrowser@outlook.com --workos-client-id client_01M4F8908R45SEPPWV0KN3Q7NW
apm-admin smoke --url https://apm.taylorrowser.com
```

Run `apm-admin` from a clean checkout of current `main`. The CloudFormation template (including the agent boundary) always comes from that checkout, not from the old release, so a rollback restores the code but keeps today's infrastructure and boundary. That's safe because the prod template stays backward compatible (`tests/test_deploy.py`).

If the old bundle can't be found, check out the known-good commit and deploy it as in "Deploy prod". The rebuilt bundle may differ byte for byte from the original.

## Restore the table

The `apm` table holds every decision, key and device, and each project's IAM policy is rebuilt from it. Point-in-time recovery (35 days) is on, and the table survives a stack deletion.

**Never let apm run on an empty or re-created `apm` table.** Request numbers would restart at 1, and the next approval for a project would rewrite its role policy from the new table alone, removing grants that are still in IAM.

To restore, AWS can't restore in place, so restore to a new table, check it, then swap it in under the same name:

```sh
T=apm-restore-$(date -u +%Y%m%d%H%M)
aws dynamodb restore-table-to-point-in-time --source-table-name apm --target-table-name $T \
  --restore-date-time <UTC time before the damage, e.g. 2026-10-12T09:00:00Z>
aws dynamodb wait table-exists --table-name $T
aws dynamodb scan --table-name $T --select COUNT                    # sanity check; inspect items as needed
BACKUP=$(aws dynamodb create-backup --table-name $T --backup-name $T --query BackupDetails.BackupArn --output text)
# Downtime starts: the dashboard and credential vending fail; IAM grants already in place keep working.
aws dynamodb delete-table --table-name apm
aws dynamodb wait table-not-exists --table-name apm
aws dynamodb restore-table-from-backup --target-table-name apm --backup-arn "$BACKUP"
aws dynamodb wait table-exists --table-name apm
aws dynamodb update-continuous-backups --table-name apm \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true   # restores don't keep PITR
```

Then open **Projects**. If any project shows "IAM doesn't match your decisions", press **Re-apply decisions**. Finally, delete `$T` and its backup.

## Something leaked

| What | Do this | Effect |
|---|---|---|
| An agent API key | **Keys** → Delete it. Then reconnect that machine (`connect` tool or `apm login`). | The key stops working on its next call. Credentials it already fetched last up to 1 hour, but only with each role's current permissions. To cut those off now, revoke the grants they could use. |
| A grant was too broad | **Projects** → Revoke it. | The role's policy changes immediately, and that applies to sessions already issued too. |
| Your phone or a browser session | **Notifications** → Remove the device, then rotate the session secret (below). | Signs every browser out. Sign back in with WorkOS. |
| The session secret | Rotate it as below. | All dashboard sessions end. |

Rotate the session secret (the value is generated locally and never printed):

```sh
aws ssm put-parameter --name /apm/session-secret --type SecureString --overwrite \
  --value "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
# The Lambda reads it once per instance; a configuration change replaces running instances.
aws lambda update-function-configuration --function-name apm \
  --description "session secret rotated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

## Where to look

- **Logs:** CloudWatch log group `/aws/lambda/apm`, kept 90 days. Push delivery logs one JSON line per device (`"event": "push"`). Errors are printed with a traceback, and the request still gets a 500 page.
- **Health:** `apm-admin smoke --url https://apm.taylorrowser.com`, or `curl https://apm.taylorrowser.com/healthz`.
- **What's deployed:** `aws s3 cp s3://$BUCKET/deployments/prod/current.json -`.
