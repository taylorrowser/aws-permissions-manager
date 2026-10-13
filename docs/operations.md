# Operating apm

What to do when something goes wrong in prod: a bad deploy, damaged data, or a leaked key, session or device. Every AWS command here uses your own admin login (`aws login`), not an agent's `apm-*` profile, because agent roles are denied all of apm's infrastructure on purpose.

Start every session with these. The last line prints a warning if the credentials are for any other account; if you see it, stop:

```sh
export AWS_REGION=us-east-1          # also set AWS_PROFILE if your admin login isn't the default profile
ACCOUNT=654654478411
BUCKET=apm-artifacts-$ACCOUNT-$AWS_REGION
[ "$(aws sts get-caller-identity --query Account --output text)" = "$ACCOUNT" ] || echo "WRONG AWS ACCOUNT: stop here"
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

A boundary change (`apm/policy.py`) takes effect only through a deploy. After one, check it with the IAM policy simulator against an agent role, e.g. `aws iam simulate-principal-policy --policy-source-arn "arn:aws:iam::${ACCOUNT}:role/agents/apm-<project>" --action-names route53domains:UpdateDomainNameservers`. It should come back `explicitDeny` or `implicitDeny`, never `allowed`.

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

A restored table only knows what happened before the restore time. Keys deleted, grants revoked and projects approved after that would come back wrong. So **a restore resets access**: it keeps the history, but every grant is revoked, every key and device is removed, and agents connect and ask again. All of it happens while apm is paused.

AWS can't restore a table in place. So restore to a new table and check it. Then pause apm, swap the copy in under the same name, and reset access on the final table before reopening.

```sh
T=apm-restore-$(date -u +%Y%m%d%H%M)
aws dynamodb restore-table-to-point-in-time --source-table-name apm --target-table-name $T \
  --restore-date-time <UTC time before the damage, e.g. 2026-10-12T09:00:00Z>
aws dynamodb wait table-exists --table-name $T
aws dynamodb scan --table-name $T --select COUNT                    # sanity check; inspect items as needed

# 1. Pause apm and let running requests finish (the Lambda timeout is 29 s).
aws lambda put-function-concurrency --function-name apm --reserved-concurrent-executions 0
sleep 60

# 2. Swap the copy in as `apm`. Nothing has written to $T since it was restored.
BACKUP=$(aws dynamodb create-backup --table-name $T --backup-name $T --query BackupDetails.BackupArn --output text)
until [ "$(aws dynamodb describe-backup --backup-arn "$BACKUP" \
           --query BackupDescription.BackupDetails.BackupStatus --output text)" = AVAILABLE ]; do sleep 10; done
aws dynamodb delete-table --table-name apm
aws dynamodb wait table-not-exists --table-name apm
aws dynamodb restore-table-from-backup --target-table-name apm --backup-arn "$BACKUP"
aws dynamodb wait table-exists --table-name apm
aws dynamodb update-continuous-backups --table-name apm \
  --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true   # restores don't keep PITR
aws dynamodb tag-resource --resource-arn "arn:aws:dynamodb:${AWS_REGION}:${ACCOUNT}:table/apm" \
  --tags Key=managed-by,Value=apm                                           # or tags
```

Step 3 resets access. It runs in bash with `-euo pipefail`, so it stops at the first failure and apm stays paused. It ends by checking the result:

```sh
AWS_REGION=$AWS_REGION bash -euo pipefail <<'RESET'
key() { printf '{"pk":{"S":"%s"}}' "$1"; }
status='{"#s":"status"}'
# Approved -> revoked (the history stays). Consistent reads, so nothing just written is missed.
approved=$(aws dynamodb scan --table-name apm --consistent-read --filter-expression "kind = :r AND #s = :a" \
  --expression-attribute-names "$status" \
  --expression-attribute-values '{":r":{"S":"req"},":a":{"S":"approved"}}' \
  --projection-expression pk --query 'Items[].pk.S' --output text)
for pk in $approved; do
  aws dynamodb update-item --table-name apm --key "$(key "$pk")" \
    --update-expression "SET #s = :v, note = :n" --expression-attribute-names "$status" \
    --expression-attribute-values '{":v":{"S":"revoked"},":n":{"S":"revoked by table restore"}}'
done
# Remove keys, connect requests and devices: agents reconnect, the phone turns notifications back on.
access=$(aws dynamodb scan --table-name apm --consistent-read --filter-expression "kind IN (:k, :c, :d)" \
  --expression-attribute-values '{":k":{"S":"key"},":c":{"S":"connect"},":d":{"S":"sub"}}' \
  --projection-expression pk --query 'Items[].pk.S' --output text)
for pk in $access; do
  aws dynamodb delete-item --table-name apm --key "$(key "$pk")"
done
# Remove every grant from every agent role, including roles the restored table doesn't know.
roles=$(aws iam list-roles --path-prefix /agents/ --query 'Roles[].RoleName' --output text)
for role in $roles; do
  has=$(aws iam list-role-policies --role-name "$role" --query "contains(PolicyNames, 'apm-grants')" --output json)
  if [ "$has" = true ]; then aws iam delete-role-policy --role-name "$role" --policy-name apm-grants; fi
done
# Verify before reopening.
left=$(aws dynamodb scan --table-name apm --consistent-read --select COUNT \
  --filter-expression "(kind = :r AND #s = :a) OR kind IN (:k, :c, :d)" --expression-attribute-names "$status" \
  --expression-attribute-values '{":r":{"S":"req"},":a":{"S":"approved"},":k":{"S":"key"},":c":{"S":"connect"},":d":{"S":"sub"}}' \
  --query Count --output json)   # json sums Count across pages
[ "$left" = 0 ] || { echo "table still grants access ($left items); apm stays paused"; exit 1; }
for role in $roles; do
  [ "$(aws iam list-role-policies --role-name "$role" --query "contains(PolicyNames, 'apm-grants')" --output json)" = false ] \
    || { echo "$role still has apm-grants; apm stays paused"; exit 1; }
done
echo "Access reset and verified."
RESET
```

4. Only after it prints `Access reset and verified.`, reopen apm with `aws lambda delete-function-concurrency --function-name apm`.

After reopening:
- Projects show only revoked grants, with no mismatch warnings.
- Turn notifications back on from your phone.
- Agents reconnect and request what they need again.
- Finally, delete `$T` and its backup.

## Something leaked

| What | Do this | Effect |
|---|---|---|
| An agent API key | **Settings** → Agent keys → Delete it. Then reconnect that machine (`connect` tool or `apm login`). | The key stops working on its next call. Credentials it already fetched last up to 1 hour, but only with each role's current permissions. To cut those off now, revoke the grants they could use. |
| A grant was too broad | **Projects** → Revoke it. | The role's policy changes immediately, and that applies to sessions already issued too. |
| Your phone or a browser session | In this order: 1) secure the email account, since sign-in codes go there; 2) in the WorkOS dashboard (production environment), revoke your user's sessions; 3) **Settings** → Notifications → Remove the device; 4) rotate the session secret (below). | Rotating last means the stolen device can't sign back in and get a new apm cookie in between. |
| The session secret | Rotate it as below. | All dashboard sessions end. |

Rotate the session secret (the value is generated locally and never printed):

```sh
aws ssm put-parameter --name /apm/session-secret --type SecureString --overwrite \
  --value "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
# The Lambda reads it once per instance; a configuration change replaces running instances.
aws lambda update-function-configuration --function-name apm \
  --description "session secret rotated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
aws lambda wait function-updated-v2 --function-name apm     # fails if the update failed
```

Then reload the dashboard on a signed-in device: it should ask you to sign in again.

## Where to look

- **Logs:** CloudWatch log group `/aws/lambda/apm`, kept 90 days. Push delivery logs one JSON line per device (`"event": "push"`). Errors are printed with a traceback, and the request still gets a 500 page.
- **Health:** `apm-admin smoke --url https://apm.taylorrowser.com`, or `curl https://apm.taylorrowser.com/healthz`.
- **What's deployed:** `aws s3 cp s3://$BUCKET/deployments/prod/current.json -`.
