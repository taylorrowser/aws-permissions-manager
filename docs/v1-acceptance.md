# V1 acceptance run

The smallest end-to-end check before tagging `v1.0.0`. It's run once against prod, after the V1 PRs are merged and deployed and the plugin is installed from GitHub.

Record each step as **PASS**, **FAIL** or **NOT RUN**, with the date and a one-line note. A step counts as passed only if it was actually done. Never write keys, codes, session values or push endpoints here.

This run approves and revokes real grants and creates and deletes a key and a device. Only Taylor runs it.

## Before starting

| Check | Result |
|---|---|
| `main` CI green on the commit to tag; prod runs exactly that artifact (`deployments/prod/current.json` sha256 matches the build) | NOT RUN |
| IAM simulator on an agent role after the deploy: denied for `route53domains:UpdateDomainNameservers`, `cloudtrail:StopLogging`, `apigateway:PATCH` on apm's API integration and `ssm:GetParameter` on `/apm/session-secret`; allowed for `s3:ListAllMyBuckets` | NOT RUN |
| Claude Code and Codex show marketplace `taylorrowser` from GitHub and plugin 0.3.1 | NOT RUN |
| The previous prod artifact (sha256 and git sha) is noted for rollback ([operations.md](operations.md#roll-back-prod)) | NOT RUN |

## Steps

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | iPhone: open https://apm.taylorrowser.com in Safari, sign in, Share → Add to Home Screen, then open the app from the Home Screen icon | Signed in, four tabs | NOT RUN |
| 2 | Notifications → Turn on notifications → Allow | A test notification arrives; the device is listed | NOT RUN |
| 3 | Lock the phone | | NOT RUN |
| 4 | In a fresh agent session on a machine with no key (or after deleting its key), ask the agent to connect; approve on the phone after checking the code | Connect push arrives; agent reports connected; `list_projects` works | NOT RUN |
| 5 | Ask the agent to request `s3:ListAllMyBuckets` on `*` for a new project `v1check`, and to send a second, duplicate request | Lock screen shows only project, request number and action count. Tapping it opens `/requests/<id>` | NOT RUN |
| 6 | Reject the duplicate, approve the real one | `check_request` reports each decision; Projects shows `v1check` with no mismatch warning | NOT RUN |
| 7 | Agent: `get_aws_credentials v1check`, then `aws --profile apm-v1check s3 ls`, then something not granted (e.g. `aws --profile apm-v1check ec2 describe-instances`) | `s3 ls` succeeds; the other gets AccessDenied | NOT RUN |
| 8 | Revoke the grant, wait a minute, run `aws --profile apm-v1check s3 ls` again | AccessDenied | NOT RUN |
| 9 | Delete the `v1check` project and the key from step 4; the agent calls `list_projects` | 401 telling it to connect; connecting again works | NOT RUN |
| 10 | Rollback | Reviewed in [operations.md](operations.md#roll-back-prod) only; not run live unless Taylor decides to | NOT RUN |
| 11 | Android (only if used) | As steps 1–5 | NOT RUN |

V1 is ready to tag when every row above step 10 is PASS. If a step fails, fix only that failure, redeploy, and re-run from the step it affects.
