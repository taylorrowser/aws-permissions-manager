# V1 acceptance run

The smallest end-to-end check before tagging `v1.0.0`. It's run once against prod, after the V1 PRs are merged and deployed and the plugin is installed from GitHub.

Record each step as **PASS**, **FAIL** or **NOT RUN**, with the date and a one-line note. A step counts as passed only if it was actually done. Never write keys, codes, session values or push endpoints here.

This run approves and revokes real grants and creates and deletes a key and a device. Only Taylor runs it.

## Before starting

| Check | Result |
|---|---|
| `main` CI green on the commit to tag; prod runs exactly that artifact (`deployments/prod/current.json` sha256 matches the build) | PASS 2026-10-11: CI green on `b96535f`; prod runs its artifact (sha256 `53a376cb…`) |
| IAM simulator on an agent role after the deploy: denied for `route53domains:UpdateDomainNameservers`, `cloudtrail:StopLogging`, `apigateway:PATCH` on apm's API integration and `ssm:GetParameter` on `/apm/session-secret`; allowed for `s3:ListAllMyBuckets` | PASS 2026-10-11: all 31 simulator checks as expected, including against an approve-everything grant |
| Claude Code and Codex show marketplace `taylorrowser` from GitHub and plugin 0.3.1 | PASS 2026-10-11: both match main |
| The previous prod artifact (sha256 and git sha) is noted for rollback ([operations.md](operations.md#roll-back-prod)) | PASS 2026-10-11: previous release `8ca2532`, sha256 `98ebf5fa…`; its zip is still in the artifact bucket |

## Steps

| # | Step | Expected | Result |
|---|---|---|---|
| 1 | iPhone: open https://apm.taylorrowser.com in Safari, sign in, Share → Add to Home Screen, then open the app from the Home Screen icon | Signed in, four tabs | PASS 2026-10-11: installed as a Home Screen app on iPhone |
| 2 | Notifications → Turn on notifications → Allow | A test notification arrives; the device is listed | PASS 2026-10-11: device subscribed; pushes for #3, #4 and #9 arrived |
| 3 | Lock the phone | | PASS 2026-10-11 |
| 4 | In a fresh agent session on a machine with no key (or after deleting its key), ask the agent to connect; approve on the phone after checking the code | Connect push arrives; agent reports connected; `list_projects` works | PASS 2026-10-11: fresh `APM_HOME` (no key); the connect code matched and was approved; `apm projects` works |
| 5 | Ask the agent to request `s3:ListAllMyBuckets` on `*` for a new project `v1check`, and to send a second, duplicate request | Lock screen shows only project, request number and action count. Tapping it opens `/requests/<id>` | PASS 2026-10-11: #4 and duplicate #9 sent; the request push carries only `Permission request #N` and `<project>: N actions to review`, and opens `/requests/N` |
| 6 | Reject the duplicate, approve the real one | `check_request` reports each decision; Projects shows `v1check` with no mismatch warning | PASS 2026-10-11: #9 rejected, #4 approved; `apm status` reports both; Projects shows `v1check` with no mismatch warning |
| 7 | Agent: `get_aws_credentials v1check`, then `aws --profile apm-v1check s3 ls`, then something not granted (e.g. `aws --profile apm-v1check ec2 describe-instances`) | `s3 ls` succeeds; the other gets AccessDenied | PASS 2026-10-11: `s3 ls` succeeded; EC2 denied |
| 8 | Revoke the grant, wait a minute, run `aws --profile apm-v1check s3 ls` again | AccessDenied | PASS 2026-10-11: #4 revoked on the phone; `s3 ls` AccessDenied about a minute later |
| 9 | Delete the `v1check` project and the key from step 4; the agent calls `list_projects` | 401 telling it to connect; connecting again works | PASS 2026-10-11: step 4's key deleted, the agent got "missing or invalid API key; connect with the `connect` MCP tool or `apm login`"; reconnect approved and `apm projects` works. The `v1check` project was left in place with no grants |
| 10 | Rollback | Reviewed in [operations.md](operations.md#roll-back-prod) only; not run live unless Taylor decides to | PASS 2026-10-11: reviewed only, not run live |
| 11 | Android (only if used) | As steps 1–5 | NOT RUN: Android not used |

V1 is ready to tag when every row above step 10 is PASS. If a step fails, fix only that failure, redeploy, and re-run from the step it affects.
