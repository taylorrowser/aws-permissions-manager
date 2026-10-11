# AWS Permissions Manager (`apm`)

Agents get AWS access per project without admin rights. They find a project, get short-lived credentials for it through an MCP server, and request new permissions. You approve or reject from a web app on your phone, which notifies you of each request.

## How it works

```
Claude Code / Codex ── MCP (plugin, local) ──HTTPS + API key──▶ https://apm.taylorrowser.com
                                                                 API Gateway → Lambda (role apm-broker)
                                                                   ├─ DynamoDB: requests, API keys, devices
you (phone/desktop web app, WorkOS sign-in) ── approve ──────────▶ ├─ IAM: edit role /agents/apm-<project>
                                                                   ├─ Web Push → your devices
agent ── aws --profile apm-<project> ── credential_process ──────▶ └─ STS: AssumeRole → 1-hour credentials
```

- **One IAM role per project**: `apm-<project>` under path `/agents/`. Its inline policy `apm-grants` holds one statement per approved request.
- **`apm-agent-boundary`**: a permissions boundary on every agent role. Even an approved grant can never give IAM writes, `sts:AssumeRole`, Organizations, account, SSO/identity or billing access. `iam:PassRole` is allowed only for other agent roles.
- **`apm-broker` role (the Lambda)**: its permissions are limited to these:
  - create roles under `/agents/`, and only with the boundary attached;
  - edit those roles' inline policies, and delete those roles;
  - assume them to vend credentials;
  - read and write its DynamoDB table.

  It can't remove a boundary or touch any other IAM resource, and no long-lived broker key exists anywhere.
- **Agents hold only an API key.** It lets them list projects, request permissions and get credentials. Approving needs your WorkOS sign-in. Any key can use any approved project; you tell each agent which one to use.
- **Credentials never reach the model.** `get_aws_credentials` writes an AWS profile whose `credential_process` fetches 1-hour credentials on demand. The agent sees only the profile name.
- **IAM enforces, DynamoDB records decisions.** The dashboard reads grants live from IAM. Each approve or revoke is recorded in DynamoDB first, then the role's policy is rewritten from that project's approved requests, read strongly consistent. Only the broker Lambda and account admins can write the table, and the boundary denies agents any access to it. Even a tampered table can only grant what the boundary allows.

## Layout

| Path | What |
|---|---|
| `apm/` | Hosted service (Lambda): `web.py` routes and auth, `pages.py` dashboard, `broker.py` IAM/STS, `store.py` DynamoDB, `push.py` Web Push, `policy.py` policies and validation, `deploy.py` + `cli.py` (`apm-admin`) owner deploy |
| `apm/static/` | Web app: manifest, service worker, icons, `app.js` |
| `plugins/aws-permissions/` | The plugin for Claude Code and Codex: MCP server + `apm` CLI in one stdlib-only script (`scripts/apm.py`), `skills/aws-access`, manifests for both tools |
| `.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json` | Marketplaces so both tools can install the plugin from this repo |

## Deploy (owner)

Prerequisites:
- A public Route 53 hosted zone for the parent domain.
- A WorkOS AuthKit application with redirect URI `https://<domain>/auth/callback`.

```sh
python3 -m venv .venv && .venv/bin/pip install -e .
aws login
.venv/bin/apm-admin deploy --domain apm.taylorrowser.com \
  --owner-email you@example.com --workos-client-id client_...
```

Settings are saved to `~/.apm/deploy.json`, so later deploys are just `apm-admin deploy`. The first deploy:
- creates `/apm/session-secret` and the VAPID push keys in SSM Parameter Store (values never printed);
- builds the Lambda bundle and uploads it to `apm-artifacts-<account>-<region>`;
- creates the `apm` CloudFormation stack: boundary, broker role, Lambda, DynamoDB table, HTTP API, ACM certificate and DNS record.

If your WorkOS application requires a client secret, store it without echoing it, then redeploy:

```sh
aws ssm put-parameter --name /apm/workos-api-key --type SecureString --value "$(pbpaste)"
```

## Use it

**On your phone:**
1. Open the site in Safari and sign in.
2. Tap Share, then Add to Home Screen.
3. Open the app from the home screen and tap **Enable notifications on this device**. iOS only allows web push for home-screen apps.

**For each machine:** install the plugin:

```sh
# Claude Code
claude plugin marketplace add taylorrowser/aws-permissions-manager   # or a local path to this repo
claude plugin install aws-permissions@taylorrowser
# Codex
codex plugin marketplace add taylorrowser/aws-permissions-manager
codex plugin add aws-permissions@taylorrowser
```

The first time an agent needs AWS on that machine, it calls the `connect` tool. The tool opens the dashboard and pings your phone, you check the code matches what the agent shows, and you tap Approve. The agent generates its own API key and sends only its hash, so no key is ever copied or pasted. Without an agent, `apm login` does the same from a terminal. `apm login --paste` or `APM_API_KEY` accept a key created in the dashboard instead.

Agents then follow the bundled `aws-access` skill:
0. `connect` once per machine, if not connected yet.
1. `list_projects` to find a project.
2. `get_aws_credentials` to set up the profile.
3. `aws --profile apm-<project> …`.
4. On AccessDenied, `request_permissions`, then `check_request` to wait for your decision.

Tell an agent which project to use in the prompt or in the repo's `CLAUDE.md`/`AGENTS.md`, e.g. "Use AWS project `myapp`."

The same script works as a CLI: `apm projects`, `apm request`, `apm status`, `apm wait`, `apm use`. Claude Code puts the plugin's `bin/apm` on the agent's PATH.

## Security notes

- Agents can never touch apm itself, whatever you approve. The boundary denies its SSM parameters (`/apm*`, including the session secret and push key), its Lambda, table, stack, `apm-*` buckets and logs, anything tagged `managed-by=apm`, and its DNS record. Without this, approving `ssm:GetParameter` or `lambda:UpdateFunctionCode` on `*` would let an agent forge your sign-in or replace the approval code. A boundary change takes effect only after a redeploy.
- Each approve, reject, revoke or project deletion runs entirely under a per-project lease in DynamoDB and re-reads the request strongly consistent inside it, so concurrent Lambda instances can't interleave. The policy is never rebuilt from an IAM read, which can be stale, so a revoked grant can't come back. If the IAM write fails, an approval goes back to pending; a revoke reports the error and can be retried.
- `ssm:GetParametersByPath` on the root path `/` is denied too, since a recursive read of `/` would otherwise return `/apm/*`.
- Approving `iam:PassRole` lets a project hand *another* agent role to a service. Approving `s3:*` on `*` means every bucket. Read the resources line; the dashboard flags wildcards.
- Revoking removes the permission from the role immediately. Credentials already issued keep working until they expire (≤1 hour), but only with the role's *current* permissions.
- An API key lets its holder use every approved project. Delete a leaked key in the dashboard. Keys are stored only as SHA-256 hashes.
- Dashboard sessions last 30 days (signed cookie). Only the configured WorkOS email(s), verified, can sign in.
- Never paste API keys or credentials into chats. `apm login --paste` reads a key with hidden input.
- Anyone can *ask* to connect (max 5 pending, each expires after 15 minutes), but only you can approve. Approve only connect requests you just started, and check the code.

## Tests

```sh
.venv/bin/python -m unittest discover -s tests
```

These use fake IAM, STS and DynamoDB. They also run the plugin's MCP server and CLI with the system `python3` against the app served locally.

## Legacy

`legacy/` holds the 7 October handoff package: an offline EC2-only broker with WorkOS auth. It's kept for reference and isn't used.
