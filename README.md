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
- **`apm-agent-boundary`**: a permissions boundary on every agent role. Even an approved grant can never give IAM writes, `sts:AssumeRole`, Organizations, account, SSO/identity, billing or domain registration access, or stop or change CloudTrail logging. `iam:PassRole` is allowed only for other agent roles.
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
| `apm/` | Hosted service (Lambda): `web.py` routes and auth, `pages.py` screens, `static/` web app (service worker, script, styles, manifest), `broker.py` IAM/STS, `store.py` DynamoDB, `push.py` Web Push, `policy.py` policies and validation, `deploy.py` + `cli.py` (`apm-admin`) owner deploy |
| `apm/static/` | Web app: manifest, service worker, icons, `app.js` |
| `plugins/aws-permissions/` | The plugin for Claude Code and Codex: MCP server + `apm` CLI in one stdlib-only script (`scripts/apm.py`), `skills/aws-access`, manifests for both tools |
| `.claude-plugin/marketplace.json`, `.agents/plugins/marketplace.json` | Marketplaces so both tools can install the plugin from this repo |
| `.github/workflows/`, `infra/`, `docs/deployment.md` | CI/CD workflows, OIDC bootstrap template (applied manually), deployment contract following the org deployment policy |

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

CI/CD follows the org deployment policy and is described in [docs/deployment.md](docs/deployment.md): PR checks without cloud credentials, opt-in per-PR previews, continuous deploy to dev with a recorded release, manual promotion of that same artifact to prod, and a separate manual rollback. Previews run PR code, so put dev and previews in a separate nonprod AWS account with no write path to anything prod reads; promotion also re-verifies each dev release against GitHub (CI run, build digest, dev deploy run) before deploying it. Its cloud workflows stay disabled until the one-time bootstrap there is done; `apm-admin deploy` keeps working as above. `apm-admin --help` lists the commands they use. `tests/test_deploy.py` and `tests/test_pipeline.py` cover stage isolation, prod template compatibility, release records, the preview cleanup allowlist and workflow hygiene, without AWS or network; the bootstrap-template checks need `cfn-lint` installed.

If your WorkOS application requires a client secret, store it without echoing it, then redeploy:

```sh
aws ssm put-parameter --name /apm/workos-api-key --type SecureString --value "$(pbpaste)"
```

## Use it

**On your phone:**
1. Open the site and sign in.
2. Install it. On iPhone or iPad, tap Share and then Add to Home Screen, then open it from the Home Screen. iOS only allows web push for Home Screen apps (iOS 16.4 or later). On Android or desktop Chrome or Edge, use **Install app** on the Notifications screen or the browser's install option.
3. On the **Notifications** screen, tap **Turn on notifications**. A test notification is sent straight away. **Send a test** repeats it at any time.

The app has four screens: **Requests** (the home screen, with pending requests and agents asking to connect), **Projects**, **Notifications** and **Keys**. Tapping a notification opens that request at `/requests/<id>` (or `/connect/<code>`). If you're signed out, you go back to it after signing in.

**What notifications contain.** Only the project name, the request number and how many actions it asks for, so nothing sensitive shows on a lock screen. The reason, actions and resources appear only in the signed-in app. Nothing can be approved from a notification.

**Delivery.** When an agent asks for something, the Lambda sends to every device in parallel. It retries a timeout, 429 or 5xx once, then gives up; the Lambda can't queue work after it responds. Devices the push service reports as gone (404/410) are removed. Other failures are recorded per device and shown on the Notifications screen. Every send logs a JSON line (`"event": "push"`) to CloudWatch with the outcome and HTTP status. A missed notification never loses a request: the Requests screen always lists everything pending. Browsers that rotate a subscription re-register it themselves, as does the app whenever it opens.

**Live updates.** Every signed-in screen keeps itself current without a reload. While the page is visible it asks `GET /poll` (session-authenticated, a fingerprint of requests, connects, keys and devices) every 10 seconds, and again whenever the app regains focus, becomes visible or a push notification arrives; when the fingerprint changes it re-fetches the screen and swaps the content in place. Approve, reject, revoke and delete submit in the page the same way. A refresh never interrupts you: it waits while you're typing, confirming, submitting or looking at a new key.

**Offline and caching.** The service worker caches only static files (CSS, JS, icons and an offline page). Signed-in pages, approvals, keys and API responses are never cached (`Cache-Control: no-store`). Offline, buttons are disabled and opening a screen shows the offline page. Nothing is queued to send later.

**For each machine:** install the plugin:

```sh
# Claude Code
claude plugin marketplace add taylorrowser/aws-permissions-manager   # or a local path to this repo
claude plugin install aws-permissions@taylorrowser
# Codex
codex plugin marketplace add taylorrowser/aws-permissions-manager
codex plugin add aws-permissions@taylorrowser
```

Install from GitHub, so agents run the reviewed `main`. A local-path marketplace installs whatever that checkout holds, including uncommitted changes. To update later:

```sh
claude plugin marketplace update taylorrowser && claude plugin update aws-permissions@taylorrowser
codex plugin marketplace upgrade taylorrowser && codex plugin add aws-permissions@taylorrowser
```

Both tools cache plugins by version, so bump `version` in both `plugin.json` files (and `VERSION` in `scripts/apm.py`) with any plugin change.

The first time an agent needs AWS on that machine, it calls the `connect` tool. The tool opens the dashboard and pings your phone, you check the code matches what the agent shows, and you tap Approve. The agent generates its own API key and sends only its hash, so no key is ever copied or pasted. Without an agent, `apm login` does the same from a terminal. `apm login --paste` or `APM_API_KEY` accept a key created in the dashboard instead.

Agents then follow the bundled `aws-access` skill:
0. `connect` once per machine, if not connected yet.
1. `list_projects` to find a project.
2. `get_aws_credentials` to set up the profile.
3. `aws --profile apm-<project> …`.
4. On AccessDenied, `request_permissions`, then `check_request` to wait for your decision.

Tell an agent which project to use in the prompt or in the repo's `CLAUDE.md`/`AGENTS.md`, e.g. "Use AWS project `myapp`."

The same script works as a CLI: `apm projects`, `apm request`, `apm status`, `apm wait`, `apm use`. Claude Code puts the plugin's `bin/apm` on the agent's PATH.

**When something goes wrong** (bad deploy, damaged data, a leaked key, session or device), see [docs/operations.md](docs/operations.md): deploy, rollback, table restore and secret rotation. [docs/v1-acceptance.md](docs/v1-acceptance.md) is the end-to-end check run before a release.

## Security notes

- Agents can never touch apm itself, whatever you approve. The boundary denies its SSM parameters (`/apm*`, including the session secret and push key), its Lambda, table, stack, `apm-*` buckets and logs, its HTTP API (routes and integrations), anything tagged `managed-by=apm`, its DNS record and domain registration (`route53domains:*`). Without this, approving `ssm:GetParameter` or `lambda:UpdateFunctionCode` on `*` would let an agent forge your sign-in or replace the approval code. A boundary change takes effect only after a redeploy.
- Each approve, reject, revoke or project deletion runs entirely under a per-project lease in DynamoDB and re-reads the request strongly consistent inside it, so concurrent Lambda instances can't interleave. The policy is never rebuilt from an IAM read, which can be stale, so a revoked grant can't come back. If IAM refuses a change before writing (the size limit), the approval goes back to pending. If an IAM write fails or its result is unknown (e.g. a timeout), the decision stays recorded. The dashboard flags any project whose IAM policy doesn't match its decisions, with a **Re-apply decisions** button.
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

These use fake IAM, STS and DynamoDB. They also run the plugin's MCP server and CLI with the system `python3` against the app served locally. If `node` is installed, they also run the service worker and page-script tests in `tests/js` (`node --test tests/js/*.test.mjs`).

To try the web app locally against the same fakes (no AWS or WorkOS), with seeded requests:

```sh
.venv/bin/python scripts/dev_server.py        # then open http://localhost:8765/dev/login
```

`tests/e2e/push_e2e.mjs` is an optional check in real Chrome. It turns on notifications, receives real Web Push through Chrome's push service, opens a request from the notification's link, and tests offline behaviour. It needs Playwright, Google Chrome and internet access; see the file's header.

## Legacy

`legacy/` holds the 7 October handoff package: an offline EC2-only broker with WorkOS auth. It's kept for reference and isn't used.
