# Deployment contract

How apm is built, deployed and promoted. Everything here that touches AWS is **disabled until the
one-time bootstrap below is done**: each cloud workflow checks a repository variable first and
otherwise skips.

| Workflow | Trigger | Runs today, before bootstrap? | Cloud access |
|---|---|---|---|
| `ci.yml` | every PR, push to `main` | yes | none |
| `preview.yml` | `preview` label on a same-repo PR, plus a daily sweep | no: needs `APM_PREVIEW_ENABLED=true` | nonprod, `preview` role |
| `deploy-dev.yml` | CI succeeded on a `main` push | no: needs `APM_DEV_ENABLED=true` | nonprod, `dev` role |
| `promote-prod.yml` | manual `workflow_dispatch` on `main` | no: needs `APM_PROD_DEPLOY_ENABLED=true` | prod, `production` role |
| `oidc-claims.yml` | manual, bootstrap helper | yes (prints claims only) | none |

The owner path still works unchanged: `apm-admin deploy` builds this checkout and deploys it to
prod with your admin login, exactly as before.

## Stages and names

A stage is `prod`, `dev` or `pr-<N>`. `apm.policy.Names(stage)` derives every AWS name from it, and
the Lambda learns its stage from the `APM_STAGE` environment variable, which every template sets.
Code that predates stages, or a Lambda without `APM_STAGE`, runs as `prod`.

| | prod (unchanged) | dev | pr-N (preview) |
|---|---|---|---|
| Domain | `apm.taylorrowser.com` | `dev.apm.taylorrowser.com` | `pr-N.preview.apm.taylorrowser.com` |
| Stack / table / function / HTTP API | `apm` | `apm-dev` | `apm-pr-N` |
| Log group | `/aws/lambda/apm` (90 days) | `/aws/lambda/apm-dev` (14 days) | `/aws/lambda/apm-pr-N` (14 days) |
| SSM prefix (`PARAM_PREFIX`) | `/apm` | `/apm-dev` | `/apm-pr-N` |
| Broker role | `/apm/apm-broker` | `/apm-dev/apm-dev__broker` | `/apm-pr-N/apm-pr-N__broker` |
| Boundary policy | `apm-agent-boundary` | `apm-dev_agent-boundary` | `apm-pr-N_agent-boundary` |
| Agent roles | `/agents/apm-<project>` | `/agents-dev/apm-dev_<project>` | `/agents-pr-N/apm-pr-N_<project>` |
| Table on stack delete | Retain | Retain | Delete (PITR off) |
| Artifact bucket | `apm-artifacts-<account>-<region>` | same pattern in its account | same pattern in its account |
| WorkOS app | existing prod app | staging app | staging app |

Why the odd separators: a project name matches `^[a-z][a-z0-9-]{1,40}$`, so it can never contain
`_`. That means:
- a nonprod role (`apm-dev_x`, `apm-pr-1__broker`) can never have the same name as a prod role
  `apm-<project>`;
- the nonprod broker's lookup pattern `role/apm-pr-1_*` can't match a prod role or stage `pr-12`;
- agent roles of different stages live under different paths, so `role/agents/*` (prod) and
  `role/agents-dev/*` don't overlap.

`tests/test_deploy.py` checks this against tricky project names. One pre-existing prod pattern does
overlap: prod's read-only `LookUpAgentRoles` statement allows `iam:GetRole`/`GetRolePolicy`/
`ListRolePolicies` on `role/apm-*`, which also matches nonprod role names when everything shares an
account. That is prod *reading* nonprod, never nonprod touching prod, and it disappears with a
separate nonprod account.

**Prod compatibility.** `tests/fixtures/prod_template_before_stages.json` was rendered by the
single-stage `deploy.py` before this change. The test asserts the prod template now equals it plus
exactly one addition, `APM_STAGE=prod` in the Lambda environment. Every resource name, SSM path,
role path, boundary, log group, bucket and domain is byte-identical.

**Use a separate nonprod AWS account (recommended).** Names keep stages apart in one account. But
agent roles in a preview could still be *granted* access to prod data in the same account, and the
deploy roles are powerful (see "Deploy role permissions"). Put dev and previews in their own account.

## Artifacts: build once, promote the same bytes

`apm-admin build --out DIR --git-sha SHA` writes:
- `lambda.zip`: the `apm` package plus the dependencies in `apm/lambda-requirements.txt`
  (cryptography, cffi, pycparser), installed with `--require-hashes --no-deps --only-binary`
  for `manylinux2014_aarch64` / CPython 3.13. Zip entries have fixed timestamps and modes, and
  host-specific files (`bin/` scripts and their dist-info `RECORD`) are left out. Two builds of the
  same tree on the same host are byte-identical; CI checks this.
- `manifest.json`: schema, `git_sha`, `sha256`, `size`, `s3_key` (`lambda/<sha256[:16]>.zip`, the
  original key scheme), runtime, Python version, architecture, `lock_sha256`, pinned dependencies.

`apm-admin verify` checks the zip against its manifest and an optional expected digest or commit.
`apm-admin deploy-artifact` always verifies before it deploys. It uploads the zip only if that
content-addressed key doesn't exist yet. It writes `manifests/<sha256>.json` and records each deploy
under `deployments/<stage>/<git_sha>.json` and `deployments/<stage>/current.json` in the artifact
bucket.

The flow:
1. **CI** (push to `main`) builds the artifact and uploads it as the workflow artifact
   `lambda-<sha>` (30 days).
2. **Deploy dev** downloads *that* artifact from the CI run, verifies it, and deploys it to `dev`.
   It skips commits older than what dev already runs, smoke tests `/healthz` and
   `/manifest.webmanifest`, then re-uploads the same files as `release-<sha>` (90 days). A
   `release-<sha>` artifact from a successful `deploy-dev.yml` run is the record that the commit
   is eligible for prod.
3. **Promote to prod** (manual, on `main`, input `sha`, optional `sha256`) does these checks:
   - the commit is an ancestor of `origin/main`;
   - an unexpired `release-<sha>` exists, from a run of `.github/workflows/deploy-dev.yml` that
     concluded `success`;
   - the downloaded zip's digest matches its manifest, the input `sha256` if given, and the commit.

   Only then does it deploy those bytes to prod, serialized with any other prod deploy, and smoke
   test them.

**Rollback** means running **Promote to prod** again with an older known-good sha. That needs its
`release-<sha>` artifact (90-day retention); its bundle is usually still in the prod bucket too.
Older than that: check out the commit and run `apm-admin deploy` as owner. DynamoDB data is not
rolled back, so keep changes to stored items backward compatible for at least one release.

Deploys never cancel each other mid-flight. `deploy-dev`, `deploy-production` and each
`preview-pr-<N>` are single concurrency groups with `cancel-in-progress: false`. PR checks in
`ci.yml` cancel superseded runs.

## Preview lifecycle

- **Opt in:** add the `preview` label to a PR whose branch is in this repo. Fork PRs are skipped,
  and the workflow uses `pull_request`, never `pull_request_target`.
- **Deploy:**
  1. The job confirms the event's head sha is still the PR's head (otherwise it skips; the newer
     push has its own run).
  2. It checks out that exact commit, not the merge ref, builds it, and deploys stage `pr-<N>`
     with the shared wildcard certificate.
  3. It smoke tests the stage and upserts one PR comment with `https://pr-<N>.preview.apm.taylorrowser.com`.
- **Update:** every push while labeled redeploys.
- **Cleanup:** closing the PR or removing the label runs `apm-admin destroy --stage pr-<N>`, using
  tooling from the base commit. It deletes these, in order:
  1. the stage's agent roles (they hold the boundary, so they go first);
  2. the stack, including its table;
  3. the stage's SSM parameters.

  `destroy` refuses `prod` and `dev`.
- **TTL sweep:** runs daily and on demand. It destroys `apm-pr-*` stacks whose PR is closed or
  unlabeled, or whose last deploy is older than `APM_PREVIEW_TTL_DAYS` (default 7). Expired
  previews also lose the label and get a comment.
- **Trust model:** a preview runs code from a branch in this repo with a nonprod OIDC role. With
  `pull_request`, the PR's own version of the workflow runs. Anyone who can push a branch here can
  therefore deploy to nonprod. That's the reason previews live in a nonprod account and the prod
  role trusts only the `production` environment subject.

## Secrets, WorkOS and per-stage settings

- **Session secret and VAPID keys:** `deploy-artifact` generates them per stage under the stage's
  SSM prefix, and never prints them. Stages never share them. The web app already reads them from
  `PARAM_PREFIX` (`web.Settings.from_env`), so no app change was needed.
- **WorkOS:** keep the existing prod app untouched. Create one **staging** WorkOS app for dev and
  previews, with these redirect URIs:
  - `https://dev.apm.taylorrowser.com/auth/callback` (exact);
  - `https://*.preview.apm.taylorrowser.com/auth/callback` (wildcard; check that WorkOS allows a
    wildcard for your environment type, otherwise add each preview's URI by hand).

  Prefer PKCE without a client secret. If the staging app needs one, store it once as SecureString
  `/apm-nonprod/workos-api-key` in the nonprod account. Preview deploys copy it inside AWS to
  `/apm-pr-N/workos-api-key` without printing it. Dev reads `/apm-dev/workos-api-key`; set that once
  yourself.
- **Owner emails** are a repository variable (not a credential). No AWS keys are stored anywhere.
  All AWS access is GitHub OIDC to environment-scoped roles.
- **Environment badge:** the PWA PR shows a badge when `APM_STAGE` isn't `prod`.

## One-time bootstrap (Taylor or the coordinator; not automated)

Do these in order. Nothing here is applied by this PR.

1. **Check your GitHub plan.** Environments in a **private** repo need GitHub Pro (or Team). The
   deploy jobs use the environments `dev`, `preview` and `production`, and the OIDC trust relies on
   the environment in `sub`. On GitHub Free, upgrade to Pro, or make the repo public, before
   enabling anything. (A running workflow that names a missing environment creates it.)
2. **Nonprod account.** Create or choose a separate AWS account for dev and previews (recommended).
   Same-account use is possible, but see "Stages and names".
3. **Read the real OIDC subjects.** Run **OIDC claims** (`oidc-claims.yml`) from `main` once each
   for `dev`, `preview` and `production`. Copy each printed `sub` exactly. This repo was created
   after 2026-07-15, so GitHub is expected to use the immutable-ID format
   `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:NAME`
   ([GitHub docs](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)).
   Don't write a trust policy from an assumed format. The workflow prints only the decoded claims,
   never the token.
4. **Deploy roles.** Review `infra/github-oidc-bootstrap.yaml`, then deploy it by hand with an
   admin login:
   - nonprod account: `AccountKind=nonprod DevSubject=<dev sub> PreviewSubject=<preview sub>`;
   - prod account 654654478411: `AccountKind=prod ProdSubject=<production sub>`.

   Set `CreateOidcProvider=false` plus `ExistingOidcProviderArn` if the account already has the
   GitHub provider. Each role trusts exactly one `sub` with `aud=sts.amazonaws.com`. The outputs
   are the role ARNs.
5. **DNS.**
   - In the nonprod account, create public hosted zones `preview.apm.taylorrowser.com` and
     `dev.apm.taylorrowser.com`.
   - In the zone that serves `apm.taylorrowser.com` today, add NS records delegating both names
     to the new zones.
6. **Certificates.**
   - In the nonprod account, us-east-1, request a DNS-validated ACM certificate for
     `*.preview.apm.taylorrowser.com` (variable `APM_PREVIEW_CERT_ARN`).
   - Dev can let its stack create its own certificate (default), or use `APM_DEV_CERT_ARN`.
7. **WorkOS staging app** as described above, and optionally `/apm-nonprod/workos-api-key`.
8. **Repository variables** (Settings → Secrets and variables → Actions → Variables). Use
   repository-level variables, because the workflows' `if:` gates are evaluated before any
   environment applies.

| Variable | Value |
|---|---|
| `APM_NONPROD_ACCOUNT_ID`, `APM_NONPROD_REGION` | nonprod account id, `us-east-1` |
| `APM_DEV_ROLE_ARN`, `APM_PREVIEW_ROLE_ARN` | outputs of the nonprod bootstrap stack |
| `APM_PROD_ACCOUNT_ID`, `APM_PROD_REGION` | `654654478411`, `us-east-1` |
| `APM_PROD_ROLE_ARN` | output of the prod bootstrap stack |
| `APM_OWNER_EMAILS` | approver email(s), comma-separated |
| `APM_PROD_WORKOS_CLIENT_ID` | existing prod WorkOS client id |
| `APM_STAGING_WORKOS_CLIENT_ID` | staging WorkOS client id |
| `APM_PREVIEW_CERT_ARN` | wildcard certificate ARN |
| `APM_PREVIEW_ZONE_ID`, `APM_DEV_ZONE_ID`, `APM_PROD_ZONE_ID`, `APM_DEV_CERT_ARN` | optional (looked up or created otherwise) |
| `APM_BASE_DOMAIN` | optional, default `apm.taylorrowser.com` |
| `APM_PREVIEW_TTL_DAYS` | optional, default `7` |
| `APM_RUNNER` | optional runner label, default `ubuntu-24.04` (see "Runners and costs") |
| `APM_DEV_ENABLED`, `APM_PREVIEW_ENABLED`, `APM_PROD_DEPLOY_ENABLED` | `true` to switch each on, last |

9. **Environments.** Create `dev`, `preview` and `production`. On Pro or Team, restrict
   `production` (and `dev`) to the `main` branch with a deployment branch policy. Then a branch
   workflow can't claim the `production` subject: with the default `sub`, the environment is the
   only thing that distinguishes prod. Without that policy, anyone who can push a branch with a
   workflow naming `production` could assume the prod role. In that case also consider a custom
   OIDC subject template that includes `job_workflow_ref`, then re-read the claims (step 3).
10. **Enable in order:**
    1. `APM_DEV_ENABLED` first, then merge or push to `main` and watch dev deploy;
    2. then `APM_PREVIEW_ENABLED`;
    3. last, `APM_PROD_DEPLOY_ENABLED`. Run **Promote to prod** with the dev-tested sha.

    The first CI deploy to prod updates the existing `apm` stack in place. The only template
    change is `APM_STAGE=prod`, plus the new pinned bundle.

### Plan limits and the prod gate

GitHub **required reviewers and wait timers are not available for private repositories on Free,
Pro or Team**. This setup doesn't pretend to have them. The baseline gate is:
- `workflow_dispatch` restricted to `main`;
- the validation job: ancestry check, a successful dev deploy of the same sha, and a digest match;
- an OIDC trust that accepts only the `production` environment subject;
- on Pro or Team, a deployment branch policy limiting `production` to `main`.

Whoever can push to `main` can deploy prod, which is acceptable for a solo owner. Don't enable
"prevent self-review": with one maintainer it only blocks you.

### Deploy role permissions

The roles are scoped to each stage's resource names. Prod's role is update-only: no stack, table,
role or log-group deletion, and SSM is read-only. A change that needs replacing a resource fails in
CI and goes through the owner's `apm-admin deploy`.

Still, any role that can write the broker role's inline policy through CloudFormation can
effectively grant itself anything in that account. The protection is the exact-match OIDC subject,
the environment branch policy and the separate nonprod account, not the IAM scoping alone.

The policies were linted, not exercised against AWS. Expect the first real deploy to reveal a
missing action or two, especially `logs:*` describe calls and API Gateway tagging. Add them to the
bootstrap template rather than broadening to `*`.

## Runners and costs

All workflows run on **standard GitHub-hosted runners** (`ubuntu-24.04`) by default. The label
comes from one repository variable: `runs-on: ${{ vars.APM_RUNNER || 'ubuntu-24.04' }}`. With the
variable unset, every job, including PR checks, uses the GitHub-hosted runner.

Measured locally (Apple Silicon, warm pip cache):
- the 41 tests take about 3 s;
- an artifact build takes about 2 s.

On a GitHub-hosted runner, a CI run is dominated by setup: checkout, Python, `pip install`. The
first real run (PR #2, `ubuntu-24.04`) took 29 s for `test` and 18 s for `build`, so about 1
billed minute per job and about 2 per CI run. Deploy jobs mostly wait on CloudFormation: ~1–3
minutes for a code-only update, 5+ minutes when a new ACM certificate is created.

| | Included (private repos) | Overage / price |
|---|---|---|
| GitHub Actions, Free | 2,000 min/month | Linux x64 2-core $0.006/min |
| GitHub Actions, Pro | 3,000 min/month | Linux x64 2-core $0.006/min |
| Blacksmith | 3,000 free min/month | Ubuntu x64 $0.004/min, ARM $0.0025/min |
| Depot (Developer plan) | $20/month, includes 2,000 GitHub Actions min | — |

At this repo's size, minutes aren't the bottleneck. Moving runners should follow a measured
problem: slow queues or slow jobs in real CI timings. Blacksmith is the first candidate in that
case. Choosing a vendor is a **pending decision for Taylor**; none is connected or authorized.

**Prerequisite for Blacksmith or Depot runners:** both require the repository to be owned by a
**GitHub organization**. `taylorrowser/aws-permissions-manager` is a personal (User-owned) repo, so
neither works today
([Blacksmith quickstart](https://docs.blacksmith.sh/introduction/quickstart),
[Depot GitHub Actions](https://depot.dev/docs/github-actions/overview); Depot CI is a separate
product that does support personal accounts). Onboarding would be:
1. Move the repo to an organization: transfer it, or create a new org.
2. Install the vendor's GitHub app on that org.
3. Only then set `APM_RUNNER`, e.g. `blacksmith-2vcpu-ubuntu-2404` or a `depot-ubuntu-24.04` label.

An org transfer has consequences:
- **OIDC:** the `sub` claim changes with the owner (owner name and owner ID). Re-run
  `oidc-claims.yml` and update every trust policy before deploying again.
- **Plugin marketplace path:** `taylorrowser/aws-permissions-manager` changes, and so do the
  install commands in the README. GitHub redirects the old path for git, but don't rely on that
  for the plugin managers.
- **Quotas and billing:** free-minute quotas and billing move to the org's plan. Environment and
  branch-policy features depend on that plan too.

## References

- [pingdotgg/t3code](https://github.com/pingdotgg/t3code): `ci.yml`, `web-preview.yml` and
  `deploy-relay.yml` were the shape reference for checks, label-driven previews and deploys.
  t3code deploys to prod automatically; apm intentionally keeps prod a manual promotion of a
  dev-tested artifact.
- SST's per-PR stage pattern (one isolated stage per PR, torn down on close) is the model for
  `pr-<N>` stages. We're not migrating to SST; plain CloudFormation from `apm/deploy.py` stays.
