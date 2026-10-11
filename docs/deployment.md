# Deployment contract

How apm is built, deployed, promoted, rolled back and previewed. Everything here that touches AWS is
**disabled until the one-time bootstrap below is done**: each cloud workflow checks a repository
variable first and otherwise skips. The owner path, `apm-admin deploy` with your admin login, keeps
working for prod exactly as before.

## Governing policy

This pipeline follows Taylor's organization deployment policy. That policy governs; this document
records how apm implements it:

- [`docs/deployment-policy.md`](https://github.com/taylorrowser-home-automation/home-automation-starter/blob/main/docs/deployment-policy.md)
  and [`docs/adoption.md`](https://github.com/taylorrowser-home-automation/home-automation-starter/blob/main/docs/adoption.md)
  on `main` of `taylorrowser-home-automation/home-automation-starter` (private).
- Pending follow-up, not yet the reference: the starter's unmerged
  [PR #5](https://github.com/taylorrowser-home-automation/home-automation-starter/pull/5) updates its
  template docs and evidence.

The starter's workflows are rehearsals; apm adapts the policy to its own constraints and doesn't
copy them.

| Policy section | apm implementation | Where |
|---|---|---|
| One long-lived `main`; dev is an environment, not a branch | No dev branch. Dev follows successful `main` CI. | `deploy-dev.yml` |
| PR previews: opt-in label or maintainer dispatch, same-repo only | `preview` label, or dispatch `action=deploy` (which adds the label). Forks are never deployed. | `preview.yml`, `apm/preview.py` |
| Previews deploy the PR head sha after its checks succeed | Runs after CI succeeds for the head sha and deploys the `lambda-<sha>` artifact CI built. | `ci.yml` build job, `preview.yml` |
| Exact namespaces per environment | `policy.Names(stage)`: `apm` / `apm-dev` / `apm-pr-N` for every stack, table, function, log group, SSM path, role, boundary and bucket. | `apm/policy.py` |
| One upserted PR comment with URL and sha; serialize per preview | Comment marked `<!-- apm-preview -->`. Deploy and remove share concurrency group `preview-pr-N`, never cancelled. | `preview.yml` |
| Never `pull_request_target` with a PR checkout; privileged code from main, given validated references | `pull_request_target` only reads label and close events, with no PR checkout. Tooling is main's. Only a validated PR number, 40-hex sha and CI run id are passed on, never PR text. A test enforces that no workflow interpolates `${{ }}` into a shell script. | `preview.yml`, `tests/test_pipeline.py` |
| Remove on close and opt-out; TTL sweeper with expiry tags; retained data handled; allowlist rejects dev/prod | Close, unlabel or dispatch `remove` destroys the stage. A daily sweep uses the `apm:expires-at` tag. `destroy` explicitly deletes leftover tables and log groups. `policy.cleanup_stage` refuses anything but `pr-<digits>`. | `apm/deploy.py`, `apm/preview.py`, `apm/policy.py` |
| Build once; record the dev release (sha, digest, CI run, deploy run, health, timestamp) | `deploy-dev.yml` writes a write-once release record to S3 after the health check. | `apm/release.py` |
| Promotion: maintainer-triggered, main only, takes a dev release id, same artifact, no rebuild, stale candidates need explicit selection | `promote-prod.yml` → `prod-release.yml`. Input `release_id`. A superseded release needs `allow_superseded`. | `apm/release.py` |
| Serialize prod; health check after deploy; keep the previous known-good artifact | Concurrency group `deploy-production`, never cancelled. Smoke test after deploy. Prod records note `previous_release_id`. | `prod-release.yml` |
| Separate manual rollback to a previously successful prod release | `rollback-prod.yml` → the same reusable workflow, validations and concurrency group. | `rollback-prod.yml` |
| Artifact retention longer than the rollback window; durable content-addressed storage | Bundles at `lambda/<sha256[:16]>.zip` (full digest re-verified on every read), records in S3. No expiry; rollback window 90 days. | "Releases" below |
| OIDC, exact-trust roles per environment; previews can't touch dev/prod; dev can't touch prod; prod trust restricted to the promotion workflow identity | `infra/github-oidc-bootstrap.yaml` (not applied). Exact `sub` only. Explicit cross-stage `Deny` statements. Prod and the release-reader role trust only the `prod-release.yml` identity (`job_workflow_ref`). | "Credentials" below |
| PR checks need no AWS role | `ci.yml` has no `id-token` permission (enforced by test). | `ci.yml` |
| Plan limits: no claimed gate; no solo-owner deadlock | No approval gate is claimed. See "GitHub plan limits". | below |
| Staging identity provider for dev and previews; prod redirects exact; never copy prod secrets | WorkOS staging app. `check_workos_copy` refuses to copy into prod or from any prefix other than `/apm-nonprod`. Workflows refuse the prod client id for nonprod. | "WorkOS" below |
| Environment-owned push/VAPID/session secrets | Generated per stage under `/apm-<stage>`. Push subscriptions live in the stage's own table. | `apm/deploy.py` |
| Prefer a separate nonprod AWS account | Strongly recommended: previews run PR code and must live in an account with no write path to anything prod reads. A preview deploy refuses to run if the nonprod and prod account variables are equal. Dev only warns in that case. Promotion re-verifies every dev release against GitHub, so a forged nonprod record can't reach prod even if nonprod is compromised. | `preview.yml`, `deploy-dev.yml`, `apm/release.py` |

## Workflows

| Workflow | Trigger | Runs before bootstrap? | Cloud access |
|---|---|---|---|
| `ci.yml` | every PR, push to `main` | yes | none (no OIDC token) |
| `deploy-dev.yml` | CI succeeded on a `main` push | no: needs `APM_DEV_ENABLED=true` | nonprod, dev role |
| `preview.yml` | CI succeeded on a PR; `preview` label added or removed; PR closed; daily; manual | no: needs `APM_PREVIEW_ENABLED=true` | nonprod, preview role |
| `promote-prod.yml` | manual, on `main`, input a **dev release id** | no: needs `APM_PROD_DEPLOY_ENABLED=true` | via `prod-release.yml` |
| `rollback-prod.yml` | manual, on `main`, input a **prod release id** | no: needs `APM_PROD_DEPLOY_ENABLED=true` | via `prod-release.yml` |
| `prod-release.yml` | reusable only: the one workflow that assumes the prod role | (gated as above) | release-reader (nonprod, read-only) and prod role |
| `oidc-claims.yml` | manual bootstrap helper | yes (prints claims only) | none |

## Stages and names

A stage is `prod`, `dev` or `pr-<N>`. `apm.policy.Names(stage)` derives every AWS name from it. The
Lambda learns its stage from `APM_STAGE`; without it, it runs as `prod`.

| | prod (unchanged) | dev | pr-N (preview) |
|---|---|---|---|
| Domain | `apm.taylorrowser.com` | `dev.apm.taylorrowser.com` | `pr-N.preview.apm.taylorrowser.com` |
| Stack / table / function / HTTP API | `apm` | `apm-dev` | `apm-pr-N` |
| Log group | `/aws/lambda/apm` (90 days) | `/aws/lambda/apm-dev` (14 days) | `/aws/lambda/apm-pr-N` (14 days) |
| SSM prefix | `/apm` | `/apm-dev` | `/apm-pr-N` |
| Broker role | `/apm/apm-broker` | `/apm-dev/apm-dev__broker` | `/apm-pr-N/apm-pr-N__broker` |
| Boundary policy | `apm-agent-boundary` | `apm-dev_agent-boundary` | `apm-pr-N_agent-boundary` |
| Agent roles | `/agents/apm-<project>` | `/agents-dev/apm-dev_<project>` | `/agents-pr-N/apm-pr-N_<project>` |
| Table on stack delete | Retain | Retain | Delete (PITR off), plus explicit delete in `destroy` |
| Artifact bucket | `apm-artifacts-<account>-<region>` | `apm-dev-artifacts-<account>-<region>` | `apm-preview-artifacts-<account>-<region>` (shared, objects expire after 30 days) |
| WorkOS app | existing prod app | staging app | staging app |

Why the separators: project names match `^[a-z][a-z0-9-]{1,40}$`, so they never contain `_`. A
nonprod IAM name (`apm-dev_x`, `apm-pr-1__broker`) therefore can't equal a prod role `apm-<project>`,
and `role/apm-pr-1_*` can't match `pr-12`. Agent roles of each stage live under their own path.
`tests/test_deploy.py` checks this with tricky project names.

One pre-existing prod pattern still overlaps: prod's read-only `LookUpAgentRoles` allows
`iam:GetRole`/`GetRolePolicy`/`ListRolePolicies` on `role/apm-*`. In a shared account that also
matches nonprod names. That is prod *reading* nonprod, never nonprod touching prod, and it goes away
with a separate nonprod account.

Why dev and previews have their own buckets: a preview runs code from any same-repo branch. In a
shared bucket, its role could plant a bundle under a key dev later reuses, or forge a dev release
record. Separate buckets plus the role scoping below prevent that. `_upload_code` also re-hashes any
existing bundle before reusing its key.

**Agent roles can't reach any apm bucket.** Every stage's agent boundary (prod, dev and each
preview) carries the baseline `DenyApmInfrastructure` statement, which denies all actions on
`arn:aws:s3:::apm-*`, and so on every artifact bucket: `apm-artifacts-*` (prod),
`apm-dev-artifacts-*` and `apm-preview-artifacts-*`, including their bundles, manifests and
release records. This matters most for previews: the preview Lambda runs PR code, and its broker
can create and assume agent roles. It can create them only under `/agents-pr-N/` and only with the
`apm-pr-N_agent-boundary` policy from its own stack, and it has no action that edits a boundary,
attaches a managed policy or writes S3 itself. `tests/test_deploy.py`
(`PreviewCannotReachReleaseArtifacts`) checks that a preview agent role is denied every write and
read on the dev and prod buckets and objects, in any region or account.

**Prod compatibility.** `tests/fixtures/prod_template_before_stages.json` was rendered by the
single-stage `deploy.py`. The test asserts the prod template equals it plus exactly
`APM_STAGE=prod` and the four agent-boundary Deny statements from the baseline security fixes
(`DenyApmInfrastructure`, `DenyApmTaggedResources`, `DenyRecursiveReadOfRoot`, `DenyApmDnsRecords`).
Every stage's boundary carries the same four; the SSM root is shared by all stages in an account, so
`DenyRecursiveReadOfRoot` is identical everywhere. A second test checks that
every resource name is byte-identical. Prod names, bucket, tags and SSM paths are unchanged.

## Releases: build once, record, promote the same bytes

`apm-admin build --out DIR --git-sha SHA` writes `lambda.zip` and `manifest.json`:
- the zip is reproducible: hash-locked dependencies, fixed timestamps and modes, no host-specific
  files;
- the manifest holds the schema, git sha, sha256, size, `s3_key`, runtime and locked dependencies.

`apm-admin verify` checks a zip against its manifest. `deploy-artifact` always verifies first.

**1. CI** builds `lambda-<sha>`:
- on `main`, from `github.sha` (30 days);
- on a PR, from the PR head sha (7 days).

These are short-lived transport only.

**2. Deploy dev** (after CI on `main`):
1. Downloads that artifact and verifies it.
2. Skips commits older than what dev runs.
3. Deploys and smoke tests `/healthz` and `/manifest.webmanifest`.
4. Writes a **dev release record**, as shown below.

```
s3://apm-dev-artifacts-<acct>-<region>/releases/dev/<release_id>.json   (write-once)
s3://apm-dev-artifacts-<acct>-<region>/releases/dev/current.json        (newest dev deploy)
```

The release id is `dev-<UTC YYYYMMDDTHHMMSSZ>-<sha12>`. The record holds:
- `git_sha`;
- `artifact` (sha256, size, bucket, `s3_key`, manifest key);
- `ci_run` (id and URL);
- `deploy_run` (id and URL);
- `health` (passed or failed, URL, `checked_at`);
- `target`;
- `created_at`.

A failed health check is recorded too (and fails the job), so it can never be promoted. The record
is the release candidate. The run summary prints its id. The run also uploads the same record as
the artifact `dev-release-<release_id>` (90 days), which promotion uses as GitHub-side evidence.

**3. Promote to prod** (`promote-prod.yml`) takes inputs `release_id` (a dev release), an optional
`sha256` and `allow_superseded`. The reusable `prod-release.yml` then works in two jobs.

*resolve* job, using the nonprod **release-reader** role (read-only):
- loads the record;
- requires `health=passed`;
- requires that dev still runs this release (`current.json`). If dev has moved on, it rejects the
  candidate unless `allow_superseded` is set, which is the explicit selection of an older *recorded,
  tested* release. It never substitutes a different sha.
- downloads the bundle and manifest and checks the full sha256 against the record (and the input);
- **verifies provenance through the GitHub API** (`apm-admin release provenance`,
  `release.verify_provenance`), because an S3 record alone is not trusted:
  - the record's CI run is a completed, successful run of `.github/workflows/ci.yml`, triggered by
    `push` on `main`, in this repository, for exactly the record's `git_sha`;
  - that run's `lambda-<sha>` artifact, downloaded with `GITHUB_TOKEN`, contains a `lambda.zip`
    with the same sha256 as the S3 bundle (and a manifest naming the same sha and digest). If GitHub
    has expired the artifact (30 days on `main`), promotion **fails closed** and tells the operator
    to rebuild and redeploy dev and promote the fresh release;
  - the record's dev deploy run is a successful `deploy-dev.yml` run (`workflow_run`, `main`, this
    repository) whose `dev-release-<release_id>` artifact names the same release id, commit, digest
    and CI run;
  - any API error fails closed;
- checks the commit is an ancestor of `main`.

So bytes that didn't come out of CI on `main` can't be promoted, even if something in the nonprod
account wrote a well-formed record and bundle claiming a real `main` commit and its real CI run.

*deploy* job, using the prod role:
- re-verifies the digest;
- deploys the same bytes, with no rebuild;
- smoke tests;
- writes a **prod release record** (`releases/prod/...` in the prod bucket), with
  `kind=promotion`, `source_release_id`, `previous_release_id` and the health result.

**4. Rollback prod** (`rollback-prod.yml`) takes a **prod** release id whose prod health check passed:
- it resolves the record and bundle from the prod bucket and re-verifies the digest;
- it verifies through the GitHub API that the record's CI run is a successful `ci.yml` push run on
  `main` for that sha, and that its deploy run is a successful promote or rollback run. The CI build
  artifact has usually expired by then, so its digest isn't required: prod records are written only
  by the prod role into the prod account's own bucket;
- it deploys through the same reusable workflow and concurrency group;
- it records `kind=rollback`.

When there's no recorded release to roll back to (before the first CI promotion), the owner path
remains: check out the known-good commit and run `apm-admin deploy`.

**Serialization.** Dev uses group `deploy-dev`. Prod promote and rollback share `deploy-production`.
Each preview uses `preview-pr-N`. All of them run with `cancel-in-progress: false`, so a running
deploy is never cancelled. (GitHub keeps at most one *pending* run per group, so a newer queued run
replaces an older queued one. Re-run it if that happens.) PR checks in `ci.yml` do cancel superseded
runs.

**Tooling provenance.** Every privileged job runs deploy tooling and templates from the reviewed
`main` commit of the run, not from the release being deployed. Rollback therefore restores code, not
infrastructure. That is safe because the template is backward compatible: prod compatibility is
tested.

### Retention and rollback window

- **Rollback window: 90 days** (`release.ROLLBACK_WINDOW_DAYS`). Rolling back to an older release
  is allowed, with a warning to check data compatibility.
- **Retention is indefinite.** The dev and prod buckets have no lifecycle expiry, and release
  records are write-once (`If-None-Match: *`). Retention therefore always exceeds the window.
  Don't add a lifecycle rule shorter than 400 days to these buckets.
- Recommended at bootstrap: enable S3 versioning on the dev and prod artifact buckets. Overwrites
  are already refused, so versioning protects against deletes.
- Actions artifacts are transport only. Nothing depends on them after the deploy run.
- Preview bundles live in a separate bucket whose objects expire after 30 days.

### Schema compatibility

DynamoDB data is not rolled back. Any change to stored items must be readable by the previous
release for at least the rollback window: add fields, don't rename or repurpose them. Note
incompatible changes in the PR, together with the release id that becomes the oldest safe rollback
target.

## Preview lifecycle

- **Opt in:**
  - add the `preview` label to a PR whose branch is in this repo; or
  - as a maintainer, run **Preview** with `action=deploy, pr=N`, which adds the label.

  Forks are never deployed.
- **Deploy:**
  1. `preview plan` (main's code, no AWS) reads the event JSON and the live PR from the API. It
     requires a same-repo PR that is open and labeled, then finds the successful `ci.yml` run for
     the **head sha**.
  2. The deploy job downloads `lambda-<sha>` from that run and verifies that it was built from that
     sha.
  3. It re-checks that the sha is still the open, labeled head.
  4. It deploys `pr-N` with the preview role and the shared wildcard certificate.
  5. It smoke tests the stage and upserts one comment with the URL, sha and CI run.

  When the label is added before CI finishes, the run after CI completes deploys it.
- **Update:** every push whose CI passes, while the label is on. Each deploy refreshes the stack's
  `apm:expires-at` tag (now + `APM_PREVIEW_TTL_DAYS`, default 7).
- **Remove:** removing the label, closing a labeled PR, or `action=remove` runs
  `apm-admin destroy --stage pr-N`. It deletes:
  1. the stage's agent roles;
  2. the stack;
  3. explicitly, any leftover table `apm-pr-N` or log group (retained data);
  4. the SSM parameters under `/apm-pr-N`, including VAPID keys, the session secret and the copied
     WorkOS key;
  5. the `deployments/pr-N/` records.

  Push subscriptions lived in the deleted table. Bundles in the preview bucket expire by lifecycle.
- **Sweeper (daily, or dispatch `action=sweep`):** it considers only stacks whose name *and*
  `apm:stage` tag both name the same `pr-<digits>` stage, and skips stacks with an operation in
  progress. It deletes a preview only for a confirmed reason:
  - the expiry tag has passed (checked without GitHub, so this alone suffices);
  - GitHub confirmed the PR is closed;
  - GitHub confirmed the PR is open without the `preview` label; or
  - GitHub confirmed the PR is open and labeled, but the expiry tag is missing or malformed.

  If GitHub can't be read (rate limit, outage, auth error) or returns an unexpected answer, the PR
  state is *unknown*: an unexpired preview is kept, the error is logged, and the next sweep retries.

  For a PR that is still open and labeled, it first removes the label and comments.
- **Cleanup allowlist:** `policy.cleanup_stage` accepts only `^pr-[0-9]+$` (ASCII, full match, a
  valid stage). It rejects `dev`, `prod`, whitespace, newlines, path tricks, Unicode digits and
  non-strings. `destroy`, the planner and the sweeper all call it, before any AWS call.
  `tests/test_pipeline.py` covers malformed inputs and hostile tags.
- **Base branch:** label and close events are acted on only for PRs targeting `main`, where the
  workflow file is reviewed. PRs stacked on other branches still get previews from the post-CI
  trigger.
- **Trust model:** the preview *code* is the PR's own and runs as the preview Lambda in the nonprod
  account. The deploy tooling, template and IAM scoping come from `main`. Anyone who can push a
  branch here can get code into a preview, which is why previews live in nonprod with a role that
  is denied every dev and prod name, and why their agent roles' boundary denies every `apm-*`
  bucket.
- **Put previews in a separate nonprod account.** Code from any PR runs there with a broker that
  can mint roles. That account must have **no write path to anything prod reads**: no prod bucket
  policy, KMS key, role trust or other resource policy may grant the nonprod account (or any role
  in it) write access, and prod must never read configuration, artifacts or records from nonprod
  except through the promotion path, which re-verifies them against GitHub. Sharing the prod
  account (654654478411) leaves IAM scoping as the only barrier; it is not recommended.

## Credentials

- **PR checks:** no AWS role. `ci.yml` has no `id-token` permission.
- **Roles** (`infra/github-oidc-bootstrap.yaml`; **not applied**):
  - **`apm-github-preview`** (nonprod): scoped to `apm-pr-*` names and the preview bucket. It has
    explicit `Deny` on every dev and prod stack, role, boundary, function, table, SSM path, log
    group and bucket, and on the `/github/` deploy roles.
  - **`apm-github-dev`** (nonprod): scoped to `apm-dev` names and the dev bucket. It has explicit
    `Deny` on every prod name and on the prod and preview buckets.
  - **`apm-github-release-reader`** (nonprod): `s3:GetObject` only on the dev bucket's
    `releases/dev/*`, `lambda/*` and `manifests/*`. Promotion reads the dev release without the dev
    role ever writing to prod.
  - **`apm-github-prod`** (prod): update-only. No stack, table, role or log-group deletion, and SSM
    is read-only.
- **Trust:** each role trusts one exact `sub` (`StringEquals`, never wildcards) with
  `aud=sts.amazonaws.com`.
  - Dev and preview trust their environment's subject.
  - Prod and release-reader trust only the subject of `prod-release.yml` in environment
    `production`.
  - Optionally, prod and release-reader also require
    `job_workflow_ref = <owner>/<repo>/.github/workflows/prod-release.yml@refs/heads/main`.
- **Pinning the prod identity:** the default `sub` (`...:environment:production`) doesn't name the
  workflow or branch. To pin both, the recommended bootstrap step is a repo OIDC subject template
  that includes `job_workflow_ref`. Then the exact `sub` names the org and repo, the environment,
  `prod-release.yml` and `refs/heads/main`.
  - Without the template, the prod gate relies on the environment branch policy (Pro or Team only),
    plus main-only dispatch.
  - The `ProdJobWorkflowRef` parameter adds a direct claim condition. AWS support for that claim
    key is **unverified** here. The condition fails closed, so test it with a first run.
- **Tests:** `tests/test_pipeline.py` evaluates the template's patterns. It checks that preview
  can't match dev or prod ARNs, that dev can't match prod ARNs, that the explicit denies cover them,
  and that trust is exact.

**Caveat:** any role that can write the broker role's inline policy through CloudFormation can
effectively grant itself anything in *its* account. The real isolation is the separate nonprod
account and the exact OIDC subject. IAM scoping and denies limit mistakes. The policies were linted,
not exercised against AWS. Expect the first real deploy to surface a missing action (for example
`logs:Describe*` or API Gateway tagging). Add each one specifically rather than widening to `*`.

## WorkOS, push and per-environment secrets

- **Prod:** the existing WorkOS app, with redirects kept exact (`https://apm.taylorrowser.com/auth/callback`).
  Don't change it.
- **Staging app** (one, for dev and previews):
  - exact `https://dev.apm.taylorrowser.com/auth/callback`;
  - narrow wildcard `https://*.preview.apm.taylorrowser.com/auth/callback`, only if WorkOS supports
    wildcards for that environment type and domain (unverified). Otherwise register each preview's
    URI by hand;
  - configure the sign-in endpoint per the WorkOS docs.
- **WorkOS secrets:**
  - Prefer PKCE without a client secret.
  - If the staging app needs a secret, store it once as `/apm-nonprod/workos-api-key` in the nonprod
    account. Preview deploys copy it inside AWS to `/apm-pr-N/` without printing it.
  - Dev reads `/apm-dev/workos-api-key`; set that once yourself.
  - `check_workos_copy` refuses any other source and any copy into prod. **Never copy the prod
    secret.**
- **Session secret, VAPID keys and push subscriptions** are per environment:
  - the session secret and VAPID keys are generated under `/apm-<stage>`;
  - subscriptions live in the stage's table.

  Use test devices for dev and previews. Workflows refuse to run dev or previews with the prod
  WorkOS client id.

## GitHub plan limits

This repo is **private and personal** (`taylorrowser/aws-permissions-manager`), and its plan wasn't
verified from here. Per [GitHub's docs](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments):
- **GitHub Free, private repos:**
  - no environment secrets;
  - no deployment branch policies;
  - no branch protection or rulesets.
- **GitHub Pro (personal) or Team (org):** deployment branches and tags, plus environment secrets
  and variables, for private repos.
- **Required reviewers and wait timers on private repos:** not available on Free, Pro or Team. Per
  the policy, that may need Enterprise.

So this pipeline claims **no approval gate**. The prod controls are:
- `workflow_dispatch` from `main` only, re-checked inside the reusable workflow;
- the release record checks (health, currency, digest, GitHub provenance, ancestry);
- the exact OIDC trust.

On Pro or Team, add a `production` deployment branch policy limited to `main`. Anyone who can push
to `main` can promote, which suits a solo owner. Don't enable "prevent self-review" or required
reviewers that only you could satisfy.

## Runners

- Every job uses `runs-on: ${{ vars.APM_RUNNER || 'ubuntu-24.04' }}`. With the variable unset,
  which is today's state, everything runs on GitHub-hosted runners. A test enforces the form.
- **Leave `APM_RUNNER` unset** while apm is in Taylor's personal account. Blacksmith and Depot
  runners require org ownership, so a vendor label here would leave jobs queued forever.
- Using a vendor runner needs an explicitly authorized transfer (or org repo change) first:
  - The org `taylorrowser-home-automation` exists, and its starter repo has Blacksmith staged.
  - Status as of 2026-10-11: the Blacksmith GitHub App is installed only for
    `home-automation-starter`. Its jobs stayed queued: Blacksmith reports the account needs
    additional verification, and a support request awaits Taylor. That starter's runner was reset
    to `ubuntu-24.04`. No paid plan exists.
  - **Blacksmith execution is not verified anywhere, and nothing in apm uses it.**
- A transfer would also change:
  - the OIDC `sub` (owner name and ID), so re-run **OIDC claims** and update every trust;
  - the plugin marketplace path and README install commands;
  - quotas and plan features.
- Measured timings:
  - **Locally:** the full test suite takes a few seconds, and so does an artifact build.
  - **On GitHub-hosted `ubuntu-24.04`**, the first run: `test` 29 s and `build` 18 s. Minutes
    aren't a bottleneck.

## One-time bootstrap (Taylor or the coordinator; separately authorized; not automated)

Nothing below is done by this PR, and each step needs its own authorization. In order:

1. **Confirm the GitHub plan** (see "GitHub plan limits"). Decide what gate you rely on.
2. **Choose the nonprod AWS account.** Use a separate account, not 654654478411: previews run PR
   code there. Give the nonprod account no write access to any prod resource (bucket policies, KMS
   key policies, role trusts), so nothing prod reads can be written from it.
3. **(Recommended) Set an OIDC subject template that includes `job_workflow_ref`**, for example
   claim keys `repo`, `context` and `job_workflow_ref`, via the repo's OIDC customization API. Do
   this before step 4, because it changes every subject.
4. **Read the real subjects.** On `main`, run **OIDC claims** for `dev`, `preview` and
   `production`. The `production` run goes through `prod-release.yml`, so it prints the exact prod
   identity. Copy each `sub` verbatim. Immutable-ID subjects (`repo:OWNER@ID/REPO@ID:...`) are
   expected for this repo, but only the printed value counts.
5. **Deploy `infra/github-oidc-bootstrap.yaml` by hand** with an admin login:
   - nonprod account: `AccountKind=nonprod DevSubject=… PreviewSubject=… ProdSubject=…`;
   - prod account: `AccountKind=prod ProdSubject=…`;
   - optionally, in both, `ProdJobWorkflowRef=<owner>/<repo>/.github/workflows/prod-release.yml@refs/heads/main`;
   - if the account already has the GitHub provider: `CreateOidcProvider=false` with
     `ExistingOidcProviderArn`.
6. **DNS:**
   - in the nonprod account, create zones `preview.apm.taylorrowser.com` and
     `dev.apm.taylorrowser.com`;
   - delegate both with NS records from the zone that serves `apm.taylorrowser.com`.
7. **Certificates:**
   - in the nonprod account, us-east-1, request a wildcard ACM certificate for
     `*.preview.apm.taylorrowser.com`;
   - dev can let its stack create its own certificate.
8. **WorkOS staging app** as above. Optionally store `/apm-nonprod/workos-api-key` and
   `/apm-dev/workos-api-key` (nonprod account only).
9. **Buckets:** after the first dev deploy and the first prod promotion create or reuse them, enable
   versioning on `apm-dev-artifacts-…` and `apm-artifacts-…`. Don't add expiry rules.
10. **Environments** `dev`, `preview` and `production`. On Pro or Team, restrict `production` (and
    `dev`) to `main`. Don't add reviewers you can't satisfy alone.
11. **Repository variables.** Use repo-level variables, because `if:` gates run before any
    environment applies.

| Variable | Value |
|---|---|
| `APM_NONPROD_ACCOUNT_ID`, `APM_NONPROD_REGION` | nonprod account id, `us-east-1` |
| `APM_DEV_ROLE_ARN`, `APM_PREVIEW_ROLE_ARN`, `APM_RELEASE_READER_ROLE_ARN` | outputs of the nonprod stack |
| `APM_PROD_ACCOUNT_ID`, `APM_PROD_REGION` | `654654478411`, `us-east-1` |
| `APM_PROD_ROLE_ARN` | output of the prod stack |
| `APM_OWNER_EMAILS` | approver email(s) |
| `APM_PROD_WORKOS_CLIENT_ID`, `APM_STAGING_WORKOS_CLIENT_ID` | the two WorkOS client ids (must differ) |
| `APM_PREVIEW_CERT_ARN` | wildcard certificate ARN |
| `APM_PREVIEW_ZONE_ID`, `APM_DEV_ZONE_ID`, `APM_PROD_ZONE_ID`, `APM_DEV_CERT_ARN` | optional |
| `APM_BASE_DOMAIN` | optional, default `apm.taylorrowser.com` |
| `APM_PREVIEW_TTL_DAYS` | optional, default `7` (1–99) |
| `APM_RUNNER` | **leave unset** (see "Runners") |
| `APM_DEV_ENABLED`, `APM_PREVIEW_ENABLED`, `APM_PROD_DEPLOY_ENABLED` | `true` to switch each on, last |

12. **Enable in order:**
    1. `APM_DEV_ENABLED`. Merge to `main` and check that a dev release record appears.
    2. `APM_PREVIEW_ENABLED`. Run the policy's first-preview test end to end: sign in, read and
       write its isolated state, push to a test device, and confirm prod is unreachable. Then close
       the PR and check that everything was removed.
    3. `APM_PROD_DEPLOY_ENABLED`. Promote the dev release id. The first promotion updates the
       existing `apm` stack in place; the only template changes are `APM_STAGE=prod` and the
       agent-boundary Deny statements from the baseline security fix. Then rehearse a
       rollback to that same release.

## Still unverified

- No cloud workflow has run, no AWS call was made and nothing was deployed. The deploy, destroy,
  sweep, release-record and rollback paths are tested only against fakes.
- The bootstrap IAM policies are only linted and pattern-tested. Expect a missing action or two.
- Whether AWS evaluates the `job_workflow_ref` condition key (`ProdJobWorkflowRef`) is unverified;
  it fails closed. The custom-subject route is the documented GitHub mechanism.
- The real OIDC `sub` formats, including immutable IDs and the custom template, are unverified.
  Read them with **OIDC claims**.
- WorkOS wildcard redirects for the staging app's preview domain are unverified.
- The GitHub plan and which environment features apply to this repo are unverified.
- S3 conditional writes (`If-None-Match`) are assumed available in the chosen region.
- The provenance check is tested against fake GitHub API responses only. That the runs API reports
  `path`, `event`, `head_branch` and `head_repository` as assumed, and that artifact downloads
  (a redirect to blob storage) work with `GITHUB_TOKEN` and `actions: read`, is unverified until
  the first real promotion.
- The zip is reproducible on the same host. Cross-host byte identity isn't guaranteed and isn't
  needed, because promotion reuses the recorded bytes.
- Blacksmith and Depot are not connected for apm. Blacksmith execution is not verified anywhere.

## References

- Governing: the org deployment policy above.
- Shape references, adapted rather than copied:
  - [pingdotgg/t3code](https://github.com/pingdotgg/t3code) workflows: checks, opt-in previews and
    release channels;
  - SST's per-PR stage lifecycle (not adopted as a framework);
  - [GitHub OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws).
