# AWS integration review packet

**Review-only local scaffold. No AWS calls, credentials, deployment, production authentication or effective revocation have been verified.** The CloudFormation JSON is deliberately undeployable: its Rules assertion is impossible to satisfy. The four runtime IAM definitions illustrate privilege separation, not deployable least-privilege policies. Placeholder account, region, role and table values are conspicuously invalid or synthetic. There are no SAM handlers, live configuration, workload credentials or deployment commands.

## Runtime boundaries

1. **Request runtime** submits bounded requests and reads public status. It cannot create approval decisions, alter administrator capabilities/ceilings, execute IAM or assume grant roles.
2. **Owner-decision runtime** records a verified human-browser decision against an exact manifest digest. It has no IAM or STS authority. Token provenance and session/CSRF protections still require a separately authenticated browser deployment; possession of an ordinary owner token alone is insufficient.
3. **Permission executor** reads frozen decisions, obtains a durable distributed fence and journals provider attempts. Its IAM write scope is one administrator-pinned empty revision role. It cannot alter the trust, boundary, ceiling policy, capabilities or its own authority. There is no public HTTP executor route. A real crash-safe/fenced worker remains a deployment prerequisite.
4. **Assume-only vendor** exchanges approved, one-use leases for bounded STS credentials. It has no IAM or EC2 permissions and cannot approve, change ceilings or edit role policies. Its injected IAM observer requires a separately authenticated read-only observation service/identity; the template intentionally does not pretend that vendor credentials can execute IAM read calls. No production transport for this observer is supplied.

The executor's PutRolePolicy permission is powerful within its ceiling. IAM does not enforce the app's approval digest, immutable revisions or distributed fencing; runtime isolation, administrator-owned boundaries and exclusive writer controls are required. The template does not deploy any resources or claim to close these gaps.

## Compiler contract and visibility

`compile_ec2(scope, account_id, region, *, not_after=None, admin_tags=None)` accepts exactly `actions` and `instance_arns`. It supports five exact actions: DescribeInstances, DescribeInstanceStatus, StartInstances, StopInstances and RebootInstances. Up to 20 exact existing-instance ARNs can be proposed. Scope cannot contain IAM policy JSON, arbitrary actions, wildcards, role IDs, tags, boundaries or trust.

Mutation statements contain exact commercial AWS partition instance ARNs and the selected region. Optional administrator-owned EC2 resource tags add conjunctive constraints. Before approval, the service must check those ARNs against its verified existing-instance inventory. Compilation does not prove that an instance exists. It never grants create, terminate, SSM, networking, PassRole or tag mutation.

Both Describe actions use Resource `*` and a regional condition because these APIs do not support instance-level authorization. Describe approval exposes that account's inventory in the approved region; listed instance ARNs and resource tags cannot narrow it. A view limited to a subset would require a trusted filtering proxy instead of direct EC2 credentials. Some EC2 start configurations can need additional resource permissions or service constraints; this compiler fails closed rather than adding broader ancillary permissions.

## Policy and session correctness

AWS merges identity policies into an effective union. Exact readback therefore includes RoleId, ARN, trust, maximum duration, all inline policies, all attached managed policy documents/default versions and the boundary document/default version. New/unrecognized identity, missing boundary, extra policy, extra attachment, changed version, missing page or altered trust fails closed. Readback is not a concurrency lock or proof that every AWS region has observed a change.

Every logical scope replacement uses a fresh physical revision role. No revision role is reused or expanded. The adapter can initialize only a known empty role; provisioning, retirement and durable fencing remain separate reviewed steps. After uncertain writes, reconcile against the recorded role identity and exact policy; never discover-and-adopt an unknown existing role or blindly replay a write.

STS requires at least 900 seconds; this implementation refuses issuance with less than 900 seconds of approved validity remaining and caps individual sessions at 3600 seconds for role-chaining compatibility. It rejects oversized inline session policy JSON above 2048 characters. It sends no managed session policy references or caller session tags. Provider packed-size errors remain possible below the plaintext limit and are sanitized/fail-closed.

Each session receives a full, immutable snapshot with an explicit Deny of every action at `aws:CurrentTime >= NotAfter`. Temporary roles also contain their grant deadline; ongoing revision roles have no grant cutoff. Each lease still gets its own immutable absolute session cutoff, bounded by the grant cutoff when present. An old session cannot gain later role scope through its snapshot and cannot regain access after its own absolute cutoff if a role policy is accidentally extended. The dedicated credential-process output reports actual AWS credential expiration; application authorization has its own earlier or equal cutoff. Do not truncate the reported token expiration and then treat that as proof the credential expired.

Stopping issuance is immediate application intent. Scope changes/revocation are not instant provider revocation. Activation must wait for all relevant old credential-validity horizons to drain, or for independently verified effective provider revocation. Attaching/reading an AWSRevokeOlderSessions deny is insufficient propagation proof. Keep the old physical role denied/retired and never restore or reuse it; restoring access creates another revision.

## Credential boundary and tests

`IAMAdapter(client)` and `STSAdapter(client, *, iam_adapter)` only accept injected clients. The module never constructs boto3 sessions or performs implicit environment/shared-file/metadata credential lookup. Test clients use explicit synthetic access keys, synthetic secret keys and an invalid endpoint. Mutating IAM and STS SDK calls require an explicitly single-attempt retry configuration (botocore Config(retries={"total_max_attempts": 1})); otherwise the adapter refuses to call. Non-SDK transports must uphold the same contract. SDK Stubber handles every queued call, and unmatched calls fail locally. No live provider calls are authorized in this artifact.

`CredentialEnvelope` redacts repr/str and exposes only non-secret metadata by default. Secret serialization is intentionally restricted to `write_credential_process(stream)` in a dedicated private AWS CLI credential_process path. Do not log that stream, return it from status/MCP/dashboard routes, or persist it as evidence. Python object privacy is not an OS isolation boundary.

Optional SDK verification (already run in the build sandbox) uses boto3/botocore 1.43.108 installed into a temporary test dependency directory. The module itself uses only the standard library. Without boto3, SDK Stubber tests explicitly skip; ordinary compiler/fake-client tests still run. Require zero skips in an SDK verification environment before accepting adapter coverage.

## Official AWS references checked 7 October 2026

- [EC2 actions, resource types and conditions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_ec2.html): the supported actions' authorization resources and region/tag constraints
- [STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html): duration, role chaining, policy intersection, session policy size and credential output
- [Policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html): identity policy union, boundary intersection and explicit deny
- [Boundary behavior](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html): ceiling limitations and resource-policy caveats
- [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html): absolute date comparison
- [GetRole](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html) and [ListRolePolicies](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListRolePolicies.html): identity/trust and complete inline-policy inventory
- [Role session revocation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html): deny-policy mechanism; do not infer globally effective revocation from write acknowledgement
- [IAM eventual consistency](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot.html#troubleshoot_general_eventual-consistency): changes require propagation and verification
- [External credential process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html): dedicated version-1 JSON output and secret-handling warning
- [CloudFormation rules](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/rules-section-structure.html): intentionally impossible assertion preventing deployment of this scaffold
