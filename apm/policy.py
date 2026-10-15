"""IAM policy documents and request validation. Pure functions, no AWS calls."""
import fnmatch
import json
import os
import re
import time
from dataclasses import dataclass

GRANTS_POLICY = "apm-grants"
MAX_INLINE_POLICY_CHARS = 10240

PROD = "prod"
# prod, dev, or pr-<number>. Short enough that every derived IAM name stays under 64 chars.
STAGE_RE = re.compile(r"^(prod|dev|pr-[1-9][0-9]{0,6})$")


@dataclass(frozen=True)
class Names:
    """Every AWS name for one deployment stage. "prod" is byte-identical to the original single-stage
    names. Other stages get isolated names that prod's IAM patterns can't match, and vice versa:

    - agent roles live under /agents-<stage>/ (prod's broker only touches role/agents/*);
    - nonprod IAM names use "_" after the stage, which a project name (and so a prod role
      "apm-<project>") can never contain, so role/apm-<stage>_* never matches a prod role and
      role/apm-pr-1_* never matches stage pr-12;
    - SSM lives under /apm-<stage>/ (prod reads parameter/apm/*).
    """
    stage: str = PROD

    def __post_init__(self):
        if not STAGE_RE.match(self.stage or ""):
            raise ValueError(f"invalid stage {self.stage!r}; use prod, dev or pr-<number>")

    @property
    def is_prod(self):
        return self.stage == PROD

    @property
    def is_preview(self):
        return self.stage.startswith("pr-")

    @property
    def base(self):  # stack, table, function, API, SSM prefix, log group
        return "apm" if self.is_prod else f"apm-{self.stage}"

    @property
    def stack(self):
        return self.base

    @property
    def table(self):
        return self.base

    @property
    def function(self):
        return self.base

    @property
    def param_prefix(self):
        return "/" + self.base

    @property
    def role_path(self):
        return "/agents/" if self.is_prod else f"/agents-{self.stage}/"

    @property
    def role_prefix(self):
        return "apm-" if self.is_prod else f"apm-{self.stage}_"

    @property
    def boundary_name(self):
        return "apm-agent-boundary" if self.is_prod else f"apm-{self.stage}_agent-boundary"

    @property
    def broker_role(self):
        # "__" can't collide with an agent role apm-<stage>_<project>: projects start with a letter.
        return "apm-broker" if self.is_prod else f"apm-{self.stage}__broker"

    @property
    def broker_role_path(self):
        return "/apm/" if self.is_prod else f"/apm-{self.stage}/"

    def artifact_bucket(self, account, region):
        """Content-addressed bundles, manifests and release records. prod's name is unchanged. dev and
        previews get their own buckets, so a preview role (which runs any same-repo branch) can never
        write a bundle or release record that dev or prod would later deploy."""
        if self.is_prod:
            return f"apm-artifacts-{account}-{region}"
        return f"apm-{'preview' if self.is_preview else 'dev'}-artifacts-{account}-{region}"


# Only previews may ever be deleted. Deliberately stricter than STAGE_RE and independent of it.
CLEANUP_RE = re.compile(r"pr-[0-9]+", re.ASCII)


def cleanup_stage(value):
    """Return value if it names a preview stage that automation may delete, else raise ValueError.
    Used by every delete path (destroy, the preview workflow, the sweeper) on any input, including
    workflow inputs and AWS tags: dev, prod and anything that isn't exactly pr-<digits> are refused."""
    if not isinstance(value, str) or not CLEANUP_RE.fullmatch(value) or value in (PROD, "dev"):
        raise ValueError(f"refusing to clean up {value!r}: only preview stages pr-<number> can be deleted")
    n = Names(value)  # also enforces the stage format (no leading zeros, length)
    if not n.is_preview or n.is_prod:
        raise ValueError(f"refusing to clean up {value!r}")
    return n.stage


def stage_from_stack(stack_name):
    """apm-pr-<N> -> pr-<N> for a preview stack name; ValueError for anything else (apm, apm-dev, ...)."""
    if not isinstance(stack_name, str) or not stack_name.startswith("apm-"):
        raise ValueError(f"{stack_name!r} is not an apm preview stack")
    stage = cleanup_stage(stack_name[len("apm-"):])
    if Names(stage).stack != stack_name:
        raise ValueError(f"{stack_name!r} is not an apm preview stack")
    return stage


def current_stage():
    """The stage this process runs as. The Lambda gets APM_STAGE from the template; unset means prod,
    which is what Lambdas deployed before stages existed run as."""
    return os.environ.get("APM_STAGE") or PROD


NAMES = Names(current_stage())
ROLE_PATH = NAMES.role_path
ROLE_PREFIX = NAMES.role_prefix
BOUNDARY_NAME = NAMES.boundary_name
BROKER_ROLE = NAMES.broker_role
BROKER_ROLE_PATH = NAMES.broker_role_path

PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*?]+$")

# Agent roles can never get these, whatever is approved. Keep in sync with boundary().
BLOCKED_ACTIONS = [
    "iam:*", "organizations:*", "account:*", "sso:*", "sso-directory:*", "identitystore:*",
    "aws-portal:*", "billing:*", "payments:*", "tax:*", "cur:*",
    # Domain registration: transferring a domain or changing its name servers would hand over
    # apm's domain (and its sign-in callback), and registering domains costs money.
    "route53domains:*",
    "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
]
# Audit-trail tampering, denied by the boundary even when e.g. cloudtrail:* is approved, so an agent
# can't hide what it did. Reading trails and events stays possible.
AUDIT_TAMPERING = [
    "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors",
    "cloudtrail:PutInsightSelectors", "cloudtrail:DeleteEventDataStore", "cloudtrail:UpdateEventDataStore",
    "cloudtrail:StopEventDataStoreIngestion",
]
# Actions that set a resource's own policy: whoever holds one can grant anyone anything on that
# resource. The dashboard labels them.
RESOURCE_POLICY_ACTIONS = [
    "s3:PutBucketPolicy", "sqs:SetQueueAttributes", "sns:SetTopicAttributes", "kms:PutKeyPolicy", "kms:CreateGrant",
    "lambda:AddPermission", "secretsmanager:PutResourcePolicy", "ecr:SetRepositoryPolicy", "logs:PutResourcePolicy",
]
# Exceptions the boundary allows back in.
IAM_ALLOWED = ["iam:Get*", "iam:List*", "iam:PassRole"]
# Actions that make some other role run code or commands: on every resource, they would let an
# agent act as any function's, service's, project's or instance's role. Refused on "*".
RUN_AS_ACTIONS = [
    "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "ecs:UpdateService", "ecs:RunTask",
    "codebuild:StartBuild", "states:UpdateStateMachine", "ssm:SendCommand", "ec2-instance-connect:SendSSHPublicKey",
]
# CloudFormation actions that change a stack, including stack refactors. They run as the stack's
# stored RoleARN (often an admin CDK execution role) without needing iam:PassRole, so they're
# refused on every stack, on a wildcard region and on any existing stack with a stored role.
STACK_WRITE_ACTIONS = [
    "cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DeleteStack",
    "cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet", "cloudformation:ContinueUpdateRollback",
    "cloudformation:RollbackStack", "cloudformation:CancelUpdateStack", "cloudformation:CreateStackRefactor",
    "cloudformation:ExecuteStackRefactor",
]
REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-[0-9]$")


def role_name(project, names=None):
    return (names or NAMES).role_prefix + project


def role_arn(account, project, names=None):
    return f"arn:aws:iam::{account}:role{(names or NAMES).role_path}{role_name(project, names)}"


def agent_roles_arn(account, names=None):
    return f"arn:aws:iam::{account}:role{(names or NAMES).role_path}*"


def boundary_arn(account, names=None):
    return f"arn:aws:iam::{account}:policy/{(names or NAMES).boundary_name}"


def broker_role_arn(account, names=None):
    n = names or NAMES
    return f"arn:aws:iam::{account}:role{n.broker_role_path}{n.broker_role}"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def apm_resources(account):
    """ARN patterns for apm's own infrastructure (every stage): its secrets, Lambda, table, stack,
    buckets and logs. An agent that could read the session secret or change the Lambda could
    forge the owner's sign-in or replace the approval logic, so the boundary denies them all."""
    return [
        f"arn:aws:ssm:*:{account}:parameter/apm*",
        f"arn:aws:lambda:*:{account}:function:apm*",
        f"arn:aws:dynamodb:*:{account}:table/apm*",
        f"arn:aws:cloudformation:*:{account}:stack/apm*",
        f"arn:aws:logs:*:{account}:log-group:/aws/lambda/apm*",
        "arn:aws:s3:::apm-*",
        "arn:aws:apigateway:*::/domainnames/*apm*",
    ]


def boundary(account, names=None):
    """Permissions boundary on every agent role: the most an agent role can ever do."""
    return doc(
        {"Sid": "AllowNonAdminServices", "Effect": "Allow", "NotAction": BLOCKED_ACTIONS, "Resource": "*"},
        {"Sid": "AllowIamRead", "Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": "*"},
        {"Sid": "AllowPassAgentRoles", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": agent_roles_arn(account, names)},
        # Whatever is approved, agents can't touch apm itself.
        {"Sid": "DenyApmInfrastructure", "Effect": "Deny", "Action": "*", "Resource": apm_resources(account)},
        # The CloudFormation stack tags everything it creates (certificate, API, ...) managed-by=apm.
        # IAM is excluded so agents can still read and pass agent roles, which carry the same tag.
        {"Sid": "DenyApmTaggedResources", "Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
         "Condition": {"StringEquals": {"aws:ResourceTag/managed-by": "apm"}}},
        # GetParametersByPath is authorized against the requested path, so reading "/" recursively
        # would return /apm/* despite the deny above. Only the root (and an empty path) can
        # contain /apm; paths like /myapp stay usable.
        {"Sid": "DenyRecursiveReadOfRoot", "Effect": "Deny", "Action": "ssm:GetParametersByPath",
         "Resource": [f"arn:aws:ssm:*:{account}:parameter/", f"arn:aws:ssm:*:{account}:parameter"]},
        {"Sid": "DenyApmDnsRecords", "Effect": "Deny", "Action": "route53:ChangeResourceRecordSets", "Resource": "*",
         "Condition": {"ForAnyValue:StringLike": {
             "route53:ChangeResourceRecordSetsNormalizedRecordNames": ["apm.*", "*.apm.*"]}}},
        {"Sid": "DenyAuditTampering", "Effect": "Deny", "Action": AUDIT_TAMPERING, "Resource": "*"},
    )


def api_deny(api_ref="Api"):
    """Boundary statement for the stack's own HTTP API (routes, integrations, stages, authorizers).
    Its id is only known inside the template, so this is CloudFormation: deploy.template() appends it.
    Without it, an approved apigateway:* could re-point apm's API at another Lambda and capture the
    owner's sign-in and approvals; the managed-by tag deny covers it too, but only as far as each
    API Gateway action supports aws:ResourceTag."""
    return {"Sid": "DenyApmApi", "Effect": "Deny", "Action": "apigateway:*", "Resource": [
        {"Fn::Sub": f"arn:aws:apigateway:*::/apis/${{{api_ref}}}"},
        {"Fn::Sub": f"arn:aws:apigateway:*::/apis/${{{api_ref}}}/*"}]}


def broker_policy(account, names=None):
    """The broker (the Lambda's role) can only create and edit agent roles, only with the
    boundary attached, and assume them to hand agents short-lived credentials."""
    n = names or NAMES
    roles = agent_roles_arn(account, n)
    return doc(
        {"Sid": "CreateAgentRolesWithBoundary", "Effect": "Allow", "Action": "iam:CreateRole",
         "Resource": roles, "Condition": {"StringEquals": {"iam:PermissionsBoundary": boundary_arn(account, n)}}},
        {"Sid": "EditAgentRoles", "Effect": "Allow", "Resource": roles, "Action": [
            "iam:GetRole", "iam:TagRole", "iam:DeleteRole", "iam:ListRolePolicies", "iam:GetRolePolicy",
            "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:ListAttachedRolePolicies"]},
        {"Sid": "VendAgentCredentials", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": roles},
        # Lookups of a role that doesn't exist yet are authorized against an ARN without the path.
        {"Sid": "LookUpAgentRoles", "Effect": "Allow",
         "Resource": f"arn:aws:iam::{account}:role/{n.role_prefix}*",
         "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies"]},
        # Read-only: a stack write is refused if the stack it names has a stored role (refusals()).
        # DescribeStacks without a stack name also needs ListStacks.
        {"Sid": "CheckStackRoles", "Effect": "Allow", "Resource": "*",
         "Action": ["cloudformation:DescribeStacks", "cloudformation:ListStacks"]},
        {"Sid": "NeverRemoveBoundary", "Effect": "Deny", "Resource": "*",
         "Action": ["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"]},
    )


def agent_role_trust(account, names=None):
    """Only the broker can assume agent roles; agents get the resulting session credentials."""
    return doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"AWS": broker_role_arn(account, names)}})


def _covers(actions, targets):
    """The target actions that these actions, wildcards included, cover."""
    return [t for t in targets if any(fnmatch.fnmatchcase(t.lower(), a.lower()) for a in actions)]


def resource_policy_actions(actions):
    """The resource-policy actions that these actions, wildcards included, cover."""
    return _covers(actions, RESOURCE_POLICY_ACTIONS)


def _arn(resource):
    """(service, region, account, resource part) of an ARN pattern, or None if it isn't a complete ARN."""
    parts = resource.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn" or not all(parts[1:3]) or not parts[5]:
        return None
    return tuple(parts[2:])


def _every(resource, service):
    """Whether a resource covers every resource of a service: "*", or its ARN with a wildcard before
    any name ("function:*", "function*", "f*"). A name prefix ("function:api-*") scopes it."""
    if resource == "*":
        return True
    arn = _arn(resource)
    if not arn or not fnmatch.fnmatchcase(service, arn[0]):
        return False
    literal = re.split(r"[*?]", arn[3], maxsplit=1)
    return len(literal) > 1 and re.fullmatch(r"[A-Za-z-]*[:/]?", literal[0]) is not None


def _stacks(resource):
    """(region, account, resource part) patterns of a resource that can match a stack, or None.
    Any wildcard resource part may match one ("*/web/*" does), so it's checked against the listing."""
    if resource == "*":
        return "*", "*", "*"
    arn = _arn(resource)
    if not arn or not fnmatch.fnmatchcase("cloudformation", arn[0]):
        return None
    region, account, rest = arn[1:]
    if not rest.startswith("stack/") and "*" not in rest and "?" not in rest:
        return None
    return region, account, rest


def refusals(actions, resources, account, list_stacks):
    """Why IAM must not hold a grant, as a list of reasons (empty if none). Checked when it's
    requested, again at approval and before every credential hand-out:

    - run-as actions on every resource (they run as some other role);
    - CloudFormation stack writes on every stack, in a wildcard region, or on any existing stack
      with a stored RoleARN (the write runs as that role). list_stacks(region) returns
      [(stack name, role ARN or "", stack id ARN)] for the account, read fresh; if it fails, the
      grant is refused;
    - policy variables and incomplete ARNs, which IAM expands, so they can't be checked as written.
    """
    out = []
    for r in resources:
        if "${" in r:
            out.append(f"{r} uses a policy variable, which can't be checked as written; name the resource")
        elif r != "*" and _arn(r) is None:
            out.append(f"{r} isn't a complete ARN (arn:partition:service:region:account:resource)")
    run_as = [a for a in _covers(actions, RUN_AS_ACTIONS) if any(_every(r, a.split(":")[0]) for r in resources)]
    if run_as:
        out.append(f"{', '.join(run_as)} on every resource would run as other roles; name the resources")
    writes = _covers(actions, STACK_WRITE_ACTIONS)
    if not writes:
        return out
    what = "CloudFormation stack writes" if len(writes) > 1 else writes[0]
    listed = {}
    for r in resources:
        target = _stacks(r)
        if not target:
            continue
        region, account_pattern, pattern = target
        if r == "*":
            out.append(f"{what} on every resource would run as any stack's stored role; name the stacks")
        elif not REGION_RE.match(region):
            out.append(f"{r} has a wildcard or unknown region; {what} must name one region")
        elif fnmatch.fnmatchcase(account, account_pattern):
            if region not in listed:
                try:
                    listed[region] = list_stacks(region)
                except Exception as e:
                    out.append(f"couldn't list CloudFormation stacks in {region} to check {r} for a stored role "
                               f"({type(e).__name__}); try again")
                    listed[region] = None
                    continue
            if listed[region] is None:
                continue
            # Matched like IAM would: the pattern against the stack's own resource part, stack/<name>/<id>.
            held = sorted(s for s, role, stack_id in listed[region]
                          if role and fnmatch.fnmatchcase(stack_id.split(":", 5)[-1], pattern))
            if held:
                out.append(f"{what} on {r} would run as the stored role of stack {', '.join(held)}")
    return out


def is_blocked(action):
    a = action.lower()
    if any(fnmatch.fnmatchcase(a, p.lower()) for p in IAM_ALLOWED):
        return False
    service = a.split(":", 1)[0]
    for pattern in BLOCKED_ACTIONS:
        p_service = pattern.lower().split(":", 1)[0]
        # A wildcard request like "sts:*" or "s*:*" overlaps a blocked action too.
        if fnmatch.fnmatchcase(a, pattern.lower()) or fnmatch.fnmatchcase(pattern.lower(), a):
            return True
        if service == p_service and "*" in a:
            return True
    return False


def validate_request(project, actions, resources, reason):
    """Return a cleaned (project, actions, resources, reason) or raise ValueError."""
    if not PROJECT_RE.match(project or ""):
        raise ValueError("project must be lowercase letters, digits and dashes, 2-41 chars, starting with a letter")
    actions = sorted({a.strip() for a in actions if a.strip()})
    if not actions:
        raise ValueError("at least one action is required")
    for a in actions:
        if not ACTION_RE.match(a):
            raise ValueError(f"invalid action {a!r}; use service:Action, e.g. s3:GetObject")
        if is_blocked(a):
            raise ValueError(f"{a} is never grantable to agent roles (IAM, STS assume, billing, org, identity and domain registration are blocked)")
    resources = sorted({r.strip() for r in resources if r.strip()}) or ["*"]
    for r in resources:
        if r != "*" and not r.startswith("arn:"):
            raise ValueError(f"invalid resource {r!r}; use an ARN or *")
    reason = (reason or "").strip()
    if not reason:
        raise ValueError("a reason is required")
    return project, actions, resources, reason


MAX_GRANTS = 9  # per request
SID_RE = re.compile(r"^Req([0-9]+)(?:g([1-9]))?$")


def sid(request_id, n=None):
    """Req<id> for a request's only grant, Req<id>g<n> for grant n of several."""
    return f"Req{request_id}" + (f"g{n}" if n else "")


def parse_sid(statement_sid):
    """(request id, grant n or None) of a Req<id>[g<n>] Sid, or None for any other Sid."""
    m = SID_RE.match(statement_sid or "")
    return (int(m.group(1)), int(m.group(2)) if m.group(2) else None) if m else None


def grants_of(r):
    """The grants a request asks for, each {"n", "sid", "actions", "resources", "suggested_hours" (None
    if the agent didn't suggest a duration), "expires_at" (0: never), "ended" ("", "revoked" or
    "expired")}. A request with one grant keeps it in its own fields and its status says whether it
    ended; a request with several stores them in "grants", each with its own end."""
    if r.get("grants"):
        return [{"n": g["n"], "sid": sid(r["id"], g["n"]), "actions": g["actions"], "resources": g["resources"],
                 "suggested_hours": g.get("suggested_hours"), "expires_at": g.get("expires_at", 0),
                 "ended": g.get("ended", "")} for g in r["grants"]]
    ended = r["status"] if r.get("status") in ("revoked", "expired") else ""
    return [{"n": 1, "sid": sid(r["id"]), "actions": r["actions"], "resources": r["resources"],
             "suggested_hours": r.get("suggested_hours"), "expires_at": r.get("expires_at", 0), "ended": ended}]


def live_grants(r):
    """The grants of a request that haven't ended: for an approved one, what IAM should hold."""
    return [g for g in grants_of(r) if not g["ended"]]


# How long a grant lasts, in hours, as the owner picks it before Approve. 0 is permanent.
DURATIONS = {1: "1 hour", 3: "3 hours", 24: "1 day", 168: "1 week", 0: "Permanent"}


def duration(hours):
    """A valid duration in hours (see DURATIONS), or ValueError."""
    if type(hours) is int and hours in DURATIONS:
        return hours
    if isinstance(hours, str) and hours.strip().isdigit() and int(hours) in DURATIONS:
        return int(hours)
    raise ValueError(f"duration must be one of {', '.join(map(str, DURATIONS))} hours (0 is permanent)")


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def grants_document(requests):
    """The project role's whole grants policy, built from its approved requests: one statement per
    grant that hasn't ended."""
    return doc(*[statement(g["sid"], g["actions"], g["resources"], g["expires_at"])
                 for r in sorted(requests, key=lambda r: r["id"]) for g in live_grants(r)])


def statement(statement_sid, actions, resources, expires_at=0):
    """One grant. A time-limited one carries its end in a condition, so IAM ends it by itself, also
    for credentials already handed out; the sweep removes it from the policy afterwards."""
    stmt = {"Sid": statement_sid, "Effect": "Allow", "Action": actions, "Resource": resources}
    if expires_at:
        stmt["Condition"] = {"DateLessThan": {"aws:CurrentTime": iso(expires_at)}}
    return stmt


def expiry(stmt):
    """When a statement ends (its DateLessThan aws:CurrentTime), as written, or "" if never."""
    return stmt.get("Condition", {}).get("DateLessThan", {}).get("aws:CurrentTime", "")


def with_statement(policy, stmt):
    policy = policy or doc()
    kept = [s for s in policy["Statement"] if s.get("Sid") != stmt["Sid"]]
    return doc(*kept, stmt)


def without_sid(policy, statement_sid):
    policy = policy or doc()
    return doc(*[s for s in policy["Statement"] if s.get("Sid") != statement_sid])


def dumps(policy):
    return json.dumps(policy, separators=(",", ":"))


# What a time limit adds to a statement. Every end is written the same way, so it's a constant.
CONDITION_CHARS = len(dumps(statement("x", [], [], 1))) - len(dumps(statement("x", [], [])))


def size(document):
    """A policy's size as IAM counts it: compact JSON."""
    return len(dumps(document))


def size_problem(project, document, names=None):
    """Why IAM would refuse this grants document for being too big, naming the policy and how far
    over it is, or "" if it fits. Checked before every write and on the card."""
    return size_message(project, size(document), names)


def size_message(project, size, names=None):
    if size <= MAX_INLINE_POLICY_CHARS:
        return ""
    return (f"the inline policy {GRANTS_POLICY} on role {role_name(project, names)} would be "
            f"{size:,} characters, {size - MAX_INLINE_POLICY_CHARS:,} over the {MAX_INLINE_POLICY_CHARS:,}-character limit")
