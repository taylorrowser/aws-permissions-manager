"""IAM policy documents and request validation. Pure functions, no AWS calls."""
import fnmatch
import json
import os
import re
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
# Exceptions the boundary allows back in.
IAM_ALLOWED = ["iam:Get*", "iam:List*", "iam:PassRole"]


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
        {"Sid": "NeverRemoveBoundary", "Effect": "Deny", "Resource": "*",
         "Action": ["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"]},
    )


def agent_role_trust(account, names=None):
    """Only the broker can assume agent roles; agents get the resulting session credentials."""
    return doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"AWS": broker_role_arn(account, names)}})


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


def sid(request_id):
    return f"Req{request_id}"


def grants_document(requests):
    """The project role's whole grants policy, built from its approved requests."""
    return doc(*[statement(r["id"], r["actions"], r["resources"]) for r in sorted(requests, key=lambda r: r["id"])])


def statement(request_id, actions, resources):
    return {"Sid": sid(request_id), "Effect": "Allow", "Action": actions, "Resource": resources}


def with_statement(policy, stmt):
    policy = policy or doc()
    kept = [s for s in policy["Statement"] if s.get("Sid") != stmt["Sid"]]
    return doc(*kept, stmt)


def without_sid(policy, statement_sid):
    policy = policy or doc()
    return doc(*[s for s in policy["Statement"] if s.get("Sid") != statement_sid])


def dumps(policy):
    return json.dumps(policy, separators=(",", ":"))
