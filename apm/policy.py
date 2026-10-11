"""IAM policy documents and request validation. Pure functions, no AWS calls."""
import fnmatch
import json
import re

ROLE_PATH = "/agents/"
ROLE_PREFIX = "apm-"
GRANTS_POLICY = "apm-grants"
BOUNDARY_NAME = "apm-agent-boundary"
BROKER_ROLE = "apm-broker"
BROKER_ROLE_PATH = "/apm/"
MAX_INLINE_POLICY_CHARS = 10240

PROJECT_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
ACTION_RE = re.compile(r"^[a-z0-9-]+:[A-Za-z0-9*?]+$")

# Agent roles can never get these, whatever is approved. Keep in sync with boundary().
BLOCKED_ACTIONS = [
    "iam:*", "organizations:*", "account:*", "sso:*", "sso-directory:*", "identitystore:*",
    "aws-portal:*", "billing:*", "payments:*", "tax:*", "cur:*",
    "sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity",
]
# Exceptions the boundary allows back in.
IAM_ALLOWED = ["iam:Get*", "iam:List*", "iam:PassRole"]


def role_name(project):
    return ROLE_PREFIX + project


def role_arn(account, project):
    return f"arn:aws:iam::{account}:role{ROLE_PATH}{role_name(project)}"


def agent_roles_arn(account):
    return f"arn:aws:iam::{account}:role{ROLE_PATH}*"


def boundary_arn(account):
    return f"arn:aws:iam::{account}:policy/{BOUNDARY_NAME}"


def broker_role_arn(account):
    return f"arn:aws:iam::{account}:role{BROKER_ROLE_PATH}{BROKER_ROLE}"


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def boundary(account):
    """Permissions boundary on every agent role: the most an agent role can ever do."""
    return doc(
        {"Sid": "AllowNonAdminServices", "Effect": "Allow", "NotAction": BLOCKED_ACTIONS, "Resource": "*"},
        {"Sid": "AllowIamRead", "Effect": "Allow", "Action": ["iam:Get*", "iam:List*"], "Resource": "*"},
        {"Sid": "AllowPassAgentRoles", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": agent_roles_arn(account)},
    )


def broker_policy(account):
    """The broker (the Lambda's role) can only create and edit agent roles, only with the
    boundary attached, and assume them to hand agents short-lived credentials."""
    roles = agent_roles_arn(account)
    return doc(
        {"Sid": "CreateAgentRolesWithBoundary", "Effect": "Allow", "Action": "iam:CreateRole",
         "Resource": roles, "Condition": {"StringEquals": {"iam:PermissionsBoundary": boundary_arn(account)}}},
        {"Sid": "EditAgentRoles", "Effect": "Allow", "Resource": roles, "Action": [
            "iam:GetRole", "iam:TagRole", "iam:DeleteRole", "iam:ListRolePolicies", "iam:GetRolePolicy",
            "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:ListAttachedRolePolicies"]},
        {"Sid": "VendAgentCredentials", "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": roles},
        # Lookups of a role that doesn't exist yet are authorized against an ARN without the path.
        {"Sid": "LookUpAgentRoles", "Effect": "Allow",
         "Resource": f"arn:aws:iam::{account}:role/{ROLE_PREFIX}*",
         "Action": ["iam:GetRole", "iam:GetRolePolicy", "iam:ListRolePolicies"]},
        {"Sid": "NeverRemoveBoundary", "Effect": "Deny", "Resource": "*",
         "Action": ["iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"]},
    )


def agent_role_trust(account):
    """Only the broker can assume agent roles; agents get the resulting session credentials."""
    return doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                "Principal": {"AWS": broker_role_arn(account)}})


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
            raise ValueError(f"{a} is never grantable to agent roles (IAM, STS assume, billing, org and identity are blocked)")
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
