"""Everything that touches IAM and STS, plus the CloudFormation reads the grant checks need. Runs
inside the Lambda as the apm-broker role."""
import json
import threading

from . import policy

_lock = threading.Lock()


class BrokerError(Exception):
    pass


# PutRolePolicy errors that mean IAM rejected the document and wrote nothing.
IAM_REFUSALS = {"LimitExceeded", "MalformedPolicyDocument"}


def _is_missing(err):
    return getattr(err, "response", {}).get("Error", {}).get("Code") == "NoSuchEntity"


class Broker:
    """Writes each project role's grants policy from the approved requests the caller passes in,
    never from a read of IAM (IAM reads are eventually consistent, and rewriting from a stale
    read could bring back a revoked grant). Callers serialize changes per project."""

    def __init__(self, account, region, iam=None, sts=None, cloudformation=None):
        self.account, self.region = account, region
        if iam is None or sts is None:
            import boto3
            iam, sts = iam or boto3.client("iam"), sts or boto3.client("sts", region_name=region)
        self.iam, self.sts = iam, sts
        self._cfn, self._cfn_clients = cloudformation, {}

    def stacks(self, region):
        """[(stack name, stored RoleARN or "", stack id ARN)] of every live stack in a region, read now. Raises if
        the listing fails: callers treat that as a refusal, never as "no stacks"."""
        client = self._cfn_clients.get(region)
        if client is None:
            if self._cfn:
                client = self._cfn(region)
            else:
                import boto3
                client = boto3.client("cloudformation", region_name=region)
            self._cfn_clients[region] = client
        out, kw = [], {}
        while True:
            page = client.describe_stacks(**kw)
            out += [(s["StackName"], s.get("RoleARN", ""), s["StackId"]) for s in page.get("Stacks", [])]
            if not page.get("NextToken"):
                return out
            kw = {"NextToken": page["NextToken"]}

    def grants(self, project):
        """Current granted policy for a project role, read live from AWS. None if no role."""
        try:
            raw = self.iam.get_role_policy(RoleName=policy.role_name(project), PolicyName=policy.GRANTS_POLICY)
        except Exception as e:
            if _is_missing(e):
                return None
            raise
        doc = raw["PolicyDocument"]
        return json.loads(doc) if isinstance(doc, str) else doc

    def sync(self, project, approved):
        """Make the role's grants exactly the given approved requests. Returns the document written,
        or None when no grants are left and the policy was deleted."""
        new = policy.grants_document(approved)
        name = policy.role_name(project)
        with _lock:
            if not new["Statement"]:
                try:
                    self.iam.delete_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY)
                except Exception as e:
                    if not _is_missing(e):
                        raise
                return None
            problem = policy.size_problem(project, new)
            if problem:
                raise BrokerError(f"{problem}; revoke or consolidate grants first")
            body = policy.dumps(new)
            self._ensure_role(project)
            try:
                self.iam.put_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY, PolicyDocument=body)
            except Exception as e:
                code = getattr(e, "response", {}).get("Error", {}).get("Code")
                if code in IAM_REFUSALS:  # IAM said no, so nothing was written
                    raise BrokerError(f"IAM refused the policy for {name} ({code}): {e}") from e
                raise
            return new

    def remove_project(self, project):
        """Delete every inline policy, then the role. Succeeds only once the role is gone."""
        name = policy.role_name(project)
        with _lock:
            try:
                names = self._all_policy_names(name)
            except Exception as e:
                if _is_missing(e):
                    return  # no role
                raise
            for p in names:
                try:
                    self.iam.delete_role_policy(RoleName=name, PolicyName=p)
                except Exception as e:
                    if not _is_missing(e):  # listed but already gone (stale listing): keep going
                        raise
            try:
                self.iam.delete_role(RoleName=name)
            except Exception as e:
                if not _is_missing(e):
                    raise

    def in_sync(self, project, approved):
        """Whether IAM currently grants exactly the approved requests, each until when it was
        approved (or extended) to (for the dashboard)."""
        def ends(d):
            return sorted((s.get("Sid", ""), policy.expiry(s)) for s in d["Statement"])
        return ends(self.grants(project) or policy.doc()) == ends(policy.grants_document(approved))

    def _all_policy_names(self, role):
        names, kw = [], {}
        while True:
            page = self.iam.list_role_policies(RoleName=role, **kw)
            names += page["PolicyNames"]
            if not page.get("IsTruncated"):
                return names
            kw = {"Marker": page["Marker"]}

    def credentials(self, project, session_name):
        """Short-lived credentials for a project role. Raises BrokerError if nothing is granted."""
        grants = self.grants(project)
        if not grants or not grants["Statement"]:
            raise BrokerError(f"project {project} has no approved permissions yet; request some first")
        c = self.sts.assume_role(RoleArn=policy.role_arn(self.account, project),
                                 RoleSessionName=session_name[:64], DurationSeconds=3600)["Credentials"]
        exp = c["Expiration"]
        return {"Version": 1, "AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"],
                "SessionToken": c["SessionToken"],
                "Expiration": exp.isoformat() if hasattr(exp, "isoformat") else str(exp)}

    def _ensure_role(self, project):
        name = policy.role_name(project)
        try:
            self.iam.get_role(RoleName=name)
            return
        except Exception as e:
            if not _is_missing(e):
                raise
        self.iam.create_role(
            RoleName=name, Path=policy.ROLE_PATH,
            AssumeRolePolicyDocument=json.dumps(policy.agent_role_trust(self.account)),
            PermissionsBoundary=policy.boundary_arn(self.account), MaxSessionDuration=3600,
            Description=f"apm agent role for project {project}",
            Tags=[{"Key": "managed-by", "Value": "apm"}, {"Key": "project", "Value": project}])

