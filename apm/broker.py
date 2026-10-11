"""Everything that touches IAM and STS. Runs inside the Lambda as the apm-broker role."""
import json
import threading

from . import policy

_lock = threading.Lock()


class BrokerError(Exception):
    pass


def _is_missing(err):
    return getattr(err, "response", {}).get("Error", {}).get("Code") == "NoSuchEntity"


class Broker:
    """Writes each project role's grants policy from the approved requests the caller passes in,
    never from a read of IAM (IAM reads are eventually consistent, and rewriting from a stale
    read could bring back a revoked grant). Callers serialize changes per project."""

    def __init__(self, account, region, iam=None, sts=None):
        self.account, self.region = account, region
        if iam is None or sts is None:
            import boto3
            iam, sts = iam or boto3.client("iam"), sts or boto3.client("sts", region_name=region)
        self.iam, self.sts = iam, sts

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
        """Make the role's grants exactly the given approved requests."""
        new = policy.grants_document(approved)
        name = policy.role_name(project)
        with _lock:
            if not new["Statement"]:
                try:
                    self.iam.delete_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY)
                except Exception as e:
                    if not _is_missing(e):
                        raise
                return
            body = policy.dumps(new)
            if len(body) > policy.MAX_INLINE_POLICY_CHARS:
                raise BrokerError(f"project {project} would exceed the {policy.MAX_INLINE_POLICY_CHARS}-char inline policy limit; revoke or consolidate grants first")
            self._ensure_role(project)
            self.iam.put_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY, PolicyDocument=body)

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
        """Whether IAM currently grants exactly the approved requests (for the dashboard)."""
        current = self.grants(project) or policy.doc()
        return sorted(s.get("Sid", "") for s in current["Statement"]) == \
            sorted(policy.sid(r["id"]) for r in approved)

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

