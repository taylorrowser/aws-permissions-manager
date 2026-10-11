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

    def approve(self, request):
        project = request["project"]
        stmt = policy.statement(request["id"], request["actions"], request["resources"])
        with _lock:
            self._ensure_role(project)
            new = policy.with_statement(self.grants(project), stmt)
            body = policy.dumps(new)
            if len(body) > policy.MAX_INLINE_POLICY_CHARS:
                raise BrokerError(f"project {project} would exceed the {policy.MAX_INLINE_POLICY_CHARS}-char inline policy limit; revoke or consolidate grants first")
            self.iam.put_role_policy(RoleName=policy.role_name(project), PolicyName=policy.GRANTS_POLICY, PolicyDocument=body)

    def revoke(self, project, statement_sid):
        with _lock:
            new = policy.without_sid(self.grants(project), statement_sid)
            name = policy.role_name(project)
            if new["Statement"]:
                self.iam.put_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY, PolicyDocument=policy.dumps(new))
            else:
                try:
                    self.iam.delete_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY)
                except Exception as e:
                    if not _is_missing(e):
                        raise

    def remove_project(self, project):
        name = policy.role_name(project)
        with _lock:
            try:
                for p in self.iam.list_role_policies(RoleName=name)["PolicyNames"]:
                    self.iam.delete_role_policy(RoleName=name, PolicyName=p)
                self.iam.delete_role(RoleName=name)
            except Exception as e:
                if not _is_missing(e):
                    raise

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
