"""Everything that touches IAM and STS. Runs inside the Lambda as the apm-broker role."""
import json
import threading

from . import policy

_lock = threading.Lock()


class BrokerError(Exception):
    pass


def _is_missing(err):
    return getattr(err, "response", {}).get("Error", {}).get("Code") == "NoSuchEntity"


class _Marks:
    """In-memory stand-in for Store's strongly consistent marks (tests, local use)."""

    def __init__(self):
        self.set = set()

    def is_marked(self, key):
        return key in self.set

    def mark(self, key):
        self.set.add(key)


class Broker:
    """Callers serialize changes per project (App holds Store.lease around each decision)."""

    def __init__(self, account, region, iam=None, sts=None, marks=None):
        self.account, self.region = account, region
        self.marks = marks or _Marks()
        if iam is None or sts is None:
            import boto3
            iam, sts = iam or boto3.client("iam"), sts or boto3.client("sts", region_name=region)
        self.iam, self.sts = iam, sts

    def _policies(self, project):
        """{policy name: document} for the project role's grant policies. None if no role."""
        name = policy.role_name(project)
        try:
            names = self.iam.list_role_policies(RoleName=name)["PolicyNames"]
        except Exception as e:
            if _is_missing(e):
                return None
            raise
        out = {}
        for p in names:
            if p == policy.GRANTS_POLICY or p.startswith(policy.GRANTS_POLICY + "-"):
                try:
                    doc = self.iam.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"]
                except Exception as e:
                    if _is_missing(e):
                        continue
                    raise
                out[p] = json.loads(doc) if isinstance(doc, str) else doc
        return out

    def grants(self, project):
        """Current granted statements for a project role, read live from AWS. None if no role."""
        policies = self._policies(project)
        if policies is None:
            return None
        statements = [s for doc in policies.values() for s in doc["Statement"]]
        return policy.doc(*sorted(statements, key=lambda s: _req_number(s.get("Sid", ""))))

    def _split_legacy(self, project):
        """Roles created before per-grant policies hold every grant in one `apm-grants` policy.
        Split it once; the mark (strongly consistent) means a stale read of the deleted legacy
        policy can never be split again and resurrect a revoked grant."""
        key = f"split#{project}"
        if self.marks.is_marked(key):
            return
        name = policy.role_name(project)
        try:
            doc = self.iam.get_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY)["PolicyDocument"]
        except Exception as e:
            if not _is_missing(e):
                raise
            doc = None
        if doc is not None:
            doc = json.loads(doc) if isinstance(doc, str) else doc
            for stmt in doc["Statement"]:
                self.iam.put_role_policy(RoleName=name, PolicyName=policy.grant_policy_name(stmt["Sid"]),
                                         PolicyDocument=policy.dumps(policy.doc(stmt)))
            self.iam.delete_role_policy(RoleName=name, PolicyName=policy.GRANTS_POLICY)
        self.marks.mark(key)

    def approve(self, request):
        project = request["project"]
        stmt = policy.statement(request["id"], request["actions"], request["resources"])
        body = policy.dumps(policy.doc(stmt))
        with _lock:
            self._ensure_role(project)
            self._split_legacy(project)
            others = {k: v for k, v in (self._policies(project) or {}).items() if k != policy.grant_policy_name(stmt["Sid"])}
            total = len(body) + sum(len(policy.dumps(d)) for d in others.values())
            if total > policy.MAX_INLINE_POLICY_CHARS:
                raise BrokerError(f"project {project} would exceed the {policy.MAX_INLINE_POLICY_CHARS}-char inline policy limit; revoke or consolidate grants first")
            self.iam.put_role_policy(RoleName=policy.role_name(project), PolicyName=policy.grant_policy_name(stmt["Sid"]),
                                     PolicyDocument=body)

    def revoke(self, project, statement_sid):
        with _lock:
            self._split_legacy(project)
            try:
                self.iam.delete_role_policy(RoleName=policy.role_name(project),
                                            PolicyName=policy.grant_policy_name(statement_sid))
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
            self.marks.mark(f"split#{project}")  # a recreated role starts with per-grant policies

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


def _req_number(statement_sid):
    return int(statement_sid[3:]) if statement_sid.startswith("Req") and statement_sid[3:].isdigit() else 0
