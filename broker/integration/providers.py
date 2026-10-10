"""Explicitly injected bridge; no discovery, metadata credentials, or client factory."""
import json
from dataclasses import dataclass
from .contracts import digest
from .service import Denied,Unconfigured
from .aws import STSAdapter,RoleExpectation

@dataclass(frozen=True)
class PinnedRevision:
    """Isolated executor receipt; never accepted from any request/MCP input.
    New AWS RoleIds are observed after creation, while human approval binds the
    planned exact ARN/name. This receipt binds the observed identity to that grant.
    """
    grant_id: str
    manifest_digest: str
    role_id: str
    snapshot_sha256: str
    expectation: RoleExpectation

class AWSRuntimeCredentials:
    def __init__(self,sts:STSAdapter|None=None,pinned_revisions=None):
        self.sts=sts;self.pinned_revisions=dict(pinned_revisions or {})
    def issue(self,grant,run,now,expires_at):
        if self.sts is None: raise Unconfigured('assume-only vendor is not installed')
        m=json.loads(grant['manifest']); pinned=self.pinned_revisions.get(grant['physical_name'])
        if not isinstance(pinned,PinnedRevision) or not isinstance(pinned.expectation,RoleExpectation): raise Denied('grant-bound executor receipt is not installed')
        expected=pinned.expectation; snapshot=expected.as_dict()
        if pinned.grant_id!=grant['id'] or pinned.manifest_digest!=digest(m) or pinned.role_id!=snapshot['role_id'] or pinned.snapshot_sha256!=expected.fingerprint:
            raise Denied('pinned executor receipt does not match the grant and observed identity')
        if (snapshot['role_name']!=grant['physical_name'] or snapshot['role_name']!=m['physical_role_name'] or snapshot['role_arn']!=m['physical_role_arn'] or snapshot['role_arn'].split(':')[4]!=m['account_id']):
            raise Denied('pinned physical role does not match the exact approved manifest')
        if run['grant_id']!=grant['id'] or expires_at>run['expires']: raise Denied('run lease does not bind this grant')
        return self.sts.issue(expected,m['scope'],m['account_id'],m['region'],expires_at=expires_at,now=now,
            session_name='run-'+run['id'].removeprefix('run_')[:32],duration_seconds=900,
            admin_tags=m['admin_tags'],grant_not_after=m['not_after'])
