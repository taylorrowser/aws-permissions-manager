"""Shared strict domain and transport contracts; no authority-bearing input fields."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator
import hashlib, json

class Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)

Action = Literal['ec2:DescribeInstances', 'ec2:DescribeInstanceStatus', 'ec2:StartInstances', 'ec2:StopInstances', 'ec2:RebootInstances']
class Scope(Contract):
    actions: list[Action] = Field(min_length=1, max_length=5)
    instance_arns: list[str] = Field(default_factory=list, max_length=20)

class RequestInput(Contract):
    logical_role: str = Field(pattern=r'^[a-z][a-z0-9-]{2,47}$')
    expected_generation: int = Field(ge=0)
    scope: Scope
    access: Literal['ongoing', 'temporary']
    not_after: int | None = None
    effective_at: int | None = None
    reason: str = Field(min_length=1,max_length=2000)
    idempotency_key: str = Field(pattern=r'^[A-Za-z0-9_-]{8,80}$')
    @model_validator(mode='after')
    def bounds(self):
        if not self.reason.strip(): raise ValueError('reason is required')
        if self.access == 'temporary' and self.effective_at is None:
            raise ValueError('temporary change requires an exact start and end')
        if (self.access == 'temporary') != (self.not_after is not None):
            raise ValueError('temporary access requires an absolute cutoff; ongoing access has none')
        return self

class RevisionInput(Contract):
    expected_revision: int = Field(ge=1)
    request: RequestInput

class DecisionInput(Contract):
    revision: int = Field(ge=1)
    digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    choice: Literal['approve','reject']
    challenge: str = Field(min_length=20,max_length=256)

class RunEnrollmentInput(Contract):
    grant_id: str
    evidence: str = Field(min_length=1,max_length=8192,repr=False)
    environment_label: str = Field(default='',max_length=128)

class LeaseInput(Contract):
    grant_id: str
    run_id: str
    idempotency_key: str = Field(pattern=r'^[A-Za-z0-9_-]{8,80}$')

class CredentialUseInput(Contract):
    handle: str = Field(min_length=20,max_length=160)

class RequestView(Contract):
    request_id: str
    revision: int
    digest: str
    state: str
    manifest: dict
    operation_id: str | None = None

class RequestList(Contract):
    requests: list[RequestView]

class NamedRole(Contract):
    logical_role: str
    generation: int
    current_grant_id: str | None

class GrantView(Contract):
    grant_id: str
    logical_role: str
    generation: int
    state: str
    scope: Scope
    not_after: int | None
    physical_role_name: str
    predecessor_grant_id: str | None
    operation_id: str

class GrantList(Contract):
    grants: list[GrantView]

class RunIdentity(Contract):
    run_id: str
    grant_id: str
    provider: str
    expires_at: int
    environment_label: str

class CredentialLease(Contract):
    handle: str
    grant_id: str
    run_id: str
    redeem_before: int
    maximum_expiration: int
    delivery: Literal['credential_process'] = 'credential_process'

class OperationView(Contract):
    operation_id: str
    state: str
    detail: str

class SessionStatus(Contract):
    authenticated: bool
    owner_id: str
    client_id: str
    actor_kind: str
    mode: str


def canonical(value):
    if isinstance(value, BaseModel): value=value.model_dump(mode='json')
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def digest(value): return hashlib.sha256(canonical(value).encode()).hexdigest()

class EnrollmentPrepareInput(Contract):
    grant_id: str
    public_jwk: dict
    lifetime: int = Field(ge=960,le=3600,description="At least 960 seconds for 900-second AWS sessions plus 60-second handle redemption; elapsed time is rechecked at issuance")
    idempotency_key: str = Field(pattern=r'^[A-Za-z0-9_-]{8,80}$')

class EnrollmentPrepared(Contract):
    enrollment_id: str
    challenge: str
    expires_at: int
    redeem_url: str
    authority: dict
    mode: str
    machine_attestation: Literal[False] = False

class EnrollmentRedeemInput(Contract):
    enrollment_id: str

class RunCredentialInput(Contract):
    run_id: str
    grant_id: str
    nonce: str
    idempotency_key: str = Field(pattern=r'^[A-Za-z0-9_-]{8,80}$')
