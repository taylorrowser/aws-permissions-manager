"""Non-live AWS integration boundaries. Clients must be explicitly injected.

Importing this module never constructs an SDK session/client or searches for credentials.
See infrastructure/README.md for the review gates before any live integration.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, TextIO
from urllib.parse import unquote

DESCRIBE_ACTIONS = frozenset({'ec2:DescribeInstances', 'ec2:DescribeInstanceStatus'})
MUTATE_ACTIONS = frozenset({'ec2:StartInstances', 'ec2:StopInstances', 'ec2:RebootInstances'})
ALLOWED_ACTIONS = DESCRIBE_ACTIONS | MUTATE_ACTIONS
MAX_INSTANCES = 20
MAX_SESSION_POLICY_CHARACTERS = 2048
REVISION_POLICY_NAME = 'ApprovedRevision'


class AWSAdapterError(ValueError):
    """Sanitized, stable error code; never include provider responses or credentials."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _timestamp(value: int) -> str:
    if type(value) is not int or value <= 0:
        raise AWSAdapterError('invalid_absolute_cutoff')
    try:
        return datetime.fromtimestamp(value, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (ValueError, OverflowError, OSError):
        raise AWSAdapterError('invalid_absolute_cutoff') from None


def _account_region(account_id: str, region: str) -> None:
    if not isinstance(account_id, str) or not re.fullmatch(r'[0-9]{12}', account_id):
        raise AWSAdapterError('invalid_account_id')
    if not isinstance(region, str) or not re.fullmatch(r'(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:[a-z]+-)?[a-z]+-[1-9][0-9]*', region):
        raise AWSAdapterError('invalid_commercial_region')
    # This slice explicitly excludes other partitions, including GovCloud and China.
    if region.startswith('us-gov-'):
        raise AWSAdapterError('unsupported_partition')


def compile_ec2(scope: dict, account_id: str, region: str, *, not_after: int | None = None,
                admin_tags: dict | None = None) -> dict:
    """Compile a small exact EC2 allowlist, never caller-supplied IAM JSON.

    Describe actions necessarily expose regional inventory (Resource '*'); instance
    ARNs and tags do NOT narrow those calls. Existing-instance membership must be
    checked against administrator inventory by the service before approval.
    """
    _account_region(account_id, region)
    if type(scope) is not dict or set(scope) != {'actions', 'instance_arns'}:
        raise AWSAdapterError('unsupported_scope_fields')
    actions, arns = scope['actions'], scope['instance_arns']
    if (type(actions) is not list or not 1 <= len(actions) <= len(ALLOWED_ACTIONS)
            or any(type(a) is not str or a not in ALLOWED_ACTIONS for a in actions)
            or len(set(actions)) != len(actions)):
        raise AWSAdapterError('unsupported_ec2_actions')
    if type(arns) is not list or len(arns) > MAX_INSTANCES or any(type(a) is not str for a in arns):
        raise AWSAdapterError('invalid_instance_arns')
    if len(set(arns)) != len(arns):
        raise AWSAdapterError('duplicate_instance_arns')
    pattern = re.compile(r'arn:aws:ec2:' + re.escape(region) + ':' + account_id + r':instance/i-(?:[0-9a-f]{8}|[0-9a-f]{17})')
    if any(not pattern.fullmatch(arn) for arn in arns):
        raise AWSAdapterError('instance_outside_exact_account_region')
    if set(actions) & MUTATE_ACTIONS and not arns:
        raise AWSAdapterError('mutation_requires_exact_existing_instances')
    if admin_tags is None:
        admin_tags = {}
    if type(admin_tags) is not dict or len(admin_tags) > 10:
        raise AWSAdapterError('invalid_administrator_tags')
    for key, value in admin_tags.items():
        if (type(key) is not str or type(value) is not str or not 1 <= len(key) <= 128
                or not 1 <= len(value) <= 256 or key.lower().startswith('aws:')
                or any(c in key + value for c in '*?${}')
                or any(ord(c) < 32 or ord(c) > 126 for c in key + value)):
            raise AWSAdapterError('invalid_administrator_tags')
    statements = []
    describe = sorted(set(actions) & DESCRIBE_ACTIONS)
    if describe:
        statements.append({'Sid': 'RegionalInventory', 'Effect': 'Allow', 'Action': describe,
                           'Resource': '*', 'Condition': {'StringEquals': {'aws:RequestedRegion': region}}})
    mutate = sorted(set(actions) & MUTATE_ACTIONS)
    if mutate:
        conditions = {'aws:RequestedRegion': region}
        conditions.update({'ec2:ResourceTag/' + k: v for k, v in sorted(admin_tags.items())})
        statements.append({'Sid': 'ExactExistingInstances', 'Effect': 'Allow', 'Action': mutate,
                           'Resource': sorted(arns), 'Condition': {'StringEquals': conditions}})
    if not_after is not None:
        # This deny is embedded in both role and session policies. An old session
        # retains its own immutable cutoff even if a later role grant is widened.
        statements.append({'Sid': 'AbsoluteNotAfter', 'Effect': 'Deny', 'Action': '*',
                           'Resource': '*', 'Condition': {'DateGreaterThanEquals': {
                               'aws:CurrentTime': _timestamp(not_after)}}})
    return {'Version': '2012-10-17', 'Statement': statements}


def _document(value: Any) -> dict:
    if isinstance(value, str):
        try:
            try:
                value = json.loads(value)
            except ValueError:
                value = json.loads(unquote(value))
        except (TypeError, ValueError):
            raise AWSAdapterError('invalid_provider_policy_document') from None
    if type(value) is not dict:
        raise AWSAdapterError('invalid_provider_policy_document')
    return json.loads(canonical(value))


class RoleExpectation:
    """Immutable administrator/captured baseline, never a request DTO.

    boundary: {arn, version_id, document}; attached_policies maps ARN to
    {version_id, document}. All attached documents and boundary versions are pinned.
    """
    __slots__ = ('_json',)

    def __init__(self, role_name: str, role_arn: str, role_id: str, trust_policy: dict,
                 boundary: dict, inline_policies: dict, attached_policies: dict,
                 max_session_duration: int = 3600):
        if not isinstance(role_name, str) or not re.fullmatch(r'[A-Za-z0-9_+=,.@-]{1,64}', role_name):
            raise AWSAdapterError('invalid_role_name')
        if (not isinstance(role_arn, str)
                or not re.fullmatch(r'arn:aws:iam::[0-9]{12}:role/(?:[A-Za-z0-9_+=,.@-]+/)*' + re.escape(role_name), role_arn)):
            raise AWSAdapterError('invalid_role_arn')
        if not isinstance(role_id, str) or not re.fullmatch(r'AROA[A-Z0-9]{12,124}', role_id):
            raise AWSAdapterError('unverified_role_identity')
        if type(max_session_duration) is not int or not 3600 <= max_session_duration <= 43200:
            raise AWSAdapterError('invalid_role_max_duration')
        if type(boundary) is not dict or set(boundary) != {'arn', 'version_id', 'document'}:
            raise AWSAdapterError('pinned_boundary_required')
        if (not isinstance(boundary['arn'], str) or not re.fullmatch(r'arn:aws:iam::[0-9]{12}:policy/[A-Za-z0-9_+=,.@/-]+', boundary['arn'])
                or not isinstance(boundary['version_id'], str) or not re.fullmatch(r'v[1-9][0-9]*', boundary['version_id'])):
            raise AWSAdapterError('invalid_boundary_snapshot')
        if boundary['arn'].split(':')[4] != role_arn.split(':')[4]:
            raise AWSAdapterError('cross_account_boundary')
        if type(inline_policies) is not dict or type(attached_policies) is not dict:
            raise AWSAdapterError('invalid_role_policies')
        for name, document in inline_policies.items():
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_+=,.@-]{1,128}', name):
                raise AWSAdapterError('invalid_inline_policy_name')
            _document(document)
        for arn, snapshot in attached_policies.items():
            if not isinstance(arn, str) or not re.fullmatch(r'arn:aws:iam::(?:[0-9]{12}|aws):policy/[A-Za-z0-9_+=,.@/-]+', arn):
                raise AWSAdapterError('invalid_attached_policy_arn')
            if type(snapshot) is not dict or set(snapshot) != {'version_id', 'document'}:
                raise AWSAdapterError('invalid_attached_policy_snapshot')
            if not isinstance(snapshot['version_id'], str) or not re.fullmatch(r'v[1-9][0-9]*', snapshot['version_id']):
                raise AWSAdapterError('invalid_attached_policy_version')
            _document(snapshot['document'])
        self._json = canonical({'role_name': role_name, 'role_arn': role_arn, 'role_id': role_id,
                                'trust_policy': _document(trust_policy), 'boundary': boundary,
                                'inline_policies': inline_policies, 'attached_policies': attached_policies,
                                'max_session_duration': max_session_duration})

    def as_dict(self) -> dict:
        return json.loads(self._json)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._json.encode()).hexdigest()

    def __repr__(self) -> str:
        return 'RoleExpectation(fingerprint=' + repr(self.fingerprint) + ')'


class RoleObservation:
    __slots__ = ('_json',)

    def __init__(self, document: dict):
        self._json = canonical(document)

    def as_dict(self) -> dict:
        return json.loads(self._json)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._json.encode()).hexdigest()


def _single_attempt_sdk(client) -> None:
    """Prevent hidden SDK retries for calls whose lost acknowledgement is uncertain.

    Non-SDK injected transports must uphold the same single-attempt contract.
    botocore's resolved retries config uses total_max_attempts; accept the raw
    max_attempts=0 spelling too. No SDK import/client construction is required.
    """
    config = getattr(getattr(client, 'meta', None), 'config', None)
    retries = getattr(config, 'retries', None)
    if isinstance(retries, dict):
        total = retries.get('total_max_attempts')
        if total is None and type(retries.get('max_attempts')) is int:
            total = retries['max_attempts'] + 1
        if total != 1:
            raise AWSAdapterError('sdk_single_attempt_configuration_required')


class IAMAdapter:
    """Injected IAM SDK calls; the constructor performs no provider calls.

    Readback is drift detection, not a consistency barrier or revocation proof.
    A deployment must fence IAM writers and persist attempts before any apply.
    """
    def __init__(self, client):
        if client is None:
            raise AWSAdapterError('explicit_iam_client_required')
        self._client = client

    def _call(self, method: str, **kwargs) -> dict:
        try:
            response = getattr(self._client, method)(**kwargs)
            if not isinstance(response, dict):
                raise ValueError()
            return response
        except Exception:
            # Never expose AWS exception text or a client response in API logs.
            raise AWSAdapterError('iam_' + method + '_failed') from None

    def _list(self, method: str, result_key: str, **kwargs) -> list:
        values, seen = [], set()
        for _ in range(100):
            page = self._call(method, **kwargs)
            part = page.get(result_key)
            if not isinstance(part, list):
                raise AWSAdapterError('invalid_iam_page')
            values.extend(part)
            if not page.get('IsTruncated', False):
                return values
            marker = page.get('Marker')
            if not isinstance(marker, str) or not marker or marker in seen:
                raise AWSAdapterError('incomplete_iam_observation')
            seen.add(marker)
            kwargs['Marker'] = marker
        raise AWSAdapterError('iam_pagination_limit')

    def _managed(self, arn: str) -> dict:
        policy = self._call('get_policy', PolicyArn=arn).get('Policy', {})
        if policy.get('Arn') != arn or not isinstance(policy.get('DefaultVersionId'), str):
            raise AWSAdapterError('managed_policy_identity_mismatch')
        version_id = policy['DefaultVersionId']
        version = self._call('get_policy_version', PolicyArn=arn, VersionId=version_id).get('PolicyVersion', {})
        if version.get('VersionId') != version_id or version.get('IsDefaultVersion') is not True:
            raise AWSAdapterError('managed_policy_version_mismatch')
        return {'version_id': version_id, 'document': _document(version.get('Document'))}

    def observe_role(self, role_name: str, expected: RoleExpectation) -> RoleObservation:
        if not isinstance(expected, RoleExpectation) or expected.as_dict()['role_name'] != role_name:
            raise AWSAdapterError('administrator_role_expectation_required')
        e = expected.as_dict()
        role = self._call('get_role', RoleName=role_name).get('Role', {})
        if role.get('RoleId') != e['role_id'] or role.get('Arn') != e['role_arn'] or role.get('RoleName') != role_name:
            raise AWSAdapterError('role_identity_drift')
        boundary = role.get('PermissionsBoundary', {})
        if (boundary.get('PermissionsBoundaryType') != 'PermissionsBoundaryPolicy'
                or boundary.get('PermissionsBoundaryArn') != e['boundary']['arn']):
            raise AWSAdapterError('role_boundary_drift')
        inline = {}
        for name in self._list('list_role_policies', 'PolicyNames', RoleName=role_name):
            if not isinstance(name, str) or name in inline:
                raise AWSAdapterError('inconsistent_inline_policy_listing')
            item = self._call('get_role_policy', RoleName=role_name, PolicyName=name)
            if item.get('RoleName') != role_name or item.get('PolicyName') != name:
                raise AWSAdapterError('inline_policy_identity_mismatch')
            inline[name] = _document(item.get('PolicyDocument'))
        attached = {}
        for item in self._list('list_attached_role_policies', 'AttachedPolicies', RoleName=role_name):
            arn = item.get('PolicyArn')
            if not isinstance(arn, str) or arn in attached:
                raise AWSAdapterError('inconsistent_attached_policy_listing')
            attached[arn] = self._managed(arn)
        observed = {'role_name': role_name, 'role_arn': role['Arn'], 'role_id': role['RoleId'],
                    'trust_policy': _document(role.get('AssumeRolePolicyDocument')),
                    'boundary': {'arn': boundary['PermissionsBoundaryArn'], **self._managed(boundary['PermissionsBoundaryArn'])},
                    'inline_policies': inline, 'attached_policies': attached,
                    'max_session_duration': role.get('MaxSessionDuration')}
        if canonical(observed) != canonical(e):
            raise AWSAdapterError('role_policy_or_trust_drift')
        return RoleObservation(observed)

    def apply_initial_policy(self, expected: RoleExpectation, scope: dict, account_id: str,
                             region: str, *, grant_not_after: int | None = None,
                             admin_tags: dict | None = None) -> RoleExpectation:
        """Initialize an empty, pinned revision role; never mutate an active revision.

        Caller must durably record the approved intent and acquire a distributed
        fence first. A timeout is uncertain: reconcile; never auto-retry/adopt.
        No network entry point exposes this method in the review candidate.
        """
        e = expected.as_dict()
        if e['inline_policies'] or e['attached_policies']:
            raise AWSAdapterError('revision_role_must_be_empty')
        if e['role_arn'].split(':')[4] != account_id:
            raise AWSAdapterError('role_account_mismatch')
        policy = compile_ec2(scope, account_id, region, not_after=grant_not_after, admin_tags=admin_tags)
        self.observe_role(e['role_name'], expected)
        _single_attempt_sdk(self._client)
        self._call('put_role_policy', RoleName=e['role_name'], PolicyName=REVISION_POLICY_NAME,
                   PolicyDocument=canonical(policy))
        e['inline_policies'] = {REVISION_POLICY_NAME: policy}
        desired = RoleExpectation(**e)
        self.observe_role(e['role_name'], desired)
        return desired


class CredentialEnvelope:
    """Credentials are deliberately absent from repr, metadata and ordinary JSON.

    This is output hygiene, not protection from arbitrary code in the same process.
    Only the dedicated credential_process endpoint should call the output method.
    """
    __slots__ = ('__access_key', '__secret', '__token', '__expiration', '__metadata')

    def __init__(self, credentials: dict, *, role_arn: str, cutoff: int, snapshot_sha256: str):
        try:
            expiration = credentials['Expiration']
            if not isinstance(expiration, datetime) or expiration.tzinfo is None:
                raise ValueError()
            for field in ('AccessKeyId', 'SecretAccessKey', 'SessionToken'):
                if type(credentials[field]) is not str or not credentials[field]:
                    raise ValueError()
            self.__access_key = credentials['AccessKeyId']
            self.__secret = credentials['SecretAccessKey']
            self.__token = credentials['SessionToken']
            self.__expiration = expiration.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        except (KeyError, TypeError, ValueError):
            raise AWSAdapterError('invalid_sts_credentials') from None
        self.__metadata = {'role_arn': role_arn, 'credential_expiration': self.__expiration,
                           'effective_not_after': _timestamp(cutoff), 'snapshot_sha256': snapshot_sha256}

    def __repr__(self) -> str:
        return 'CredentialEnvelope(credentials=<redacted>)'

    __str__ = __repr__

    def metadata(self) -> dict:
        return dict(self.__metadata)

    def write_credential_process(self, stream: TextIO) -> None:
        """Write AWS credential_process v1 JSON to its dedicated private stdout."""
        json.dump({'Version': 1, 'AccessKeyId': self.__access_key, 'SecretAccessKey': self.__secret,
                   'SessionToken': self.__token, 'Expiration': self.__expiration}, stream,
                  sort_keys=True, separators=(',', ':'))
        stream.write('\n')


class STSAdapter:
    """STS issuance for approved immutable snapshots, with just-in-time IAM readback."""
    def __init__(self, client, *, iam_adapter: IAMAdapter):
        if client is None or iam_adapter is None:
            raise AWSAdapterError('explicit_sts_and_iam_clients_required')
        self._client, self._iam = client, iam_adapter

    def issue(self, role: RoleExpectation, scope: dict, account_id: str, region: str, *,
              expires_at: int, now: int, session_name: str, duration_seconds: int = 900,
              admin_tags: dict | None = None, grant_not_after: int | None = None) -> CredentialEnvelope:
        if not isinstance(role, RoleExpectation):
            raise AWSAdapterError('administrator_role_expectation_required')
        if type(now) is not int or type(expires_at) is not int or expires_at - now < 900:
            raise AWSAdapterError('less_than_sts_minimum_remaining')
        if type(duration_seconds) is not int or not 900 <= duration_seconds <= 3600:
            # A conservative role-chaining-safe ceiling; never silently clamp.
            raise AWSAdapterError('invalid_sts_duration')
        if duration_seconds > expires_at - now:
            raise AWSAdapterError('duration_exceeds_approved_cutoff')
        if not isinstance(session_name, str) or not re.fullmatch(r'[A-Za-z0-9_+=,.@-]{2,64}', session_name):
            raise AWSAdapterError('invalid_role_session_name')
        e = role.as_dict()
        if e['role_arn'].split(':')[4] != account_id:
            raise AWSAdapterError('role_account_mismatch')
        if duration_seconds > e['max_session_duration']:
            raise AWSAdapterError('duration_exceeds_role_maximum')
        if grant_not_after is not None:
            _timestamp(grant_not_after)
            if expires_at > grant_not_after:
                raise AWSAdapterError('session_exceeds_grant_cutoff')
        role_policy = compile_ec2(scope, account_id, region, not_after=grant_not_after, admin_tags=admin_tags)
        policy = compile_ec2(scope, account_id, region, not_after=expires_at, admin_tags=admin_tags)
        if e['inline_policies'] != {REVISION_POLICY_NAME: role_policy} or e['attached_policies']:
            raise AWSAdapterError('session_must_match_approved_revision_snapshot')
        packed = canonical(policy)
        if len(packed) > MAX_SESSION_POLICY_CHARACTERS:
            raise AWSAdapterError('session_policy_exceeds_2048_characters')
        _single_attempt_sdk(self._client)
        self._iam.observe_role(e['role_name'], role)
        try:
            response = self._client.assume_role(RoleArn=e['role_arn'], RoleSessionName=session_name,
                                                DurationSeconds=duration_seconds, Policy=packed)
        except Exception:
            raise AWSAdapterError('sts_assume_role_failed') from None
        if not isinstance(response, dict):
            raise AWSAdapterError('invalid_sts_response')
        principal = response.get('AssumedRoleUser', {})
        expected_principal = e['role_id'] + ':' + session_name
        expected_arn = 'arn:aws:sts::' + account_id + ':assumed-role/' + e['role_name'] + '/' + session_name
        if (not isinstance(principal, dict) or principal.get('AssumedRoleId') != expected_principal
                or principal.get('Arn') != expected_arn):
            raise AWSAdapterError('sts_role_identity_mismatch')
        credentials = response.get('Credentials', {})
        if not isinstance(credentials, dict):
            raise AWSAdapterError('invalid_sts_credentials')
        expiration = credentials.get('Expiration')
        if not isinstance(expiration, datetime) or expiration.tzinfo is None or expiration.timestamp() <= now:
            raise AWSAdapterError('invalid_sts_expiration')
        # Actual provider expiry may be slightly later than request-time + duration.
        # Absolute authorization ends at the immutable session-policy cutoff; lease
        # draining must nevertheless use the ACTUAL credential expiration returned.
        return CredentialEnvelope(credentials, role_arn=e['role_arn'], cutoff=expires_at,
                                  snapshot_sha256=hashlib.sha256(packed.encode()).hexdigest())
