"""Offline AWS compiler/adapters, including real botocore shapes and Stubber.

SDK tests use explicitly synthetic credentials and never implicit auth discovery.
Run with PYTHONPATH=/tmp/permission-broker-sdk:. when the optional SDK is installed.
"""
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

from integration.aws import (AWSAdapterError, compile_ec2, canonical, IAMAdapter,
                             STSAdapter, RoleExpectation, CredentialEnvelope, REVISION_POLICY_NAME)
try:
    import boto3
    from botocore.stub import Stubber
    from botocore.config import Config
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False

ACCOUNT = '123456789012'
REGION = 'us-east-1'
INSTANCE = f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0123456789abcdef0'
ROLE_NAME = 'broker-r000001'
ROLE_ARN = f'arn:aws:iam::{ACCOUNT}:role/broker-revisions/{ROLE_NAME}'
ROLE_ID = 'AROA1234567890EXAMPLE1'
BOUNDARY_ARN = f'arn:aws:iam::{ACCOUNT}:policy/broker-ceiling'
NOW = 1800000000
EXPIRES = NOW + 1800
SCOPE = {'actions': ['ec2:DescribeInstances', 'ec2:StopInstances'], 'instance_arns': [INSTANCE]}
TRUST = {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
          'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT}:role/broker-vendor'}}]}
BOUNDARY_POLICY = compile_ec2(SCOPE, ACCOUNT, REGION)


def expectation(*, scope=None, cutoff=None, empty=False, attached=None):
    return RoleExpectation(ROLE_NAME, ROLE_ARN, ROLE_ID, TRUST,
        {'arn': BOUNDARY_ARN, 'version_id': 'v1', 'document': BOUNDARY_POLICY},
        {} if empty else {REVISION_POLICY_NAME: compile_ec2(scope or SCOPE, ACCOUNT, REGION, not_after=cutoff)},
        attached or {})


def role_response(expected=None):
    e = (expected or expectation()).as_dict()
    return {'Role': {'Path': '/broker-revisions/', 'RoleName': e['role_name'], 'RoleId': e['role_id'],
            'Arn': e['role_arn'], 'CreateDate': datetime.fromtimestamp(NOW - 5000, timezone.utc),
            'AssumeRolePolicyDocument': e['trust_policy'], 'MaxSessionDuration': e['max_session_duration'],
            'PermissionsBoundary': {'PermissionsBoundaryType': 'PermissionsBoundaryPolicy',
                                    'PermissionsBoundaryArn': e['boundary']['arn']}}}


def fake_iam(expected=None):
    e = (expected or expectation()).as_dict()
    client = Mock()
    client.get_role.return_value = role_response(expected)
    client.list_role_policies.return_value = {'PolicyNames': list(e['inline_policies']), 'IsTruncated': False}
    client.get_role_policy.side_effect = lambda **k: {'RoleName': k['RoleName'], 'PolicyName': k['PolicyName'],
                                                   'PolicyDocument': e['inline_policies'][k['PolicyName']]}
    client.list_attached_role_policies.return_value = {'AttachedPolicies': [{'PolicyArn': arn} for arn in e['attached_policies']], 'IsTruncated': False}
    snapshots = {**e['attached_policies'], e['boundary']['arn']: e['boundary']}
    client.get_policy.side_effect = lambda **k: {'Policy': {'Arn': k['PolicyArn'], 'DefaultVersionId': snapshots[k['PolicyArn']]['version_id']}}
    client.get_policy_version.side_effect = lambda **k: {'PolicyVersion': {'VersionId': k['VersionId'], 'IsDefaultVersion': True,
            'Document': snapshots[k['PolicyArn']]['document']}}
    return client


def sts_response(session='lease-123', expiration=EXPIRES):
    return {'Credentials': {'AccessKeyId': 'ASIA' + 'SYNTHETIC0' * 2, 'SecretAccessKey': 'synthetic-secret-value-only',
                           'SessionToken': 'synthetic-session-token-only',
                           'Expiration': datetime.fromtimestamp(expiration, timezone.utc)},
            'AssumedRoleUser': {'AssumedRoleId': ROLE_ID + ':' + session,
                               'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE_NAME}/{session}'}}


def issue(sts=None, iam=None, role=None, scope=None, **changes):
    client = sts or Mock()
    client.assume_role.return_value = sts_response()
    expected = role or expectation()
    kwargs = {'expires_at': EXPIRES, 'now': NOW, 'session_name': 'lease-123', 'duration_seconds': 900}
    kwargs.update(changes)
    return STSAdapter(client, iam_adapter=IAMAdapter(iam or fake_iam(expected))).issue(
        expected, scope or SCOPE, ACCOUNT, REGION, **kwargs)


class CompilerTests(unittest.TestCase):
    def test_describe_is_explicitly_regional_inventory(self):
        p = compile_ec2({'actions': ['ec2:DescribeInstances', 'ec2:DescribeInstanceStatus'], 'instance_arns': [INSTANCE]}, ACCOUNT, REGION,
                        admin_tags={'Project': 'plants'})
        s = p['Statement'][0]
        self.assertEqual(s['Resource'], '*')
        self.assertEqual(s['Condition'], {'StringEquals': {'aws:RequestedRegion': REGION}})
        self.assertNotIn('Project', canonical(p))

    def test_mutations_exact_and_administrator_tags_conjunctive(self):
        p = compile_ec2({'actions': ['ec2:RebootInstances', 'ec2:StartInstances', 'ec2:StopInstances'], 'instance_arns': [INSTANCE]}, ACCOUNT, REGION,
                        admin_tags={'Project': 'plants', 'Environment': 'preview'})
        s = p['Statement'][0]
        self.assertEqual(s['Resource'], [INSTANCE])
        self.assertEqual(s['Condition']['StringEquals']['ec2:ResourceTag/Project'], 'plants')
        self.assertEqual(s['Condition']['StringEquals']['ec2:ResourceTag/Environment'], 'preview')

    def test_absolute_cutoff_is_explicit_deny_inclusive(self):
        p = compile_ec2(SCOPE, ACCOUNT, REGION, not_after=EXPIRES)
        s = p['Statement'][-1]
        self.assertEqual(s['Effect'], 'Deny')
        self.assertEqual((s['Action'], s['Resource']), ('*', '*'))
        self.assertEqual(s['Condition'], {'DateGreaterThanEquals': {'aws:CurrentTime': '2027-01-15T08:30:00Z'}})

    def test_scope_rejects_unknown_fields_policy_tags_and_wildcards(self):
        for key in ('policy', 'admin_tags', 'conditions', 'owner', 'boundary', 'role_arn', 'not_after'):
            with self.subTest(key=key), self.assertRaises(AWSAdapterError):
                compile_ec2({**SCOPE, key: '*'}, ACCOUNT, REGION)
        for action in ('*', 'ec2:*', 'ec2:Describe*', 'ec2:RunInstances', 'ec2:TerminateInstances', 'iam:PassRole', 'ssm:SendCommand', 'EC2:StopInstances'):
            with self.subTest(action=action), self.assertRaises(AWSAdapterError):
                compile_ec2({**SCOPE, 'actions': [action]}, ACCOUNT, REGION)

    def test_instance_mismatch_malformed_duplicate_unbounded(self):
        bad = ['*', INSTANCE.replace(ACCOUNT, '999999999999'), INSTANCE.replace(REGION, 'us-west-2'),
               INSTANCE.replace('arn:aws:', 'arn:aws-us-gov:'), INSTANCE.replace('instance/', 'volume/'),
               INSTANCE.replace('abcdef0', '*'), INSTANCE + ':suffix', INSTANCE.upper()]
        for arn in bad:
            with self.subTest(arn=arn), self.assertRaises(AWSAdapterError):
                compile_ec2({**SCOPE, 'instance_arns': [arn]}, ACCOUNT, REGION)
        for arns in ([], [INSTANCE, INSTANCE], [INSTANCE] * 21, 'not-a-list'):
            with self.subTest(arns=arns), self.assertRaises(AWSAdapterError):
                compile_ec2({**SCOPE, 'instance_arns': arns}, ACCOUNT, REGION)

    def test_type_and_tag_injection_fail_closed(self):
        for actions in ([], ['ec2:StopInstances'] * 2, None, 'ec2:StopInstances', [dict()]):
            with self.subTest(actions=actions), self.assertRaises(AWSAdapterError):
                compile_ec2({**SCOPE, 'actions': actions}, ACCOUNT, REGION)
        for tags in ({'aws:owner': 'x'}, {'Project': '${aws:username}'}, {'Project': '*'}, {'Project': ['x']}, {'': 'x'}, {'Project': 'a\nb'}):
            with self.subTest(tags=tags), self.assertRaises(AWSAdapterError):
                compile_ec2(SCOPE, ACCOUNT, REGION, admin_tags=tags)
        for cutoff in (True, -1, 0, '123', 10**50):
            with self.subTest(cutoff=cutoff), self.assertRaises(AWSAdapterError):
                compile_ec2(SCOPE, ACCOUNT, REGION, not_after=cutoff)

    def test_compiler_deterministic_and_does_not_mutate_input(self):
        scope = deepcopy(SCOPE)
        reversed_scope = {**scope, 'actions': list(reversed(scope['actions']))}
        self.assertEqual(compile_ec2(scope, ACCOUNT, REGION), compile_ec2(reversed_scope, ACCOUNT, REGION))
        self.assertEqual(scope, SCOPE)

    def test_review_template_has_four_roles_and_impossible_rule(self):
        path = Path(__file__).parents[1] / 'integration/infrastructure/review-only.template.json'
        template = json.loads(path.read_text())
        self.assertIs(template['Metadata']['DeploymentReady'], False)
        self.assertEqual(set(template['Resources']), {'RequestRuntimeRole', 'OwnerDecisionRuntimeRole', 'PermissionExecutorRuntimeRole', 'AssumeOnlyVendorRuntimeRole'})
        assertion = template['Rules']['DeploymentIsIntentionallyBlocked']['Assertions'][0]['Assert']['Fn::Equals']
        self.assertNotIn(assertion[1], template['Parameters'][assertion[0]['Ref']]['AllowedValues'])
        for name in ('RequestRuntimeRole', 'OwnerDecisionRuntimeRole', 'AssumeOnlyVendorRuntimeRole'):
            statements = template['Resources'][name]['Properties']['Policies'][0]['PolicyDocument']['Statement']
            allowed = [s['Action'] for s in statements if s['Effect'] == 'Allow']
            self.assertNotIn('iam:PutRolePolicy', canonical(allowed))


class AdapterBoundaryTests(unittest.TestCase):
    def test_constructors_do_not_lookup_credentials_or_call_provider(self):
        c = Mock()
        IAMAdapter(c)
        STSAdapter(c, iam_adapter=IAMAdapter(c))
        self.assertEqual(c.mock_calls, [])
        with self.assertRaises(AWSAdapterError):
            IAMAdapter(None)

    def test_unknown_role_cannot_be_adopted(self):
        c = fake_iam()
        with self.assertRaises(AWSAdapterError):
            IAMAdapter(c).observe_role(ROLE_NAME, None)
        c.get_role.assert_not_called()
        c.get_role.return_value['Role']['RoleId'] = 'AROA9999999999EXAMPLE1'
        with self.assertRaisesRegex(AWSAdapterError, 'identity_drift'):
            IAMAdapter(c).observe_role(ROLE_NAME, expectation())
        c.put_role_policy.assert_not_called()

    def test_observation_exact_trust_boundary_inline_and_managed_union(self):
        e = expectation()
        self.assertEqual(IAMAdapter(fake_iam()).observe_role(ROLE_NAME, e).fingerprint, e.fingerprint)
        for kind in ('trust', 'boundary', 'inline', 'attached', 'version', 'duration'):
            c = fake_iam()
            if kind == 'trust':
                c.get_role.return_value['Role']['AssumeRolePolicyDocument'] = {'Version': '2012-10-17', 'Statement': []}
            elif kind == 'boundary':
                del c.get_role.return_value['Role']['PermissionsBoundary']
            elif kind == 'inline':
                c.list_role_policies.return_value['PolicyNames'] = []
            elif kind == 'attached':
                arn = f'arn:aws:iam::{ACCOUNT}:policy/extra'
                c.list_attached_role_policies.return_value['AttachedPolicies'] = [{'PolicyArn': arn}]
                c.get_policy.side_effect = lambda **k: {'Policy': {'Arn': k['PolicyArn'], 'DefaultVersionId': 'v1'}}
                c.get_policy_version.side_effect = lambda **k: {'PolicyVersion': {'VersionId': 'v1', 'IsDefaultVersion': True, 'Document': BOUNDARY_POLICY}}
            elif kind == 'version':
                c.get_policy.side_effect = lambda **k: {'Policy': {'Arn': k['PolicyArn'], 'DefaultVersionId': 'v2'}}
            else:
                c.get_role.return_value['Role']['MaxSessionDuration'] = 7200
            with self.subTest(kind=kind), self.assertRaises(AWSAdapterError):
                IAMAdapter(c).observe_role(ROLE_NAME, e)
            c.put_role_policy.assert_not_called()

    def test_boundary_document_change_without_version_change_detected(self):
        c = fake_iam()
        c.get_policy_version.side_effect = lambda **k: {'PolicyVersion': {'VersionId': 'v1', 'IsDefaultVersion': True,
            'Document': {'Version': '2012-10-17', 'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]}}}
        with self.assertRaisesRegex(AWSAdapterError, 'drift'):
            IAMAdapter(c).observe_role(ROLE_NAME, expectation())

    def test_expectation_copies_mutable_configuration(self):
        trust = deepcopy(TRUST)
        expected = RoleExpectation(ROLE_NAME, ROLE_ARN, ROLE_ID, trust,
            {'arn': BOUNDARY_ARN, 'version_id': 'v1', 'document': BOUNDARY_POLICY}, {}, {})
        trust['Statement'].clear()
        copy = expected.as_dict()
        copy['trust_policy']['Statement'].clear()
        self.assertEqual(expected.as_dict()['trust_policy'], TRUST)

    def test_pagination_is_complete_or_rejected(self):
        c = fake_iam()
        c.list_role_policies.side_effect = [{'PolicyNames': [], 'IsTruncated': True, 'Marker': 'page2'},
                                           {'PolicyNames': [REVISION_POLICY_NAME], 'IsTruncated': False}]
        IAMAdapter(c).observe_role(ROLE_NAME, expectation())
        self.assertEqual(c.list_role_policies.call_args.kwargs['Marker'], 'page2')
        for page in ({'PolicyNames': [], 'IsTruncated': True}, {'PolicyNames': [], 'IsTruncated': True, 'Marker': 'repeat'}):
            c = fake_iam()
            c.list_role_policies.return_value = page
            with self.assertRaisesRegex(AWSAdapterError, 'incomplete'):
                IAMAdapter(c).observe_role(ROLE_NAME, expectation())

    def test_attached_managed_policy_is_observed_with_exact_version_and_document(self):
        arn = f'arn:aws:iam::{ACCOUNT}:policy/extra-reviewed'
        e = expectation(attached={arn: {'version_id': 'v9', 'document': BOUNDARY_POLICY}})
        c = fake_iam(e)
        IAMAdapter(c).observe_role(ROLE_NAME, e)
        c.get_policy_version.assert_any_call(PolicyArn=arn, VersionId='v9')
        c.assume_role.assert_not_called()
        with self.assertRaisesRegex(AWSAdapterError, 'snapshot'):
            issue(role=e)

    def test_automatic_sdk_retries_are_rejected_for_writes_and_sts(self):
        c = fake_iam(expectation(empty=True))
        c.meta.config.retries = {'mode': 'standard', 'total_max_attempts': 3}
        with self.assertRaisesRegex(AWSAdapterError, 'single_attempt'):
            IAMAdapter(c).apply_initial_policy(expectation(empty=True), SCOPE, ACCOUNT, REGION)
        c.put_role_policy.assert_not_called()
        c = Mock()
        c.meta.config.retries = {'mode': 'legacy'}
        with self.assertRaisesRegex(AWSAdapterError, 'single_attempt'):
            issue(sts=c)
        c.assume_role.assert_not_called()

    def test_malformed_sts_response_is_sanitized(self):
        for response in (None, {'AssumedRoleUser': []}, {**sts_response(), 'Credentials': None}):
            c = Mock()
            c.assume_role.side_effect = lambda response=response, **k: response
            with self.subTest(kind=type(response).__name__), self.assertRaises(AWSAdapterError):
                issue(sts=c)

    def test_existing_nonempty_revision_never_overwritten(self):
        c = fake_iam()
        with self.assertRaisesRegex(AWSAdapterError, 'must_be_empty'):
            IAMAdapter(c).apply_initial_policy(expectation(), SCOPE, ACCOUNT, REGION)
        c.put_role_policy.assert_not_called()
        c.get_role.assert_not_called()

    def test_apply_error_is_uncertain_and_never_retried(self):
        e = expectation(empty=True)
        c = fake_iam(e)
        c.put_role_policy.side_effect = RuntimeError('SENSITIVE raw provider body')
        with self.assertRaisesRegex(AWSAdapterError, '^iam_put_role_policy_failed$'):
            IAMAdapter(c).apply_initial_policy(e, SCOPE, ACCOUNT, REGION, grant_not_after=EXPIRES)
        self.assertEqual(c.put_role_policy.call_count, 1)

    def test_sts_approved_snapshot_cutoff_and_output_redaction(self):
        c = Mock()
        envelope = issue(sts=c)
        args = c.assume_role.call_args.kwargs
        self.assertEqual(set(args), {'RoleArn', 'RoleSessionName', 'DurationSeconds', 'Policy'})
        self.assertEqual(json.loads(args['Policy']), compile_ec2(SCOPE, ACCOUNT, REGION, not_after=EXPIRES))
        self.assertEqual(args['DurationSeconds'], 900)
        self.assertNotIn('synthetic-secret', repr(envelope))
        self.assertNotIn('synthetic-session', canonical(envelope.metadata()))
        with self.assertRaises(TypeError):
            json.dumps(envelope)
        out = io.StringIO()
        envelope.write_credential_process(out)
        body = json.loads(out.getvalue())
        self.assertEqual(body['Version'], 1)
        self.assertEqual(body['SecretAccessKey'], 'synthetic-secret-value-only')
        self.assertEqual(set(body), {'Version', 'AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'})

    def test_sts_ongoing_role_can_issue_different_pinned_lease_expiries(self):
        e = expectation()
        first, second = Mock(), Mock()
        issue(sts=first, role=e)
        issue(sts=second, role=e, expires_at=EXPIRES + 900)
        self.assertNotEqual(first.assume_role.call_args.kwargs['Policy'], second.assume_role.call_args.kwargs['Policy'])
        self.assertNotIn('AbsoluteNotAfter', canonical(e.as_dict()['inline_policies']))

    def test_sts_temporary_grant_bounds_and_snapshot_mismatch(self):
        e = expectation(cutoff=EXPIRES + 900)
        issue(role=e, grant_not_after=EXPIRES + 900)
        for kwargs in ({'grant_not_after': EXPIRES - 1}, {'grant_not_after': None}, {'scope': {**SCOPE, 'actions': ['ec2:StartInstances']}}):
            c = Mock()
            with self.subTest(kwargs=kwargs), self.assertRaises(AWSAdapterError):
                issue(sts=c, role=e, **kwargs)
            c.assume_role.assert_not_called()

    def test_sts_minimum_duration_invalid_type_and_chain_maximum(self):
        for kwargs in ({'expires_at': NOW + 899}, {'duration_seconds': 899}, {'duration_seconds': True},
                       {'duration_seconds': 3601}, {'duration_seconds': 2000}, {'now': 'bad'},
                       {'session_name': 'x'}, {'session_name': 'space name'}):
            c = Mock()
            with self.subTest(kwargs=kwargs), self.assertRaises(AWSAdapterError):
                issue(sts=c, **kwargs)
            c.assume_role.assert_not_called()

    def test_sts_rejects_policy_over_plaintext_limit(self):
        scope = {'actions': sorted(SCOPE['actions']), 'instance_arns': [f'arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-{i:017x}' for i in range(20)]}
        # Add administrator conditions so the resulting snapshot exceeds 2048.
        tags = {'Project': 'p' * 200, 'Environment': 'e' * 200}
        e = expectation(scope=scope).as_dict()
        e['inline_policies'] = {REVISION_POLICY_NAME: compile_ec2(scope, ACCOUNT, REGION, admin_tags=tags)}
        c = Mock()
        with self.assertRaisesRegex(AWSAdapterError, '2048'):
            issue(sts=c, role=RoleExpectation(**e), scope=scope, admin_tags=tags)
        c.assume_role.assert_not_called()

    def test_drift_blocks_sts_before_issuance(self):
        c = Mock()
        iam = fake_iam()
        iam.get_role.return_value['Role']['RoleId'] = 'AROA9999999999EXAMPLE1'
        with self.assertRaisesRegex(AWSAdapterError, 'identity_drift'):
            issue(sts=c, iam=iam)
        c.assume_role.assert_not_called()

    def test_raw_provider_errors_and_credentials_do_not_escape(self):
        c = Mock()
        c.assume_role.side_effect = RuntimeError('synthetic-secret-value-only')
        with self.assertRaisesRegex(AWSAdapterError, '^sts_assume_role_failed$'):
            issue(sts=c)

    def test_sts_wrong_assumed_role_id_rejected(self):
        c = Mock()
        response = sts_response()
        response['AssumedRoleUser']['AssumedRoleId'] = 'AROA9999999999EXAMPLE1:lease-123'
        c.assume_role.side_effect = lambda **k: response
        with self.assertRaisesRegex(AWSAdapterError, 'role_identity_mismatch'):
            issue(sts=c)


@unittest.skipUnless(SDK_AVAILABLE, 'Install optional boto3 for actual SDK Stubber verification')
class SDKStubberTests(unittest.TestCase):
    def setUp(self):
        # Both explicit credential arguments are synthetic. Invalid endpoint +
        # patched transport prohibit accidental provider networking even on bugs.
        self.transport = patch('botocore.httpsession.URLLib3Session.send', side_effect=AssertionError('network prohibited'))
        self.transport.start()
        self.addCleanup(self.transport.stop)
        self.iam = boto3.client('iam', region_name=REGION, aws_access_key_id='SYNTHETIC_TEST_ONLY',
                                aws_secret_access_key='SYNTHETIC_TEST_ONLY', endpoint_url='https://aws.invalid', config=Config(retries={'total_max_attempts': 1}))
        self.sts = boto3.client('sts', region_name=REGION, aws_access_key_id='SYNTHETIC_TEST_ONLY',
                                aws_secret_access_key='SYNTHETIC_TEST_ONLY', endpoint_url='https://aws.invalid', config=Config(retries={'total_max_attempts': 1}))
        self.iam_stub, self.sts_stub = Stubber(self.iam), Stubber(self.sts)
        self.iam_stub.activate()
        self.sts_stub.activate()
        self.addCleanup(self.iam_stub.deactivate)
        self.addCleanup(self.sts_stub.deactivate)

    def queue_observation(self, expected, *, encoded=False):
        e = expected.as_dict()
        response = role_response(expected)
        response['Role']['AssumeRolePolicyDocument'] = quote(canonical(TRUST), safe='') if encoded else canonical(TRUST)
        self.iam_stub.add_response('get_role', response, {'RoleName': ROLE_NAME})
        self.iam_stub.add_response('list_role_policies', {'PolicyNames': list(e['inline_policies']), 'IsTruncated': False}, {'RoleName': ROLE_NAME})
        for name, policy in e['inline_policies'].items():
            self.iam_stub.add_response('get_role_policy', {'RoleName': ROLE_NAME, 'PolicyName': name,
                'PolicyDocument': quote(canonical(policy), safe='') if encoded else canonical(policy)}, {'RoleName': ROLE_NAME, 'PolicyName': name})
        self.iam_stub.add_response('list_attached_role_policies', {'AttachedPolicies': [], 'IsTruncated': False}, {'RoleName': ROLE_NAME})
        self.iam_stub.add_response('get_policy', {'Policy': {'Arn': BOUNDARY_ARN, 'DefaultVersionId': 'v1'}}, {'PolicyArn': BOUNDARY_ARN})
        self.iam_stub.add_response('get_policy_version', {'PolicyVersion': {'VersionId': 'v1', 'IsDefaultVersion': True,
            'Document': canonical(BOUNDARY_POLICY)}}, {'PolicyArn': BOUNDARY_ARN, 'VersionId': 'v1'})

    def test_real_sdk_iam_and_sts_shapes_credential_process(self):
        e = expectation()
        self.queue_observation(e, encoded=True)
        self.sts_stub.add_response('assume_role', sts_response(), {'RoleArn': ROLE_ARN, 'RoleSessionName': 'lease-123', 'DurationSeconds': 900,
            'Policy': canonical(compile_ec2(SCOPE, ACCOUNT, REGION, not_after=EXPIRES))})
        env = STSAdapter(self.sts, iam_adapter=IAMAdapter(self.iam)).issue(e, SCOPE, ACCOUNT, REGION,
            expires_at=EXPIRES, now=NOW, session_name='lease-123')
        self.assertEqual(env.metadata()['credential_expiration'], '2027-01-15T08:30:00Z')
        self.iam_stub.assert_no_pending_responses()
        self.sts_stub.assert_no_pending_responses()

    def test_real_sdk_initial_empty_revision_write_and_readback(self):
        before, after = expectation(empty=True), expectation(cutoff=EXPIRES)
        self.queue_observation(before)
        self.iam_stub.add_response('put_role_policy', {}, {'RoleName': ROLE_NAME, 'PolicyName': REVISION_POLICY_NAME,
            'PolicyDocument': canonical(after.as_dict()['inline_policies'][REVISION_POLICY_NAME])})
        self.queue_observation(after)
        actual = IAMAdapter(self.iam).apply_initial_policy(before, SCOPE, ACCOUNT, REGION, grant_not_after=EXPIRES)
        self.assertEqual(actual.fingerprint, after.fingerprint)
        self.iam_stub.assert_no_pending_responses()

    def test_real_sdk_packed_size_denial_sanitized(self):
        e = expectation()
        self.queue_observation(e)
        self.sts_stub.add_client_error('assume_role', service_error_code='PackedPolicyTooLarge', service_message='synthetic-sensitive-details',
            http_status_code=400, expected_params={'RoleArn': ROLE_ARN, 'RoleSessionName': 'lease-123', 'DurationSeconds': 900,
                'Policy': canonical(compile_ec2(SCOPE, ACCOUNT, REGION, not_after=EXPIRES))})
        with self.assertRaisesRegex(AWSAdapterError, '^sts_assume_role_failed$'):
            STSAdapter(self.sts, iam_adapter=IAMAdapter(self.iam)).issue(e, SCOPE, ACCOUNT, REGION,
                expires_at=EXPIRES, now=NOW, session_name='lease-123')
        self.sts_stub.assert_no_pending_responses()

    def test_real_sdk_unknown_role_error_does_not_create_or_write(self):
        self.iam_stub.add_client_error('get_role', service_error_code='NoSuchEntity', http_status_code=404,
            expected_params={'RoleName': ROLE_NAME})
        with self.assertRaisesRegex(AWSAdapterError, '^iam_get_role_failed$'):
            IAMAdapter(self.iam).observe_role(ROLE_NAME, expectation())
        self.iam_stub.assert_no_pending_responses()


if __name__ == '__main__':
    unittest.main()
