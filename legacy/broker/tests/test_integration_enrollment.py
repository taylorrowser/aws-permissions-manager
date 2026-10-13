"""NON-LIVE key-bound coordinator enrollment. Fresh test-only P-256 keys."""
import base64
import dataclasses
import hashlib
import json
import secrets
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from integration.auth import AuthUnconfigured, AuthConfigurationError, Principal
from integration.enrollment import CoordinatorEnrollment, EnrollmentDenied, StandingTrust, binding_hash, jwk_thumbprint, fresh_key, make_proof, EMPTY_BODY_DIGEST

NOW = 1_800_000_000
REDEEM = 'https://broker.example.test/v1/runs/redeem'
REQUEST = 'https://broker.example.test/v1/credentials/lease'


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'offline.sqlite3'
        self.now = NOW
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        self.other_key = ec.generate_private_key(ec.SECP256R1())
        self.other_jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.other_key.public_key(), as_dict=True)
        self.principal = Principal('offline-subject', 'offline-owner', 'offline-client',
                                   'bearer_user', None, 'offline-authentication')
        self.trust = StandingTrust('offline-owner', 'offline-subject', 'offline-client',
                                   'offline-authentication', 'offline-connection', 3600)
        self.binding = dict(grant_id='grant_offline', revision=2, digest='a' * 64,
                            roles=['offline-role'], not_after=NOW + 4000)
        self.current = {**self.binding, 'state': 'active', 'owner_id': self.principal.owner_id,
                        'subject': self.principal.subject, 'client_id': self.principal.client_id}
        self.enrollment = self.make()

    def tearDown(self):
        self.tmp.cleanup()

    def make(self, **overrides):
        args = dict(configured=True, offline_mode=True, trust=(self.trust,),
                    active_grant=lambda grant_id: dict(self.current), redeem_url=REDEEM,
                    clock=lambda: self.now)
        args.update(overrides)
        return CoordinatorEnrollment(self.path, **args)

    def prepare(self, **overrides):
        args = dict(principal=self.principal, public_jwk=self.jwk,
                    grant_binding=self.binding, lifetime=1200, idempotency_key='offline-request-1')
        args.update(overrides)
        return self.enrollment.prepare(**args)

    def proof(self, prepared=None, run=None, *, key=None, jwk=None, method='POST', url=None,
              nonce=None, jti=None, claim_overrides=None, header_overrides=None):
        binding = self.binding
        claims = dict(htm=method, htu=url or (REDEEM if prepared else REQUEST), iat=self.now,
                      jti=jti or secrets.token_hex(16),
                      nonce=nonce or (prepared['challenge'] if prepared else run['nonce']),
                      binding_hash=binding_hash(binding), body_digest=EMPTY_BODY_DIGEST)
        claims['enrollment_id' if prepared else 'run_id'] = prepared['enrollment_id'] if prepared else run['run_id']
        claims.update(claim_overrides or {})
        header = {'typ': 'dpop+jwt', 'jwk': jwk or self.jwk}
        header.update(header_overrides or {})
        return jwt.encode(claims, key or self.key, algorithm='ES256', headers=header)

    def run_identity(self):
        prepared = self.prepare()
        return self.enrollment.redeem(prepared['enrollment_id'], self.proof(prepared=prepared))

    def validate(self, run, proof=None, **overrides):
        args = dict(run_id=run['run_id'], proof=proof or self.proof(run=run), method='POST',
                    url=REQUEST, nonce=run['nonce'], grant_binding=self.binding)
        args.update(overrides)
        return self.enrollment.validate_request(**args)

    def count(self, table):
        with sqlite3.connect(self.path) as db:
            return db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]

    def test_default_and_production_configuration_fail_closed_without_creating_database(self):
        other_path = Path(self.tmp.name) / 'unconfigured.sqlite3'
        provider = CoordinatorEnrollment(other_path)
        with self.assertRaises(AuthUnconfigured):
            provider.prepare(self.principal, self.jwk, self.binding, 30, 'offline-1')
        self.assertFalse(other_path.exists())
        with self.assertRaises(AuthUnconfigured):
            self.make(offline_mode=False)
        with self.assertRaises(AuthUnconfigured):
            self.make(active_grant=None)
        with self.assertRaises(AuthConfigurationError):
            self.make(trust=(self.trust, self.trust))

    def test_client_helper_generates_memory_only_key_and_real_verifiable_proofs(self):
        private, public = fresh_key()
        prepared = self.prepare(public_jwk=public)
        proof = make_proof(private, public, 'POST', REDEEM, prepared['challenge'],
                           self.binding, enrollment_id=prepared['enrollment_id'], clock=lambda: self.now)
        run = self.enrollment.redeem(prepared['enrollment_id'], proof)
        request = make_proof(private, public, 'POST', REQUEST, run['nonce'], self.binding,
                             run_id=run['run_id'], clock=lambda: self.now)
        self.validate(run, request)
        self.assertNotIn('PRIVATE KEY', repr(private))
        self.assertNotIn('d', public)
        self.assertEqual(set(Path(self.tmp.name).iterdir()), {self.path})
        with self.assertRaises(EnrollmentDenied):
            make_proof(private, self.other_jwk, 'POST', REDEEM, prepared['challenge'],
                       self.binding, enrollment_id=prepared['enrollment_id'])
        with self.assertRaises(EnrollmentDenied):
            make_proof(private, public, 'POST', REDEEM, prepared['challenge'], self.binding,
                       enrollment_id=prepared['enrollment_id'], run_id=run['run_id'])

    def test_narrowed_standing_lifetime_invalidates_existing_run(self):
        run = self.run_identity()
        self.enrollment = self.make(trust=(dataclasses.replace(self.trust, max_lifetime=1800),))
        with self.assertRaises(EnrollmentDenied):
            self.validate(run)

    def test_signed_body_digest_must_match_exact_route_request_body(self):
        prepared = self.prepare()
        body = hashlib.sha256(b'{"enrollment_id":"exact"}').hexdigest()
        proof = make_proof(self.key, self.jwk, 'POST', REDEEM, prepared['challenge'],
                           self.binding, enrollment_id=prepared['enrollment_id'],
                           body_digest=body, clock=lambda: self.now)
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.redeem(prepared['enrollment_id'], proof, body_digest=EMPTY_BODY_DIGEST)
        run = self.enrollment.redeem(prepared['enrollment_id'], proof, body_digest=body)
        request = make_proof(self.key, self.jwk, 'POST', REQUEST, run['nonce'], self.binding,
                             run_id=run['run_id'], body_digest=body, clock=lambda: self.now)
        with self.assertRaises(EnrollmentDenied):
            self.validate(run, request, body_digest='b' * 64)
        self.validate(run, request, body_digest=body)

    def test_explicit_trust_tuple_required_owner_subject_client_and_authentication(self):
        for fields in ({'owner_id': 'another'}, {'subject': 'another'}, {'client_id': 'another'},
                       {'authentication_id': 'thread_id_is_not_authentication'}, {'actor_kind': 'human_browser'}):
            with self.subTest(fields=list(fields)), self.assertRaises(EnrollmentDenied):
                self.prepare(principal=dataclasses.replace(self.principal, **fields))
        self.assertEqual(self.count('coordinator_enrollments'), 0)

    def test_rfc7638_thumbprint_uses_only_canonical_public_members(self):
        public = {key: self.jwk[key] for key in ('crv', 'kty', 'x', 'y')}
        encoded = json.dumps(public, sort_keys=True, separators=(',', ':')).encode()
        expected = base64.urlsafe_b64encode(hashlib.sha256(encoded).digest()).rstrip(b'=').decode()
        self.assertEqual(jwk_thumbprint(self.jwk), expected)
        self.assertEqual(jwk_thumbprint({**self.jwk, 'kid': 'ignored-metadata'}), expected)
        private = jwt.algorithms.ECAlgorithm.to_jwk(self.key, as_dict=True)
        for bad in (private, {**self.jwk, 'crv': 'P-384'}, {**self.jwk, 'use': 'enc'},
                    {**self.jwk, 'x': 'invalid'}, {**self.jwk, 'alg': 'HS256'}):
            with self.assertRaises(EnrollmentDenied):
                jwk_thumbprint(bad)

    def test_prepare_exact_idempotency_is_durable_but_conflicting_payload_denied(self):
        first = self.prepare()
        self.assertEqual(first, self.prepare())
        self.enrollment = self.make()
        self.assertEqual(first, self.prepare())
        for fields in ({'lifetime': 1100}, {'public_jwk': self.other_jwk}):
            with self.subTest(fields=list(fields)), self.assertRaises(EnrollmentDenied):
                self.prepare(**fields)
        self.assertEqual(self.count('coordinator_enrollments'), 1)
        self.assertFalse(first['machine_attestation'])
        self.assertEqual(first['authority']['grant_binding'], self.binding)

    def test_prepare_never_exceeds_grant_cutoff_or_standing_lifetime(self):
        for lifetime in (True, 0, 3601):
            with self.assertRaises(EnrollmentDenied):
                self.prepare(lifetime=lifetime)
        self.binding['not_after'] = NOW + 100
        self.current.update(self.binding)
        with self.assertRaises(EnrollmentDenied):
            self.prepare(lifetime=101)
        self.assertEqual(self.prepare(lifetime=100)['authority']['run_expires_at'], NOW + 100)

    def test_prepare_requires_current_active_exact_grant_and_ownership(self):
        original = dict(self.current)
        for fields in ({'state': 'revoked'}, {'revision': 3}, {'digest': 'b' * 64},
                       {'roles': ['different-role']}, {'not_after': NOW},
                       {'owner_id': 'other'}, {'subject': 'other'}, {'client_id': 'other'}):
            self.current = {**original, **fields}
            with self.subTest(fields=list(fields)), self.assertRaises(EnrollmentDenied):
                self.prepare()
        self.assertEqual(self.count('coordinator_enrollments'), 0)

    def test_redemption_requires_matching_key_and_atomic_one_time_challenge(self):
        prepared = self.prepare()
        wrong = self.proof(prepared=prepared, key=self.other_key, jwk=self.other_jwk)
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.redeem(prepared['enrollment_id'], wrong)
        proof = self.proof(prepared=prepared)
        run = self.enrollment.redeem(prepared['enrollment_id'], proof)
        self.assertEqual(run['key_thumbprint'], jwk_thumbprint(self.jwk))
        self.assertEqual(run['grant_binding'], self.binding)
        self.assertEqual(run['expires_at'], NOW + 1200)
        self.assertFalse(run['machine_attestation'])
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.redeem(prepared['enrollment_id'], proof)
        with self.assertRaises(EnrollmentDenied):
            self.prepare()
        self.assertEqual(self.count('coordinator_runs'), 1)

    def test_concurrent_redemption_creates_exactly_one_run_across_provider_instances(self):
        prepared = self.prepare()
        proof = self.proof(prepared=prepared)
        second = self.make()
        barrier = threading.Barrier(8)
        def redeem(i):
            barrier.wait()
            try:
                (self.enrollment if i % 2 else second).redeem(prepared['enrollment_id'], proof)
                return True
            except EnrollmentDenied:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(redeem, range(8))), 1)
        self.assertEqual(self.count('coordinator_runs'), 1)

    def test_redemption_rejects_expired_challenge_changed_grant_and_wrong_endpoint(self):
        prepared = self.prepare()
        proof = self.proof(prepared=prepared)
        for fields in ({'method': 'GET'}, {'url': 'https://different.example.test/redeem'}):
            with self.assertRaises(EnrollmentDenied):
                self.enrollment.redeem(prepared['enrollment_id'], proof, **fields)
        self.current['revision'] = 3
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.redeem(prepared['enrollment_id'], proof)
        self.current['revision'] = 2
        self.now += 120
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.redeem(prepared['enrollment_id'], proof)
        self.assertEqual(self.count('coordinator_runs'), 0)

    def test_request_proof_checks_signature_method_url_time_type_nonce_and_binding(self):
        run = self.run_identity()
        bad_claims = [{'htm': 'GET'}, {'htu': 'https://other.example.test/lease'},
                      {'iat': self.now + 1}, {'iat': self.now - 61}, {'iat': True},
                      {'nonce': 'x' * 43}, {'binding_hash': 'b' * 64},
                      {'run_id': 'run_other'}, {'jti': ''}, {'body_digest': 'b' * 64}]
        for fields in bad_claims:
            proof = self.proof(run=run, claim_overrides=fields)
            with self.subTest(fields=list(fields)), self.assertRaises(EnrollmentDenied):
                self.validate(run, proof)
        for fields in ({'typ': 'JWT'}, {'kid': 'forbidden'}, {'jku': 'https://attacker.example.test/jwk'}):
            with self.assertRaises(EnrollmentDenied):
                self.validate(run, self.proof(run=run, header_overrides=fields))
        with self.assertRaises(EnrollmentDenied):
            self.validate(run, self.proof(run=run, key=self.other_key))
        valid = self.validate(run)
        self.assertEqual(valid['run_id'], run['run_id'])

    def test_nonce_and_jti_replay_denied_after_restart(self):
        run = self.run_identity()
        proof = self.proof(run=run, jti='unique-proof-id')
        updated = self.validate(run, proof)
        self.enrollment = self.make()
        with self.assertRaises(EnrollmentDenied):
            self.validate(run, proof)
        with self.assertRaises(EnrollmentDenied):
            self.validate(updated, self.proof(run=updated, jti='unique-proof-id'))
        self.validate(updated, self.proof(run=updated))

    def test_nonce_cannot_be_moved_to_another_run_or_used_after_expiry(self):
        first = self.run_identity()
        prepared = self.prepare(idempotency_key='offline-request-2')
        second = self.enrollment.redeem(prepared['enrollment_id'], self.proof(prepared=prepared))
        moved = {**second, 'nonce': first['nonce']}
        with self.assertRaises(EnrollmentDenied):
            self.validate(moved)
        self.now += 60
        with self.assertRaises(EnrollmentDenied):
            self.validate(second)
        second['nonce'] = self.enrollment.issue_nonce(second['run_id'])
        self.validate(second)

    def test_concurrent_request_replay_has_one_winner(self):
        run = self.run_identity()
        proof = self.proof(run=run)
        barrier = threading.Barrier(8)
        def verify(_):
            barrier.wait()
            try:
                self.validate(run, proof)
                return True
            except EnrollmentDenied:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(verify, range(8))), 1)

    def test_run_read_is_pure_and_rechecks_revocation_expiration_grant(self):
        run = self.run_identity()
        before = self.path.read_bytes()
        self.assertEqual(self.enrollment.get_run(run['run_id'])['state'], 'active')
        self.assertEqual(self.path.read_bytes(), before)
        self.current['state'] = 'stopped'
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.get_run(run['run_id'])
        self.assertEqual(self.path.read_bytes(), before)
        self.current['state'] = 'active'
        self.now = run['expires_at']
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.get_run(run['run_id'])

    def test_grant_replacement_revision_digest_roles_and_owner_changes_invalidate_run(self):
        run = self.run_identity()
        original = dict(self.current)
        for fields in ({'revision': 3}, {'digest': 'b' * 64}, {'roles': ['other-role']},
                       {'owner_id': 'other'}, {'not_after': NOW + 2000}):
            self.current = {**original, **fields}
            with self.subTest(fields=list(fields)), self.assertRaises(EnrollmentDenied):
                self.validate(run)
        self.current = original
        with self.assertRaises(EnrollmentDenied):
            self.validate(run, grant_binding={**self.binding, 'revision': 3})

    def test_run_revocation_immediately_blocks_validate_renew_and_nonce(self):
        run = self.run_identity()
        other = dataclasses.replace(self.principal, authentication_id='other')
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.revoke_run(run['run_id'], other)
        self.enrollment.revoke_run(run['run_id'], self.principal)
        self.enrollment.revoke_run(run['run_id'], self.principal)
        with self.assertRaises(EnrollmentDenied):
            self.validate(run)
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.issue_nonce(run['run_id'])
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.renew(run['run_id'], self.proof(run=run), 'POST', REQUEST,
                                  run['nonce'], self.binding, 1200)

    def test_connection_revocation_blocks_pending_and_active_and_new_preparation(self):
        run = self.run_identity()
        prepared = self.prepare(idempotency_key='offline-request-2')
        self.enrollment.revoke_connection(self.trust.connection_id, self.principal)
        self.enrollment = self.make()
        for call in (lambda: self.validate(run),
                     lambda: self.enrollment.redeem(prepared['enrollment_id'], self.proof(prepared=prepared)),
                     lambda: self.prepare(idempotency_key='offline-request-3')):
            with self.assertRaises(EnrollmentDenied):
                call()

    def test_removing_configured_trust_invalidates_existing_run(self):
        run = self.run_identity()
        other = dataclasses.replace(self.trust, authentication_id='different-session')
        self.enrollment = self.make(trust=(other,))
        with self.assertRaises(EnrollmentDenied):
            self.validate(run)

    def test_renewal_is_key_bound_and_never_expands_original_authority(self):
        run = self.run_identity()
        self.now += 100
        run['nonce'] = self.enrollment.issue_nonce(run['run_id'])
        proof = self.proof(run=run)
        updated = self.enrollment.renew(run['run_id'], proof, 'POST', REQUEST,
                                       run['nonce'], self.binding, 1800)
        self.assertEqual(updated['expires_at'], NOW + 1900)
        self.assertEqual(updated['maximum_expires_at'], NOW + 3600)
        self.assertEqual(updated['grant_binding'], self.binding)
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.renew(updated['run_id'], self.proof(run=updated), 'POST', REQUEST,
                                  updated['nonce'], self.binding, 3600)
        with self.assertRaises(EnrollmentDenied):
            self.enrollment.renew(updated['run_id'], self.proof(run=updated), 'POST', REQUEST,
                                  updated['nonce'], {**self.binding, 'roles': ['other-role']}, 1800)

    def test_proof_failure_does_not_echo_secret_input_or_provider_errors(self):
        prepared = self.prepare()
        with self.assertRaisesRegex(EnrollmentDenied, '^invalid key-bound request proof$') as result:
            self.enrollment.redeem(prepared['enrollment_id'], 'private-data-not-a-proof')
        self.assertNotIn('private-data', str(result.exception))
        self.enrollment.active_grant = lambda _: (_ for _ in ()).throw(RuntimeError('sensitive-provider-detail'))
        with self.assertRaisesRegex(EnrollmentDenied, '^exact grant is no longer active$'):
            self.prepare()


if __name__ == '__main__':
    unittest.main()
