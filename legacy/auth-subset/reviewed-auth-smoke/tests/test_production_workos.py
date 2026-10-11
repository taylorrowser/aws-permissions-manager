"""All provider transports are offline stubs; no real IDs, tokens or network."""
import dataclasses
import io
import json
import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from integration.auth import (AuthConfigurationError, AuthError, AuthUnconfigured,
                              BearerVerifier, DeviceTokens, WorkOSConfig)
from integration.workos import (API_ORIGIN, AUTHENTICATE, DEVICE_AUTHORIZE,
    CachedBearerVerifier, InvocationApproval, IssuerPinnedJWKS, JWKSConfig,
    SDKCodeExchange, TransportConfig, WorkOSPending, WorkOSPublicClient,
    WorkOSReconnectRequired, WorkOSSlowDown, WorkOSTransient)

NOW = 1_800_000_000
ISSUER = 'https://offline-auth.example.test'
CLIENT = 'client_offline_cli'
SUBJECT = 'user_offline_owner'
VERIFY = ISSUER + '/device'
REFRESH = 'offline-refresh-fixture'
DEVICE = 'offline-device-fixture'


class Clock:
    def __init__(self): self.value = NOW
    def __call__(self): return self.value
    def advance(self, amount): self.value += amount


class WorkOSFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.jwk = jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key(), as_dict=True)
        cls.jwk.update(kid='offline-key-1', use='sig', alg='RS256')
        cls.jwk2 = jwt.algorithms.RSAAlgorithm.to_jwk(cls.other_key.public_key(), as_dict=True)
        cls.jwk2.update(kid='offline-key-2', use='sig', alg='RS256')

    def setUp(self):
        self.clock = Clock()
        self.config = WorkOSConfig(issuer=ISSUER, audience=None, owner_id='offline-owner',
            owner_subject=SUBJECT, allowed_client_ids=frozenset({CLIENT}),
            organization_mode='none', token_profile='session')
        self.tc = TransportConfig(ISSUER, CLIENT)
        self.verifier = BearerVerifier(self.config, {'keys': [self.jwk, self.jwk2]}, clock=self.clock)
        self.requests = []

    def token(self, *, key=None, kid='offline-key-1', **overrides):
        claims = dict(iss=ISSUER, sub=SUBJECT, client_id=CLIENT,
            sid='session_offline_1', iat=int(self.clock()), exp=int(self.clock()) + 300)
        claims.update(overrides)
        return jwt.encode(claims, key or self.private_key, algorithm='RS256', headers={'kid': kid})

    def token_body(self, **overrides):
        body = dict(access_token=self.token(), refresh_token=REFRESH,
            user={'object': 'user', 'id': SUBJECT, 'first_name': None, 'last_name': None,
                  'profile_picture_url': None, 'email': 'fixture@example.test',
                  'email_verified': True, 'external_id': None, 'last_sign_in_at': None,
                  'created_at': '2026-01-01T00:00:00Z', 'updated_at': '2026-01-01T00:00:00Z'})
        body.update(overrides)
        return body

    def start_body(self, **overrides):
        body = dict(device_code=DEVICE, user_code='ABCD-EFGH', verification_uri=VERIFY,
                    expires_in=300, interval=5)
        body.update(overrides)
        return body

    def transport(self, responses):
        queue = list(responses)
        def handle(request):
            self.requests.append(request)
            if not queue:
                raise AssertionError('unexpected offline provider request')
            item = queue.pop(0)
            if isinstance(item, Exception): raise item
            if callable(item): return item(request)
            status, body = item
            return httpx.Response(status, json=body)
        return httpx.MockTransport(handle)

    def client(self, responses, **kwargs):
        return WorkOSPublicClient(self.tc, self.verifier, VERIFY,
            transport=self.transport(responses), clock=self.clock, monotonic=self.clock, **kwargs)

    def login(self, client):
        challenge = client.start()
        self.clock.advance(challenge.interval)
        return client.poll(challenge.device_code)


class TransportGateTests(WorkOSFixtures):
    def test_default_real_dispatch_is_disabled_before_http_client_exists(self):
        client = WorkOSPublicClient(self.tc, self.verifier, VERIFY, clock=self.clock)
        with patch('integration.workos.httpx.Client') as factory:
            with self.assertRaises(AuthUnconfigured): client.start()
            factory.assert_not_called()

    def test_live_flag_alone_is_not_invocation_approval(self):
        client = WorkOSPublicClient(dataclasses.replace(self.tc, allow_live=True),
            self.verifier, VERIFY, clock=self.clock)
        with patch('integration.workos.httpx.Client') as factory:
            with self.assertRaises(AuthUnconfigured): client.start()
            factory.assert_not_called()

    def test_approval_is_bound_to_exact_issuer_client_operation_and_expiry(self):
        base = dict(issuer=ISSUER, client_id=CLIENT,
                    operations=frozenset({'device_start'}), expires_at=NOW + 60)
        for delta in ({'issuer': 'https://other.example.test'}, {'client_id': 'client_other'},
                      {'operations': frozenset({'refresh'})}, {'expires_at': NOW}):
            approval = InvocationApproval(**{**base, **delta})
            client = WorkOSPublicClient(dataclasses.replace(self.tc, allow_live=True),
                self.verifier, VERIFY, approval=approval, clock=self.clock)
            with patch('integration.workos.httpx.Client') as factory:
                with self.assertRaises(AuthUnconfigured): client.start()
                factory.assert_not_called()

    def test_real_transport_cannot_disguise_itself_as_offline(self):
        class OfflineLookingTransport(httpx.BaseTransport):
            def handle_request(self, request):
                raise AssertionError('transport should not be called')
        client = WorkOSPublicClient(self.tc, self.verifier, VERIFY,
                                   transport=OfflineLookingTransport(), clock=self.clock)
        with self.assertRaises(AuthUnconfigured): client.start()

    def test_configured_approved_path_still_uses_offline_transport_stub(self):
        response = self.start_body()
        class StubTransport(httpx.BaseTransport):
            def handle_request(self, request): return httpx.Response(200, json=response)
        client = WorkOSPublicClient(dataclasses.replace(self.tc, allow_live=True),
            self.verifier, VERIFY, transport=StubTransport(), clock=self.clock,
            approval=InvocationApproval(ISSUER, CLIENT, frozenset({'device_start'}), NOW + 60))
        self.assertEqual(client.start().verification_uri, VERIFY)

    def test_https_and_bounds_are_mandatory(self):
        for delta in ({'issuer': 'http://example.test'}, {'timeout_seconds': 0},
                      {'timeout_seconds': True}, {'max_response_bytes': 999999}):
            with self.assertRaises(AuthConfigurationError): dataclasses.replace(self.tc, **delta)


class PublicDeviceTests(WorkOSFixtures):
    def test_device_start_and_poll_exact_public_contract(self):
        c = self.client([(200, self.start_body()), (200, self.token_body())])
        tokens = self.login(c)
        self.assertEqual(tokens.identity_binding['authentication_kind'], 'authkit_session')
        self.assertEqual(tokens.identity_binding['authentication_id'], 'session_offline_1')
        self.assertEqual(tokens.expires_in, 295)
        self.assertEqual([str(r.url) for r in self.requests], [DEVICE_AUTHORIZE, AUTHENTICATE])
        fields = [parse_qs(r.content.decode()) for r in self.requests]
        self.assertEqual(set(fields[0]), {'client_id'})
        self.assertEqual(set(fields[1]), {'client_id', 'device_code', 'grant_type'})
        self.assertTrue(all('authorization' not in r.headers for r in self.requests))
        self.assertNotIn(REFRESH, repr(tokens))

    def test_local_pending_blocks_fast_poll_without_dispatch(self):
        c = self.client([(200, self.start_body())])
        c.start()
        with self.assertRaises(WorkOSPending) as cm: c.poll(DEVICE)
        self.assertEqual(cm.exception.next_interval, 5)
        self.assertEqual(len(self.requests), 1)

    def test_server_pending_and_slow_down_persist_for_later_polls(self):
        c = self.client([(200, self.start_body()), (400, {'error': 'authorization_pending'}),
                         (400, {'error': 'slow_down'}), (400, {'error': 'slow_down'})])
        c.start(); self.clock.advance(5)
        with self.assertRaises(WorkOSPending) as cm: c.poll(DEVICE)
        self.assertEqual(cm.exception.next_interval, 5)
        self.clock.advance(5)
        with self.assertRaises(WorkOSSlowDown) as cm: c.poll(DEVICE)
        self.assertEqual(cm.exception.next_interval, 10)
        self.clock.advance(5)
        with self.assertRaises(WorkOSPending): c.poll(DEVICE)
        self.assertEqual(len(self.requests), 3)
        self.clock.advance(5)
        with self.assertRaises(WorkOSSlowDown) as cm: c.poll(DEVICE)
        self.assertEqual(cm.exception.next_interval, 15)

    def test_expiry_and_unknown_device_fail_without_poll(self):
        c = self.client([(200, self.start_body(expires_in=5))])
        c.start(); self.clock.advance(5)
        with self.assertRaises(WorkOSReconnectRequired): c.poll(DEVICE)
        with self.assertRaises(WorkOSReconnectRequired): c.poll('unknown-fixture')
        self.assertEqual(len(self.requests), 1)

    def test_provider_denial_stops_future_polling(self):
        for error in ('access_denied', 'expired_token', 'unexpected'):
            self.requests = []
            c = self.client([(200, self.start_body()), (400, {'error': error})])
            c.start(); self.clock.advance(5)
            with self.assertRaises(WorkOSReconnectRequired): c.poll(DEVICE)
            self.clock.advance(5)
            with self.assertRaises(WorkOSReconnectRequired): c.poll(DEVICE)
            self.assertEqual(len(self.requests), 2)

    def test_verification_uri_and_response_types_are_pinned(self):
        for delta in ({'verification_uri': 'https://phishing.example.test/device'},
                      {'expires_in': True}, {'interval': 0}, {'user_code': 'BAD\nCODE'}):
            c = self.client([(200, self.start_body(**delta))])
            with self.assertRaises(AuthError): c.start()

    def test_poll_transient_does_not_destroy_pending_authorization(self):
        c = self.client([(200, self.start_body()), (503, {}), (200, self.token_body())])
        c.start(); self.clock.advance(5)
        with self.assertRaises(WorkOSTransient): c.poll(DEVICE)
        self.clock.advance(10)
        self.assertIsInstance(c.poll(DEVICE), DeviceTokens)

    def test_response_expired_during_dispatch_is_rejected(self):
        def delayed(request):
            self.clock.advance(400)
            return httpx.Response(200, json=self.token_body())
        c = self.client([(200, self.start_body()), delayed])
        with self.assertRaises(WorkOSReconnectRequired): self.login(c)

    def test_token_issuer_client_owner_org_sid_and_audience_are_verified(self):
        for delta in ({'iss': 'https://wrong.example.test'}, {'client_id': 'client_wrong'},
                      {'sub': 'user_wrong'}, {'org_id': 'org_wrong'}, {'sid': ''},
                      {'aud': 'wrong-resource'}, {'exp': NOW - 1}):
            c = self.client([(200, self.start_body()),
                             (200, self.token_body(access_token=self.token(**delta)))])
            with self.assertRaises(WorkOSReconnectRequired): self.login(c)

    def test_connect_profile_is_not_a_public_authkit_session_client(self):
        cfg = dataclasses.replace(self.config, token_profile='connect', audience='offline-resource')
        verifier = BearerVerifier(cfg, {'keys': [self.jwk]}, clock=self.clock)
        with self.assertRaises(AuthConfigurationError):
            WorkOSPublicClient(self.tc, verifier, VERIFY)

    def test_redirect_oversize_and_duplicate_json_are_refused(self):
        cases = [lambda r: httpx.Response(302, headers={'Location': 'https://other.example.test'}),
                 lambda r: httpx.Response(200, content=b'x' * 65537),
                 lambda r: httpx.Response(200, content=b'{"device_code":"a","device_code":"b"}')]
        for case in cases:
            self.requests = []
            c = self.client([case])
            with self.assertRaises(AuthError): c.start()
            self.assertEqual(len(self.requests), 1)

    def test_pending_memory_is_bounded(self):
        c = self.client([(200, self.start_body())], max_pending=1)
        c.start()
        with self.assertRaises(AuthError): c.start()
        self.assertEqual(len(self.requests), 1)


class SDKAndRefreshTests(WorkOSFixtures):
    def test_actual_sdk_pkce_has_exact_client_and_no_environment_api_key(self):
        exchange = SDKCodeExchange(self.tc, 'https://offline-web.example.test/callback',
            transport=self.transport([(200, self.token_body())]), clock=self.clock)
        with patch.dict(os.environ, {'WORKOS_API_KEY': 'offline-environment-sentinel',
                                     'WORKOS_BASE_URL': 'https://unexpected.example.test'}):
            result = exchange.exchange(code='offline-code', client_id=CLIENT,
                redirect_uri='https://offline-web.example.test/callback', code_verifier='v' * 43)
        body = json.loads(self.requests[0].content)
        self.assertEqual(set(body), {'grant_type', 'client_id', 'code', 'code_verifier'})
        self.assertEqual(body['client_id'], CLIENT)
        self.assertEqual(str(self.requests[0].url), AUTHENTICATE)
        self.assertNotIn('authorization', self.requests[0].headers)
        self.assertTrue(bool(result.access_token))
        self.assertNotIn(result.access_token, repr(result))

    def test_code_exchange_rejects_redirect_client_and_pkce_drift(self):
        ex = SDKCodeExchange(self.tc, 'https://offline-web.example.test/callback',
                             transport=self.transport([]), clock=self.clock)
        base = dict(code='offline-code', client_id=CLIENT,
                    redirect_uri='https://offline-web.example.test/callback', code_verifier='v' * 43)
        for delta in ({'client_id': 'client_other'}, {'redirect_uri': 'https://evil.example.test'},
                      {'code_verifier': 'short'}):
            with self.assertRaises(AuthError): ex.exchange(**{**base, **delta})
        self.assertFalse(self.requests)

    def test_code_sdk_stub_failures_are_sanitized(self):
        class BadSDK:
            user_management = None
            def __init__(self): self.user_management = self
            def authenticate_with_code_pkce(self, **kwargs): raise ValueError('SECRET-fixture-error')
        ex = SDKCodeExchange(self.tc, 'https://offline-web.example.test/callback', sdk=BadSDK(),
                             transport=self.transport([]), clock=self.clock)
        with self.assertRaises(AuthError) as cm:
            ex.exchange(code='offline-code', client_id=CLIENT,
                redirect_uri='https://offline-web.example.test/callback', code_verifier='v' * 43)
        self.assertNotIn('SECRET', str(cm.exception))

    def test_actual_sdk_refresh_rotation_preserves_identity_with_new_jti(self):
        c = self.client([(200, self.start_body()), (200, self.token_body()),
            (200, self.token_body(access_token=self.token(jti='new-audit-id'), refresh_token='rotated-fixture'))])
        old = self.login(c)
        rotated = c.refresh(old.refresh_token, expected_binding=old.identity_binding)
        self.assertTrue(rotated.refresh_token != old.refresh_token)
        self.assertEqual(rotated.identity_binding, old.identity_binding)
        body = json.loads(self.requests[-1].content)
        self.assertEqual(set(body), {'grant_type', 'client_id', 'refresh_token'})
        self.assertNotIn('authorization', self.requests[-1].headers)
        with self.assertRaises(WorkOSReconnectRequired): c.refresh(old.refresh_token)

    def test_refresh_accepts_trusted_prior_binding_after_restart_without_old_access(self):
        original = self.client([(200, self.start_body()), (200, self.token_body())])
        saved = self.login(original)
        self.clock.advance(400)  # Old access has expired; never use it as authority.
        restarted = self.client([(200, self.token_body(refresh_token='new-fixture'))])
        renewed = restarted.refresh(saved.refresh_token, expected_binding=saved.identity_binding)
        self.assertEqual(renewed.identity_binding, saved.identity_binding)
        with self.assertRaises(AuthError): self.verifier.verify(saved.access_token)

    def test_refresh_continuity_rejects_new_sid_even_same_owner_client(self):
        c = self.client([(200, self.start_body()), (200, self.token_body()),
            (200, self.token_body(access_token=self.token(sid='session_other'), refresh_token='rotated-fixture'))])
        saved = self.login(c)
        with self.assertRaises(WorkOSReconnectRequired): c.refresh(saved.refresh_token)
        with self.assertRaises(WorkOSReconnectRequired): c.refresh(saved.refresh_token)
        self.assertEqual(len(self.requests), 3)

    def test_refresh_expected_binding_rejects_config_drift_before_dispatch(self):
        c = self.client([])
        p = self.verifier.verify(self.token())
        for field, value in (('issuer', 'https://other.example.test'), ('subject', 'user_other'),
                             ('client_id', 'client_other'), ('organization_id', 'org_other'),
                             ('authentication_kind', 'connect_consent')):
            binding = {**dataclasses.asdict(p), field: value}
            with self.assertRaises(WorkOSReconnectRequired):
                c.refresh(REFRESH, expected_binding=binding)
        self.assertFalse(self.requests)

    def test_refresh_transients_retain_binding_but_never_extend_access_expiry(self):
        for failure in ((408, {}), (429, {}), (500, {}), (503, {}),
                        httpx.ConnectError('SECRET-network-fixture')):
            self.clock = Clock(); self.verifier.clock = self.clock
            c = self.client([(200, self.start_body()), (200, self.token_body()), failure,
                             (200, self.token_body(refresh_token='rotated-fixture'))])
            saved = self.login(c)
            self.clock.advance(400)
            with self.assertRaises(WorkOSTransient) as cm: c.refresh(saved.refresh_token)
            self.assertNotIn('SECRET', str(cm.exception))
            self.assertEqual(c.session_for(saved.refresh_token).subject, SUBJECT)
            with self.assertRaises(AuthError): self.verifier.verify(saved.access_token)

    def test_invalid_grant_terminal_discards_binding_and_no_automatic_retry(self):
        c = self.client([(200, self.start_body()), (200, self.token_body()),
                         (400, {'error': 'invalid_grant', 'error_description': 'SECRET-provider-body'})])
        saved = self.login(c)
        with self.assertRaises(WorkOSReconnectRequired) as cm: c.refresh(saved.refresh_token)
        self.assertNotIn('SECRET', str(cm.exception))
        with self.assertRaises(WorkOSReconnectRequired): c.refresh(saved.refresh_token)
        self.assertEqual(len(self.requests), 3)

    def test_provider_revoke_requires_verified_session_and_explicit_boundary(self):
        calls = []
        revoker = SimpleNamespace(revoke_session=lambda principal: calls.append(principal))
        c = self.client([(200, self.start_body()), (200, self.token_body())], revoker=revoker)
        saved = self.login(c)
        c.revoke(saved.refresh_token, expected_binding=saved.identity_binding)
        self.assertEqual(calls[0].authentication_id, 'session_offline_1')
        self.assertEqual(calls[0].authentication_kind, 'authkit_session')
        with self.assertRaises(WorkOSReconnectRequired): c.session_for(saved.refresh_token)
        restarted = self.client([], revoker=revoker)
        with self.assertRaises(WorkOSReconnectRequired):
            restarted.revoke(saved.refresh_token, expected_binding=saved.identity_binding)
        self.assertEqual(len(calls), 1)

    def test_missing_revoker_does_not_claim_logout_success(self):
        c = self.client([(200, self.start_body()), (200, self.token_body())],
                        sign_out_uri='https://offline-web.example.test/signed-out')
        saved = self.login(c)
        with self.assertRaises(AuthUnconfigured): c.revoke(saved.refresh_token)
        url = c.logout_url(saved.refresh_token, return_to='https://offline-web.example.test/signed-out')
        self.assertTrue(url.startswith(API_ORIGIN + '/user_management/sessions/logout?'))
        self.assertNotIn(saved.access_token, url)
        self.assertNotIn(saved.refresh_token, url)
        with self.assertRaises(AuthConfigurationError):
            c.logout_url(saved.refresh_token, return_to='https://other.example.test/signed-out')

    def test_success_and_failure_produce_no_token_or_error_output(self):
        output = io.StringIO()
        c = self.client([(200, self.start_body()), (200, self.token_body()),
                         (400, {'error': 'invalid_grant', 'error_description': 'SECRET-fixture'})])
        with redirect_stdout(output), redirect_stderr(output):
            tokens = self.login(c)
            with self.assertRaises(WorkOSReconnectRequired): c.refresh(tokens.refresh_token)
        self.assertEqual(output.getvalue(), '')


class JWKSCacheTests(WorkOSFixtures):
    def cache(self, responses, **kwargs):
        cfg = JWKSConfig(ISSUER, CLIENT, 'session', API_ORIGIN + '/sso/jwks/' + CLIENT, **kwargs)
        return IssuerPinnedJWKS(cfg, transport=self.transport(responses), clock=self.clock)

    def test_source_is_explicit_and_not_from_token_header(self):
        with self.assertRaises(AuthConfigurationError):
            JWKSConfig(ISSUER, CLIENT, 'session', 'https://evil.example.test/jwks')
        cache = self.cache([(200, {'keys': [self.jwk]})])
        verifier = CachedBearerVerifier(self.config, cache, clock=self.clock)
        bad = jwt.encode(dict(iss=ISSUER), self.private_key, algorithm='RS256',
                         headers={'kid': 'offline-key-1', 'jku': 'https://evil.example.test/jwks'})
        with self.assertRaises(AuthError): verifier.verify(bad)
        self.assertFalse(self.requests)
        self.assertEqual(verifier.verify(self.token()).client_id, CLIENT)
        self.assertEqual(str(self.requests[0].url), API_ORIGIN + '/sso/jwks/' + CLIENT)

    def test_cache_hit_avoids_network_and_unknown_kid_is_throttled(self):
        cache = self.cache([(200, {'keys': [self.jwk]})])
        cache.for_kid('offline-key-1'); cache.for_kid('offline-key-1')
        for _ in range(20):
            with self.assertRaises(AuthError): cache.for_kid('offline-unknown')
        self.assertEqual(len(self.requests), 1)

    def test_rotation_replaces_old_key_set(self):
        cache = self.cache([(200, {'keys': [self.jwk]}), (200, {'keys': [self.jwk2]})])
        verifier = CachedBearerVerifier(self.config, cache, clock=self.clock)
        verifier.verify(self.token())
        self.clock.advance(5)
        verifier.verify(self.token(key=self.other_key, kid='offline-key-2'))
        with self.assertRaises(AuthError): verifier.verify(self.token())
        self.assertEqual(len(self.requests), 2)

    def test_expired_cache_fails_closed_during_outage(self):
        cache = self.cache([(200, {'keys': [self.jwk]}), (503, {})], ttl_seconds=10)
        verifier = CachedBearerVerifier(self.config, cache, clock=self.clock)
        token = self.token()
        verifier.verify(token); self.clock.advance(10)
        with self.assertRaises(WorkOSTransient): verifier.verify(token)
        with self.assertRaises(AuthError): verifier.verify(token)
        self.assertEqual(len(self.requests), 2)

    def test_concurrent_cache_miss_fetches_only_once(self):
        cache = self.cache([(200, {'keys': [self.jwk]})])
        with ThreadPoolExecutor(max_workers=8) as pool:
            result = list(pool.map(lambda _: cache.for_kid('offline-key-1'), range(20)))
        self.assertEqual(len(result), 20)
        self.assertEqual(len(self.requests), 1)

    def test_duplicate_private_weak_wrong_algorithm_and_oversize_key_sets_fail(self):
        for keys in ([self.jwk, self.jwk], [{**self.jwk, 'd': 'private-fixture'}],
                     [{**self.jwk, 'p': 'private-fixture'}], [{**self.jwk, 'alg': 'HS256'}],
                     [{**self.jwk, 'key_ops': ['sign']}], [{**self.jwk, 'n': 'a' * 1401}], []):
            cache = self.cache([(200, {'keys': keys})])
            with self.assertRaises(AuthError): cache.for_kid('offline-key-1')

    def test_connect_and_authkit_key_sources_cannot_be_mixed(self):
        cfg = JWKSConfig(ISSUER, CLIENT, 'connect', ISSUER + '/oauth2/jwks')
        keys = IssuerPinnedJWKS(cfg, transport=self.transport([]), clock=self.clock)
        with self.assertRaises(AuthConfigurationError): CachedBearerVerifier(self.config, keys)


if __name__ == '__main__': unittest.main()

class ReviewFixTests(WorkOSFixtures):
    def test_invalid_grant_evidence_is_narrow_provider_response_only(self):
        from integration.workos import WorkOSInvalidGrant
        for status,body,positive in ((400,{'error':'invalid_grant'},True),(403,{'error':'invalid_grant'},False),(400,{'error':'invalid_request'},False),(200,{'unexpected':'SECRET'},False)):
            c=self.client([(200,self.start_body()),(200,self.token_body()),(status,body)]);saved=self.login(c)
            with self.assertRaises(WorkOSReconnectRequired) as caught:c.refresh(saved.refresh_token)
            self.assertEqual(isinstance(caught.exception,WorkOSInvalidGrant),positive)
        c=self.client([])
        with self.assertRaises(WorkOSReconnectRequired) as caught:c.refresh('unknown-local-token')
        self.assertNotIsInstance(caught.exception,WorkOSInvalidGrant)
    def test_rotated_pair_survives_jwks_outage_without_repeating_refresh(self):
        cfg=JWKSConfig(ISSUER,CLIENT,'session',API_ORIGIN+'/sso/jwks/'+CLIENT,ttl_seconds=300)
        cache=IssuerPinnedJWKS(cfg,transport=self.transport([(200,{'keys':[self.jwk]}),(503,{}),(200,{'keys':[self.jwk2]})]),clock=self.clock)
        self.verifier=CachedBearerVerifier(self.config,cache,clock=self.clock)
        c=self.client([(200,self.start_body()),(200,self.token_body()),lambda r:httpx.Response(200,json=self.token_body(access_token=self.token(key=self.other_key,kid='offline-key-2'),refresh_token='unique-rotated-refresh'))])
        old=self.login(c);self.clock.advance(301)
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token,expected_binding=old.identity_binding)
        self.assertEqual(c.session_for(old.refresh_token).subject,SUBJECT);self.assertEqual(len(c._unverified),1)
        with self.assertRaises(AuthError):self.verifier.verify(old.access_token)
        exchanges=lambda:sum(1 for r in self.requests if r.method=='POST' and r.headers.get('content-type','').startswith('application/json') and json.loads(r.content).get('grant_type')=='refresh_token')
        self.assertEqual(exchanges(),1);self.clock.advance(5)
        renewed=c.refresh(old.refresh_token,expected_binding=old.identity_binding)
        self.assertEqual(renewed.refresh_token,'unique-rotated-refresh');self.assertEqual(exchanges(),1);self.assertFalse(c._unverified)
    def test_pending_candidate_is_bounded_and_clearable(self):
        class FailingVerifier:
            def __init__(self,base):self.base=base;self.config=base.config;self.calls=0
            def verify_details(self,token):
                self.calls+=1
                if self.calls>1:raise WorkOSTransient()
                return self.base.verify_details(token)
        self.verifier=FailingVerifier(self.verifier)
        c=self.client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(refresh_token='pending-rotated-secret'))]);old=self.login(c)
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token)
        self.assertNotIn('pending-rotated-secret',repr(c._unverified));self.clock.advance(301)
        with self.assertRaises(WorkOSReconnectRequired):c.refresh(old.refresh_token)
        self.assertFalse(c._unverified);c.clear_memory();self.assertFalse(c._pending);self.assertFalse(c._sessions)
    def test_same_principal_refresh_cannot_grow_session_map(self):
        c=self.client([(200,self.start_body()),(200,self.token_body()),*[(200,self.token_body(refresh_token='rotated-'+str(i))) for i in range(5)]],max_sessions=1)
        saved=self.login(c)
        for i in range(5):
            c.refresh('another-old-token-'+str(i),expected_binding=saved.identity_binding)
            self.assertLessEqual(len(c._sessions),1)
    def test_session_signing_client_is_separate_from_expected_token_client(self):
        signing='client_environment_signing';url=API_ORIGIN+'/sso/jwks/'+signing
        cfg=JWKSConfig(ISSUER,CLIENT,'session',url,signing_client_id=signing)
        cache=IssuerPinnedJWKS(cfg,transport=self.transport([(200,{'keys':[self.jwk]})]),clock=self.clock)
        verifier=CachedBearerVerifier(self.config,cache,clock=self.clock)
        self.assertEqual(verifier.verify(self.token()).client_id,CLIENT);self.assertEqual(str(self.requests[-1].url),url)
        with self.assertRaises(AuthError):verifier.verify(self.token(client_id=signing))
        with self.assertRaises(AuthConfigurationError):JWKSConfig(ISSUER,CLIENT,'session',url)
    def test_compressed_response_rejected_before_decoded_body(self):
        import gzip
        reads=[]
        def handle(request):
            self.assertEqual(request.headers['accept-encoding'],'identity')
            return httpx.Response(200,headers={'Content-Encoding':'gzip'},content=gzip.compress(b'x'*100000))
        c=WorkOSPublicClient(self.tc,self.verifier,VERIFY,transport=httpx.MockTransport(handle),clock=self.clock,monotonic=self.clock)
        with self.assertRaisesRegex(AuthError,'compressed'):c.start()
    def test_successful_cache_cooldown_preserves_new_rotation_candidate(self):
        cfg=JWKSConfig(ISSUER,CLIENT,'session',API_ORIGIN+'/sso/jwks/'+CLIENT)
        cache=IssuerPinnedJWKS(cfg,transport=self.transport([(200,{'keys':[self.jwk]}),(200,{'keys':[self.jwk2]})]),clock=self.clock)
        self.verifier=CachedBearerVerifier(self.config,cache,clock=self.clock)
        c=self.client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(access_token=self.token(key=self.other_key,kid='offline-key-2'),refresh_token='rotation-during-cooldown'))])
        old=self.login(c)
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token)
        self.assertEqual(len(c._unverified),1);self.clock.advance(5)
        new=c.refresh(old.refresh_token);self.assertEqual(new.refresh_token,'rotation-during-cooldown');self.assertFalse(c._unverified)
    def test_revoke_drops_unverified_candidates_and_blocks_local_rebind(self):
        from types import SimpleNamespace
        class Flaky:
            def __init__(self,base):self.base=base;self.config=base.config;self.block=False
            def verify_details(self,token):
                if self.block:raise WorkOSTransient()
                return self.base.verify_details(token)
        self.verifier=Flaky(self.verifier);calls=[]
        c=self.client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(refresh_token='revoked-candidate'))],revoker=SimpleNamespace(revoke_session=lambda p:calls.append(p)))
        old=self.login(c);self.verifier.block=True
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token)
        self.assertTrue(c._unverified);c.revoke(old.refresh_token);self.assertFalse(c._unverified);self.assertFalse(c._sessions);self.assertEqual(len(calls),1)
        self.verifier.block=False
        with self.assertRaises(WorkOSReconnectRequired):c.bind_tokens(old)
