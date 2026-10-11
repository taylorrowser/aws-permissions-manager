"""Offline RSA fixtures only. No WorkOS/AWS network, real IDs or credentials."""
import base64
import dataclasses
import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from integration.auth import (
    AuthConfigurationError, AuthError, AuthUnconfigured, BearerVerifier,
    BrowserAuth, BrowserConfig, CodeExchangeResult, DeviceAuthorization,
    DeviceTokens, Principal, UnconfiguredCodeExchange, UnconfiguredDeviceAuth,
    WorkOSConfig,
)

NOW = 1_800_000_000
ISSUER = 'https://offline-auth.example.test'
ORIGIN = 'http://127.0.0.1:8765'
OWNER = 'offline-owner'
SUBJECT = 'user_offline_owner'
WEB = 'client_offline_browser'
CLI = 'client_offline_cli'
MACHINE = 'client_offline_machine'
RESOURCE = 'https://offline-api.example.test'
ENVIRONMENT = 'client_offline_environment'
DIGEST = 'a' * 64


class OfflineCodeExchange:
    def __init__(self, token):
        self.token = token
        self.calls = []

    def exchange(self, **kwargs):
        self.calls.append(kwargs)
        return CodeExchangeResult(self.token)


class AuthFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key = jwt.algorithms.RSAAlgorithm.to_jwk(cls.private_key.public_key(), as_dict=True)
        key.update(kid='offline-test-signing-key', use='sig', alg='RS256')
        cls.jwks = {'keys': [key]}

    def setUp(self):
        self.now = NOW

    def config(self, **overrides):
        args = dict(issuer=ISSUER, audience=RESOURCE, owner_id=OWNER,
                    owner_subject=SUBJECT, allowed_client_ids=frozenset({WEB, CLI, MACHINE}),
                    organization_mode='none', machine_client_ids=frozenset({MACHINE}),
                    machine_audience=ENVIRONMENT)
        args.update(overrides)
        return WorkOSConfig(**args)

    def verifier(self, **overrides):
        return BearerVerifier(self.config(**overrides), self.jwks, clock=lambda: self.now)

    def claims(self, **overrides):
        args = dict(iss=ISSUER, aud=RESOURCE, sub=SUBJECT, client_id=CLI,
                    sid='offline-consent', jti='offline-token-id', iat=NOW, exp=NOW + 300)
        args.update(overrides)
        return args

    def token(self, claims=None, *, key=None, headers=None, **overrides):
        claims = self.claims(**overrides) if claims is None else claims
        return jwt.encode(claims, key or self.private_key, algorithm='RS256',
                          headers=headers or {'kid': 'offline-test-signing-key'})

    def browser(self, *, exchange=None, offline_mode=False):
        verifier = self.verifier(audience=None, allowed_client_ids=frozenset({WEB, CLI}),
                                 machine_client_ids=frozenset(), machine_audience=None,
                                 token_profile='session')
        config = BrowserConfig(WEB, ORIGIN, ORIGIN + '/auth/callback',
                               ISSUER + '/user_management/authorize', production=False)
        return BrowserAuth(config, verifier, exchange, offline_mode=offline_mode,
                           clock=lambda: self.now)

    def session_claims(self, **overrides):
        claims = self.claims(client_id=WEB, sid='offline-session', **overrides)
        claims.pop('aud', None)
        return claims

    def login(self, browser=None):
        token = self.token(self.session_claims())
        browser = browser or self.browser(exchange=OfflineCodeExchange(token))
        start = browser.start_login()
        state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        login = browser.finish_login(code='offline-code', state=state, state_cookie=start.state_cookie)
        return browser, login, browser.human_session(login.session_cookie)


class BearerVerificationTests(AuthFixtures):
    def test_unconfigured_defaults_fail_closed(self):
        for verifier in (BearerVerifier(), BearerVerifier(self.config())):
            with self.assertRaises(AuthUnconfigured):
                verifier.verify('fixture-does-not-authenticate')

    def test_signed_user_token_mapped_owner_and_no_scope_entitlement(self):
        token = self.token(scope='openid admin aws:*', owner_id='attacker', actor_kind='human_browser')
        principal = self.verifier().verify(token)
        self.assertEqual(principal, Principal(SUBJECT, OWNER, CLI, 'bearer_user', None, 'offline-token-id'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            principal.actor_kind = 'human_browser'
        self.assertNotIn(token, repr(principal))
        self.assertFalse(hasattr(principal, 'scopes'))

    def test_exact_bearer_header(self):
        verifier, token = self.verifier(), self.token()
        self.assertEqual(verifier.verify_authorization('Bearer ' + token).client_id, CLI)
        for header in (None, '', token, 'Basic ' + token, 'bearer ' + token,
                       'Bearer  ' + token, 'Bearer ' + token + '\n'):
            with self.subTest(header_type=type(header).__name__), self.assertRaises(AuthError):
                verifier.verify_authorization(header)

    def test_wrong_app_same_issuer_and_owner_denied(self):
        with self.assertRaises(AuthError):
            self.verifier().verify(self.token(client_id='client_unapproved_same_environment'))

    def test_wrong_issuer_audience_subject_and_missing_claims_denied(self):
        wrong = [dict(iss=ISSUER + '/'), dict(aud=ENVIRONMENT), dict(aud=[RESOURCE]),
                 dict(sub='user_other'), dict(exp=True), dict(iat=str(NOW)),
                 dict(jti=''), dict(sid=''), dict(client_id=['bad']), dict(org_id=None)]
        for change in wrong:
            with self.subTest(fields=list(change)), self.assertRaises(AuthError):
                self.verifier().verify(self.token(**change))
        for field in ('iss', 'aud', 'sub', 'client_id', 'sid', 'jti', 'exp', 'iat'):
            claims = self.claims()
            claims.pop(field)
            with self.subTest(missing=field), self.assertRaises(AuthError):
                self.verifier().verify(self.token(claims))

    def test_time_contract_expiry_future_issue_nbf_and_excessive_lifetime(self):
        for change in (dict(exp=NOW), dict(iat=NOW + 1), dict(nbf=NOW + 1),
                       dict(nbf=True), dict(exp=NOW - 1), dict(exp=NOW + 3601),
                       dict(iat=NOW + 100, exp=NOW + 99)):
            with self.subTest(fields=list(change)), self.assertRaises(AuthError):
                self.verifier().verify(self.token(**change))
        self.now = NOW + 300
        with self.assertRaises(AuthError):
            self.verifier().verify(self.token())

    def test_config_requires_explicit_org_and_machine_environment_audience(self):
        for change in (dict(organization_mode='infer'), dict(organization_id='org_guessed'),
                       dict(organization_mode='required'), dict(machine_audience=None),
                       dict(audience=None), dict(clock_skew_seconds=61), dict(allowed_client_ids=CLI)):
            with self.subTest(fields=list(change)), self.assertRaises(AuthConfigurationError):
                self.config(**change)

    def test_exact_org_binding_and_no_org_contract(self):
        org_verifier = self.verifier(organization_mode='required', organization_id='org_offline')
        self.assertEqual(org_verifier.verify(self.token(org_id='org_offline')).organization_id, 'org_offline')
        for verifier, token in ((self.verifier(), self.token(org_id='org_offline')),
                                (org_verifier, self.token()),
                                (org_verifier, self.token(org_id='org_other'))):
            with self.assertRaises(AuthError):
                verifier.verify(token)

    def test_machine_subject_and_environment_audience(self):
        claims = self.claims(sub=MACHINE, client_id=MACHINE, aud=ENVIRONMENT)
        claims.pop('sid')
        principal = self.verifier().verify(self.token(claims))
        self.assertEqual(principal.actor_kind, 'machine')
        self.assertEqual(principal.owner_id, OWNER)
        for change in ({'sub': SUBJECT}, {'aud': RESOURCE}, {'sid': 'not-a-human-session'}):
            with self.subTest(fields=list(change)), self.assertRaises(AuthError):
                self.verifier().verify(self.token({**claims, **change}))

    def test_signature_kid_and_algorithm_enforcement(self):
        tokens = [self.token(key=self.foreign_key),
                  self.token(headers={'kid': 'unknown-key'}),
                  self.token(headers={'kid': 'offline-test-signing-key', 'jku': 'https://attacker.invalid/jwks'}),
                  self.token(headers={'kid': 'offline-test-signing-key', 'crit': []}),
                  jwt.encode(self.claims(), 'not-an-rsa-key-and-not-a-secret-00000000', algorithm='HS256',
                             headers={'kid': 'offline-test-signing-key'}),
                  jwt.encode(self.claims(), '', algorithm='none'), 'not-a-token']
        for token in tokens:
            with self.subTest(prefix=token[:8]), self.assertRaisesRegex(AuthError, '^invalid bearer token$'):
                self.verifier().verify(token)

    def test_key_set_rejects_private_duplicate_nonsigning_and_wrong_algorithm(self):
        private = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key, as_dict=True)
        private['kid'] = 'offline-private-key'
        valid = self.jwks['keys'][0]
        for keys in ([], [valid, valid], [private], [{**valid, 'use': 'enc'}],
                     [{**valid, 'alg': 'RS512'}], [{**valid, 'key_ops': ['sign']}],
                     [{**valid, 'kid': ''}]):
            with self.subTest(count=len(keys)), self.assertRaises(AuthConfigurationError):
                BearerVerifier(self.config(), {'keys': keys})

    def test_session_profile_uses_its_exact_observed_claim_contract(self):
        verifier = self.browser().token_verifier
        token = self.token(self.session_claims())
        self.assertEqual(verifier.verify(token).actor_kind, 'bearer_user')
        for claim in ({'aud': RESOURCE}, {'act': {'sub': 'admin@example.test'}}, {'impersonator': {}}):
            with self.subTest(fields=list(claim)), self.assertRaises(AuthError):
                verifier.verify(self.token({**self.session_claims(), **claim}))
        with self.assertRaises(AuthError):
            self.verifier().verify(token)


class BrowserAuthenticationTests(AuthFixtures):
    def test_browser_defaults_exchange_and_production_persistence_unconfigured(self):
        browser = BrowserAuth()
        for call in (browser.start_login, lambda: browser.human_session('unused')):
            with self.assertRaises(AuthUnconfigured):
                call()
        with self.assertRaises(AuthUnconfigured):
            self.browser().start_login()
        with self.assertRaisesRegex(AuthUnconfigured, 'durable atomic session store'):
            BrowserAuth(BrowserConfig(WEB, 'https://broker.example.test',
                        'https://broker.example.test/callback', ISSUER + '/authorize'))
        with self.assertRaises(AuthUnconfigured):
            UnconfiguredCodeExchange().exchange(code='secret', client_id=WEB,
                redirect_uri=ORIGIN + '/callback', code_verifier='secret')

    def test_production_cookie_policy_and_offline_label(self):
        browser = BrowserAuth()
        self.assertEqual(browser.cookie_name, '__Host-broker')
        self.assertEqual(browser.cookie_options['path'], '/')
        self.assertTrue(browser.cookie_options['secure'])
        self.assertTrue(browser.cookie_options['httponly'])
        self.assertEqual(browser.cookie_options['samesite'], 'strict')
        self.assertNotIn('domain', browser.cookie_options)
        self.assertEqual(browser.state_cookie_options['samesite'], 'lax')
        self.assertIn('offline', self.browser().cookie_name)

    def test_auth_url_binds_exact_client_redirect_state_and_s256_pkce(self):
        exchange = OfflineCodeExchange(self.token(self.session_claims()))
        browser = self.browser(exchange=exchange)
        start = browser.start_login()
        params = parse_qs(urlsplit(start.authorization_url).query)
        self.assertEqual(params['client_id'], [WEB])
        self.assertEqual(params['redirect_uri'], [ORIGIN + '/auth/callback'])
        self.assertEqual(params['code_challenge_method'], ['S256'])
        self.assertEqual(params['max_age'], ['0'])
        self.assertNotIn('code_verifier', params)
        login = browser.finish_login(code='offline-code', state=params['state'][0], state_cookie=start.state_cookie)
        exchanged = exchange.calls[0]
        expected = base64.urlsafe_b64encode(hashlib.sha256(exchanged['code_verifier'].encode()).digest()).rstrip(b'=').decode()
        self.assertEqual(params['code_challenge'], [expected])
        self.assertEqual(exchanged['client_id'], WEB)
        self.assertEqual(exchanged['redirect_uri'], ORIGIN + '/auth/callback')
        self.assertEqual(login.principal.actor_kind, 'human_browser')
        self.assertEqual(login.expires_at, NOW + 300)  # bounded by verified token expiry
        for secret in (start.state_cookie, params['state'][0], login.session_cookie, login.csrf):
            self.assertNotIn(secret, repr(start) + repr(login))

    def test_callback_bad_signature_does_not_create_browser_session(self):
        token = self.token(self.session_claims(), key=self.foreign_key)
        browser = self.browser(exchange=OfflineCodeExchange(token))
        start = browser.start_login()
        state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        with self.assertRaises(AuthError):
            browser.finish_login(code='offline-code', state=state, state_cookie=start.state_cookie)
        self.assertEqual(len(browser._sessions), 0)

    def test_state_cookie_callback_replay_is_denied(self):
        browser = self.browser(exchange=OfflineCodeExchange(self.token(self.session_claims())))
        start = browser.start_login()
        state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        browser.finish_login(code='offline-code', state=state, state_cookie=start.state_cookie)
        with self.assertRaises(AuthError):
            browser.finish_login(code='offline-code', state=state, state_cookie=start.state_cookie)

    def test_wrong_state_cookie_and_expired_login_never_exchange(self):
        for mode in ('wrong_state', 'wrong_cookie', 'expired'):
            with self.subTest(mode=mode):
                exchange = OfflineCodeExchange(self.token(self.session_claims()))
                browser = self.browser(exchange=exchange)
                start = browser.start_login()
                state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
                if mode == 'expired':
                    self.now += 301
                with self.assertRaises(AuthError):
                    browser.finish_login(code='offline-code',
                        state='x' * 43 if mode == 'wrong_state' else state,
                        state_cookie='x' * 43 if mode == 'wrong_cookie' else start.state_cookie)
                self.assertEqual(exchange.calls, [])
                self.now = NOW

    def test_callback_exact_browser_client_owner_signature_and_impersonation(self):
        cases = [{'client_id': CLI}, {'sub': 'user_other'},
                 {'act': {'sub': 'admin@example.test'}}, {'org_id': 'org_other'}]
        for change in cases:
            with self.subTest(fields=list(change)):
                token = self.token({**self.session_claims(), **change})
                browser = self.browser(exchange=OfflineCodeExchange(token))
                start = browser.start_login()
                state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
                with self.assertRaises(AuthError):
                    browser.finish_login(code='offline-code', state=state, state_cookie=start.state_cookie)
                self.assertEqual(len(browser._sessions), 0)

    def test_provider_failure_is_sanitized(self):
        class BadProvider:
            def exchange(self, **kwargs):
                raise RuntimeError('sensitive-provider-token-and-code')
        browser = self.browser(exchange=BadProvider())
        start = browser.start_login()
        state = parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        with self.assertRaisesRegex(AuthError, '^invalid browser login callback$') as result:
            browser.finish_login(code='sensitive-code', state=state, state_cookie=start.state_cookie)
        self.assertTrue(result.exception.__suppress_context__)

    def test_same_owner_bearer_and_constructed_session_cannot_approve(self):
        browser, login, session = self.login()
        bearer = self.verifier().verify(self.token())
        for fake in (bearer, login.principal, dataclasses.replace(session), login.session_cookie):
            with self.subTest(type=type(fake).__name__), self.assertRaises(AuthError):
                browser.new_challenge(fake, 'req-offline', 1, DIGEST)
        with self.assertRaises(AuthError):
            browser.human_session(self.token())

    def test_challenge_exact_binding_and_replay(self):
        browser, login, session = self.login()
        challenge = browser.new_challenge(session, 'req-offline', 1, DIGEST)
        result = browser.consume_challenge(session, ORIGIN, login.csrf, challenge,
                                           'req-offline', 1, DIGEST)
        self.assertEqual(result, login.principal)
        with self.assertRaises(AuthError):
            browser.consume_challenge(session, ORIGIN, login.csrf, challenge, 'req-offline', 1, DIGEST)

    def test_challenge_rejects_other_request_revision_digest_origin_and_csrf(self):
        browser, login, session = self.login()
        mutations = [{'request_id': 'req-other'}, {'revision': 2}, {'digest': 'b' * 64},
                     {'origin': 'http://evil.example.test'}, {'csrf': 'x' * 43},
                     {'revision': True}, {'digest': '*'}]
        for mutation in mutations:
            challenge = browser.new_challenge(session, 'req-offline', 1, DIGEST)
            kwargs = dict(session=session, origin=ORIGIN, csrf=login.csrf,
                          challenge=challenge, request_id='req-offline', revision=1, digest=DIGEST)
            kwargs.update(mutation)
            with self.subTest(fields=list(mutation)), self.assertRaises(AuthError):
                browser.consume_challenge(**kwargs)

    def test_challenge_bound_to_specific_browser_session(self):
        browser, login, first = self.login()
        _, second_login, second = self.login(browser)
        challenge = browser.new_challenge(first, 'req-offline', 1, DIGEST)
        with self.assertRaises(AuthError):
            browser.consume_challenge(second, ORIGIN, second_login.csrf, challenge, 'req-offline', 1, DIGEST)

    def test_concurrent_challenge_replay_has_exactly_one_winner(self):
        browser, login, session = self.login()
        challenge = browser.new_challenge(session, 'req-offline', 1, DIGEST)
        barrier = threading.Barrier(8)
        def consume(_):
            barrier.wait()
            try:
                browser.consume_challenge(session, ORIGIN, login.csrf, challenge, 'req-offline', 1, DIGEST)
                return True
            except AuthError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(consume, range(8))), 1)

    def test_expired_challenge_and_browser_session_denied(self):
        browser, login, session = self.login()
        challenge = browser.new_challenge(session, 'req-offline', 1, DIGEST)
        self.now += 60
        with self.assertRaises(AuthError):
            browser.consume_challenge(session, ORIGIN, login.csrf, challenge, 'req-offline', 1, DIGEST)
        self.now = login.expires_at
        with self.assertRaises(AuthError):
            browser.human_session(login.session_cookie)
        with self.assertRaises(AuthError):
            browser.new_challenge(session, 'req-offline', 1, DIGEST)

    def test_logout_destroys_session_and_pending_approval_challenges(self):
        browser, login, session = self.login()
        challenge = browser.new_challenge(session, 'req-offline', 1, DIGEST)
        browser.logout(login.session_cookie)
        with self.assertRaises(AuthError):
            browser.human_session(login.session_cookie)
        with self.assertRaises(AuthError):
            browser.consume_challenge(session, ORIGIN, login.csrf, challenge, 'req-offline', 1, DIGEST)
        browser.logout(login.session_cookie)

    def test_fixture_login_requires_explicit_internal_offline_opt_in(self):
        principal = Principal(SUBJECT, OWNER, WEB, 'bearer_user', None, 'offline-test-only')
        with self.assertRaises(AuthUnconfigured):
            self.browser().fixture_login(principal)
        browser = self.browser(offline_mode=True)
        login = browser.fixture_login(principal)
        self.assertEqual(browser.human_session(login.session_cookie).principal.actor_kind, 'human_browser')
        for override in ({'owner_id': 'other-owner'}, {'subject': 'other-subject'},
                         {'client_id': CLI}, {'actor_kind': 'machine'}):
            with self.subTest(fields=list(override)), self.assertRaises(AuthError):
                browser.fixture_login(dataclasses.replace(principal, **override))

    def test_connect_token_profile_cannot_back_browser_callback(self):
        browser = self.browser(exchange=OfflineCodeExchange(self.token(client_id=WEB)))
        browser.token_verifier = self.verifier()
        with self.assertRaises(AuthConfigurationError):
            browser.start_login()

    def test_browser_configuration_refuses_cross_origin_redirect_and_unbounded_ttls(self):
        for override in ({'redirect_uri': 'http://127.0.0.1:8765.evil.test/callback'},
                         {'origin': ORIGIN + '/'}, {'session_ttl': 901},
                         {'authorization_endpoint': ISSUER + '/authorize?client_id=bad'},
                         {'redirect_uri': ORIGIN + '/callback#leak'},
                         {'authorization_endpoint': ISSUER + '/\nauthorize'}):
            args = dict(client_id=WEB, origin=ORIGIN, redirect_uri=ORIGIN + '/callback',
                        authorization_endpoint=ISSUER + '/authorize', production=False)
            args.update(override)
            with self.subTest(fields=list(override)), self.assertRaises(AuthConfigurationError):
                BrowserConfig(**args)


class DeviceBoundaryTests(unittest.TestCase):
    def test_all_device_operations_are_unconfigured_and_do_not_echo_secrets(self):
        device = UnconfiguredDeviceAuth()
        for call in (device.start, lambda: device.poll('secret-device-code'),
                     lambda: device.refresh('secret-refresh-token'),
                     lambda: device.revoke('secret-refresh-token')):
            with self.assertRaises(AuthUnconfigured) as result:
                call()
            self.assertNotIn('secret', str(result.exception))
        tokens = DeviceTokens('secret-access', 'secret-refresh', 300)
        auth = DeviceAuthorization('secret-device', 'secret-code', 'https://example.test/verify', 300, 5)
        self.assertNotIn('secret', repr(tokens) + repr(auth) + repr(CodeExchangeResult('secret-token')))


if __name__ == '__main__':
    unittest.main()
