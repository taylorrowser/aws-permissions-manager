"""Durable browser-session state, entirely offline with ephemeral encryption keys."""
import unittest,tempfile,os,sqlite3,dataclasses,threading,json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs,urlsplit
from integration.session_store import SQLiteBrowserState,AESGCMRecordCipher
from integration.auth import *
from test_integration_auth import AuthFixtures,OfflineCodeExchange,ORIGIN,ISSUER,WEB,OWNER,SUBJECT,DIGEST

class DurableSessions(AuthFixtures):
    def setUp(self):
        super().setUp();self.tmp=tempfile.TemporaryDirectory();self.path=self.tmp.name+'/browser.db';self.key=os.urandom(32)
    def tearDown(self):self.tmp.cleanup()
    def durable(self,**changes):
        store=SQLiteBrowserState(self.path,cipher=AESGCMRecordCipher(self.key))
        base=self.browser(exchange=OfflineCodeExchange(self.token(self.session_claims())))
        args={'config':base.config,'token_verifier':base.token_verifier,'exchange':base.exchange,'clock':lambda:self.now,'state_store':store}
        args.update(changes);return BrowserAuth(**args)
    def login_durable(self,browser=None):
        browser=browser or self.durable();start=browser.start_login();state=parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        login=browser.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
        return browser,login,browser.human_session(login.session_cookie)
    def dump(self):
        with sqlite3.connect(self.path) as db:return '\n'.join(db.iterdump())
    def test_restart_preserves_session_and_exact_one_use_challenge(self):
        first,login,session=self.login_durable();challenge=first.new_challenge(session,'request-1',1,DIGEST)
        second=self.durable();fresh=second.human_session(login.session_cookie)
        self.assertEqual(second.consume_challenge(fresh,ORIGIN,login.csrf,challenge,'request-1',1,DIGEST).subject,SUBJECT)
        with self.assertRaises(AuthError):first.consume_challenge(session,ORIGIN,login.csrf,challenge,'request-1',1,DIGEST)
    def test_concurrent_challenge_consumption_across_instances_single_effect(self):
        first,login,session=self.login_durable();challenge=first.new_challenge(session,'request-1',1,DIGEST)
        barrier=threading.Barrier(2)
        def attempt():
            b=self.durable();s=b.human_session(login.session_cookie);barrier.wait()
            try:b.consume_challenge(s,ORIGIN,login.csrf,challenge,'request-1',1,DIGEST);return True
            except AuthError:return False
        with ThreadPoolExecutor(2) as pool:a=pool.submit(attempt);b=pool.submit(attempt);self.assertEqual(sum((a.result(),b.result())),1)
    def test_login_state_survives_restart_and_consumes_once_before_exchange(self):
        first=self.durable();start=first.start_login();state=parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        second=self.durable();login=second.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
        self.assertEqual(second.human_session(login.session_cookie).principal.subject,SUBJECT)
        with self.assertRaises(AuthError):first.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
    def test_expired_reads_are_pure_and_cleanup_is_explicit(self):
        b,login,session=self.login_durable();self.now+=1000;before=self.dump()
        with self.assertRaises(AuthError):b.human_session(login.session_cookie)
        self.assertEqual(before,self.dump());self.assertGreater(b.state_store.cleanup_expired(self.now),0)
    def test_ciphertext_cannot_be_swapped_or_tampered(self):
        b,login,session=self.login_durable()
        with sqlite3.connect(self.path) as db:db.execute("UPDATE browser_state SET expires=expires+1 WHERE kind='session'")
        with self.assertRaisesRegex(AuthError,'integrity'):b.human_session(login.session_cookie)
    def test_wrong_record_key_and_identity_context_denied(self):
        b,login,session=self.login_durable()
        wrong=self.durable(state_store=SQLiteBrowserState(self.path,cipher=AESGCMRecordCipher(os.urandom(32))))
        with self.assertRaises(AuthError):wrong.human_session(login.session_cookie)
        vc=dataclasses.replace(b.token_verifier.config,owner_id='different-owner')
        other=self.durable(token_verifier=BearerVerifier(vc,self.jwks,clock=lambda:self.now))
        with self.assertRaises(AuthError):other.human_session(login.session_cookie)
    def test_database_contains_no_plaintext_login_or_csrf_secrets(self):
        b=self.durable();start=b.start_login();state=parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        raw=Path(self.path).read_bytes();self.assertNotIn(state.encode(),raw);self.assertNotIn(start.state_cookie.encode(),raw)
        login=b.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
        raw=Path(self.path).read_bytes();self.assertNotIn(login.csrf.encode(),raw);self.assertNotIn(login.session_cookie.encode(),raw)
        self.assertEqual(os.stat(self.path).st_mode&0o777,0o600);self.assertNotIn(self.key.hex(),repr(b.state_store.cipher))
    def test_logout_invalidates_orphan_challenges_across_restart(self):
        b,login,session=self.login_durable();challenge=b.new_challenge(session,'request-1',1,DIGEST)
        other=self.durable();other.logout(login.session_cookie)
        with self.assertRaises(AuthError):b.consume_challenge(session,ORIGIN,login.csrf,challenge,'request-1',1,DIGEST)
        with self.assertRaises(AuthError):self.durable().human_session(login.session_cookie)
    def test_durable_store_does_not_claim_production_readiness(self):
        b=self.durable()
        with self.assertRaises(AuthUnconfigured):self.durable(config=dataclasses.replace(b.config,origin='https://browser.example',redirect_uri='https://browser.example/auth/callback',production=True))
    def test_lax_database_permissions_are_rejected(self):
        path=self.tmp.name+'/public.db';fd=os.open(path,os.O_CREAT|os.O_WRONLY,0o644);os.close(fd)
        with self.assertRaises(AuthConfigurationError):SQLiteBrowserState(path,cipher=AESGCMRecordCipher(self.key))
    def test_session_without_jti_uses_verified_sid_and_optional_audit_id(self):
        claims=self.session_claims();claims.pop('jti');verified=self.verifier(token_profile='session',audience=None,allowed_client_ids=frozenset([WEB]),machine_client_ids=frozenset(),machine_audience=None).verify_details(self.token(claims))
        self.assertEqual(verified.principal.authentication_id,claims['sid']);self.assertEqual(verified.principal.authentication_kind,'authkit_session');self.assertIsNone(verified.provider_token_id)
    def test_provider_jti_rotation_preserves_verified_typed_sid(self):
        one=self.verifier().verify_details(self.token(jti='provider-id-one'))
        two=self.verifier().verify_details(self.token(jti='provider-id-two'))
        self.assertEqual(one.principal,two.principal);self.assertNotEqual(one.provider_token_id,two.provider_token_id)
        self.assertEqual(one.principal.authentication_kind,'connect_consent');self.assertEqual(one.principal.issuer,ISSUER)
    def test_transaction_reauthentication_binds_exact_revision_and_fresh_auth_time(self):
        b=self.durable();config=dataclasses.replace(b.config,approval_reauth_seconds=120)
        claims=self.session_claims();claims['auth_time']=self.now
        b=self.durable(config=config,exchange=OfflineCodeExchange(self.token(claims)))
        start=b.start_approval_login('request-1',2,DIGEST);state=parse_qs(urlsplit(start.authorization_url).query)['state'][0]
        restarted=self.durable(config=config,exchange=b.exchange)
        login=restarted.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
        session=restarted.human_session(login.session_cookie)
        self.assertEqual(session.approval_binding,('request-1',2,DIGEST))
        challenge=restarted.new_challenge(session,'request-1',2,DIGEST)
        with self.assertRaises(AuthError):restarted.new_challenge(session,'request-1',3,DIGEST)
        with self.assertRaises(AuthError):restarted.new_challenge(session,'other-request',2,DIGEST)
        self.now+=121
        with self.assertRaises(AuthError):restarted.consume_challenge(session,ORIGIN,login.csrf,challenge,'request-1',2,DIGEST)
    def test_old_or_absent_auth_time_cannot_finish_transaction_login(self):
        base=self.durable();config=dataclasses.replace(base.config,approval_reauth_seconds=120)
        for auth_time in (None,self.now-1):
            claims=self.session_claims()
            if auth_time is not None:claims['auth_time']=auth_time
            b=self.durable(config=config,exchange=OfflineCodeExchange(self.token(claims)))
            start=b.start_approval_login('request-1',1,DIGEST);state=parse_qs(urlsplit(start.authorization_url).query)['state'][0]
            with self.assertRaises(AuthError):b.finish_login(code='offline-code',state=state,state_cookie=start.state_cookie)
    def test_unbound_login_does_not_authorize_stepup_approval(self):
        base=self.durable();claims=self.session_claims();claims['auth_time']=self.now
        b=self.durable(config=dataclasses.replace(base.config,approval_reauth_seconds=120),exchange=OfflineCodeExchange(self.token(claims)))
        b,login,session=self.login_durable(b)
        with self.assertRaises(AuthError):b.new_challenge(session,'request-1',1,DIGEST)
    def test_coordinator_trust_binds_issuer_and_session_kind(self):
        from integration.enrollment import CoordinatorEnrollment,StandingTrust,EnrollmentDenied,fresh_key
        principal=self.verifier().verify(self.token());binding={'grant_id':'grant-test','revision':1,'digest':DIGEST,'roles':['role-test'],'not_after':None}
        current={**binding,'state':'active','owner_id':principal.owner_id,'subject':principal.subject,'client_id':principal.client_id}
        trust=StandingTrust(principal.owner_id,principal.subject,principal.client_id,principal.authentication_id,'connection-test',issuer=principal.issuer,authentication_kind=principal.authentication_kind)
        e=CoordinatorEnrollment(self.tmp.name+'/enrollment.db',configured=True,offline_mode=True,trust=(trust,),active_grant=lambda _:current,redeem_url=ORIGIN+'/enrollment/redeem',clock=lambda:self.now)
        _,public=fresh_key();self.assertIsNotNone(e.prepare(principal,public,binding,1200,'trusted-request'))
        for forged in (dataclasses.replace(principal,issuer='https://other-issuer.invalid'),dataclasses.replace(principal,authentication_kind='authkit_session')):
            with self.assertRaises(EnrollmentDenied):e.prepare(forged,public,binding,1200,'forged-request')
