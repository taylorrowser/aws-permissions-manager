"""Memory-only harness checks using the actual SDK adapter plus offline HTTP."""
import dataclasses,io,json,unittest
from contextlib import redirect_stdout,redirect_stderr
from integration.auth_smoke import MemorySmoke,SmokeConfig,SmokeStopped,configured_smoke
from integration.auth import AuthUnconfigured
from integration.workos import WorkOSTransient
from test_production_workos import WorkOSFixtures,NOW,ISSUER,CLIENT,SUBJECT,VERIFY,REFRESH

class SmokeTests(WorkOSFixtures):
    def smoke_config(self):return SmokeConfig(ISSUER,CLIENT,'offline-owner',SUBJECT,VERIFY,'https://api.workos.com/sso/jwks/'+CLIENT,int(self.clock())+3600)
    def harness(self,responses):return MemorySmoke(self.client(responses),self.verifier,self.smoke_config(),clock=self.clock,monotonic=self.clock)
    def login(self,responses):
        smoke=self.harness([(200,self.start_body()),(200,self.token_body()),*responses]);start=smoke.start();self.clock.advance(5);status=smoke.poll();self.assertTrue(status['authenticated']);return smoke,start,status
    def test_default_factory_refuses_live_invocation(self):
        with self.assertRaises(AuthUnconfigured):configured_smoke(self.smoke_config())
    def test_device_code_and_tokens_never_reach_safe_output(self):
        smoke,start,status=self.login([]);serialized=json.dumps([start,status,smoke.status()])+repr(smoke)
        self.assertIn('ABCD-EFGH',serialized);self.assertIn('session_offline_1',serialized)
        for value in ('offline-device-fixture',REFRESH,'access_token','refresh_token','eyJ'):self.assertNotIn(value,serialized)
    def test_pending_slowdown_and_expiry_do_not_dump_responses(self):
        smoke=self.harness([(200,self.start_body()),(400,{'error':'authorization_pending','error_description':'SECRET_MARKER'}),(400,{'error':'slow_down','error_description':'SECRET_MARKER'})]);smoke.start();self.clock.advance(5)
        a=smoke.poll();self.assertEqual(a['phase'],'awaiting_user');self.clock.advance(5);b=smoke.poll();self.assertGreaterEqual(b['next_poll_in'],10)
        self.assertNotIn('SECRET_MARKER',json.dumps([a,b]));self.clock.advance(3601)
        with self.assertRaises(SmokeStopped):smoke.poll()
        self.assertIsNone(smoke._device);self.assertIsNone(smoke._tokens)
    def test_refresh_rotates_without_reporting_tokens(self):
        smoke,_,_=self.login([(200,self.token_body(refresh_token='new-offline-refresh'))])
        result=smoke.refresh();self.assertTrue(result['refresh_verified']);self.assertTrue(result['refresh_rotated']);self.assertNotIn('new-offline-refresh',json.dumps(result))
    def test_provider_exact_invalid_grant_is_revocation_evidence(self):
        smoke,_,_=self.login([(400,{'error':'invalid_grant','error_description':'SECRET_MARKER'})])
        before=len(self.requests);result=smoke.refresh(verify_revoked=True)
        self.assertEqual(len(self.requests),before+1);self.assertEqual(result['phase'],'revocation_confirmed');self.assertTrue(result['provider_refresh_denial_verified']);self.assertIsNone(smoke._tokens)
        self.assertNotIn('SECRET_MARKER',json.dumps(result))
    def test_other_denials_never_claim_revocation(self):
        for status,body in ((403,{'error':'access_denied'}),(400,{'error':'invalid_request'}),(200,{'unexpected':'SECRET_MARKER'})):
            self.clock.value=NOW;smoke,_,_=self.login([(status,body)])
            result=smoke.refresh(verify_revoked=True);self.assertFalse(result['provider_refresh_denial_verified']);self.assertNotEqual(result['phase'],'revocation_confirmed')
    def test_refresh_transient_does_not_extend_signed_authentication(self):
        smoke,_,_=self.login([(503,{'error_description':'SECRET_MARKER'})]);self.clock.advance(301)
        result=smoke.refresh();self.assertEqual(result['phase'],'provider_transient');self.assertTrue(result['session_retained']);self.assertFalse(result['authenticated']);self.assertIsNotNone(smoke._tokens)
    def test_hard_deadline_blocks_further_dispatch_and_discards_memory(self):
        smoke,_,_=self.login([]);before=len(self.requests);self.clock.advance(3601)
        with self.assertRaises(SmokeStopped):smoke.refresh()
        self.assertEqual(len(self.requests),before);self.assertIsNone(smoke._tokens)
    def test_changed_session_is_not_accepted_as_continuity(self):
        smoke,_,_=self.login([(200,self.token_body(access_token=self.token(sid='different-session'),refresh_token='other-refresh'))])
        result=smoke.refresh(verify_revoked=True);self.assertFalse(result['provider_refresh_denial_verified']);self.assertIsNone(smoke._tokens)
    def test_no_file_token_store_or_management_revoke_in_harness(self):
        import ast,pathlib
        source=pathlib.Path(__file__).parents[1].joinpath('integration/auth_smoke.py').read_text();tree=ast.parse(source)
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)]
        self.assertFalse(any(isinstance(c.func,ast.Attribute) and c.func.attr in ('save','write_text','write_bytes','revoke','revoke_session','setxattr') for c in calls))
        self.assertFalse(any(isinstance(c.func,ast.Name) and c.func.id=='TokenStore' for c in calls))
    def test_post_call_deadline_clears_tokens_before_acceptance(self):
        def delayed(request):self.clock.advance(3601);return __import__('httpx').Response(200,json=self.token_body())
        smoke,_,_=self.login([delayed]);before=len(self.requests)
        with self.assertRaises(SmokeStopped):smoke.refresh()
        self.assertEqual(len(self.requests),before+1);self.assertIsNone(smoke._tokens)
    def test_executable_harness_installs_alarm_and_core_dump_guard(self):
        import ast,pathlib
        tree=ast.parse(pathlib.Path(__file__).parents[1].joinpath('integration/auth_smoke.py').read_text())
        attrs={n.func.attr for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute)}
        self.assertIn('setitimer',attrs);self.assertIn('setrlimit',attrs)
    def test_harness_second_validation_retains_rotated_pair_without_reexchange(self):
        smoke,_,_=self.login([(200,self.token_body(refresh_token='harness-rotated-candidate'))])
        base=self.verifier.verify_details;calls=[0]
        def flaky(token):
            calls[0]+=1
            if calls[0]==2:raise WorkOSTransient()
            return base(token)
        self.verifier.verify_details=flaky
        result=smoke.refresh();self.assertEqual(result['phase'],'provider_transient');self.assertIsNotNone(smoke._candidate)
        requests=len(self.requests);self.clock.advance(1);result=smoke.refresh()
        self.assertTrue(result['refresh_verified']);self.assertFalse(result['provider_refresh_attempted']);self.assertEqual(len(self.requests),requests)
        self.assertEqual(smoke._tokens.refresh_token,'harness-rotated-candidate');self.assertNotIn('harness-rotated-candidate',json.dumps(result));self.assertIsNone(smoke._candidate)
    def test_harness_second_validation_retains_device_pair_without_repoll(self):
        smoke=self.harness([(200,self.start_body()),(200,self.token_body())]);smoke.start();self.clock.advance(5)
        base=self.verifier.verify_details;calls=[0]
        def flaky(token):
            calls[0]+=1
            if calls[0]==2:raise WorkOSTransient()
            return base(token)
        self.verifier.verify_details=flaky
        first=smoke.poll();self.assertEqual(first['phase'],'provider_transient');self.assertIsNone(smoke._tokens);self.assertIsNotNone(smoke._candidate)
        requests=len(self.requests);self.clock.advance(1);status=smoke.poll()
        self.assertTrue(status['authenticated']);self.assertEqual(len(self.requests),requests);self.assertIsNone(smoke._candidate)
